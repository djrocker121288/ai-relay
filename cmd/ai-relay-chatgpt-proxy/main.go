// ai-relay-chatgpt-proxy is the public OAuth boundary for a loopback AI Relay.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type client struct {
	Redirects []string
	Secret    string
}
type authCode struct {
	ClientID            string
	Redirect            string
	Resource            string
	CodeChallenge       string
	CodeChallengeMethod string
	Until               time.Time
}
type token struct {
	Until    time.Time
	Resource string
}
type server struct {
	base, upstream, relayToken, approval string
	clientFile                           string
	upstreamClient                       *http.Client
	mu                                   sync.Mutex
	clients                              map[string]client
	codes                                map[string]authCode
	tokens                               map[string]token
}

const (
	maxOAuthFormBytes           = 16 << 10
	maxOAuthBearerBytes         = 4 << 10
	maxOAuthRegistrationBytes   = 64 << 10
	maxOAuthContentTypeBytes    = 256
	maxMCPProxyRequestBytes     = 64 << 10
	maxMCPProxyResponseBytes    = 256 << 10
	maxMCPProxyContentTypeBytes = 256
	// Direct library callers can construct arbitrarily large Header value
	// slices. Authentication and framing only need a singleton-versus-duplicate
	// distinction, so retain at most two matching values before validation.
	maxMCPProxyHeaderValues = 2
	// Normal net/http serving applies wire-level header limits. Direct library
	// callers can otherwise force every case-insensitive lookup to scan an
	// arbitrarily large map or field name before authentication.
	maxMCPProxyHeaderFields    = 256
	maxMCPProxyHeaderNameBytes = 256
	// Framing tokens are short by definition. Bound direct-call inspection
	// before trimming, parsing, or comparing attacker-controlled strings.
	maxMCPProxyFramingValueBytes = 256
	maxMCPProxyUpstreamDuration  = 30 * time.Second
	maxOAuthClientRegistryBytes  = 8 << 20
	maxOAuthClients              = 1024
	maxOAuthCodes                = 4096
	maxOAuthTokens               = 4096
)

func (s *server) loadClients() error {
	if strings.TrimSpace(s.clientFile) == "" {
		return fmt.Errorf("client registry path is required")
	}
	if err := validateClientRegistryPath(s.clientFile); err != nil {
		return err
	}
	f, err := os.Open(s.clientFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open client registry: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxOAuthClientRegistryBytes+1))
	if err != nil {
		return fmt.Errorf("read client registry: %w", err)
	}
	if len(b) > maxOAuthClientRegistryBytes {
		return fmt.Errorf("client registry exceeds %d bytes", maxOAuthClientRegistryBytes)
	}
	var clients map[string]client
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&clients); err != nil {
		return fmt.Errorf("decode client registry: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode client registry: trailing data")
		}
		return fmt.Errorf("decode client registry: %w", err)
	}
	if clients == nil || len(clients) > maxOAuthClients {
		return fmt.Errorf("client registry contains too many clients")
	}
	for id, registered := range clients {
		if strings.TrimSpace(id) == "" || len(id) > maxOAuthBearerBytes || registered.Secret == "" || len(registered.Secret) > maxOAuthBearerBytes || len(registered.Redirects) == 0 {
			return fmt.Errorf("client registry contains an invalid client")
		}
		for _, redirect := range registered.Redirects {
			if !validRedirectURI(redirect) {
				return fmt.Errorf("client registry contains an invalid redirect")
			}
		}
	}
	s.clients = clients
	return nil
}
func (s *server) saveClients() error {
	if strings.TrimSpace(s.clientFile) == "" {
		return fmt.Errorf("client registry path is required")
	}
	if err := validateClientRegistryPath(s.clientFile); err != nil {
		return err
	}
	if len(s.clients) > maxOAuthClients {
		return fmt.Errorf("client registry contains too many clients")
	}
	b, err := json.Marshal(s.clients)
	if err != nil {
		return fmt.Errorf("marshal client registry: %w", err)
	}
	if len(b) > maxOAuthClientRegistryBytes {
		return fmt.Errorf("client registry exceeds %d bytes", maxOAuthClientRegistryBytes)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.clientFile), "."+filepath.Base(s.clientFile)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create client registry replacement: %w", err)
	}
	tmpName := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("protect client registry: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		return fmt.Errorf("write client registry: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync client registry: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close client registry: %w", err)
	}
	if err := validateClientRegistryPath(s.clientFile); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.clientFile); err != nil {
		return fmt.Errorf("replace client registry: %w", err)
	}
	keep = true
	return nil
}

// validateClientRegistryPath keeps persisted client secrets inside a private
// local boundary. Missing registry files are allowed for first registration,
// but existing files must be regular, non-symlink files with no group/other
// permission bits. Existing parents must not be redirected or writable by
// group/other; sticky shared directories such as /tmp remain usable when the
// private directory below them is the ownership boundary. Windows ACLs are not
// represented by portable mode bits and remain a supervisor-host gate.
func validateClientRegistryPath(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	parent, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("validate client registry parent: %w", err)
	}
	for current := filepath.Clean(parent); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if filepath.Dir(current) == current {
				break
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("validate client registry parent: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("client registry parent must be a directory")
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("client registry parent is writable by group or other")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("validate client registry: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("client registry must be a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("client registry must be private")
	}
	return nil
}

func random(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func secret(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		log.Fatal(e)
	}
	return strings.TrimSpace(string(b))
}
func main() {
	listen := flag.String("listen", "127.0.0.1:8788", "loopback listen address")
	base := flag.String("public-base", os.Getenv("AI_RELAY_CHATGPT_PUBLIC_BASE"), "public HTTPS base URL")
	upstream := flag.String("upstream", "http://127.0.0.1:8743", "loopback gateway")
	relayTokenFile := flag.String("relay-token-file", os.Getenv("AI_RELAY_MCP_TOKEN_FILE"), "gateway MCP bearer token file")
	approvalFile := flag.String("approval-file", os.Getenv("AI_RELAY_CHATGPT_APPROVAL_FILE"), "protected one-time approval code file")
	flag.Parse()
	publicBase, err := validatePublicBase(*base)
	if err != nil {
		log.Fatalf("invalid public-base: %v", err)
	}
	loopbackListen, err := validateLoopbackListenAddress(*listen)
	if err != nil {
		log.Fatalf("invalid listen address: %v", err)
	}
	loopbackUpstream, err := validateLoopbackUpstream(*upstream)
	if err != nil {
		log.Fatalf("invalid upstream: %v", err)
	}
	if *relayTokenFile == "" || *approvalFile == "" {
		log.Fatal("token/approval files are required")
	}
	clientFile := *approvalFile + ".clients.json"
	relayToken := secret(*relayTokenFile)
	approval := secret(*approvalFile)
	if relayToken == "" || approval == "" {
		log.Fatal("token/approval files must not be empty")
	}
	s := &server{base: publicBase, upstream: loopbackUpstream, relayToken: relayToken, approval: approval, clientFile: clientFile, clients: map[string]client{}, codes: map[string]authCode{}, tokens: map[string]token{}}
	if err := s.loadClients(); err != nil {
		log.Fatalf("load client registry: %v", err)
	}
	http.HandleFunc("/.well-known/oauth-protected-resource", s.resource)
	http.HandleFunc("/.well-known/oauth-authorization-server", s.metadata)
	http.HandleFunc("/register", s.register)
	http.HandleFunc("/authorize", s.authorize)
	http.HandleFunc("/token", s.exchange)
	http.HandleFunc("/mcp", s.mcp)
	log.Printf("ChatGPT OAuth proxy on %s", loopbackListen)
	log.Fatal(http.ListenAndServe(loopbackListen, nil))
}

func validatePublicBase(raw string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || !validURLPort(u) || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("public base must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	return base, nil
}

func validateLoopbackListenAddress(raw string) (string, error) {
	listen := strings.TrimSpace(raw)
	host, port, err := net.SplitHostPort(listen)
	if err != nil || host == "" {
		return "", fmt.Errorf("listen address must be host:port on loopback")
	}
	if strings.EqualFold(host, "localhost") {
		// localhost is the only hostname accepted here. Resolving arbitrary
		// names during startup would make the bind policy dependent on DNS.
	} else {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", fmt.Errorf("listen address must use localhost or a loopback IP")
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("listen address must use a valid TCP port")
	}
	return listen, nil
}

func validateLoopbackUpstream(raw string) (string, error) {
	upstream := strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" || !validURLPort(u) || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("upstream must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	host := u.Hostname()
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", fmt.Errorf("upstream host must be localhost or a loopback IP")
		}
	}
	return upstream, nil
}

// validURLPort rejects an explicit port outside the TCP range, including zero
// and an empty port after a trailing colon. net/url validates the port's
// decimal grammar but intentionally leaves range validation to callers; these
// URLs are later used as public metadata or as an upstream dial target, so a
// malformed authority must fail before startup or request handling.
func validURLPort(u *url.URL) bool {
	if u == nil {
		return false
	}
	host := u.Host
	port := ""
	hasPort := false
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndexByte(host, ']')
		if end < 0 {
			return false
		}
		if end+1 < len(host) {
			if host[end+1] != ':' {
				return false
			}
			hasPort = true
			port = host[end+2:]
		}
	} else if colon := strings.LastIndexByte(host, ':'); colon >= 0 {
		hasPort = true
		port = host[colon+1:]
	}
	if !hasPort {
		return true
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber >= 1 && portNumber <= 65535
}

func newMCPProxyClient() *http.Client {
	return &http.Client{
		Timeout: maxMCPProxyUpstreamDuration,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func jsonw(w http.ResponseWriter, v any) {
	setOAuthResponseHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// setOAuthResponseHeaders prevents client secrets and bearer tokens returned
// by the OAuth endpoints from being retained by an intermediary or browser.
// The same nosniff policy applies to every JSON response emitted by this
// boundary, including discovery metadata.
func setOAuthResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// setMCPResponseHeaders keeps authenticated, resource-dependent responses
// out of shared caches and prevents content-type confusion at the public
// proxy boundary. The upstream remains responsible for its representation;
// this policy does not broaden the accepted request or response formats.
func setMCPResponseHeaders(w http.ResponseWriter) {
	setOAuthResponseHeaders(w)
	w.Header().Set("Vary", "Authorization")
}

func (s *server) resourceURL() string {
	return strings.TrimRight(s.base, "/") + "/mcp"
}

func oneValue(values url.Values, key string) (string, bool) {
	items, ok := values[key]
	if !ok {
		return "", true
	}
	if len(items) != 1 {
		return "", false
	}
	return items[0], true
}

// pruneOAuthStateLocked bounds the in-memory one-time authorization and
// bearer-token registries even when clients stop before completing a flow.
// The caller must hold s.mu.
func (s *server) pruneOAuthStateLocked(now time.Time) {
	for code, value := range s.codes {
		if !now.Before(value.Until) {
			delete(s.codes, code)
		}
	}
	for access, value := range s.tokens {
		if !now.Before(value.Until) {
			delete(s.tokens, access)
		}
	}
}

// expired uses the same inclusive boundary as pruneOAuthStateLocked. A code
// or token is no longer usable at its expiry instant; keeping this rule in one
// helper prevents acceptance and cleanup from disagreeing at an exact
// timestamp.
func expired(now, until time.Time) bool {
	return !now.Before(until)
}

func (s *server) resource(w http.ResponseWriter, r *http.Request) {
	if !metadataRequest(w, r) {
		return
	}
	if r.Method == http.MethodHead {
		return
	}
	jsonw(w, map[string]any{"resource": s.resourceURL(), "authorization_servers": []string{s.base}, "scopes_supported": []string{"ai_relay"}})
}
func (s *server) metadata(w http.ResponseWriter, r *http.Request) {
	if !metadataRequest(w, r) {
		return
	}
	if r.Method == http.MethodHead {
		return
	}
	jsonw(w, map[string]any{"issuer": s.base, "authorization_endpoint": s.base + "/authorize", "token_endpoint": s.base + "/token", "registration_endpoint": s.base + "/register", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "token_endpoint_auth_methods_supported": []string{"client_secret_post"}, "code_challenge_methods_supported": []string{"S256"}})
}

// metadataRequest keeps the discovery surface read-only and prevents an
// intermediary from caching a response without the security headers that
// describe this dynamic, deployment-specific resource. HEAD is accepted for
// ordinary HTTP metadata probes but never emits a body.
func metadataRequest(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func validPKCEChallenge(challenge, method string) bool {
	if challenge == "" {
		return method == ""
	}
	if method != "S256" || len(challenge) < 43 || len(challenge) > 128 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size
}

func verifyPKCE(challenge, verifier string) bool {
	if challenge == "" || !validPKCEVerifier(verifier) {
		return challenge == "" && verifier == ""
	}
	digest := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		c := verifier[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	return true
}

func parseForm(r *http.Request) (url.Values, error) {
	if r == nil || r.URL == nil {
		return nil, fmt.Errorf("request is required")
	}
	if !validDirectHeaderMap(r.Header) {
		return nil, fmt.Errorf("request headers exceed direct-call bounds")
	}
	if !validRequestFraming(r) || r.ContentLength < -1 {
		return nil, fmt.Errorf("invalid request framing")
	}
	values := r.URL.Query()
	if r.Body == nil {
		return values, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxOAuthFormBytes+1))
	if err != nil || len(body) > maxOAuthFormBytes {
		return nil, fmt.Errorf("form body exceeds limit")
	}
	if r.ContentLength < -1 || (r.ContentLength >= 0 && int64(len(body)) != r.ContentLength) {
		return nil, fmt.Errorf("invalid request framing")
	}
	if len(body) == 0 {
		return values, nil
	}
	contentTypeValues := headerValuesCaseInsensitive(r.Header, "Content-Type")
	if len(contentTypeValues) != 1 || len(contentTypeValues[0]) > maxOAuthContentTypeBytes {
		return nil, fmt.Errorf("ambiguous content type")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypeValues[0])
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("form content type required")
	}
	bodyValues, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("invalid form body")
	}
	for key, items := range bodyValues {
		values[key] = append(values[key], items...)
	}
	return values, nil
}

func parseJSONBody(r *http.Request, dst any) error {
	if r == nil || r.Body == nil {
		return fmt.Errorf("request body is required")
	}
	if !validDirectHeaderMap(r.Header) {
		return fmt.Errorf("request headers exceed direct-call bounds")
	}
	if !validRequestFraming(r) {
		return fmt.Errorf("invalid request framing")
	}
	contentTypeValues := headerValuesCaseInsensitive(r.Header, "Content-Type")
	if len(contentTypeValues) == 0 {
		return fmt.Errorf("content type required")
	}
	if len(contentTypeValues) != 1 || len(contentTypeValues[0]) > maxOAuthContentTypeBytes {
		return fmt.Errorf("ambiguous content type")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypeValues[0])
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("json content type required")
	}
	if r.ContentLength < -1 {
		return fmt.Errorf("invalid request framing")
	}
	if r.ContentLength > maxOAuthRegistrationBytes {
		return fmt.Errorf("request body exceeds limit")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxOAuthRegistrationBytes+1))
	if err != nil || len(body) > maxOAuthRegistrationBytes {
		return fmt.Errorf("request body exceeds limit")
	}
	if r.ContentLength >= 0 && int64(len(body)) != r.ContentLength {
		return fmt.Errorf("invalid request framing")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid json")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing json")
	}
	return nil
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || strings.Contains(raw, "#") {
		return false
	}
	return true
}

// headerValuesCaseInsensitive mirrors net/http's header-name semantics while
// also handling direct callers that construct a Header map without first
// canonicalizing its keys. A differently cased duplicate must remain visible
// to this boundary instead of being hidden by Header.Values' canonical lookup.
func headerValuesCaseInsensitive(header http.Header, name string) []string {
	var values []string
	for key, entries := range header {
		if strings.EqualFold(key, name) {
			remaining := maxMCPProxyHeaderValues - len(values)
			if remaining <= 0 {
				return values
			}
			if len(entries) > remaining {
				return append(values, entries[:remaining]...)
			}
			values = append(values, entries...)
		}
	}
	return values
}

func headerNamePresentCaseInsensitive(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

// validRequestFraming accepts the framing net/http presents for a normal
// request: no transfer-coding metadata, or one final chunked coding paired
// with the standard library's unknown-length sentinel. Direct callers can
// construct ambiguous metadata that an intermediary would interpret
// differently, so reject it before reading or forwarding an authenticated
// request.
func validRequestFraming(r *http.Request) bool {
	if r == nil || !validDirectHeaderMap(r.Header) {
		return false
	}
	// net/http normally consumes these fields from the wire and leaves their
	// parsed values on Request. Direct callers can construct a Header map
	// independently, though; reject raw metadata that is duplicated, malformed,
	// or inconsistent with the parsed request boundary.
	contentLengthHeaders := headerValuesCaseInsensitive(r.Header, "Content-Length")
	if headerNamePresentCaseInsensitive(r.Header, "Content-Length") && len(contentLengthHeaders) == 0 {
		return false
	}
	if len(contentLengthHeaders) > 1 {
		return false
	}
	if len(contentLengthHeaders) == 1 {
		if len(contentLengthHeaders[0]) > maxMCPProxyFramingValueBytes {
			return false
		}
		rawLength := strings.TrimSpace(contentLengthHeaders[0])
		if rawLength == "" {
			return false
		}
		for index := 0; index < len(rawLength); index++ {
			if rawLength[index] < '0' || rawLength[index] > '9' {
				return false
			}
		}
		declared, err := strconv.ParseInt(rawLength, 10, 64)
		if err != nil || declared != r.ContentLength {
			return false
		}
	}
	transferEncodingHeaders := headerValuesCaseInsensitive(r.Header, "Transfer-Encoding")
	if headerNamePresentCaseInsensitive(r.Header, "Transfer-Encoding") && len(transferEncodingHeaders) == 0 {
		return false
	}
	if len(transferEncodingHeaders) > 0 {
		if len(transferEncodingHeaders[0]) > maxMCPProxyFramingValueBytes {
			return false
		}
		if len(transferEncodingHeaders) != 1 || len(r.TransferEncoding) != 1 ||
			!strings.EqualFold(strings.TrimSpace(transferEncodingHeaders[0]), "chunked") {
			return false
		}
	}
	if len(r.TransferEncoding) == 0 {
		return true
	}
	if len(r.TransferEncoding[0]) > maxMCPProxyFramingValueBytes {
		return false
	}
	return len(r.TransferEncoding) == 1 &&
		strings.EqualFold(r.TransferEncoding[0], "chunked") &&
		r.ContentLength == -1
}

// validDirectHeaderMap bounds field-name inspection for direct library
// callers. Normal net/http serving applies wire-level header-name limits, but
// an in-process caller can construct a map with a small number of enormous
// keys and otherwise force every case-insensitive lookup to scan them.
func validDirectHeaderMap(header http.Header) bool {
	if len(header) > maxMCPProxyHeaderFields {
		return false
	}
	for key := range header {
		if len(key) > maxMCPProxyHeaderNameBytes {
			return false
		}
	}
	return true
}

// closeRequestBody contains a malformed direct caller's Close implementation.
// net/http normally owns request-body cleanup, but these handlers are also
// exercised directly by the supervisor and future library integrations. A
// cleanup panic must not escape after an OAuth response has been written.
func closeRequestBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	_ = body.Close()
}

func requestBodyCleanup(r *http.Request) func() {
	if r == nil || r.Body == nil {
		return func() {}
	}
	body := r.Body
	return func() { closeRequestBody(body) }
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	setOAuthResponseHeaders(w)
	if r == nil || r.URL == nil {
		http.Error(w, "request", http.StatusBadRequest)
		return
	}
	defer requestBodyCleanup(r)()
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	var q struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if parseJSONBody(r, &q) != nil || len(q.RedirectURIs) == 0 {
		http.Error(w, "invalid redirect_uris", 400)
		return
	}
	for _, v := range q.RedirectURIs {
		if !validRedirectURI(v) {
			http.Error(w, "HTTPS redirect required", 400)
			return
		}
	}
	id, sec := random(18), random(32)
	s.mu.Lock()
	if len(s.clients) >= maxOAuthClients {
		s.mu.Unlock()
		http.Error(w, "client registration unavailable", http.StatusServiceUnavailable)
		return
	}
	s.clients[id] = client{q.RedirectURIs, sec}
	if err := s.saveClients(); err != nil {
		delete(s.clients, id)
		s.mu.Unlock()
		http.Error(w, "client registration unavailable", http.StatusInternalServerError)
		return
	}
	s.mu.Unlock()
	jsonw(w, map[string]any{"client_id": id, "client_secret": sec, "redirect_uris": q.RedirectURIs, "token_endpoint_auth_method": "client_secret_post"})
}

var page = template.Must(template.New("p").Parse(`<!doctype html><title>Authorize AI Relay</title><h1>Authorize AI Relay</h1><p>Enter the local installation approval code to allow this ChatGPT connection.</p><form method="post"><input type="hidden" name="client_id" value="{{.Client}}"><input type="hidden" name="redirect_uri" value="{{.Redirect}}"><input type="hidden" name="resource" value="{{.Resource}}"><input type="hidden" name="state" value="{{.State}}"><input type="hidden" name="code_challenge" value="{{.CodeChallenge}}"><input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}"><label>Approval code <input name="approval_code" autofocus></label><button>Authorize</button></form>`))

func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	setOAuthResponseHeaders(w)
	if r == nil || r.URL == nil {
		http.Error(w, "request", http.StatusBadRequest)
		return
	}
	defer requestBodyCleanup(r)()
	if r.Method == "GET" {
		q := r.URL.Query()
		clientID, clientOK := oneValue(q, "client_id")
		redirect, redirectOK := oneValue(q, "redirect_uri")
		challenge, challengeOK := oneValue(q, "code_challenge")
		method, methodOK := oneValue(q, "code_challenge_method")
		resource, resourceOK := oneValue(q, "resource")
		state, stateOK := oneValue(q, "state")
		if !clientOK || !redirectOK || !challengeOK || !methodOK || !resourceOK || !stateOK || (resource != "" && resource != s.resourceURL()) || !s.validClient(clientID, redirect) || !validPKCEChallenge(challenge, method) {
			http.Error(w, "invalid client", 400)
			return
		}
		page.Execute(w, map[string]string{"Client": clientID, "Redirect": redirect, "Resource": s.resourceURL(), "State": state, "CodeChallenge": challenge, "CodeChallengeMethod": method})
		return
	}
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	form, err := parseForm(r)
	if err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	id, idOK := oneValue(form, "client_id")
	redirect, redirectOK := oneValue(form, "redirect_uri")
	resource, resourceOK := oneValue(form, "resource")
	challenge, challengeOK := oneValue(form, "code_challenge")
	method, methodOK := oneValue(form, "code_challenge_method")
	approval, approvalOK := oneValue(form, "approval_code")
	state, stateOK := oneValue(form, "state")
	if !idOK || !redirectOK || !resourceOK || !challengeOK || !methodOK || !approvalOK || !stateOK || (resource != "" && resource != s.resourceURL()) || !s.validClient(id, redirect) || !validPKCEChallenge(challenge, method) || subtle.ConstantTimeCompare([]byte(approval), []byte(s.approval)) != 1 {
		http.Error(w, "authorization denied", 403)
		return
	}
	resource = s.resourceURL()
	code := random(24)
	s.mu.Lock()
	s.pruneOAuthStateLocked(time.Now())
	if len(s.codes) >= maxOAuthCodes {
		s.mu.Unlock()
		http.Error(w, "authorization temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	s.codes[code] = authCode{ClientID: id, Redirect: redirect, Resource: resource, CodeChallenge: challenge, CodeChallengeMethod: method, Until: time.Now().Add(5 * time.Minute)}
	s.mu.Unlock()
	u, _ := url.Parse(redirect)
	q := u.Query()
	q.Set("code", code)
	// Preserve the caller's CSRF correlation value from the bounded form we
	// actually parsed. parseForm intentionally does not mutate r.Form, so
	// reading r.Form here would silently drop state on the approval redirect.
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), 302)
}
func (s *server) validClient(id, redirect string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return false
	}
	for _, v := range c.Redirects {
		if v == redirect {
			return true
		}
	}
	return false
}
func (s *server) exchange(w http.ResponseWriter, r *http.Request) {
	setOAuthResponseHeaders(w)
	if r == nil || r.URL == nil {
		http.Error(w, "request", http.StatusBadRequest)
		return
	}
	defer requestBodyCleanup(r)()
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	form, err := parseForm(r)
	if err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	id, idOK := oneValue(form, "client_id")
	sec, secOK := oneValue(form, "client_secret")
	code, codeOK := oneValue(form, "code")
	verifier, verifierOK := oneValue(form, "code_verifier")
	requestedResource, resourceOK := oneValue(form, "resource")
	s.mu.Lock()
	c, ok := s.clients[id]
	ac, found := s.codes[code]
	delete(s.codes, code)
	s.mu.Unlock()
	resource := requestedResource
	if found && ac.Resource != "" {
		if resource != "" && resource != ac.Resource {
			resourceOK = false
		}
		resource = ac.Resource
	} else if resource != "" && resource != s.resourceURL() {
		resourceOK = false
	} else {
		// Legacy in-memory authorization codes did not carry a resource. Bind
		// their compatibility token to this proxy's only protected resource.
		resource = s.resourceURL()
	}
	if !idOK || !secOK || !codeOK || !verifierOK || !resourceOK || !ok || !found || ac.ClientID != id || expired(time.Now(), ac.Until) || subtle.ConstantTimeCompare([]byte(sec), []byte(c.Secret)) != 1 || !verifyPKCE(ac.CodeChallenge, verifier) {
		http.Error(w, "invalid grant", 400)
		return
	}
	access := random(32)
	s.mu.Lock()
	s.pruneOAuthStateLocked(time.Now())
	if len(s.tokens) >= maxOAuthTokens {
		s.mu.Unlock()
		http.Error(w, "token issuance temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	s.tokens[access] = token{Until: time.Now().Add(12 * time.Hour), Resource: resource}
	s.mu.Unlock()
	jsonw(w, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 43200, "scope": "ai_relay"})
}

func bearerToken(r *http.Request) (string, bool) {
	if r == nil || !validDirectHeaderMap(r.Header) {
		return "", false
	}
	values := headerValuesCaseInsensitive(r.Header, "Authorization")
	if len(values) != 1 || len(values[0]) > maxOAuthBearerBytes {
		return "", false
	}
	const prefix = "Bearer "
	if len(values[0]) < len(prefix) || !strings.EqualFold(values[0][:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(values[0][len(prefix):])
	return token, token != ""
}

func (s *server) mcp(w http.ResponseWriter, r *http.Request) {
	setMCPResponseHeaders(w)
	if r == nil || r.URL == nil {
		http.Error(w, "request", http.StatusBadRequest)
		return
	}
	defer requestBodyCleanup(r)()
	if !validDirectHeaderMap(r.Header) {
		http.Error(w, "request headers", http.StatusBadRequest)
		return
	}
	auth, valid := bearerToken(r)
	s.mu.Lock()
	t, ok := s.tokens[auth]
	s.mu.Unlock()
	if !valid || !ok || expired(time.Now(), t.Until) || (t.Resource != "" && t.Resource != s.resourceURL()) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, s.base))
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !validRequestFraming(r) {
		http.Error(w, "request framing", http.StatusBadRequest)
		return
	}
	contentTypeValues := headerValuesCaseInsensitive(r.Header, "Content-Type")
	if len(contentTypeValues) == 0 {
		http.Error(w, "content type", http.StatusUnsupportedMediaType)
		return
	}
	if len(contentTypeValues) != 1 || len(contentTypeValues[0]) > maxMCPProxyContentTypeBytes {
		http.Error(w, "content type", http.StatusBadRequest)
		return
	}
	mediaType, _, e := mime.ParseMediaType(contentTypeValues[0])
	if e != nil || mediaType != "application/json" {
		http.Error(w, "content type", http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength < -1 {
		http.Error(w, "request framing", http.StatusBadRequest)
		return
	}
	if r.ContentLength > maxMCPProxyRequestBytes {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	if r.Body == nil {
		http.Error(w, "request body", http.StatusBadRequest)
		return
	}
	upstream, e := validateLoopbackUpstream(s.upstream)
	if e != nil {
		http.Error(w, "upstream", http.StatusBadGateway)
		return
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, maxMCPProxyRequestBytes+1))
	if e != nil {
		http.Error(w, "request body", http.StatusBadRequest)
		return
	}
	if len(body) > maxMCPProxyRequestBytes {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	if r.ContentLength >= 0 && int64(len(body)) != r.ContentLength {
		http.Error(w, "request framing", http.StatusBadRequest)
		return
	}
	req, e := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream+"/mcp", bytes.NewReader(body))
	if e != nil {
		http.Error(w, "upstream", 502)
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.relayToken)
	req.Header.Set("Content-Type", contentTypeValues[0])
	client := s.upstreamClient
	if client == nil {
		client = newMCPProxyClient()
	}
	resp, e := client.Do(req)
	if e != nil {
		http.Error(w, "upstream", 502)
		return
	}
	defer resp.Body.Close()
	responseBody, e := io.ReadAll(io.LimitReader(resp.Body, maxMCPProxyResponseBytes+1))
	if e != nil {
		http.Error(w, "upstream", 502)
		return
	}
	if len(responseBody) > maxMCPProxyResponseBytes {
		http.Error(w, "upstream response too large", 502)
		return
	}
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(responseBody)
}
