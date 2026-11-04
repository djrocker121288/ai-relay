package arpl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	relayHeaderPair      = "X-ARPL-Pair"
	relayHeaderRole      = "X-ARPL-Role"
	relayHeaderEndpoint  = "X-ARPL-Endpoint"
	relayHeaderDirection = "X-ARPL-Direction"
	relayHeaderPublicKey = "X-ARPL-Public-Key"
	relayHeaderTimestamp = "X-ARPL-Timestamp"
	relayHeaderNonce     = "X-ARPL-Nonce"
	relayHeaderSignature = "X-ARPL-Signature"
)

type HTTPRelayTransport struct {
	URL               string
	PairID            string
	Token             string
	Identity          Identity
	Client            *http.Client
	AllowInsecureHTTP bool
}

func (t HTTPRelayTransport) Dial(ctx context.Context) (net.Conn, error) {
	return openHTTPRelayConn(ctx, t.Client, t.URL, t.PairID, "dial", t.Token, t.Identity, t.AllowInsecureHTTP)
}

type HTTPRelayListener struct {
	URL               string
	PairID            string
	Token             string
	Identity          Identity
	Client            *http.Client
	AllowInsecureHTTP bool

	once   sync.Once
	closed chan struct{}
	slot   chan struct{}
}

func NewHTTPRelayListener(rawURL, pairID, token string, client *http.Client, allowInsecureHTTP bool) (*HTTPRelayListener, error) {
	if err := validateRelayURL(rawURL, allowInsecureHTTP); err != nil {
		return nil, err
	}
	if err := validatePairID(pairID); err != nil {
		return nil, err
	}
	l := &HTTPRelayListener{
		URL: rawURL, PairID: pairID, Token: token, Client: client,
		AllowInsecureHTTP: allowInsecureHTTP,
		closed:            make(chan struct{}),
		slot:              make(chan struct{}, 1),
	}
	l.slot <- struct{}{}
	return l, nil
}

func (l *HTTPRelayListener) Accept() (net.Conn, error) {
	if l == nil || l.closed == nil || l.slot == nil {
		return nil, net.ErrClosed
	}
	// One relay pair represents one persistent device-to-device logical link.
	// Generic servers call Accept again immediately after a connection is
	// accepted, so serialize Accept calls until the live relay connection
	// closes rather than registering a competing accept endpoint (HTTP 409).
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.slot:
	}
	release := func() {
		select {
		case l.slot <- struct{}{}:
		default:
		}
	}
	select {
	case <-l.closed:
		release()
		return nil, net.ErrClosed
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-l.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	backoff := 50 * time.Millisecond
	for {
		conn, err := openHTTPRelayConn(ctx, l.Client, l.URL, l.PairID, "accept", l.Token, l.Identity, l.AllowInsecureHTTP)
		if err == nil {
			return &cancelConn{Conn: conn, cancel: cancel, onClose: release}, nil
		}
		select {
		case <-l.closed:
			cancel()
			release()
			return nil, net.ErrClosed
		case <-ctx.Done():
			cancel()
			release()
			return nil, net.ErrClosed
		case <-time.After(backoff):
		}
		if backoff < 2*time.Second {
			backoff *= 2
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
		}
	}
}

func (l *HTTPRelayListener) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.closed != nil {
			close(l.closed)
		}
	})
	return nil
}

func (l *HTTPRelayListener) Addr() net.Addr {
	if l == nil {
		return relayAddr("relay")
	}
	return relayAddr(l.URL)
}

type cancelConn struct {
	net.Conn
	once    sync.Once
	cancel  context.CancelFunc
	onClose func()
}

func (c *cancelConn) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		if c.Conn != nil {
			err = c.Conn.Close()
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func NewRelayPairID() (string, error) {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func DeterministicRelayPairID(clientDeviceID, hostDeviceID string) (string, error) {
	clientDeviceID = strings.ToLower(strings.TrimSpace(clientDeviceID))
	hostDeviceID = strings.ToLower(strings.TrimSpace(hostDeviceID))
	if len(clientDeviceID) != 64 || len(hostDeviceID) != 64 {
		return "", errors.New("ARPL device IDs must be 32-byte hex")
	}
	if _, err := hex.DecodeString(clientDeviceID); err != nil {
		return "", errors.New("invalid client device ID")
	}
	if _, err := hex.DecodeString(hostDeviceID); err != nil {
		return "", errors.New("invalid host device ID")
	}
	sum := sha256.Sum256([]byte("ARPL relay pair v1\x00" + clientDeviceID + "\x00" + hostDeviceID))
	return hex.EncodeToString(sum[:]), nil
}

func validatePairID(pair string) error {
	if len(pair) != 64 {
		return errors.New("ARPL relay pair ID must be 32-byte hex")
	}
	b, err := hex.DecodeString(pair)
	if err != nil || len(b) != 32 {
		return errors.New("ARPL relay pair ID must be 32-byte hex")
	}
	return nil
}

func validateEndpointID(endpoint string) bool {
	if len(endpoint) != 32 {
		return false
	}
	b, err := hex.DecodeString(endpoint)
	return err == nil && len(b) == 16
}

const relayStreamPrefaceSize = 4096
const relayStreamPrefaceMagic = "ARPL-RELAY-STREAM-v1\n"

func makeRelayStreamPreface() []byte {
	b := make([]byte, relayStreamPrefaceSize)
	copy(b, []byte(relayStreamPrefaceMagic))
	for i := len(relayStreamPrefaceMagic); i < len(b); i++ {
		b[i] = 0xa5
	}
	return b
}

func writeRelayStreamPreface(w io.Writer) error {
	_, err := w.Write(makeRelayStreamPreface())
	return err
}

func readRelayStreamPreface(r io.Reader) error {
	b := make([]byte, relayStreamPrefaceSize)
	if _, err := io.ReadFull(r, b); err != nil {
		return fmt.Errorf("ARPL relay stream preface: %w", err)
	}
	if string(b[:len(relayStreamPrefaceMagic)]) != relayStreamPrefaceMagic {
		return errors.New("invalid ARPL relay stream preface")
	}
	for _, v := range b[len(relayStreamPrefaceMagic):] {
		if v != 0xa5 {
			return errors.New("invalid ARPL relay stream preface padding")
		}
	}
	return nil
}

func validateRelayURL(rawURL string, allowInsecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return errors.New("invalid ARPL relay URL")
	}
	if u.Scheme != "https" && !(allowInsecure && u.Scheme == "http") {
		return errors.New("ARPL relay URL must use https")
	}
	return nil
}

type httpRelayConn struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc
	once   sync.Once
	local  net.Addr
	remote net.Addr

	postDone chan struct{}
	postMu   sync.Mutex
	postErr  error
}

func (c *httpRelayConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *httpRelayConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *httpRelayConn) Close() error {
	var err error
	c.once.Do(func() {
		// Gracefully finish the streaming upload first. io.Pipe.Write only
		// guarantees that the HTTP transport consumed the bytes locally; it
		// does not guarantee that they have reached the relay peer. Closing
		// the writer and waiting for the POST response gives the relay a chance
		// to drain all final ARPL bytes before request cancellation.
		_ = c.writer.Close()
		if c.postDone != nil {
			select {
			case <-c.postDone:
			case <-time.After(3 * time.Second):
			}
		}
		if c.cancel != nil {
			c.cancel()
		}
		err = c.reader.Close()
		c.postMu.Lock()
		if err == nil && c.postErr != nil {
			err = c.postErr
		}
		c.postMu.Unlock()
	})
	return err
}
func (c *httpRelayConn) LocalAddr() net.Addr              { return c.local }
func (c *httpRelayConn) RemoteAddr() net.Addr             { return c.remote }
func (c *httpRelayConn) SetDeadline(time.Time) error      { return nil }
func (c *httpRelayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *httpRelayConn) SetWriteDeadline(time.Time) error { return nil }

type relayAddr string

func (a relayAddr) Network() string { return "https-relay" }
func (a relayAddr) String() string  { return string(a) }

func openHTTPRelayConn(parent context.Context, client *http.Client, rawURL, pairID, role, token string, identity Identity, allowInsecure bool) (net.Conn, error) {
	if err := validateRelayURL(rawURL, allowInsecure); err != nil {
		return nil, err
	}
	if err := validatePairID(pairID); err != nil {
		return nil, err
	}
	if role != "dial" && role != "accept" {
		return nil, errors.New("invalid ARPL relay role")
	}
	if client == nil {
		client = &http.Client{Transport: http.DefaultTransport}
	}
	endpointBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, endpointBytes); err != nil {
		return nil, err
	}
	endpoint := hex.EncodeToString(endpointBytes)
	ctx, cancel := context.WithCancel(parent)

	pr, pw := io.Pipe()
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, pr)
	if err != nil {
		cancel()
		return nil, err
	}
	if err = setRelayHeaders(postReq, pairID, role, endpoint, "send", token, identity); err != nil {
		cancel()
		_ = pw.Close()
		return nil, err
	}
	postReq.Header.Set("Content-Type", "application/octet-stream")
	postDone := make(chan struct{})
	var postMu sync.Mutex
	var postResult error
	go func() {
		defer close(postDone)
		resp, doErr := client.Do(postReq)
		if doErr != nil {
			_ = pr.CloseWithError(doErr)
			postMu.Lock()
			postResult = doErr
			postMu.Unlock()
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			doErr = fmt.Errorf("ARPL relay send rejected: HTTP %d", resp.StatusCode)
			_ = pr.CloseWithError(doErr)
		}
		postMu.Lock()
		postResult = doErr
		postMu.Unlock()
	}()

	// Force an initial request-body chunk through reverse proxies before
	// opening the receive half. The relay origin consumes this transport
	// preface; it never reaches the ARPL handshake or encrypted frame layer.
	if err = writeRelayStreamPreface(pw); err != nil {
		cancel()
		_ = pw.Close()
		return nil, err
	}

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		cancel()
		_ = pw.Close()
		return nil, err
	}
	if err = setRelayHeaders(getReq, pairID, role, endpoint, "recv", token, identity); err != nil {
		cancel()
		_ = pw.Close()
		return nil, err
	}
	resp, err := client.Do(getReq)
	if err != nil {
		cancel()
		_ = pw.Close()
		select {
		case <-postDone:
			postMu.Lock()
			postFailure := postResult
			postMu.Unlock()
			if postFailure != nil {
				return nil, postFailure
			}
		default:
		}
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("ARPL relay receive rejected: HTTP %d", resp.StatusCode)
	}
	if err = readRelayStreamPreface(resp.Body); err != nil {
		cancel()
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, err
	}

	u, _ := url.Parse(rawURL)
	conn := &httpRelayConn{
		reader: resp.Body, writer: pw, cancel: cancel,
		local: relayAddr(role + ":" + endpoint), remote: relayAddr(u.Host),
		postDone: postDone,
	}
	// Copy the upload result into connection-owned state after completion.
	// We intentionally do not auto-close the connection here: a failed POST
	// closes the pipe reader with that error, so the next Write/heartbeat
	// observes the failure and the resident reconnect loop takes over.
	go func() {
		<-postDone
		postMu.Lock()
		e := postResult
		postMu.Unlock()
		conn.postMu.Lock()
		conn.postErr = e
		conn.postMu.Unlock()
	}()
	return conn, nil
}

func relaySignaturePayload(method, path, pairID, role, endpoint, direction, timestamp, nonce string) []byte {
	return []byte(strings.Join([]string{
		"ARPL relay request v1",
		method, path, pairID, role, endpoint, direction, timestamp, nonce,
	}, "\n"))
}

func setRelayHeaders(req *http.Request, pairID, role, endpoint, direction, token string, identity Identity) error {
	req.Header.Set(relayHeaderPair, pairID)
	req.Header.Set(relayHeaderRole, role)
	req.Header.Set(relayHeaderEndpoint, endpoint)
	req.Header.Set(relayHeaderDirection, direction)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
	if err := identity.Validate(); err != nil {
		return errors.New("ARPL relay requires bearer token or valid device identity")
	}
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := hex.EncodeToString(nonceBytes)
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	payload := relaySignaturePayload(req.Method, path, pairID, role, endpoint, direction, ts, nonce)
	sig := ed25519.Sign(identity.PrivateKey, payload)
	req.Header.Set(relayHeaderPublicKey, base64.RawStdEncoding.EncodeToString(identity.PublicKey))
	req.Header.Set(relayHeaderTimestamp, ts)
	req.Header.Set(relayHeaderNonce, nonce)
	req.Header.Set(relayHeaderSignature, base64.RawStdEncoding.EncodeToString(sig))
	return nil
}

type HTTPRelayHub struct {
	Token       string
	Peers       *PeerRegistry
	MaxPairs    int
	IdleTimeout time.Duration
	AuthSkew    time.Duration

	mu         sync.Mutex
	pairs      map[string]*relayPair
	seenNonces map[string]time.Time
}

type relayPair struct {
	roles map[string]*relayEndpoint
}

type relayEndpoint struct {
	id   string
	send *relaySendHalf
	recv *relayRecvHalf
}

type relaySendHalf struct {
	body io.ReadCloser
	done chan struct{}
	once sync.Once
}

type relayRecvHalf struct {
	w       http.ResponseWriter
	flusher http.Flusher
	done    chan struct{}
	once    sync.Once
	paired  chan struct{}

	// Pair metadata is assigned while h.mu is held. The receive HTTP handler
	// performs io.Copy itself after paired is closed, so ResponseWriter is
	// never used from a goroutine after ServeHTTP returns.
	source       io.ReadCloser
	send         *relaySendHalf
	sendRole     string
	sendEndpoint string
}

func NewHTTPRelayHub(token string) *HTTPRelayHub {
	return &HTTPRelayHub{Token: token, MaxPairs: 1024, IdleTimeout: 2 * time.Minute, AuthSkew: 90 * time.Second, pairs: map[string]*relayPair{}, seenNonces: map[string]time.Time{}}
}

func (h *HTTPRelayHub) verifySignedRequest(r *http.Request, pairID, role, endpointID, direction string) error {
	if h.Peers == nil {
		return errors.New("signed relay authentication is not configured")
	}
	pubBytes, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(r.Header.Get(relayHeaderPublicKey)))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("invalid relay public key")
	}
	pub := ed25519.PublicKey(pubBytes)
	deviceID := DeviceID(pub)
	if err = h.Peers.Check(deviceID, pub); err != nil {
		return err
	}
	tsRaw := strings.TrimSpace(r.Header.Get(relayHeaderTimestamp))
	tsUnix, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return errors.New("invalid relay timestamp")
	}
	skew := h.AuthSkew
	if skew <= 0 {
		skew = 90 * time.Second
	}
	now := time.Now()
	ts := time.Unix(tsUnix, 0)
	if ts.Before(now.Add(-skew)) || ts.After(now.Add(skew)) {
		return errors.New("relay timestamp outside allowed window")
	}
	nonce := strings.ToLower(strings.TrimSpace(r.Header.Get(relayHeaderNonce)))
	if !validateEndpointID(nonce) {
		return errors.New("invalid relay nonce")
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(r.Header.Get(relayHeaderSignature)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid relay signature")
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	payload := relaySignaturePayload(r.Method, path, pairID, role, endpointID, direction, tsRaw, nonce)
	if !ed25519.Verify(pub, payload, sig) {
		return errors.New("relay signature verification failed")
	}
	cacheKey := deviceID + "\x00" + nonce
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seenNonces == nil {
		h.seenNonces = map[string]time.Time{}
	}
	for k, expiry := range h.seenNonces {
		if now.After(expiry) {
			delete(h.seenNonces, k)
		}
	}
	if _, exists := h.seenNonces[cacheKey]; exists {
		return errors.New("relay request replay detected")
	}
	h.seenNonces[cacheKey] = now.Add(2 * skew)
	return nil
}

func (h *HTTPRelayHub) Handler() http.Handler {
	return http.HandlerFunc(h.serveHTTP)
}

func (h *HTTPRelayHub) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil {
		http.Error(w, "relay unavailable", http.StatusServiceUnavailable)
		return
	}
	pairID := strings.ToLower(strings.TrimSpace(r.Header.Get(relayHeaderPair)))
	role := strings.ToLower(strings.TrimSpace(r.Header.Get(relayHeaderRole)))
	endpointID := strings.ToLower(strings.TrimSpace(r.Header.Get(relayHeaderEndpoint)))
	direction := strings.ToLower(strings.TrimSpace(r.Header.Get(relayHeaderDirection)))
	if validatePairID(pairID) != nil || (role != "dial" && role != "accept") || !validateEndpointID(endpointID) || (direction != "send" && direction != "recv") {
		http.Error(w, "invalid relay headers", http.StatusBadRequest)
		return
	}
	if h.Token != "" {
		want := "Bearer " + h.Token
		got := r.Header.Get("Authorization")
		if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	} else if err := h.verifySignedRequest(r, pairID, role, endpointID, direction); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if direction == "send" && r.Method != http.MethodPost {
		http.Error(w, "send requires POST", http.StatusMethodNotAllowed)
		return
	}
	if direction == "recv" && r.Method != http.MethodGet {
		http.Error(w, "recv requires GET", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")

	if direction == "send" {
		// Consume the transport preface immediately. This forces the request
		// body through buffering reverse proxies before ARPL pairing begins.
		if err := readRelayStreamPreface(r.Body); err != nil {
			http.Error(w, "invalid relay stream preface", http.StatusBadRequest)
			return
		}
		// Keep the POST response pending for the lifetime of the upload body.
		// Returning a success response before the streaming request body is
		// complete can cause HTTP/1 clients/proxies to stop transmitting it.
		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex()
		half := &relaySendHalf{body: r.Body, done: make(chan struct{})}
		if err := h.registerSend(pairID, role, endpointID, half); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		select {
		case <-half.done:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
			h.cancelSend(pairID, role, endpointID, half)
		}
		return
	}

	flusher, _ := w.(http.Flusher)
	half := &relayRecvHalf{
		w: w, flusher: flusher,
		done: make(chan struct{}), paired: make(chan struct{}),
	}
	if err := h.registerRecv(pairID, role, endpointID, half); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	// Commit and force a response-body chunk through reverse proxies before
	// pairing. The client consumes this transport preface before exposing the
	// net.Conn to the ARPL handshake.
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(makeRelayStreamPreface()); err != nil {
		h.cancelRecv(pairID, role, endpointID, half)
		return
	}
	if flusher != nil {
		flusher.Flush()
	}
	select {
	case <-half.paired:
		// Important: copy on the request handler goroutine. net/http
		// ResponseWriter is not safe to keep using after ServeHTTP returns.
		h.pipe(pairID, half.sendRole, half.sendEndpoint, half.send, role, endpointID, half)
	case <-r.Context().Done():
		h.cancelRecv(pairID, role, endpointID, half)
	}
}

func (h *HTTPRelayHub) ensureEndpointLocked(pairID, role, endpointID string) (*relayPair, *relayEndpoint, error) {
	if h.pairs == nil {
		h.pairs = map[string]*relayPair{}
	}
	pair := h.pairs[pairID]
	if pair == nil {
		max := h.MaxPairs
		if max <= 0 {
			max = 1024
		}
		if len(h.pairs) >= max {
			return nil, nil, errors.New("relay pair capacity reached")
		}
		pair = &relayPair{roles: map[string]*relayEndpoint{}}
		h.pairs[pairID] = pair
	}
	ep := pair.roles[role]
	if ep == nil {
		ep = &relayEndpoint{id: endpointID}
		pair.roles[role] = ep
	} else if ep.id != endpointID {
		return nil, nil, errors.New("relay role is already active")
	}
	return pair, ep, nil
}

func (h *HTTPRelayHub) registerSend(pairID, role, endpointID string, half *relaySendHalf) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	pair, ep, err := h.ensureEndpointLocked(pairID, role, endpointID)
	if err != nil || ep.send != nil {
		if half.body != nil {
			_ = half.body.Close()
		}
		half.once.Do(func() { close(half.done) })
		if err != nil {
			return err
		}
		return errors.New("duplicate relay send stream")
	}
	ep.send = half
	h.tryPairLocked(pairID, pair)
	return nil
}

func (h *HTTPRelayHub) registerRecv(pairID, role, endpointID string, half *relayRecvHalf) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	pair, ep, err := h.ensureEndpointLocked(pairID, role, endpointID)
	if err != nil || ep.recv != nil {
		half.once.Do(func() { close(half.done) })
		if err != nil {
			return err
		}
		return errors.New("duplicate relay receive stream")
	}
	ep.recv = half
	h.tryPairLocked(pairID, pair)
	return nil
}

func oppositeRelayRole(role string) string {
	if role == "dial" {
		return "accept"
	}
	return "dial"
}

func (h *HTTPRelayHub) tryPairLocked(pairID string, pair *relayPair) {
	if pair == nil {
		return
	}
	for _, fromRole := range []string{"dial", "accept"} {
		from := pair.roles[fromRole]
		to := pair.roles[oppositeRelayRole(fromRole)]
		if from == nil || to == nil || from.send == nil || to.recv == nil {
			continue
		}
		send := from.send
		recv := to.recv
		from.send = nil
		to.recv = nil
		recv.source = send.body
		recv.send = send
		recv.sendRole = fromRole
		recv.sendEndpoint = from.id
		close(recv.paired)
	}
}

type relayFlushWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (w relayFlushWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 && w.flusher != nil {
		w.flusher.Flush()
	}
	return n, err
}

func (h *HTTPRelayHub) pipe(pairID, sendRole, sendEndpoint string, send *relaySendHalf, recvRole, recvEndpoint string, recv *relayRecvHalf) {
	_, _ = io.Copy(relayFlushWriter{w: recv.w, flusher: recv.flusher}, send.body)
	_ = send.body.Close()
	send.once.Do(func() { close(send.done) })
	recv.once.Do(func() { close(recv.done) })

	h.mu.Lock()
	defer h.mu.Unlock()
	pair := h.pairs[pairID]
	if pair == nil {
		return
	}
	h.cleanupEndpointLocked(pair, sendRole, sendEndpoint)
	h.cleanupEndpointLocked(pair, recvRole, recvEndpoint)
	if len(pair.roles) == 0 {
		delete(h.pairs, pairID)
	}
	h.tryPairLocked(pairID, pair)
}

func (h *HTTPRelayHub) cleanupEndpointLocked(pair *relayPair, role, endpointID string) {
	ep := pair.roles[role]
	if ep != nil && ep.id == endpointID && ep.send == nil && ep.recv == nil {
		delete(pair.roles, role)
	}
}

func (h *HTTPRelayHub) cancelSend(pairID, role, endpointID string, half *relaySendHalf) {
	h.mu.Lock()
	defer h.mu.Unlock()
	_ = half.body.Close()
	pair := h.pairs[pairID]
	if pair != nil {
		if ep := pair.roles[role]; ep != nil && ep.id == endpointID && ep.send == half {
			ep.send = nil
			half.once.Do(func() { close(half.done) })
			h.cleanupEndpointLocked(pair, role, endpointID)
		}
		if len(pair.roles) == 0 {
			delete(h.pairs, pairID)
		}
	}
}

func (h *HTTPRelayHub) cancelRecv(pairID, role, endpointID string, half *relayRecvHalf) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pair := h.pairs[pairID]
	if pair != nil {
		if ep := pair.roles[role]; ep != nil && ep.id == endpointID && ep.recv == half {
			ep.recv = nil
			half.once.Do(func() { close(half.done) })
			h.cleanupEndpointLocked(pair, role, endpointID)
		}
		if len(pair.roles) == 0 {
			delete(h.pairs, pairID)
		}
	}
}
