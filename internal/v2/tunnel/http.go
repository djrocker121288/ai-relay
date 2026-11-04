package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxHTTPHeaderFields = 256
	maxHTTPHeaderName   = 256
	maxHTTPHeaderValue  = 16 << 10
	maxHTTPHeaderBytes  = 64 << 10
	maxHTTPBodyBytes    = 64 << 10
	maxHTTPResponseBody = 256 << 10
	maxHTTPContentType  = 256
)

// HTTPConfig describes the local handoff from an HTTP request to an already
// authenticated distribution action. It does not configure a route, listener,
// TLS, or provider transport.
type HTTPConfig struct {
	Config         Config
	Authenticator  Authenticator
	RequiredScopes []string
	Handle         func(context.Context, Principal, *http.Request) (HTTPResponse, error)
}

// HTTPResponse is the bounded response returned by an authenticated action.
// Headers are intentionally not caller-controlled: the adapter owns the
// cache and content-sniffing policy and does not provide a response-header
// injection surface.
type HTTPResponse struct {
	Status      int
	ContentType string
	Body        []byte
}

// HTTPHandler authenticates one request before invoking the configured action.
// It is safe to construct and test without starting a server; deployment code
// remains responsible for an authenticated HTTPS listener and provider.
type HTTPHandler struct {
	config         Config
	authenticator  Authenticator
	requiredScopes []string
	handle         func(context.Context, Principal, *http.Request) (HTTPResponse, error)
}

// NewHTTPHandler validates and copies the policy needed for an authenticated
// distribution handoff. The returned handler performs no network or storage
// work during construction.
func NewHTTPHandler(config HTTPConfig) (*HTTPHandler, error) {
	if err := ValidateConfig(config.Config); err != nil {
		return nil, err
	}
	if nilAuthenticator(config.Authenticator) {
		return nil, fmt.Errorf("%w: authenticator is required", ErrInvalid)
	}
	if config.Handle == nil {
		return nil, fmt.Errorf("%w: HTTP action is required", ErrInvalid)
	}
	if err := validateRequiredScopes(config.RequiredScopes); err != nil {
		return nil, err
	}
	return &HTTPHandler{
		config:         config.Config,
		authenticator:  config.Authenticator,
		requiredScopes: append([]string(nil), config.RequiredScopes...),
		handle:         config.Handle,
	}, nil
}

// ServeHTTP applies the authenticated distribution boundary and then invokes
// the caller's action. Authentication failures never reach the action, and
// verifier, callback, token, and request details are not written to clients.
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if w == nil {
		return
	}
	if h == nil || r == nil || r.URL == nil {
		writeHTTPProblem(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !validHTTPFraming(r) {
		writeHTTPProblem(w, http.StatusBadRequest, "invalid request framing")
		return
	}
	if !validHTTPResourceTarget(h.config.Resource, r) {
		writeHTTPProblem(w, http.StatusBadRequest, "invalid request target")
		return
	}

	authorization, err := authorizationHeaders(r.Header)
	if err != nil {
		writeHTTPProblem(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	principal, err := Authenticate(r.Context(), h.authenticator, h.config, authorization, h.requiredScopes)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeHTTPProblem(w, http.StatusRequestTimeout, "request canceled")
			return
		}
		writeHTTPProblem(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if r.Body != nil {
		originalBody := r.Body
		defer closeRequestBody(originalBody)
		body, bodyErr := readHTTPBody(w, originalBody, r.ContentLength)
		if bodyErr != nil {
			writeHTTPProblem(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if !validHTTPTrailerMap(r.Trailer) {
			writeHTTPProblem(w, http.StatusBadRequest, "invalid request trailers")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		defer closeRequestBody(r.Body)
	}
	response, callbackErr := invokeHTTPAction(h.handle, r.Context(), principal, r)
	if callbackErr != nil || !validHTTPResponse(response) {
		writeHTTPProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Vary", "Authorization")
	contentType := response.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(response.Status)
	if response.Status != http.StatusNoContent && response.Status != http.StatusNotModified {
		_, _ = w.Write(response.Body)
	}
}

func readHTTPBody(w http.ResponseWriter, body io.ReadCloser, contentLength int64) (payload []byte, err error) {
	defer func() {
		if recover() != nil {
			payload = nil
			err = errors.New("request body read failed")
		}
	}()
	limited := http.MaxBytesReader(w, body, maxHTTPBodyBytes+1)
	payload, err = io.ReadAll(limited)
	if err != nil || len(payload) > maxHTTPBodyBytes {
		return nil, errors.New("request body exceeds the bounded limit")
	}
	if contentLength >= 0 && int64(len(payload)) != contentLength {
		return nil, errors.New("request body length does not match framing")
	}
	return payload, nil
}

func validateRequiredScopes(scopes []string) error {
	if len(scopes) > maxRequiredScopes {
		return fmt.Errorf("%w: required scope list exceeds the bounded limit", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if err := validText("required scope", scope, maxScopeBytes); err != nil {
			return err
		}
		if _, duplicate := seen[scope]; duplicate {
			return fmt.Errorf("%w: duplicate required scope", ErrInvalid)
		}
		seen[scope] = struct{}{}
	}
	return nil
}

// validHTTPResourceTarget binds the request authority and path to the exact
// configured protected resource before authentication or callback dispatch.
// Server requests normally carry a relative URL and put the authority in
// Request.Host; absolute-form requests are accepted only when both
// authorities identify the configured HTTPS resource. Query and fragment
// state is never part of this handoff identity.
func validHTTPResourceTarget(resource string, request *http.Request) bool {
	configured, err := url.Parse(resource)
	if err != nil || !strings.EqualFold(configured.Scheme, "https") || configured.Host == "" || configured.RawQuery != "" || configured.ForceQuery || configured.Fragment != "" || configured.User != nil || configured.Opaque != "" {
		return false
	}
	target := request.URL
	if target == nil || target.User != nil || target.Opaque != "" || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" {
		return false
	}
	if target.IsAbs() {
		if !strings.EqualFold(target.Scheme, configured.Scheme) || target.Host == "" || !strings.EqualFold(target.Host, configured.Host) || !sameEscapedPath(target, configured) {
			return false
		}
		return request.Host == "" || sameHTTPAuthority(request.Host, configured.Host)
	}
	if target.Scheme != "" || target.Host != "" || request.Host == "" || !sameEscapedPath(target, configured) {
		return false
	}
	return sameHTTPAuthority(request.Host, configured.Host)
}

func sameEscapedPath(left, right *url.URL) bool {
	return canonicalEscapedPath(left) == canonicalEscapedPath(right)
}

func canonicalEscapedPath(value *url.URL) string {
	path := value.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func sameHTTPAuthority(candidate, configured string) bool {
	parsed, err := url.Parse("https://" + candidate)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return false
	}
	return strings.EqualFold(parsed.Host, configured)
}

func authorizationHeaders(headers http.Header) ([]string, error) {
	if !validHTTPHeaderMap(headers) {
		return nil, ErrUnauthorized
	}
	values := make([]string, 0, 2)
	bytes := 0
	for name, entries := range headers {
		if len(name) == 0 || len(name) > maxHTTPHeaderName {
			return nil, ErrUnauthorized
		}
		bytes += len(name)
		if bytes > maxHTTPHeaderBytes {
			return nil, ErrUnauthorized
		}
		for _, entry := range entries {
			if len(entry) > maxHTTPHeaderValue {
				return nil, ErrUnauthorized
			}
			bytes += len(entry)
			if bytes > maxHTTPHeaderBytes {
				return nil, ErrUnauthorized
			}
			if !strings.EqualFold(name, "Authorization") {
				continue
			}
			if len(values) < 2 {
				values = append(values, entry)
			}
		}
		if strings.EqualFold(name, "Authorization") && len(entries) == 0 {
			return nil, ErrUnauthorized
		}
	}
	if len(values) != 1 {
		return nil, ErrUnauthorized
	}
	return values, nil
}

func validHTTPHeaderMap(headers http.Header) bool {
	if len(headers) > maxHTTPHeaderFields {
		return false
	}
	bytes := 0
	for name, entries := range headers {
		if !validHTTPHeaderName(name) {
			return false
		}
		bytes += len(name)
		if bytes > maxHTTPHeaderBytes {
			return false
		}
		for _, entry := range entries {
			if !validHTTPHeaderValue(entry) {
				return false
			}
			bytes += len(entry)
			if bytes > maxHTTPHeaderBytes {
				return false
			}
		}
	}
	return true
}

// validHTTPHeaderName keeps direct in-process callers on the same token
// grammar that net/http accepts from the wire. Header names are ASCII tokens;
// accepting arbitrary map keys here would let a callback receive metadata that
// could never have arrived through the reviewed HTTP transport.
func validHTTPHeaderName(name string) bool {
	if len(name) == 0 || len(name) > maxHTTPHeaderName {
		return false
	}
	for index := 0; index < len(name); index++ {
		if !isHTTPTokenByte(name[index]) {
			return false
		}
	}
	return true
}

// validHTTPHeaderValue rejects field-value control bytes while preserving
// horizontal tab and RFC 9110 obs-text. Valid UTF-8 metadata is additionally
// kept free of Unicode control, format, and line/paragraph separator runes so
// direct callbacks cannot receive a value with an ambiguous visual record
// boundary. Invalid UTF-8 remains possible obs-text rather than being treated
// as a reason to reject an otherwise valid wire header.
func validHTTPHeaderValue(value string) bool {
	if len(value) > maxHTTPHeaderValue {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 && value[index] != '\t' || value[index] == 0x7f {
			return false
		}
	}
	if !utf8.ValidString(value) {
		return true
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return false
		}
	}
	return true
}

func isHTTPTokenByte(value byte) bool {
	if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') {
		return true
	}
	switch value {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func validHTTPFraming(request *http.Request) bool {
	if request == nil || !validHTTPHeaderMap(request.Header) || !validHTTPTrailerMap(request.Trailer) || request.ContentLength < -1 || request.ContentLength > maxHTTPBodyBytes {
		return false
	}
	contentLength := headerValues(request.Header, "Content-Length")
	if headerPresent(request.Header, "Content-Length") && len(contentLength) != 1 {
		return false
	}
	if len(contentLength) == 1 {
		value := contentLength[0]
		if value == "" || len(value) > maxHTTPHeaderValue {
			return false
		}
		for _, char := range value {
			if char < '0' || char > '9' {
				return false
			}
		}
		declared, err := strconv.ParseInt(value, 10, 64)
		if err != nil || declared != request.ContentLength {
			return false
		}
	}
	transferEncoding := headerValues(request.Header, "Transfer-Encoding")
	if headerPresent(request.Header, "Transfer-Encoding") && len(transferEncoding) != 1 {
		return false
	}
	if len(transferEncoding) == 1 && (len(transferEncoding[0]) > maxHTTPHeaderValue || !strings.EqualFold(strings.TrimSpace(transferEncoding[0]), "chunked")) {
		return false
	}
	if len(request.TransferEncoding) == 0 {
		if len(transferEncoding) != 0 {
			return false
		}
	} else if len(request.TransferEncoding) != 1 || !strings.EqualFold(request.TransferEncoding[0], "chunked") || request.ContentLength != -1 {
		return false
	}
	if request.ContentLength > 0 && request.Body == nil {
		return false
	}
	if request.ContentLength == -1 && request.Body == nil {
		return false
	}
	return true
}

// validHTTPTrailerMap applies the same bounded field grammar to direct
// in-process trailers and rejects fields that must not be reintroduced after
// the authenticated request headers have been processed. A body reader may
// populate Trailer while it is consumed, so ServeHTTP rechecks this boundary
// immediately before callback dispatch as well.
func validHTTPTrailerMap(trailer http.Header) bool {
	if !validHTTPHeaderMap(trailer) {
		return false
	}
	for name := range trailer {
		switch {
		case strings.EqualFold(name, "Authorization"),
			strings.EqualFold(name, "Content-Length"),
			strings.EqualFold(name, "Host"),
			strings.EqualFold(name, "Trailer"),
			strings.EqualFold(name, "Transfer-Encoding"):
			return false
		}
	}
	return true
}

func headerValues(headers http.Header, target string) []string {
	values := make([]string, 0, 2)
	for name, entries := range headers {
		if !strings.EqualFold(name, target) {
			continue
		}
		if len(entries) == 0 {
			return nil
		}
		if len(values) <= 1 {
			values = append(values, entries...)
		}
	}
	return values
}

func headerPresent(headers http.Header, target string) bool {
	for name := range headers {
		if strings.EqualFold(name, target) {
			return true
		}
	}
	return false
}

func validHTTPResponse(response HTTPResponse) bool {
	if response.Status < 200 || response.Status > 599 || len(response.Body) > maxHTTPResponseBody {
		return false
	}
	if response.ContentType == "" {
		return true
	}
	return len(response.ContentType) <= maxHTTPContentType && validText("response content type", response.ContentType, maxHTTPContentType) == nil
}

func invokeHTTPAction(action func(context.Context, Principal, *http.Request) (HTTPResponse, error), ctx context.Context, principal Principal, request *http.Request) (response HTTPResponse, err error) {
	defer func() {
		if recover() != nil {
			response = HTTPResponse{}
			err = errors.New("HTTP action failed")
		}
	}()
	return action(ctx, principal, request)
}

func writeHTTPProblem(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Vary", "Authorization")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	http.Error(w, message, status)
}

func closeRequestBody(body interface{ Close() error }) {
	defer func() { _ = recover() }()
	_ = body.Close()
}
