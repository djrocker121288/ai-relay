package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type trackingBody struct {
	io.ReadCloser
	closed bool
}

func (b *trackingBody) Close() error {
	b.closed = true
	return b.ReadCloser.Close()
}

type panicCloseBody struct {
	io.ReadCloser
}

func (panicCloseBody) Close() error {
	panic("test request-body close panic")
}

func testOAuthServer() *server {
	return &server{
		base:     "https://relay.example",
		approval: "approval",
		clients:  map[string]client{"client": {Redirects: []string{"https://client.example/callback"}, Secret: "secret"}},
		codes:    map[string]authCode{},
		tokens:   map[string]token{},
	}
}

func privateClientRegistryPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "clients.json")
}

func pkcePair() (string, string) {
	verifier := strings.Repeat("verifier-", 8)
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:])
}

func authorizeCode(t *testing.T, s *server, challenge, state string) (string, string) {
	t.Helper()
	form := url.Values{
		"client_id":             {"client"},
		"redirect_uri":          {"https://client.example/callback"},
		"resource":              {s.resourceURL()},
		"approval_code":         {s.approval},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	req := httptest.NewRequest(http.MethodPost, s.base+"/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	s.authorize(response, req)
	if response.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302: %s", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("authorize response did not contain a code")
	}
	return code, location.Query().Get("state")
}

func TestPKCEAuthorizationCodeExchange(t *testing.T) {
	s := testOAuthServer()
	verifier, challenge := pkcePair()
	code, state := authorizeCode(t, s, challenge, "state")
	if state != "state" {
		t.Fatalf("authorization state = %q, want state", state)
	}

	form := url.Values{"client_id": {"client"}, "client_secret": {"secret"}, "code": {code}, "code_verifier": {verifier}, "resource": {s.resourceURL()}}
	req := httptest.NewRequest(http.MethodPost, s.base+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	s.exchange(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("token status = %d, want 200: %s", response.Code, response.Body.String())
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &tokenResponse); err != nil || tokenResponse.AccessToken == "" {
		t.Fatalf("token response = %s", response.Body.String())
	}
}

func TestOAuthHandlersCloseCallerOwnedRequestBodies(t *testing.T) {
	s := testOAuthServer()
	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
		path    string
		body    string
	}{
		{name: "register", handler: s.register, method: http.MethodGet, path: "/register", body: "ignored"},
		{name: "authorize", handler: s.authorize, method: http.MethodGet, path: "/authorize", body: "ignored"},
		{name: "exchange", handler: s.exchange, method: http.MethodGet, path: "/token", body: "ignored"},
		{name: "mcp", handler: s.mcp, method: http.MethodGet, path: "/mcp", body: "ignored"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, s.base+tc.path, strings.NewReader(tc.body))
			body := &trackingBody{ReadCloser: req.Body}
			req.Body = body
			response := httptest.NewRecorder()

			tc.handler(response, req)

			if !body.closed {
				t.Fatal("handler did not close caller-owned request body")
			}
		})
	}
}

func TestOAuthRequestBodyClosePanicIsContained(t *testing.T) {
	s := testOAuthServer()
	req := httptest.NewRequest(http.MethodDelete, s.base+"/authorize", strings.NewReader("ignored"))
	req.Body = panicCloseBody{ReadCloser: req.Body}
	response := httptest.NewRecorder()

	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("handler propagated request-body close panic: %v", recovered)
			}
		}()
		s.authorize(response, req)
	}()
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func TestPKCERejectsWrongVerifierAndUnsupportedChallenge(t *testing.T) {
	s := testOAuthServer()
	verifier, challenge := pkcePair()
	code, _ := authorizeCode(t, s, challenge, "state")
	form := url.Values{"client_id": {"client"}, "client_secret": {"secret"}, "code": {code}, "code_verifier": {verifier + "wrong"}, "resource": {s.resourceURL()}}
	req := httptest.NewRequest(http.MethodPost, s.base+"/token", strings.NewReader(form.Encode()))
	response := httptest.NewRecorder()
	s.exchange(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("wrong verifier status = %d, want 400", response.Code)
	}

	bad := httptest.NewRequest(http.MethodGet, s.base+"/authorize?client_id=client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&code_challenge=plain&code_challenge_method=plain", nil)
	response = httptest.NewRecorder()
	s.authorize(response, bad)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unsupported method status = %d, want 400", response.Code)
	}
}

func TestOAuthRejectsDuplicateCriticalParameters(t *testing.T) {
	s := testOAuthServer()
	verifier, challenge := pkcePair()

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "duplicate client", path: s.base + "/authorize?client_id=client&client_id=client&redirect_uri=" + url.QueryEscape("https://client.example/callback") + "&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256"},
		{name: "duplicate redirect", path: s.base + "/authorize?client_id=client&redirect_uri=" + url.QueryEscape("https://client.example/callback") + "&redirect_uri=" + url.QueryEscape("https://client.example/callback") + "&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256"},
		{name: "duplicate challenge", path: s.base + "/authorize?client_id=client&redirect_uri=" + url.QueryEscape("https://client.example/callback") + "&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			s.authorize(response, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("duplicate authorization parameter status = %d, want 400", response.Code)
			}
			if len(s.codes) != 0 {
				t.Fatal("duplicate authorization parameter created a code")
			}
		})
	}

	for _, field := range []string{"approval_code", "state"} {
		t.Run("duplicate "+field, func(t *testing.T) {
			form := url.Values{
				"client_id":     {"client"},
				"redirect_uri":  {"https://client.example/callback"},
				"approval_code": {s.approval},
				"state":         {"state"},
			}
			form.Add(field, form.Get(field))
			req := httptest.NewRequest(http.MethodPost, s.base+"/authorize", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			s.authorize(response, req)
			if response.Code != http.StatusForbidden {
				t.Fatalf("duplicate %s status = %d, want 403", field, response.Code)
			}
			if len(s.codes) != 0 {
				t.Fatal("duplicate approval parameter created a code")
			}
		})
	}

	for _, field := range []string{"client_secret", "code", "code_verifier"} {
		t.Run("duplicate "+field, func(t *testing.T) {
			code, _ := authorizeCode(t, s, challenge, "state")
			form := url.Values{"client_id": {"client"}, "client_secret": {"secret"}, "code": {code}, "code_verifier": {verifier}, "resource": {s.resourceURL()}}
			form.Add(field, map[string]string{"client_secret": "secret", "code": code, "code_verifier": verifier}[field])
			req := httptest.NewRequest(http.MethodPost, s.base+"/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			s.exchange(response, req)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("duplicate %s status = %d, want 400", field, response.Code)
			}
		})
	}
}

func TestOAuthFormBodyIsBounded(t *testing.T) {
	s := testOAuthServer()
	form := url.Values{"client_id": {"client"}, "client_secret": {"secret"}, "code": {strings.Repeat("x", maxOAuthFormBytes)}}
	req := httptest.NewRequest(http.MethodPost, s.base+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	s.exchange(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized form status = %d, want 400", response.Code)
	}
}

func TestOAuthFormRejectsAmbiguousOrMismatchedFraming(t *testing.T) {
	for _, tc := range []struct {
		name          string
		contentTypes  []string
		contentLength int64
	}{
		{name: "duplicate content type", contentTypes: []string{"application/x-www-form-urlencoded", "application/x-www-form-urlencoded"}},
		{name: "declared shorter", contentTypes: []string{"application/x-www-form-urlencoded"}, contentLength: 1},
		{name: "declared longer", contentTypes: []string{"application/x-www-form-urlencoded"}, contentLength: 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "client_id=client"
			req := httptest.NewRequest(http.MethodPost, "https://relay.example/authorize", strings.NewReader(body))
			for _, value := range tc.contentTypes {
				req.Header.Add("Content-Type", value)
			}
			if tc.contentLength != 0 {
				req.ContentLength = tc.contentLength
			}
			if _, err := parseForm(req); err == nil {
				t.Fatal("parseForm accepted ambiguous or mismatched framing")
			}
		})
	}
}

func TestOAuthFormAndJSONRejectInvalidTransferEncoding(t *testing.T) {
	formBody := "client_id=client"
	for _, tc := range []struct {
		name             string
		transferEncoding []string
		contentLength    int64
	}{
		{name: "unsupported", transferEncoding: []string{"gzip"}, contentLength: int64(len(formBody))},
		{name: "repeated", transferEncoding: []string{"chunked", "chunked"}, contentLength: -1},
		{name: "conflicting length", transferEncoding: []string{"chunked"}, contentLength: int64(len(formBody))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://relay.example/token", strings.NewReader(formBody))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.TransferEncoding = tc.transferEncoding
			req.ContentLength = tc.contentLength
			if _, err := parseForm(req); err == nil {
				t.Fatal("parseForm accepted invalid transfer framing")
			}

			jsonRequest := httptest.NewRequest(http.MethodPost, "https://relay.example/register", strings.NewReader(`{"redirect_uris":["https://client.example/callback"]}`))
			jsonRequest.Header.Set("Content-Type", "application/json")
			jsonRequest.TransferEncoding = tc.transferEncoding
			jsonRequest.ContentLength = tc.contentLength
			var registration struct {
				RedirectURIs []string `json:"redirect_uris"`
			}
			if err := parseJSONBody(jsonRequest, &registration); err == nil {
				t.Fatal("parseJSONBody accepted invalid transfer framing")
			}
		})
	}
}

func TestOAuthRejectsDifferentlyCasedDuplicateHeaders(t *testing.T) {
	s := testOAuthServer()
	form := "client_id=client"
	formRequest := httptest.NewRequest(http.MethodPost, s.base+"/token", strings.NewReader(form))
	formRequest.Header = http.Header{
		"Content-Type": []string{"application/x-www-form-urlencoded"},
		"content-type": []string{"application/x-www-form-urlencoded"},
	}
	if _, err := parseForm(formRequest); err == nil {
		t.Fatal("parseForm accepted differently cased duplicate content type")
	}

	jsonRequest := httptest.NewRequest(http.MethodPost, s.base+"/register", strings.NewReader(`{"redirect_uris":["https://client.example/callback"]}`))
	jsonRequest.Header = http.Header{
		"Content-Type": []string{"application/json"},
		"content-type": []string{"application/json"},
	}
	var registration struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := parseJSONBody(jsonRequest, &registration); err == nil {
		t.Fatal("parseJSONBody accepted differently cased duplicate content type")
	}

	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	bearerRequest := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
	bearerRequest.Header = http.Header{
		"Authorization": []string{"Bearer access"},
		"authorization": []string{"Bearer access"},
	}
	if _, ok := bearerToken(bearerRequest); ok {
		t.Fatal("bearerToken accepted differently cased duplicate authorization")
	}
}

func TestMCPRejectsDifferentlyCasedDuplicateContentTypeBeforeUpstream(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer access")
	req.Header = http.Header{
		"Authorization": []string{"Bearer access"},
		"Content-Type":  []string{"application/json"},
		"content-type":  []string{"application/json"},
	}
	response := httptest.NewRecorder()
	s.mcp(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestOAuthHandlersRejectNilDirectRequests(t *testing.T) {
	s := testOAuthServer()
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	for _, tc := range []struct {
		name string
		hand func(http.ResponseWriter, *http.Request)
	}{
		{name: "authorize", hand: s.authorize},
		{name: "exchange", hand: s.exchange},
		{name: "mcp", hand: s.mcp},
		{name: "register", hand: s.register},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("nil request panicked: %v", recovered)
					}
				}()
				tc.hand(response, nil)
			}()
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestOAuthFormRejectsNilURL(t *testing.T) {
	for _, request := range []*http.Request{
		{Method: http.MethodPost, Body: http.NoBody},
		{Method: http.MethodPost, URL: nil, Body: http.NoBody},
	} {
		if _, err := parseForm(request); err == nil {
			t.Fatal("parseForm accepted request without URL")
		}
	}
}

func TestOAuthMetadataAdvertisesS256(t *testing.T) {
	s := testOAuthServer()
	response := httptest.NewRecorder()
	s.metadata(response, httptest.NewRequest(http.MethodGet, s.base+"/.well-known/oauth-authorization-server", nil))
	var metadata struct {
		Methods []string `json:"code_challenge_methods_supported"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Methods) != 1 || metadata.Methods[0] != "S256" {
		t.Fatalf("PKCE metadata = %#v", metadata.Methods)
	}
	for _, header := range []string{"Cache-Control", "Pragma", "X-Content-Type-Options"} {
		if response.Header().Get(header) == "" {
			t.Fatalf("metadata response missing %s header", header)
		}
	}
}

func TestOAuthMetadataEndpointsAreReadOnlyAndBounded(t *testing.T) {
	s := testOAuthServer()
	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{name: "resource", handler: s.resource},
		{name: "authorization server", handler: s.metadata},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
				response := httptest.NewRecorder()
				tc.handler(response, httptest.NewRequest(method, s.base+"/.well-known/metadata", nil))
				if response.Code != http.StatusMethodNotAllowed {
					t.Fatalf("%s status = %d, want %d", method, response.Code, http.StatusMethodNotAllowed)
				}
				if response.Header().Get("Allow") != "GET, HEAD" {
					t.Fatalf("%s Allow = %q, want GET, HEAD", method, response.Header().Get("Allow"))
				}
			}

			head := httptest.NewRecorder()
			tc.handler(head, httptest.NewRequest(http.MethodHead, s.base+"/.well-known/metadata", nil))
			if head.Code != http.StatusOK || head.Body.Len() != 0 {
				t.Fatalf("HEAD response = %d %q, want 200 with empty body", head.Code, head.Body.String())
			}
		})
	}
}

func TestProxyURLValidationKeepsPublicBaseHTTPSAndUpstreamLoopback(t *testing.T) {
	if got, err := validatePublicBase(" https://relay.example/base/ "); err != nil || got != "https://relay.example/base" {
		t.Fatalf("valid public base = %q/%v", got, err)
	}
	for _, raw := range []string{
		"http://relay.example",
		"https://user:secret@relay.example",
		"https://relay.example?redirect=elsewhere",
		"https://relay.example/#fragment",
		"https://relay.example:0",
		"https://relay.example:65536",
		"https://relay.example:",
	} {
		if _, err := validatePublicBase(raw); err == nil {
			t.Fatalf("public base %q was accepted", raw)
		}
	}

	for _, raw := range []string{
		"http://127.0.0.1:8743/gateway",
		"https://[::1]:8743/gateway/",
		"http://LOCALHOST:8743",
	} {
		if _, err := validateLoopbackUpstream(raw); err != nil {
			t.Fatalf("loopback upstream %q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://192.0.2.1:8743",
		"http://127.0.0.1.evil:8743",
		"http://user:secret@127.0.0.1:8743",
		"http://127.0.0.1:8743?next=https://outside.example",
		"http://127.0.0.1:8743/#outside",
		"http://127.0.0.1:0",
		"http://127.0.0.1:65536",
		"http://127.0.0.1:",
		"file:///tmp/relay",
	} {
		if _, err := validateLoopbackUpstream(raw); err == nil {
			t.Fatalf("unsafe upstream %q was accepted", raw)
		}
	}
}

func TestProxyListenAddressRemainsLoopbackOnly(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1:8788",
		"[::1]:8788",
		"LOCALHOST:8788",
	} {
		if got, err := validateLoopbackListenAddress(raw); err != nil || got != raw {
			t.Fatalf("loopback listen %q = %q/%v", raw, got, err)
		}
	}
	for _, raw := range []string{
		":8788",
		"0.0.0.0:8788",
		"[::]:8788",
		"192.0.2.1:8788",
		"relay.example:8788",
		"127.0.0.1:0",
		"127.0.0.1:65536",
		"127.0.0.1:not-a-port",
	} {
		if _, err := validateLoopbackListenAddress(raw); err == nil {
			t.Fatalf("unsafe listen address %q was accepted", raw)
		}
	}
}

func TestOAuthRegistrationRequiresBoundedJSONFraming(t *testing.T) {
	s := testOAuthServer()
	validBody := `{"redirect_uris":["https://client.example/callback"]}`
	cases := []struct {
		name       string
		content    []string
		body       string
		contentLen int64
		wantStatus int
	}{
		{name: "missing content type", body: validBody, wantStatus: http.StatusBadRequest},
		{name: "wrong content type", content: []string{"text/plain"}, body: validBody, wantStatus: http.StatusBadRequest},
		{name: "duplicate content type", content: []string{"application/json", "application/json"}, body: validBody, wantStatus: http.StatusBadRequest},
		{name: "oversized content type", content: []string{"application/json" + strings.Repeat(" ", maxOAuthContentTypeBytes)}, body: validBody, wantStatus: http.StatusBadRequest},
		{name: "oversized body", content: []string{"application/json"}, body: strings.Repeat("x", maxOAuthRegistrationBytes+1), wantStatus: http.StatusBadRequest},
		{name: "trailing json", content: []string{"application/json"}, body: validBody + ` {}`, wantStatus: http.StatusBadRequest},
		{name: "malformed content length", content: []string{"application/json"}, body: validBody, contentLen: -2, wantStatus: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, s.base+"/register", strings.NewReader(tc.body))
			for _, value := range tc.content {
				req.Header.Add("Content-Type", value)
			}
			if tc.contentLen != 0 {
				req.ContentLength = tc.contentLen
			}
			response := httptest.NewRecorder()
			s.register(response, req)
			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, tc.wantStatus, response.Body.String())
			}
		})
	}

	request := &http.Request{Method: http.MethodPost, Header: http.Header{"Content-Type": []string{"application/json"}}}
	response := httptest.NewRecorder()
	s.register(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("nil body status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestOAuthRegistrationRejectsMismatchedContentLength(t *testing.T) {
	const body = `{"redirect_uris":["https://client.example/callback"]}`
	for _, tc := range []struct {
		name     string
		declared int64
	}{
		{name: "declared shorter", declared: 1},
		{name: "declared longer", declared: int64(len(body)) + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testOAuthServer()
			s.clientFile = privateClientRegistryPath(t)
			req := httptest.NewRequest(http.MethodPost, s.base+"/register", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.ContentLength = tc.declared
			response := httptest.NewRecorder()
			s.register(response, req)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestOAuthRegistrationAcceptsJSONMediaTypeParameters(t *testing.T) {
	s := testOAuthServer()
	s.clientFile = privateClientRegistryPath(t)
	req := httptest.NewRequest(http.MethodPost, s.base+"/register", strings.NewReader(`{"redirect_uris":["https://client.example/callback"]}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	response := httptest.NewRecorder()
	s.register(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
}

func TestOAuthRegistrationPersistsClientRegistry(t *testing.T) {
	s := testOAuthServer()
	s.clientFile = privateClientRegistryPath(t)
	req := httptest.NewRequest(http.MethodPost, s.base+"/register", strings.NewReader(`{"redirect_uris":["https://new-client.example/callback"]}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	s.register(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	var registered struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &registered); err != nil || registered.ClientID == "" {
		t.Fatalf("registration response = %s", response.Body.String())
	}

	reloaded := &server{clientFile: s.clientFile, clients: map[string]client{}}
	if err := reloaded.loadClients(); err != nil {
		t.Fatalf("load persisted clients: %v", err)
	}
	if _, ok := reloaded.clients[registered.ClientID]; !ok {
		t.Fatalf("persisted client %q was not loaded", registered.ClientID)
	}
}

func TestOAuthClientRegistryUsesExclusiveReplacementFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "clients.json")
	fixedTemp := path + ".tmp"
	if err := os.WriteFile(fixedTemp, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	s := testOAuthServer()
	s.clientFile = path
	if err := s.saveClients(); err != nil {
		t.Fatalf("save client registry: %v", err)
	}
	if got, err := os.ReadFile(fixedTemp); err != nil || string(got) != "sentinel" {
		t.Fatalf("fixed temporary path changed: %q/%v", got, err)
	}
}

func TestOAuthClientRegistryLoadFailsClosedForMalformedOrOversizedState(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{name: "unknown field", data: `{"client":{"Redirects":["https://client.example/callback"],"Secret":"secret","Extra":"rejected"}}`},
		{name: "trailing data", data: `{"client":{"Redirects":["https://client.example/callback"],"Secret":"secret"}} {}`},
		{name: "oversized", data: strings.Repeat("x", maxOAuthClientRegistryBytes+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := privateClientRegistryPath(t)
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			s := testOAuthServer()
			s.clientFile = path
			if err := s.loadClients(); err == nil {
				t.Fatal("malformed client registry loaded successfully")
			}
		})
	}
}

func TestOAuthClientRegistryRejectsUnsafeFileBeforeLoad(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("portable mode bits do not represent Windows ACLs")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"client":{"Redirects":["https://client.example/callback"],"Secret":"secret"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "clients.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	s := testOAuthServer()
	s.clientFile = path
	if err := s.loadClients(); err == nil {
		t.Fatal("symlinked client registry loaded successfully")
	}
}

func TestOAuthClientRegistryRejectsUnsafeFileBeforeReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("portable mode bits do not represent Windows ACLs")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "clients.json")
	const sentinel = `{"sentinel":true}`
	if err := os.WriteFile(path, []byte(sentinel), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	s := testOAuthServer()
	s.clientFile = path
	if err := s.saveClients(); err == nil {
		t.Fatal("insecure client registry replaced successfully")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != sentinel {
		t.Fatalf("registry after rejected replacement = %q/%v, want sentinel", got, err)
	}
}

func TestOAuthClientRegistryRejectsUnsafeParentBeforeReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("portable mode bits do not represent Windows ACLs")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "clients.json")
	s := testOAuthServer()
	s.clientFile = path
	if err := s.saveClients(); err == nil {
		t.Fatal("client registry replacement succeeded through writable parent")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("registry path after rejected replacement = %v, want absent", err)
	}
}

func TestOAuthRegistrationRollsBackWhenClientRegistryCannotBeWritten(t *testing.T) {
	s := testOAuthServer()
	s.clientFile = filepath.Join(t.TempDir(), "missing", "clients.json")
	req := httptest.NewRequest(http.MethodPost, s.base+"/register", strings.NewReader(`{"redirect_uris":["https://new-client.example/callback"]}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	s.register(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", response.Code, response.Body.String())
	}
	if len(s.clients) != 1 {
		t.Fatalf("client count after failed registration = %d, want existing client only", len(s.clients))
	}
}

func TestOAuthRegistrationRejectsMalformedHTTPSRedirectURIs(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{name: "missing host", uri: "https:///callback"},
		{name: "opaque URI", uri: "https:client.example/callback"},
		{name: "fragment", uri: "https://client.example/callback#fragment"},
		{name: "empty fragment", uri: "https://client.example/callback#"},
		{name: "userinfo", uri: "https://user:password@client.example/callback"},
		{name: "plaintext", uri: "http://client.example/callback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testOAuthServer()
			s.clientFile = privateClientRegistryPath(t)
			body, err := json.Marshal(map[string]any{"redirect_uris": []string{tc.uri}})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, s.base+"/register", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			s.register(response, req)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
			}
			if len(s.clients) != 1 {
				t.Fatalf("client count = %d, want existing client only", len(s.clients))
			}
		})
	}
}

func TestLegacyConfidentialClientStillExchanges(t *testing.T) {
	s := testOAuthServer()
	s.codes["legacy-code"] = authCode{ClientID: "client", Redirect: "https://client.example/callback", Until: time.Now().Add(time.Minute)}
	form := url.Values{"client_id": {"client"}, "client_secret": {"secret"}, "code": {"legacy-code"}}
	req := httptest.NewRequest(http.MethodPost, s.base+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	s.exchange(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("legacy token status = %d, want 200: %s", response.Code, response.Body.String())
	}
}

func TestOAuthBindsAuthorizationCodesAndTokensToProtectedResource(t *testing.T) {
	s := testOAuthServer()
	verifier, challenge := pkcePair()

	wrongResource := httptest.NewRequest(http.MethodGet, s.base+"/authorize?client_id=client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&resource=https%3A%2F%2Fother.example%2Fmcp&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256", nil)
	response := httptest.NewRecorder()
	s.authorize(response, wrongResource)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("wrong authorization resource status = %d, want 400", response.Code)
	}

	code, _ := authorizeCode(t, s, challenge, "state")
	form := url.Values{"client_id": {"client"}, "client_secret": {"secret"}, "code": {code}, "code_verifier": {verifier}, "resource": {"https://other.example/mcp"}}
	req := httptest.NewRequest(http.MethodPost, s.base+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	s.exchange(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("wrong token resource status = %d, want 400", response.Code)
	}

	code, _ = authorizeCode(t, s, challenge, "state")
	form.Set("code", code)
	form.Set("resource", s.resourceURL())
	req = httptest.NewRequest(http.MethodPost, s.base+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	s.exchange(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("bound token status = %d, want 200: %s", response.Code, response.Body.String())
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	bound := s.tokens[tokenResponse.AccessToken]
	s.mu.Unlock()
	if bound.Resource != s.resourceURL() {
		t.Fatalf("token resource = %q, want %q", bound.Resource, s.resourceURL())
	}
}

func TestOAuthStateRegistriesPruneExpiredEntriesAndRejectCapacity(t *testing.T) {
	t.Run("authorization codes", func(t *testing.T) {
		s := testOAuthServer()
		now := time.Now()
		for i := 0; i < maxOAuthCodes; i++ {
			s.codes["expired-"+strconv.Itoa(i)] = authCode{Until: now.Add(-time.Second)}
		}
		_, challenge := pkcePair()
		form := url.Values{
			"client_id":             {"client"},
			"redirect_uri":          {"https://client.example/callback"},
			"resource":              {s.resourceURL()},
			"approval_code":         {s.approval},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"state":                 {"state"},
		}
		req := httptest.NewRequest(http.MethodPost, s.base+"/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		s.authorize(response, req)
		if response.Code != http.StatusFound {
			t.Fatalf("expired authorization capacity status = %d, want 302: %s", response.Code, response.Body.String())
		}
		if len(s.codes) != 1 {
			t.Fatalf("authorization code count after pruning = %d, want 1", len(s.codes))
		}

		for i := 0; i < maxOAuthCodes; i++ {
			s.codes["active-"+strconv.Itoa(i)] = authCode{Until: now.Add(time.Hour)}
		}
		req = httptest.NewRequest(http.MethodPost, s.base+"/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response = httptest.NewRecorder()
		s.authorize(response, req)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("active authorization capacity status = %d, want 503", response.Code)
		}
	})

	t.Run("access tokens", func(t *testing.T) {
		s := testOAuthServer()
		verifier, challenge := pkcePair()
		code, _ := authorizeCode(t, s, challenge, "state")
		for i := 0; i < maxOAuthTokens; i++ {
			s.tokens["expired-"+strconv.Itoa(i)] = token{Until: time.Now().Add(-time.Second)}
		}
		form := url.Values{"client_id": {"client"}, "client_secret": {"secret"}, "code": {code}, "code_verifier": {verifier}, "resource": {s.resourceURL()}}
		req := httptest.NewRequest(http.MethodPost, s.base+"/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		s.exchange(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("expired token capacity status = %d, want 200: %s", response.Code, response.Body.String())
		}
		if len(s.tokens) != 1 {
			t.Fatalf("token count after pruning = %d, want 1", len(s.tokens))
		}

		code, _ = authorizeCode(t, s, challenge, "state")
		for i := 0; i < maxOAuthTokens; i++ {
			s.tokens["active-"+strconv.Itoa(i)] = token{Until: time.Now().Add(time.Hour)}
		}
		form.Set("code", code)
		req = httptest.NewRequest(http.MethodPost, s.base+"/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response = httptest.NewRecorder()
		s.exchange(response, req)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("active token capacity status = %d, want 503", response.Code)
		}
	})
}

func TestOAuthExpiryBoundaryIsInclusive(t *testing.T) {
	now := time.Unix(1700000000, 123)
	if !expired(now, now) {
		t.Fatal("credential at its expiry instant was accepted")
	}
	if expired(now, now.Add(time.Nanosecond)) {
		t.Fatal("credential before its expiry instant was rejected")
	}
}

func TestMCPRejectsAmbiguousOrOversizedBearerHeaders(t *testing.T) {
	s := testOAuthServer()
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	for _, tc := range []struct {
		name   string
		values []string
	}{
		{name: "duplicate", values: []string{"Bearer access", "Bearer access"}},
		{name: "large duplicate list", values: []string{"Bearer access", "Bearer access", "Bearer access", "Bearer access"}},
		{name: "oversized", values: []string{"Bearer " + strings.Repeat("a", maxOAuthBearerBytes)}},
		{name: "wrong scheme", values: []string{"Basic access"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
			for _, value := range tc.values {
				req.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			s.mcp(response, req)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
		})
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0 for rejected credentials", upstreamCalls)
	}
}

func TestProxyHeaderCollectorCapsDirectCallValues(t *testing.T) {
	header := http.Header{"authorization": {"one", "two", "three", "four"}}
	values := headerValuesCaseInsensitive(header, "Authorization")
	if len(values) != maxMCPProxyHeaderValues {
		t.Fatalf("collected values = %d, want %d", len(values), maxMCPProxyHeaderValues)
	}
}

func TestMCPRejectsOversizedDirectHeaderMapAndNameBeforeAuthentication(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	overdueMap := make(http.Header, maxMCPProxyHeaderFields+1)
	overdueMap.Set("Authorization", "Bearer access")
	overdueMap.Set("Content-Type", "application/json")
	for index := 0; len(overdueMap) <= maxMCPProxyHeaderFields; index++ {
		overdueMap.Set("X-Direct-Field-"+strconv.Itoa(index), "bounded")
	}

	overdueName := http.Header{
		"Authorization": {"Bearer access"},
		"Content-Type":  {"application/json"},
		strings.Repeat("x", maxMCPProxyHeaderNameBytes+1): {"ignored"},
	}
	for _, tc := range []struct {
		name   string
		header http.Header
	}{
		{name: "oversized field map", header: overdueMap},
		{name: "oversized field name", header: overdueName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
			req.Header = tc.header
			response := httptest.NewRecorder()
			s.mcp(response, req)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
			}
		})
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0 for rejected direct headers", upstreamCalls)
	}
}

func TestOAuthParsersRejectOversizedDirectHeaderMap(t *testing.T) {
	header := make(http.Header, maxMCPProxyHeaderFields+1)
	header.Set("Content-Type", "application/json")
	for index := 0; len(header) <= maxMCPProxyHeaderFields; index++ {
		header.Set("X-Direct-Field-"+strconv.Itoa(index), "bounded")
	}

	jsonRequest := httptest.NewRequest(http.MethodPost, "https://relay.example/register", strings.NewReader(`{}`))
	jsonRequest.Header = header
	if err := parseJSONBody(jsonRequest, &struct{}{}); err == nil {
		t.Fatal("parseJSONBody accepted an oversized direct Header map")
	}

	formRequest := httptest.NewRequest(http.MethodPost, "https://relay.example/authorize", strings.NewReader("state=bounded"))
	formRequest.Header = header
	if _, err := parseForm(formRequest); err == nil {
		t.Fatal("parseForm accepted an oversized direct Header map")
	}
}

func TestMCPRejectsInvalidRequestFramingBeforeUpstream(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	cases := []struct {
		name       string
		method     string
		content    []string
		body       string
		wantStatus int
	}{
		{name: "get", method: http.MethodGet, wantStatus: http.StatusMethodNotAllowed},
		{name: "missing content type", method: http.MethodPost, wantStatus: http.StatusUnsupportedMediaType},
		{name: "wrong content type", method: http.MethodPost, content: []string{"text/plain"}, wantStatus: http.StatusUnsupportedMediaType},
		{name: "duplicate content type", method: http.MethodPost, content: []string{"application/json", "application/json"}, wantStatus: http.StatusBadRequest},
		{name: "oversized content type", method: http.MethodPost, content: []string{"application/json" + strings.Repeat(" ", maxMCPProxyContentTypeBytes)}, wantStatus: http.StatusBadRequest},
		{name: "oversized body", method: http.MethodPost, content: []string{"application/json"}, body: strings.Repeat("x", maxMCPProxyRequestBytes+1), wantStatus: http.StatusRequestEntityTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, s.base+"/mcp", strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer access")
			for _, value := range tc.content {
				req.Header.Add("Content-Type", value)
			}
			response := httptest.NewRecorder()
			s.mcp(response, req)
			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, tc.wantStatus, response.Body.String())
			}
		})
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0 for rejected framing", upstreamCalls)
	}
}

func TestMCPRejectsInvalidTransferEncodingBeforeUpstream(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	const body = `{}`
	for _, tc := range []struct {
		name             string
		transferEncoding []string
		contentLength    int64
	}{
		{name: "unsupported", transferEncoding: []string{"gzip"}, contentLength: int64(len(body))},
		{name: "repeated", transferEncoding: []string{"chunked", "chunked"}, contentLength: -1},
		{name: "conflicting length", transferEncoding: []string{"chunked"}, contentLength: int64(len(body))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer access")
			req.Header.Set("Content-Type", "application/json")
			req.TransferEncoding = tc.transferEncoding
			req.ContentLength = tc.contentLength
			response := httptest.NewRecorder()
			s.mcp(response, req)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", response.Code)
			}
		})
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0 for invalid transfer framing", upstreamCalls)
	}
}

func TestMCPRejectsRawFramingHeaderAmbiguity(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	const body = `{}`
	for _, tc := range []struct {
		name             string
		contentLengths   []string
		transferEncoding []string
		rawTransfer      []string
		emptyContent     bool
		emptyTransfer    bool
		contentLength    int64
	}{
		{name: "signed content length", contentLengths: []string{"-1"}, contentLength: -1},
		{name: "mismatched content length", contentLengths: []string{"3"}, contentLength: int64(len(body))},
		{name: "case-insensitive duplicate content length", contentLengths: []string{"2", "2"}, contentLength: int64(len(body))},
		{name: "raw unsupported transfer encoding", rawTransfer: []string{"gzip"}, contentLength: int64(len(body))},
		{name: "raw transfer encoding without parsed value", rawTransfer: []string{"chunked"}, contentLength: int64(len(body))},
		{name: "oversized raw content length", contentLengths: []string{strings.Repeat("1", maxMCPProxyFramingValueBytes+1)}, contentLength: int64(len(body))},
		{name: "oversized raw transfer encoding", rawTransfer: []string{strings.Repeat("x", maxMCPProxyFramingValueBytes+1)}, contentLength: int64(len(body))},
		{name: "oversized parsed transfer encoding", transferEncoding: []string{strings.Repeat("x", maxMCPProxyFramingValueBytes+1)}, contentLength: -1},
		{name: "empty raw content length", emptyContent: true, contentLength: int64(len(body))},
		{name: "empty raw transfer encoding", emptyTransfer: true, contentLength: int64(len(body))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer access")
			req.Header.Set("Content-Type", "application/json")
			for _, value := range tc.contentLengths {
				req.Header.Add("Content-Length", value)
			}
			for _, value := range tc.rawTransfer {
				req.Header.Add("Transfer-Encoding", value)
			}
			if tc.emptyContent {
				req.Header["Content-Length"] = nil
			}
			if tc.emptyTransfer {
				req.Header["Transfer-Encoding"] = nil
			}
			req.TransferEncoding = tc.transferEncoding
			req.ContentLength = tc.contentLength
			response := httptest.NewRecorder()
			s.mcp(response, req)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
			}
		})
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0 for ambiguous raw framing", upstreamCalls)
	}
}

func TestMCPRejectsMismatchedContentLengthBeforeUpstream(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	const body = `{}`
	for _, declared := range []int64{int64(len(body)) - 1, int64(len(body)) + 1} {
		req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer access")
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = declared
		response := httptest.NewRecorder()
		s.mcp(response, req)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("declared length %d status = %d, want 400", declared, response.Code)
		}
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0 for mismatched framing", upstreamCalls)
	}
}

func TestMCPRejectsOversizedUpstreamResponse(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Repeat("x", maxMCPProxyResponseBytes+1)))
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer access")
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	s.mcp(response, req)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
}

func TestMCPAcceptsOneBoundedBearerHeader(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer relay-token" {
			t.Errorf("upstream authorization = %q, want relay token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0"}`))
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer access")
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	s.mcp(response, req)
	if response.Code != http.StatusOK || response.Body.String() != `{"jsonrpc":"2.0"}` {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	assertNoStoreJSONHeaders(t, response)
	if got := response.Header().Get("Vary"); got != "Authorization" {
		t.Fatalf("Vary = %q, want Authorization", got)
	}
}

func TestOAuthJSONAndMCPErrorResponsesAreNotCacheable(t *testing.T) {
	s := testOAuthServer()
	s.clientFile = privateClientRegistryPath(t)

	registration := httptest.NewRequest(http.MethodPost, s.base+"/register", strings.NewReader(`{"redirect_uris":["https://client.example/callback"]}`))
	registration.Header.Set("Content-Type", "application/json")
	registrationResponse := httptest.NewRecorder()
	s.register(registrationResponse, registration)
	if registrationResponse.Code != http.StatusOK {
		t.Fatalf("registration status = %d, want 200", registrationResponse.Code)
	}
	assertNoStoreJSONHeaders(t, registrationResponse)

	s.relayToken = "relay-token"
	unauthorized := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
	unauthorized.Header.Set("Authorization", "Bearer unknown")
	unauthorized.Header.Set("Content-Type", "application/json")
	unauthorizedResponse := httptest.NewRecorder()
	s.mcp(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want 401", unauthorizedResponse.Code)
	}
	assertNoStoreJSONHeaders(t, unauthorizedResponse)
	if got := unauthorizedResponse.Header().Get("Vary"); got != "Authorization" {
		t.Fatalf("unauthorized Vary = %q, want Authorization", got)
	}
}

func TestOAuthAuthorizationPageAndErrorsAreNotCacheable(t *testing.T) {
	s := testOAuthServer()
	s.clients["client"] = client{Redirects: []string{"https://client.example/callback"}, Secret: "secret"}

	pageRequest := httptest.NewRequest(http.MethodGet, s.base+"/authorize?client_id=client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&state=state", nil)
	pageResponse := httptest.NewRecorder()
	s.authorize(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusOK {
		t.Fatalf("authorization page status = %d, want 200", pageResponse.Code)
	}
	assertNoStoreJSONHeaders(t, pageResponse)

	badRequest := httptest.NewRequest(http.MethodPost, s.base+"/authorize", strings.NewReader("bad"))
	badRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badResponse := httptest.NewRecorder()
	s.authorize(badResponse, badRequest)
	if badResponse.Code != http.StatusForbidden {
		t.Fatalf("authorization error status = %d, want 403", badResponse.Code)
	}
	assertNoStoreJSONHeaders(t, badResponse)
}

func assertNoStoreJSONHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Pragma":                 "no-cache",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := response.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestMCPAcceptsCaseInsensitiveBearerScheme(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer relay-token" {
			t.Errorf("upstream authorization = %q, want relay token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0"}`))
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "bEaReR access")
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	s.mcp(response, req)
	if response.Code != http.StatusOK || response.Body.String() != `{"jsonrpc":"2.0"}` {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestMCPMapsBoundedUpstreamTimeoutToBadGateway(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer upstream.Close()
	s.upstream = upstream.URL
	s.upstreamClient = &http.Client{Timeout: 20 * time.Millisecond}

	req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer access")
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	started := time.Now()
	s.mcp(response, req)
	close(release)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded upstream request took %s", elapsed)
	}
}

func TestMCPRejectsNonLoopbackUpstreamBeforeDial(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	s.upstream = "http://192.0.2.1:8743"

	req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer access")
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	s.mcp(response, req)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
}

func TestMCPDoesNotFollowUpstreamRedirects(t *testing.T) {
	s := testOAuthServer()
	s.relayToken = "relay-token"
	s.tokens["access"] = token{Until: time.Now().Add(time.Minute)}
	externalCalls := 0
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalCalls++
	}))
	defer external.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, external.URL+"/exfiltrate", http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()
	s.upstream = upstream.URL

	req := httptest.NewRequest(http.MethodPost, s.base+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer access")
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	s.mcp(response, req)
	if response.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusTemporaryRedirect)
	}
	if externalCalls != 0 {
		t.Fatalf("external redirect calls = %d, want 0", externalCalls)
	}
}
