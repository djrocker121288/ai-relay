package tunnel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type readCloserFunc func([]byte) (int, error)

func (f readCloserFunc) Read(p []byte) (int, error) { return f(p) }
func (readCloserFunc) Close() error                 { return nil }

func TestHTTPHandlerAuthenticatesBeforeBoundedAction(t *testing.T) {
	auth := &fakeAuthenticator{principal: validPrincipal()}
	var received string
	handler, err := NewHTTPHandler(HTTPConfig{
		Config:         validTunnelConfig,
		Authenticator:  auth,
		RequiredScopes: []string{"job.read"},
		Handle: func(_ context.Context, principal Principal, request *http.Request) (HTTPResponse, error) {
			if principal.Subject != "controller-1" {
				t.Fatalf("principal=%+v", principal)
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return HTTPResponse{}, err
			}
			received = string(body)
			return HTTPResponse{Status: http.StatusCreated, Body: []byte(`{"accepted":true}`)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, validTunnelConfig.Resource, strings.NewReader(`{"job":"one"}`))
	request.Header["authorization"] = []string{"Bearer opaque-token"}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Body.String() != `{"accepted":true}` {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	if received != `{"job":"one"}` || auth.calls != 1 || auth.token != "opaque-token" {
		t.Fatalf("received=%q calls=%d token=%q", received, auth.calls, auth.token)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Vary") != "Authorization" {
		t.Fatalf("response headers=%v", response.Header())
	}
}

func TestHTTPHandlerBindsRequestTargetToConfiguredResource(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://relay.example.test/resource", nil)
	if validHTTPResourceTarget("http://relay.example.test/resource", request) {
		t.Fatal("HTTP configured resource passed the HTTPS target guard")
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "wrong path", mutate: func(request *http.Request) { request.URL.Path = "/other" }},
		{name: "query", mutate: func(request *http.Request) { request.URL.RawQuery = "scope=other" }},
		{name: "wrong authority", mutate: func(request *http.Request) { request.Host = "other.example.test" }},
		{name: "absolute authority drift", mutate: func(request *http.Request) { request.URL.Host = "other.example.test" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &fakeAuthenticator{principal: validPrincipal()}
			actionCalls := 0
			handler, err := NewHTTPHandler(HTTPConfig{
				Config:        validTunnelConfig,
				Authenticator: auth,
				Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
					actionCalls++
					return HTTPResponse{Status: http.StatusOK}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, validTunnelConfig.Resource, nil)
			request.Header.Set("Authorization", "Bearer token")
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || response.Body.String() != "invalid request target\n" || auth.calls != 0 || actionCalls != 0 {
				t.Fatalf("response=%d %q auth=%d action=%d", response.Code, response.Body.String(), auth.calls, actionCalls)
			}
		})
	}

	auth := &fakeAuthenticator{principal: validPrincipal()}
	handler, err := NewHTTPHandler(HTTPConfig{
		Config:        validTunnelConfig,
		Authenticator: auth,
		Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
			return HTTPResponse{Status: http.StatusOK}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	relative := httptest.NewRequest(http.MethodGet, "/resource", nil)
	relative.Host = "relay.example.test"
	relative.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, relative)
	if response.Code != http.StatusOK || auth.calls != 1 {
		t.Fatalf("relative target response=%d auth=%d", response.Code, auth.calls)
	}

	rootConfig := validTunnelConfig
	rootConfig.Resource = "https://relay.example.test"
	rootAuth := &fakeAuthenticator{principal: Principal{
		Subject:   "controller-1",
		Audience:  rootConfig.Audience,
		Resource:  rootConfig.Resource,
		Scopes:    []string{"job.read"},
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	rootHandler, err := NewHTTPHandler(HTTPConfig{
		Config:         rootConfig,
		Authenticator:  rootAuth,
		RequiredScopes: []string{"job.read"},
		Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
			return HTTPResponse{Status: http.StatusOK}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rootRequest := httptest.NewRequest(http.MethodGet, "https://relay.example.test/", nil)
	rootRequest.Header.Set("Authorization", "Bearer token")
	rootResponse := httptest.NewRecorder()
	rootHandler.ServeHTTP(rootResponse, rootRequest)
	if rootResponse.Code != http.StatusOK || rootAuth.calls != 1 {
		t.Fatalf("root target response=%d auth=%d", rootResponse.Code, rootAuth.calls)
	}
}

func TestHTTPHandlerRejectsDuplicateAuthorizationBeforeVerifier(t *testing.T) {
	auth := &fakeAuthenticator{principal: validPrincipal()}
	handler, err := NewHTTPHandler(HTTPConfig{
		Config:        validTunnelConfig,
		Authenticator: auth,
		Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
			t.Fatal("action called for duplicate authorization")
			return HTTPResponse{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, validTunnelConfig.Resource, nil)
	request.Header["Authorization"] = []string{"Bearer one"}
	request.Header["authorization"] = []string{"Bearer two"}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || auth.calls != 0 || !strings.Contains(response.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("response=%d headers=%v calls=%d", response.Code, response.Header(), auth.calls)
	}
}

func TestHTTPHandlerContainsFailuresAndBoundsResponses(t *testing.T) {
	tests := []struct {
		name     string
		response HTTPResponse
		err      error
	}{
		{name: "callback error", err: errors.New("secret callback detail")},
		{name: "oversized body", response: HTTPResponse{Status: http.StatusOK, Body: make([]byte, maxHTTPResponseBody+1)}},
		{name: "invalid status", response: HTTPResponse{Status: http.StatusContinue}},
		{name: "header injection", response: HTTPResponse{Status: http.StatusOK, ContentType: "application/json\r\nX-Leak: secret"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &fakeAuthenticator{principal: validPrincipal()}
			handler, err := NewHTTPHandler(HTTPConfig{
				Config:        validTunnelConfig,
				Authenticator: auth,
				Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
					return test.response, test.err
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, validTunnelConfig.Resource, nil)
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "secret") {
				t.Fatalf("response=%d %q", response.Code, response.Body.String())
			}
		})
	}
}

func TestHTTPHandlerCapsCallbackRequestBody(t *testing.T) {
	auth := &fakeAuthenticator{principal: validPrincipal()}
	handler, err := NewHTTPHandler(HTTPConfig{
		Config:        validTunnelConfig,
		Authenticator: auth,
		Handle: func(_ context.Context, _ Principal, request *http.Request) (HTTPResponse, error) {
			_, err := io.ReadAll(request.Body)
			return HTTPResponse{}, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, validTunnelConfig.Resource, strings.NewReader(strings.Repeat("a", maxHTTPBodyBytes+1)))
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || response.Body.String() != "invalid request framing\n" {
		t.Fatalf("oversized body response=%d %q", response.Code, response.Body.String())
	}
}

func TestHTTPHandlerContainsRequestBodyReaderPanic(t *testing.T) {
	auth := &fakeAuthenticator{principal: validPrincipal()}
	actionCalls := 0
	handler, err := NewHTTPHandler(HTTPConfig{
		Config:        validTunnelConfig,
		Authenticator: auth,
		Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
			actionCalls++
			return HTTPResponse{Status: http.StatusOK}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, validTunnelConfig.Resource, strings.NewReader("body"))
	request.Header.Set("Authorization", "Bearer token")
	request.Body = readCloserFunc(func([]byte) (int, error) {
		panic("body reader secret")
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || response.Body.String() != "invalid request body\n" || auth.calls != 1 || actionCalls != 0 {
		t.Fatalf("response=%d %q auth=%d action=%d", response.Code, response.Body.String(), auth.calls, actionCalls)
	}
}

func TestHTTPHandlerValidatesBodyBeforeAction(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "short declared body", mutate: func(request *http.Request) {
			request.Header.Set("Content-Length", "5")
			request.ContentLength = 5
		}},
		{name: "oversized unknown-length body", mutate: func(request *http.Request) {
			request.Header.Set("Transfer-Encoding", "chunked")
			request.TransferEncoding = []string{"chunked"}
			request.ContentLength = -1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &fakeAuthenticator{principal: validPrincipal()}
			actionCalls := 0
			handler, err := NewHTTPHandler(HTTPConfig{
				Config:        validTunnelConfig,
				Authenticator: auth,
				Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
					actionCalls++
					return HTTPResponse{Status: http.StatusOK}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			body := strings.NewReader("body")
			if test.name == "oversized unknown-length body" {
				body = strings.NewReader(strings.Repeat("a", maxHTTPBodyBytes+1))
			}
			request := httptest.NewRequest(http.MethodPost, validTunnelConfig.Resource, body)
			request.Header.Set("Authorization", "Bearer token")
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || response.Body.String() != "invalid request body\n" || auth.calls != 1 || actionCalls != 0 {
				t.Fatalf("response=%d %q auth=%d action=%d", response.Code, response.Body.String(), auth.calls, actionCalls)
			}
		})
	}
}

func TestHTTPHandlerRejectsMalformedDirectRequestsAndCancellation(t *testing.T) {
	auth := &fakeAuthenticator{principal: validPrincipal()}
	handler, err := NewHTTPHandler(HTTPConfig{
		Config:        validTunnelConfig,
		Authenticator: auth,
		Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
			t.Fatal("action called for malformed request")
			return HTTPResponse{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tooManyHeaders := httptest.NewRequest(http.MethodGet, validTunnelConfig.Resource, nil)
	for index := 0; index <= maxHTTPHeaderFields; index++ {
		tooManyHeaders.Header["X-"+string(rune('a'+index%26))+string(rune('0'+index%10))] = []string{"value"}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, tooManyHeaders)
	if response.Code != http.StatusUnauthorized || auth.calls != 0 {
		t.Fatalf("oversized header map response=%d calls=%d", response.Code, auth.calls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := httptest.NewRequestWithContext(ctx, http.MethodGet, validTunnelConfig.Resource, nil)
	canceled.Header.Set("Authorization", "Bearer token")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, canceled)
	if response.Code != http.StatusRequestTimeout || auth.calls != 0 {
		t.Fatalf("canceled response=%d calls=%d", response.Code, auth.calls)
	}
}

func TestHTTPHandlerRejectsMalformedHeaderSyntaxBeforeAuthentication(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{name: "non-token field name", header: "X Bad", value: "value"},
		{name: "control value", header: "X-Value", value: "safe\r\nX-Leak: secret"},
		{name: "unicode format value", header: "X-Value", value: "safe\u202evalue"},
		{name: "unicode line separator", header: "X-Value", value: "safe\u2028value"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &fakeAuthenticator{principal: validPrincipal()}
			handler, err := NewHTTPHandler(HTTPConfig{
				Config:        validTunnelConfig,
				Authenticator: auth,
				Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
					t.Fatal("action called for malformed header metadata")
					return HTTPResponse{}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, validTunnelConfig.Resource, nil)
			request.Header.Set("Authorization", "Bearer token")
			request.Header[test.header] = []string{test.value}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || auth.calls != 0 {
				t.Fatalf("response=%d %q auth=%d", response.Code, response.Body.String(), auth.calls)
			}
		})
	}
}

func TestHTTPHandlerRejectsMalformedDirectFramingBeforeAuthentication(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "invalid content length", mutate: func(request *http.Request) {
			request.Header.Set("Content-Length", "not-a-length")
		}},
		{name: "duplicate content length", mutate: func(request *http.Request) {
			request.Header["Content-Length"] = []string{"1"}
			request.Header["content-length"] = []string{"2"}
		}},
		{name: "contradictory parsed length", mutate: func(request *http.Request) {
			request.Header.Set("Content-Length", "1")
			request.ContentLength = 2
		}},
		{name: "oversized parsed length", mutate: func(request *http.Request) {
			request.ContentLength = maxHTTPBodyBytes + 1
		}},
		{name: "unsupported transfer encoding", mutate: func(request *http.Request) {
			request.Header.Set("Transfer-Encoding", "gzip")
			request.TransferEncoding = []string{"gzip"}
			request.ContentLength = -1
		}},
		{name: "declared body without reader", mutate: func(request *http.Request) {
			request.Body = nil
			request.ContentLength = 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &fakeAuthenticator{principal: validPrincipal()}
			handler, err := NewHTTPHandler(HTTPConfig{
				Config:        validTunnelConfig,
				Authenticator: auth,
				Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
					t.Fatal("action called for malformed request framing")
					return HTTPResponse{}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, validTunnelConfig.Resource, strings.NewReader("body"))
			request.Header.Set("Authorization", "Bearer token")
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || auth.calls != 0 {
				t.Fatalf("response=%d %q calls=%d", response.Code, response.Body.String(), auth.calls)
			}
		})
	}
}

func TestHTTPHandlerRejectsMalformedTrailersBeforeAuthentication(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "non-token field name", mutate: func(request *http.Request) {
			request.Trailer["X Bad"] = []string{"value"}
		}},
		{name: "control value", mutate: func(request *http.Request) {
			request.Trailer["X-Trailer"] = []string{"safe\r\nX-Leak: secret"}
		}},
		{name: "oversized value", mutate: func(request *http.Request) {
			request.Trailer["X-Trailer"] = []string{strings.Repeat("a", maxHTTPHeaderValue+1)}
		}},
		{name: "authorization field", mutate: func(request *http.Request) {
			request.Trailer["Authorization"] = []string{"Bearer second-token"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &fakeAuthenticator{principal: validPrincipal()}
			handler, err := NewHTTPHandler(HTTPConfig{
				Config:        validTunnelConfig,
				Authenticator: auth,
				Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
					t.Fatal("action called for malformed request trailers")
					return HTTPResponse{}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, validTunnelConfig.Resource, strings.NewReader("body"))
			request.Header.Set("Authorization", "Bearer token")
			request.Trailer = make(http.Header)
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || auth.calls != 0 {
				t.Fatalf("response=%d %q auth=%d", response.Code, response.Body.String(), auth.calls)
			}
		})
	}
}

func TestHTTPHandlerRechecksTrailersAfterBodyRead(t *testing.T) {
	auth := &fakeAuthenticator{principal: validPrincipal()}
	mutated := false
	request := httptest.NewRequest(http.MethodPost, validTunnelConfig.Resource, strings.NewReader("body"))
	request.Header.Set("Authorization", "Bearer token")
	request.Trailer = make(http.Header)
	originalBody := request.Body
	request.Body = readCloserFunc(func(p []byte) (int, error) {
		if !mutated {
			mutated = true
			request.Trailer["X Bad"] = []string{"value"}
		}
		return originalBody.Read(p)
	})
	handler, err := NewHTTPHandler(HTTPConfig{
		Config:        validTunnelConfig,
		Authenticator: auth,
		Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) {
			t.Fatal("action called after body-time trailer mutation")
			return HTTPResponse{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || auth.calls != 1 || !mutated {
		t.Fatalf("response=%d %q auth=%d mutated=%v", response.Code, response.Body.String(), auth.calls, mutated)
	}
}

func TestNewHTTPHandlerValidatesAndCopiesPolicy(t *testing.T) {
	auth := &fakeAuthenticator{principal: validPrincipal()}
	base := HTTPConfig{Config: validTunnelConfig, Authenticator: auth, RequiredScopes: []string{"job.read"}, Handle: func(context.Context, Principal, *http.Request) (HTTPResponse, error) { return HTTPResponse{}, nil }}
	if _, err := NewHTTPHandler(base); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*HTTPConfig){
		func(c *HTTPConfig) { c.Config = Config{} },
		func(c *HTTPConfig) { c.Authenticator = nil },
		func(c *HTTPConfig) { c.Handle = nil },
		func(c *HTTPConfig) { c.RequiredScopes = []string{"job.read", "job.read"} },
	} {
		candidate := base
		mutate(&candidate)
		if _, err := NewHTTPHandler(candidate); !errors.Is(err, ErrInvalid) {
			t.Fatalf("NewHTTPHandler() = %v, want ErrInvalid", err)
		}
	}
	handler, err := NewHTTPHandler(base)
	if err != nil {
		t.Fatal(err)
	}
	base.RequiredScopes[0] = "mutated"
	if handler.requiredScopes[0] != "job.read" {
		t.Fatal("handler retained caller scope slice")
	}
}
