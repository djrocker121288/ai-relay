package tunnel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAuthenticateBindsPrincipalAndScopesWithoutExposingToken(t *testing.T) {
	const token = "opaque-token_123"
	auth := &fakeAuthenticator{principal: Principal{
		Subject:   "controller-1",
		Audience:  validTunnelConfig.Audience,
		Resource:  validTunnelConfig.Resource,
		Scopes:    []string{"job.read", "job.submit"},
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	principal, err := Authenticate(context.Background(), auth, validTunnelConfig, []string{"bEaReR " + token}, []string{"job.read"})
	if err != nil {
		t.Fatalf("Authenticate() = %v", err)
	}
	if principal.Subject != "controller-1" || auth.token != token {
		t.Fatalf("principal=%+v token=%q", principal, auth.token)
	}
	if strings.Contains(errString(auth.err), token) {
		t.Fatalf("verifier detail unexpectedly retained token: %v", auth.err)
	}
	principal.Scopes[0] = "mutated"
	if auth.principal.Scopes[0] != "job.read" {
		t.Fatal("returned scopes alias verifier state")
	}
}

func TestAuthenticateRejectsMalformedHeadersAndBindingFailures(t *testing.T) {
	valid := &fakeAuthenticator{principal: validPrincipal()}
	tests := []struct {
		name          string
		headers       []string
		mutateConfig  func(*Config)
		mutateSubject func(*Principal)
		required      []string
	}{
		{name: "duplicate headers", headers: []string{"Bearer one", "Bearer two"}},
		{name: "wrong scheme", headers: []string{"Basic one"}},
		{name: "token whitespace", headers: []string{"Bearer one two"}},
		{name: "oversized token", headers: []string{"Bearer " + strings.Repeat("a", maxAuthorizationBytes)}},
		{name: "audience mismatch", headers: []string{"Bearer one"}, mutateConfig: func(c *Config) { c.Audience = "other" }},
		{name: "resource mismatch", headers: []string{"Bearer one"}, mutateSubject: func(p *Principal) { p.Resource = "https://other.example.test/resource" }},
		{name: "missing scope", headers: []string{"Bearer one"}, required: []string{"job.control"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validTunnelConfig
			if test.mutateConfig != nil {
				test.mutateConfig(&config)
			}
			auth := *valid
			auth.principal = validPrincipal()
			if test.mutateSubject != nil {
				test.mutateSubject(&auth.principal)
			}
			headers := test.headers
			if headers == nil {
				headers = []string{"Bearer one"}
			}
			if _, err := Authenticate(context.Background(), &auth, config, headers, test.required); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("Authenticate() = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestAuthenticateRejectsMalformedRequiredScopesBeforeVerifier(t *testing.T) {
	cases := []struct {
		name     string
		required []string
	}{
		{name: "oversized", required: make([]string, maxRequiredScopes+1)},
		{name: "empty", required: []string{""}},
		{name: "format", required: []string{"job.\u200bread"}},
		{name: "duplicate", required: []string{"job.read", "job.read"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := &fakeAuthenticator{principal: validPrincipal()}
			if _, err := Authenticate(context.Background(), auth, validTunnelConfig, []string{"Bearer token"}, tc.required); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("Authenticate() = %v, want ErrUnauthorized", err)
			}
			if auth.calls != 0 {
				t.Fatalf("verifier calls = %d, want 0 for malformed required-scope policy", auth.calls)
			}
		})
	}
}

func TestAuthenticateContainsVerifierFailurePanicAndCancellation(t *testing.T) {
	auth := &fakeAuthenticator{principal: validPrincipal(), err: errors.New("secret verifier detail")}
	if _, err := Authenticate(context.Background(), auth, validTunnelConfig, []string{"Bearer token"}, nil); !errors.Is(err, ErrUnauthorized) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("verifier error = %v", err)
	}

	auth.err = nil
	auth.panic = true
	if _, err := Authenticate(context.Background(), auth, validTunnelConfig, []string{"Bearer token"}, nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("verifier panic = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	auth.panic = false
	auth.calls = 0
	if _, err := Authenticate(ctx, auth, validTunnelConfig, []string{"Bearer token"}, nil); !errors.Is(err, context.Canceled) || auth.calls != 0 {
		t.Fatalf("canceled Authenticate() = %v calls=%d", err, auth.calls)
	}
}

func TestValidatePrincipalRejectsDuplicateAndExpiredScopes(t *testing.T) {
	principal := validPrincipal()
	principal.Scopes = []string{"job.read", "job.read"}
	if err := ValidatePrincipal(validTunnelConfig, principal, nil, time.Now()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("duplicate principal scopes = %v", err)
	}
	principal = validPrincipal()
	principal.ExpiresAt = time.Now().Add(-time.Second)
	if err := ValidatePrincipal(validTunnelConfig, principal, nil, time.Now()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired principal = %v", err)
	}
}

func validPrincipal() Principal {
	return Principal{Subject: "controller-1", Audience: validTunnelConfig.Audience, Resource: validTunnelConfig.Resource, Scopes: []string{"job.read"}, ExpiresAt: time.Now().Add(time.Hour)}
}

type fakeAuthenticator struct {
	principal Principal
	token     string
	err       error
	panic     bool
	calls     int
}

func (a *fakeAuthenticator) Authorize(_ context.Context, token string, _ Config) (Principal, error) {
	a.calls++
	a.token = token
	if a.panic {
		panic("verifier detail")
	}
	return a.principal, a.err
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
