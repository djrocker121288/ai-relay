package main

import (
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
)

func TestOAuthMobileFormUsesCleanAction(t *testing.T) {
    s := testOAuthServer()
    _, challenge := pkcePair()
    fields := url.Values{
        "client_id": {"client"},
        "redirect_uri": {"https://client.example/callback"},
        "resource": {s.resourceURL()},
        "response_type": {"code"},
        "state": {"grok-mobile"},
        "code_challenge": {challenge},
        "code_challenge_method": {"S256"},
    }
    request := httptest.NewRequest("GET", s.base+"/authorize?"+fields.Encode(), nil)
    page := httptest.NewRecorder()
    s.authorize(page, request)
    if page.Code != 200 {
        t.Fatalf("OAuth GET authorization page status=%d", page.Code)
    }
    if !strings.Contains(page.Body.String(), "method=\"post\" action=\"/authorize\"") {
        t.Fatal("OAuth form must submit without duplicate GET query fields")
    }
    fields.Del("response_type")
    fields.Set("approval_code", s.approval)
    post := httptest.NewRequest("POST", s.base+"/authorize", strings.NewReader(fields.Encode()))
    post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    result := httptest.NewRecorder()
    s.authorize(result, post)
    if result.Code != http.StatusFound {
        t.Fatalf("correct approval refused: status %d", result.Code)
    }
    target, err := url.Parse(result.Header().Get("Location"))
    if err != nil || target.Query().Get("code") == "" || target.Query().Get("state") != "grok-mobile" {
        t.Fatal("OAuth redirect missing code/state")
    }
}
EOF
gofmt -w cmd/ai-relay-chatgpt-proxy/mobile_oauth_fix_test.go
go test -count=1 ./cmd/ai-relay-chatgpt-proxy
echo PUBLIC_SOURCE_TEST_PASS
