package gateway

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOversizedRequestRejectedBeforeDecode(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", maxCommandBody+1)
	w := httptest.NewRecorder()
	s.requestHandler(w, httptest.NewRequest("POST", "/v1/request", strings.NewReader(body)))
	if w.Code != 413 {
		t.Fatalf("oversized request accepted: %d", w.Code)
	}
	var out any
	if decodeRequest(httptest.NewRequest("POST", "/mcp", strings.NewReader(body)), &out) == nil {
		t.Fatal("oversized decoder body accepted")
	}
	if _, err := readRequestBody(httptest.NewRequest("POST", "/v1/agent/result", bytes.NewReader(make([]byte, maxResultBody+1)))); err == nil {
		t.Fatal("oversized result accepted")
	}
}
func TestStoredOutputTailIsExplicitlyTruncated(t *testing.T) {
	out, truncated := storedOutput("prefix" + strings.Repeat("x", maxStoredOutput) + "end")
	if !truncated || len(out) != maxStoredOutput || !strings.HasSuffix(out, "end") {
		t.Fatal("stored output cap lost tail or flag")
	}
}
