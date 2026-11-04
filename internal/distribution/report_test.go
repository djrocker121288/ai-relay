package distribution

import (
	"strings"
	"testing"
)

func TestRedactionAndConsent(t *testing.T) {
	b := NewDiagnostic([]string{"exec"}, "token=supersecret /home/example/private", []string{"Authorization: Bearer abc123 /Users/example/file"})
	raw, _ := b.JSON()
	s := string(raw)
	if strings.Contains(s, "supersecret") || strings.Contains(s, "abc123") || strings.Contains(s, "/home/example") {
		t.Fatalf("secret/path leaked: %s", s)
	}
	if err := SubmitReport(nil, "https://example.invalid", b, false, nil); err == nil {
		t.Fatal("report submitted without consent")
	}
}
