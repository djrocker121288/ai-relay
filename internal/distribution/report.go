package distribution

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type DiagnosticBundle struct {
	Version       string   `json:"version"`
	Platform      string   `json:"platform"`
	Architecture  string   `json:"architecture"`
	Capabilities  []string `json:"capabilities,omitempty"`
	ServiceStatus string   `json:"service_status,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

var secretRE = regexp.MustCompile(`(?i)(bearer|token|secret|password|api[_-]?key|authorization)(\s*[=:]\s*|\s+)[^\s,;]+`)
var pathRE = regexp.MustCompile(`(?:/home/[^\s"']+|/Users/[^\s"']+|[A-Za-z]:\\[^\s"']+)`)

func Redact(s string) string {
	s = regexp.MustCompile(`(?i)\bBearer\s+[^\s,;]+`).ReplaceAllString(s, "Bearer [REDACTED]")
	s = secretRE.ReplaceAllString(s, "$1=[REDACTED]")
	s = pathRE.ReplaceAllString(s, "[PATH]")
	if u, err := os.UserHomeDir(); err == nil {
		s = strings.ReplaceAll(s, u, "[HOME]")
	}
	if u := os.Getenv("USER"); u != "" {
		s = strings.ReplaceAll(s, u, "[USER]")
	}
	return s
}
func NewDiagnostic(capabilities []string, serviceStatus string, errs []string) DiagnosticBundle {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, Redact(e))
	}
	caps := make([]string, len(capabilities))
	for i, c := range capabilities {
		caps[i] = Redact(c)
	}
	return DiagnosticBundle{Version: Version, Platform: runtime.GOOS, Architecture: runtime.GOARCH, Capabilities: caps, ServiceStatus: Redact(serviceStatus), Errors: out}
}
func (b DiagnosticBundle) JSON() ([]byte, error) { return json.MarshalIndent(b, "", "  ") }
func SaveDiagnostic(path string, b DiagnosticBundle) error {
	data, err := b.JSON()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

// Submit requires the caller to pass approved=true after showing JSON() to the user.
func SubmitReport(ctx context.Context, endpoint string, b DiagnosticBundle, approved bool, h *http.Client) error {
	if !approved {
		return errors.New("report submission requires explicit approval")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" {
		return errors.New("report endpoint must be HTTPS")
	}
	data, _ := b.JSON()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	if h == nil {
		h = http.DefaultClient
	}
	r, err := h.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode/100 != 2 {
		return errors.New("report endpoint rejected bundle")
	}
	return nil
}
