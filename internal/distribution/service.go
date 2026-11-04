package distribution

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Service is deliberately separate from the gateway/MCP control plane. It stores
// aggregate telemetry and user-submitted redacted reports as append-only JSONL.
type Service struct {
	ManifestDir, ArtifactDir, DataDir string
	Tunnel                            TunnelConfig
	mu                                sync.Mutex
}

var artifactPartRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func (s *Service) Routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthz", s.health)
	m.HandleFunc("/v1/updates/", s.update)
	m.HandleFunc("/v1/telemetry/heartbeat", s.telemetry)
	m.HandleFunc("/v1/reports", s.report)
	return m
}
func (s *Service) health(w http.ResponseWriter, _ *http.Request) {
	tunnel := map[string]any{"enabled": s.Tunnel.Enabled()}
	if s.Tunnel.Enabled() {
		tunnel["provider"] = s.Tunnel.Provider
		tunnel["hostname"] = s.Tunnel.Hostname
		tunnel["target"] = s.Tunnel.Target
	}
	writeJSON(w, map[string]any{"ok": true, "service": "ai-relay-distribution", "tunnel": tunnel})
}
func (s *Service) update(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", 405)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/updates/"), "/")
	if len(parts) != 2 || !artifactPartRE.MatchString(parts[0]) || !artifactPartRE.MatchString(parts[1]) {
		http.Error(w, "platform and architecture required", 400)
		return
	}
	b, err := os.ReadFile(filepath.Join(s.ManifestDir, parts[0]+"-"+parts[1]+".json"))
	if err != nil {
		http.Error(w, "update not found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}
func (s *Service) telemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var p TelemetryPayload
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&p) != nil || p.InstallationID == "" || p.Version == "" || p.Platform == "" || p.Architecture == "" {
		http.Error(w, "invalid telemetry payload", 400)
		return
	}
	if err := s.append("telemetry.jsonl", p); err != nil {
		http.Error(w, "store failed", 500)
		return
	}
	writeJSON(w, map[string]any{"accepted": true})
}
func (s *Service) report(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var b DiagnosticBundle
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&b) != nil || b.Version == "" || b.Platform == "" || b.Architecture == "" {
		http.Error(w, "invalid report", 400)
		return
	}
	if err := s.append("reports.jsonl", b); err != nil {
		http.Error(w, "store failed", 500)
		return
	}
	writeJSON(w, map[string]any{"accepted": true})
}
func (s *Service) append(name string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.DataDir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(s.DataDir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Service) String() string {
	return fmt.Sprintf("distribution manifests=%s data=%s", s.ManifestDir, s.DataDir)
}
