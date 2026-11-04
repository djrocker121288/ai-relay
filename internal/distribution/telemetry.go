package distribution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type TelemetryConfig struct {
	InstallationID string `json:"installation_id"`
	Enabled        bool   `json:"enabled"`
	FirstSeen      int64  `json:"first_seen"`
	LastSeen       int64  `json:"last_seen"`
}
type TelemetryPayload struct {
	InstallationID string `json:"installation_id"`
	Version        string `json:"version"`
	Platform       string `json:"platform"`
	Architecture   string `json:"architecture"`
	FirstSeen      int64  `json:"first_seen"`
	LastSeen       int64  `json:"last_seen"`
}

func LoadTelemetry(path string) (TelemetryConfig, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		now := time.Now().Unix()
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			return TelemetryConfig{}, err
		}
		return TelemetryConfig{InstallationID: hex.EncodeToString(id), FirstSeen: now, LastSeen: now}, nil
	}
	if err != nil {
		return TelemetryConfig{}, err
	}
	var c TelemetryConfig
	err = json.Unmarshal(b, &c)
	if err == nil && c.InstallationID == "" {
		return c, errors.New("telemetry config has no installation ID")
	}
	return c, err
}
func SaveTelemetry(path string, c TelemetryConfig) error {
	if c.InstallationID == "" {
		return errors.New("missing installation ID")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func SetTelemetry(path string, enabled bool) (TelemetryConfig, error) {
	c, err := LoadTelemetry(path)
	if err != nil {
		return c, err
	}
	c.Enabled = enabled
	c.LastSeen = time.Now().Unix()
	return c, SaveTelemetry(path, c)
}
func (c TelemetryConfig) Payload() TelemetryPayload {
	return TelemetryPayload{c.InstallationID, Version, runtime.GOOS, runtime.GOARCH, c.FirstSeen, c.LastSeen}
}
func SendTelemetry(ctx context.Context, endpoint, path string, h *http.Client) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" {
		return errors.New("telemetry endpoint must be HTTPS")
	}
	c, err := LoadTelemetry(path)
	if err != nil {
		return err
	}
	if !c.Enabled {
		return errors.New("telemetry is disabled")
	}
	c.LastSeen = time.Now().Unix()
	if err := SaveTelemetry(path, c); err != nil {
		return err
	}
	b, _ := json.Marshal(c.Payload())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(string(b)))
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
		return errors.New("telemetry endpoint rejected payload")
	}
	return nil
}
