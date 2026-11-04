package arpl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type FleetRecord struct {
	DeviceID       string    `json:"device_id"`
	OS             string    `json:"os,omitempty"`
	Arch           string    `json:"arch,omitempty"`
	Version        string    `json:"version,omitempty"`
	BuildHash      string    `json:"build_hash,omitempty"`
	Roles          []string  `json:"roles,omitempty"`
	Capabilities   []string  `json:"capabilities,omitempty"`
	Connected      bool      `json:"connected"`
	Path           string    `json:"path,omitempty"`
	LatencyMS      int64     `json:"latency_ms,omitempty"`
	UptimeSeconds  int64     `json:"uptime_seconds,omitempty"`
	LastConnect    time.Time `json:"last_connect,omitempty"`
	LastDisconnect time.Time `json:"last_disconnect,omitempty"`
}
type FleetStore struct {
	Path string
	mu   sync.Mutex
}

func (s *FleetStore) Update(r FleetRecord) error {
	if s == nil || s.Path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	var all map[string]FleetRecord
	b, _ := os.ReadFile(s.Path)
	_ = json.Unmarshal(b, &all)
	if all == nil {
		all = map[string]FleetRecord{}
	}
	if previous, ok := all[r.DeviceID]; ok {
		if r.OS == "" {
			r.OS = previous.OS
		}
		if r.Arch == "" {
			r.Arch = previous.Arch
		}
		if r.Version == "" {
			r.Version = previous.Version
		}
		if r.BuildHash == "" {
			r.BuildHash = previous.BuildHash
		}
		if len(r.Roles) == 0 {
			r.Roles = previous.Roles
		}
		if len(r.Capabilities) == 0 {
			r.Capabilities = previous.Capabilities
		}
		if r.Path == "" {
			r.Path = previous.Path
		}
		if r.LatencyMS == 0 {
			r.LatencyMS = previous.LatencyMS
		}
		if r.LastConnect.IsZero() {
			r.LastConnect = previous.LastConnect
		}
		if r.LastDisconnect.IsZero() {
			r.LastDisconnect = previous.LastDisconnect
		}
		if r.UptimeSeconds == 0 {
			r.UptimeSeconds = previous.UptimeSeconds
		}
	}
	all[r.DeviceID] = r
	out, _ := json.MarshalIndent(all, "", "  ")
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0600)
	return os.Rename(tmp, s.Path)
}
func (s *FleetStore) List() ([]FleetRecord, error) {
	if s == nil || s.Path == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var all map[string]FleetRecord
	if err = json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	out := make([]FleetRecord, 0, len(all))
	for _, r := range all {
		out = append(out, r)
	}
	return out, nil
}
