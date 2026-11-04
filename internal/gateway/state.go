package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ai-relay/ai-relay/internal/security"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type persistedState struct {
	Devices     map[string]*DeviceRecord     `json:"devices"`
	Secrets     map[string]string            `json:"secrets"`
	Jobs        map[string]*JobRecord        `json:"jobs"`
	Controllers map[string]*ControllerRecord `json:"controllers"`
	CodexJobs   map[string]*CodexJobRecord   `json:"codex_jobs"`
}

func (s *Server) statePath() string { return filepath.Join(s.state, "state.json") }
func (s *Server) loadState() error {
	b, err := os.ReadFile(s.statePath())
	if err == nil {
		_ = os.Chmod(s.statePath(), 0600)
	}
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	b, err = decryptStateWithKey(b, s.stateKey)
	if err != nil {
		return err
	}
	var p persistedState
	if err = json.Unmarshal(b, &p); err != nil {
		return err
	}
	for id, d := range p.Devices {
		if d != nil {
			d.Secret = p.Secrets[id]
			d.Online = false
			s.devices[id] = d
		}
	}
	var dispatch []*JobRecord
	for id, j := range p.Jobs {
		if j == nil {
			continue
		}
		s.jobs[id] = j
		if j.State == "running" {
			s.active[j.DeviceID] = true
		}
		if j.State == "queued" || j.Status == "control_queued" {
			dispatch = append(dispatch, j)
		}
	}
	sort.Slice(dispatch, func(i, j int) bool {
		if dispatch[i].Created == dispatch[j].Created {
			return dispatch[i].ID < dispatch[j].ID
		}
		return dispatch[i].Created < dispatch[j].Created
	})
	for _, job := range dispatch {
		s.pending[job.DeviceID] = append(s.pending[job.DeviceID], job.ID)
	}
	for id, c := range p.Controllers {
		s.controllers[id] = c
	}
	for id, j := range p.CodexJobs {
		s.codexJobs[id] = j
	}
	return nil
}
func (s *Server) saveStateLocked() error {
	p := persistedState{Devices: map[string]*DeviceRecord{}, Secrets: map[string]string{}, Jobs: s.jobs, Controllers: s.controllers, CodexJobs: s.codexJobs}
	for id, d := range s.devices {
		cp := *d
		cp.Secret = ""
		p.Devices[id] = &cp
		p.Secrets[id] = d.Secret
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	b, err = encryptStateWithKey(b, s.stateKey)
	if err != nil {
		return err
	}
	tmp := s.statePath() + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath())
}
func (s *Server) touchJobLocked(j *JobRecord) { j.Updated = time.Now().Unix(); _ = s.saveStateLocked() }

func ensureStateKey(state string) ([]byte, error) {
	v := strings.TrimSpace(os.Getenv("AI_RELAY_STATE_KEY"))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("RLI_STATE_KEY"))
	}
	if v != "" {
		if b, e := hex.DecodeString(v); e == nil && len(b) == 32 {
			return b, nil
		}
		h := sha256.Sum256([]byte(v))
		return h[:], nil
	}
	path := os.Getenv("AI_RELAY_STATE_KEY_FILE")
	if path == "" {
		path = os.Getenv("RLI_STATE_KEY_FILE")
	}
	if path == "" {
		path = filepath.Join(state, "state.key")
	}
	if b, err := os.ReadFile(path); err == nil {
		if err := security.CheckProtectedFile(path); err != nil {
			return nil, fmt.Errorf("state key protection: %w", err)
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("state key must contain exactly 32 bytes")
		}
		return b, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	b, err := security.Random(32)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	if err = security.ProtectFile(path); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	return b, nil
}
func encryptStateWithKey(b, k []byte) ([]byte, error) {
	if k == nil {
		return b, nil
	}
	block, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = io.ReadFull(rand.Reader, n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, b, nil), nil
}
func decryptStateWithKey(b, k []byte) ([]byte, error) {
	if k == nil {
		return b, nil
	}
	block, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	if len(b) < g.NonceSize() {
		return nil, fmt.Errorf("invalid encrypted state")
	}
	n := b[:g.NonceSize()]
	return g.Open(nil, n, b[g.NonceSize():], nil)
}
