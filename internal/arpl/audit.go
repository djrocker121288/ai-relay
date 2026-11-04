package arpl

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AuditEvent struct {
	Time       time.Time         `json:"time"`
	Event      string            `json:"event"`
	PeerID     string            `json:"peer_id,omitempty"`
	Capability string            `json:"capability,omitempty"`
	Action     string            `json:"action,omitempty"`
	OK         bool              `json:"ok"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// AuditLog is a bounded JSONL local trail. It intentionally accepts metadata,
// never arbitrary command bodies or file contents.
type AuditLog struct {
	Path     string
	MaxBytes int64
	Keep     int
	mu       sync.Mutex
}

func (a *AuditLog) Write(e AuditEvent) error {
	if a == nil || strings.TrimSpace(a.Path) == "" {
		return nil
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Metadata != nil {
		for k, v := range e.Metadata {
			e.Metadata[k] = redactAudit(v)
		}
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = os.MkdirAll(filepath.Dir(a.Path), 0700); err != nil {
		return err
	}
	if a.MaxBytes <= 0 {
		a.MaxBytes = 4 << 20
	}
	if st, statErr := os.Stat(a.Path); statErr == nil && st.Size()+int64(len(b)+1) > a.MaxBytes {
		keep := a.Keep
		if keep <= 0 {
			keep = 3
		}
		for i := keep - 1; i >= 1; i-- {
			_ = os.Rename(a.Path+"."+itoa(i), a.Path+"."+itoa(i+1))
		}
		_ = os.Rename(a.Path, a.Path+".1")
	}
	f, err := os.OpenFile(a.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func redactAudit(v string) string {
	low := strings.ToLower(v)
	for _, marker := range []string{"token=", "secret=", "password=", "private_key", "authorization:", "bearer ", "api-key:"} {
		if i := strings.Index(low, marker); i >= 0 {
			return v[:i] + "[REDACTED]"
		}
	}
	if len(v) > 512 {
		return v[:512] + "[TRUNCATED]"
	}
	return v
}

func QueryAudit(path string, w io.Writer, jsonOutput bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 16<<20))
	sc.Buffer(make([]byte, 4096), 1<<20)
	var events []AuditEvent
	for sc.Scan() {
		var e AuditEvent
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			events = append(events, e)
		}
	}
	if err = sc.Err(); err != nil {
		return err
	}
	if jsonOutput {
		return json.NewEncoder(w).Encode(events)
	}
	for _, e := range events {
		if _, err := io.WriteString(w, e.Time.Format(time.RFC3339)+" "+e.Event+" ok="+boolString(e.OK)+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
func itoa(v int) string { return strconv.Itoa(v) }
