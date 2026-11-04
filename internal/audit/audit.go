package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Event struct {
	Time       string `json:"time"`
	Device     string `json:"device"`
	Action     string `json:"action"`
	Privileged bool   `json:"privileged"`
	Detail     any    `json:"detail,omitempty"`
}
type Log struct {
	mu sync.Mutex
	f  *os.File
}

func Open(path string) (*Log, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	return &Log{f: f}, nil
}
func (l *Log) Write(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(e)
	_, er := l.f.Write(append(b, '\n'))
	return er
}
func (l *Log) Close() { l.f.Close() }
