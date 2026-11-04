package agentcore

import "sync"

const MaxOutputBytes = 1024 * 1024
const MaxFinishedJobs = 128

func outputTail(current, data string) (string, bool) {
	if len(data) >= MaxOutputBytes {
		return data[len(data)-MaxOutputBytes:], len(current)+len(data) > MaxOutputBytes
	}
	excess := len(current) + len(data) - MaxOutputBytes
	if excess > 0 {
		return current[excess:] + data, true
	}
	return current + data, false
}

type tailWriter struct {
	mu        sync.Mutex
	data      string
	truncated bool
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	data, truncated := outputTail(w.data, string(p))
	w.data, w.truncated = data, w.truncated || truncated
	return len(p), nil
}
