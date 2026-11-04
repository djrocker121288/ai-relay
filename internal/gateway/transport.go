package gateway

import (
	"encoding/json"
	"fmt"
	"github.com/ai-relay/ai-relay/internal/protocol"
	"github.com/ai-relay/ai-relay/internal/security"
	"net/http"
	"strings"
	"time"
)

func (s *Server) authenticate(r *http.Request) (*protocol.Request, *DeviceRecord, bool) {
	var q protocol.Request
	if decodeRequest(r, &q) != nil || !protocol.AcceptsVersion(q.Version) || len(q.Nonce) > 256 || len(q.ID) > 256 {
		return nil, nil, false
	}
	s.mu.Lock()
	d := s.devices[q.DeviceID]
	s.mu.Unlock()
	if d == nil || d.Revoked || !security.Verify(d.Secret, q.Signature, q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(q.Params)) {
		return &q, d, false
	}
	s.mu.Lock()
	accepted := s.acceptNonceLocked(q.DeviceID, q.Nonce, time.Now())
	s.mu.Unlock()
	return &q, d, accepted
}
func (s *Server) agentPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	q, d, ok := s.authenticate(r)
	if !ok || q.Method != "agent.poll" {
		http.Error(w, "unauthorized", 401)
		return
	}
	s.mu.Lock()
	d.Online = true
	d.LastSeen = time.Now().Unix()
	var c *protocol.Command
	ids := s.pending[d.ID]
	dispatch := -1
	for index, id := range ids {
		job := s.jobs[id]
		if job != nil && (!s.active[d.ID] || job.Method == "agent.cancel" || job.Method == "agent.stdin") {
			dispatch = index
			break
		}
	}
	if dispatch >= 0 {
		id := ids[dispatch]
		s.pending[d.ID] = append(ids[:dispatch], ids[dispatch+1:]...)
		if j := s.jobs[id]; j != nil {
			c = &protocol.Command{JobID: j.ID, Method: j.Method, Params: j.Params}
			if j.Method == "agent.exec" {
				j.State = "running"
				s.active[d.ID] = true
			}
			j.Updated = time.Now().Unix()
		}
	}
	if c != nil {
		_ = s.saveStateLocked()
	}
	s.mu.Unlock()
	write(w, map[string]any{"command": c})
}
func (s *Server) agentResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	q, _, ok := s.authenticate(r)
	if !ok || q.Method != "agent.result" {
		http.Error(w, "unauthorized", 401)
		return
	}
	var result protocol.CommandResult
	b, _ := json.Marshal(q.Params)
	if json.Unmarshal(b, &result) != nil {
		http.Error(w, "bad result", 400)
		return
	}
	s.mu.Lock()
	j := s.jobs[result.JobID]
	if j == nil || j.DeviceID != q.DeviceID {
		s.mu.Unlock()
		http.Error(w, "job not found for device", http.StatusNotFound)
		return
	}
	if j.State == "completed" || j.State == "failed" || j.State == "canceled" {
		s.mu.Unlock()
		write(w, map[string]any{"accepted": true})
		return
	}
	if j != nil {
		j.State = "completed"
		if result.Error != "" {
			j.Stderr, j.StderrTruncated = storedOutput(result.Error)
			j.State = "failed"
		}
		if out, ok := result.Result.(map[string]any); ok {
			if truncated, ok := out["stdout_truncated"].(bool); ok {
				j.StdoutTruncated = truncated
			}
			if truncated, ok := out["stderr_truncated"].(bool); ok {
				j.StderrTruncated = truncated
			}
			if v, ok := out["exit_code"].(float64); ok {
				code := int(v)
				j.Exit = &code
				if code != 0 {
					j.State = "failed"
				}
			}
			if canceled, ok := out["canceled"].(bool); ok && canceled {
				j.State = "canceled"
			}
			if v, ok := out["stdout"].(string); ok {
				tail, truncated := storedOutput(v)
				j.Stdout = tail
				j.StdoutTruncated = j.StdoutTruncated || truncated
			}
			if v, ok := out["stderr"].(string); ok {
				tail, truncated := storedOutput(v)
				j.Stderr = tail
				j.StderrTruncated = j.StderrTruncated || truncated
			}
		}
		j.Updated = time.Now().Unix()
		delete(s.active, j.DeviceID)
		_ = s.saveStateLocked()
	}
	s.mu.Unlock()
	write(w, map[string]any{"accepted": j != nil})
}
func (s *Server) enqueue(deviceID, method string, params any, owners ...string) (*JobRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil || d.Revoked {
		return nil, fmt.Errorf("device unavailable")
	}
	id, e := security.Token(12)
	if e != nil {
		return nil, e
	}
	now := time.Now().Unix()
	owner := controllerChatGPT
	if len(owners) > 0 {
		owner = owners[0]
	}
	j := &JobRecord{ID: id, DeviceID: deviceID, Method: method, Params: params, Command: method, State: "queued", Created: now, Updated: now, Owner: owner, Target: deviceID}
	if s.jobs == nil {
		s.jobs = map[string]*JobRecord{}
	}
	if s.pending == nil {
		s.pending = map[string][]string{}
	}
	s.jobs[id] = j
	s.pending[deviceID] = append(s.pending[deviceID], id)
	_ = s.saveStateLocked()
	return j, nil
}

func (s *Server) jobHandler(w http.ResponseWriter, r *http.Request) {
	c := s.controllerFromRequest(r)
	if c == nil || !hasScope(c, scopeRead) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/jobs/")
	s.mu.Lock()
	j := copyJob(s.jobs[id])
	s.mu.Unlock()
	if j == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if j.Owner != c.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	write(w, j)
}

func copyJob(job *JobRecord) *JobRecord {
	if job == nil {
		return nil
	}
	snapshot := *job
	return &snapshot
}
