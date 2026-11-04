package arpl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type JobRecord struct {
	ID        string    `json:"id"`
	Argv      []string  `json:"argv"`
	Cwd       string    `json:"cwd,omitempty"`
	State     string    `json:"state"`
	ExitCode  int       `json:"exit_code"`
	Error     string    `json:"error,omitempty"`
	Started   time.Time `json:"started,omitempty"`
	Finished  time.Time `json:"finished,omitempty"`
	Log       string    `json:"log"`
	Truncated bool      `json:"truncated,omitempty"`
}

var jobMu sync.Mutex

func (s *OperationServer) jobDir() string {
	if s.JobsDir != "" {
		return s.JobsDir
	}
	if s.FileRoot != "" {
		return filepath.Join(s.FileRoot, ".arpl-jobs")
	}
	return filepath.Join(os.TempDir(), "ai-relay-arpl-jobs")
}
func (s *OperationServer) handleJob(ctx context.Context, state SessionState, frame Frame, req OpMessage, send func(Frame) error) error {
	_ = ctx
	switch req.Action {
	case "job_run":
		return s.jobRun(state.PeerID, frame, req, send)
	case "job_status":
		return s.jobStatus(frame, req, send)
	case "job_logs":
		return s.jobLogs(frame, req, send)
	case "job_cancel":
		return s.jobCancel(frame, req, send)
	case "job_list":
		return s.jobList(frame, send)
	}
	return nil
}
func (s *OperationServer) jobRun(peerID string, frame Frame, req OpMessage, send func(Frame) error) error {
	if err := validateArgv(req.Argv); err != nil {
		return s.respond(frame, send, OpMessage{Action: "job_result", Error: err.Error()})
	}
	if err := os.MkdirAll(s.jobDir(), 0700); err != nil {
		return s.respond(frame, send, OpMessage{Action: "job_result", Error: err.Error()})
	}
	if req.Cwd != "" && s.FileRoot != "" {
		cwd, err := SecureSyncPath(s.FileRoot, req.Cwd)
		if err != nil {
			return s.respond(frame, send, OpMessage{Action: "job_result", Error: "job cwd is outside the configured file root"})
		}
		st, statErr := os.Stat(cwd)
		if statErr != nil || !st.IsDir() {
			return s.respond(frame, send, OpMessage{Action: "job_result", Error: "job cwd is not a directory"})
		}
		req.Cwd = cwd
	}
	id := NewSessionID()
	rec := JobRecord{ID: id, Argv: append([]string(nil), req.Argv...), Cwd: req.Cwd, State: "running", Started: time.Now().UTC(), Log: filepath.Join(s.jobDir(), id+".log")}
	if err := saveJob(s.jobDir(), rec); err != nil {
		return s.respond(frame, send, OpMessage{Action: "job_result", Error: err.Error()})
	}
	jobCtx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.jobCancels[id] = cancel
	s.mu.Unlock()
	go s.runJob(jobCtx, rec, req.TimeoutMS)
	if s.Audit != nil {
		_ = s.Audit.Write(AuditEvent{Event: "job", PeerID: peerID, Action: "job_run", OK: true, Metadata: map[string]string{"job_id": id}})
	}
	return s.respond(frame, send, OpMessage{Action: "job_result", OK: true, JobID: id, JobState: "running"})
}
func (s *OperationServer) runJob(parent context.Context, rec JobRecord, timeoutMS int64) {
	max := s.JobOutputMax
	if max <= 0 {
		max = 16 << 20
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = s.CommandTimeout
	}
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	defer func() { s.mu.Lock(); delete(s.jobCancels, rec.ID); s.mu.Unlock() }()
	cmd := exec.CommandContext(ctx, rec.Argv[0], rec.Argv[1:]...)
	cmd.Dir = rec.Cwd
	f, err := os.OpenFile(rec.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		rec.State = "failed"
		rec.Error = err.Error()
		rec.Finished = time.Now().UTC()
		_ = saveJob(s.jobDir(), rec)
		return
	}
	defer f.Close()
	out := &jobWriter{f: f, limit: max}
	cmd.Stdout = out
	cmd.Stderr = out
	err = cmd.Run()
	rec.Finished = time.Now().UTC()
	rec.Truncated = out.truncated
	if ctx.Err() == context.DeadlineExceeded {
		rec.State = "timeout"
		rec.Error = "job timed out"
	} else if ctx.Err() == context.Canceled {
		rec.State = "cancelled"
		rec.Error = "job cancelled"
		rec.ExitCode = -1
	} else if err == nil {
		rec.State = "succeeded"
	} else {
		rec.State = "failed"
		rec.Error = err.Error()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			rec.ExitCode = ee.ExitCode()
		}
	}
	_ = saveJob(s.jobDir(), rec)
}

type jobWriter struct {
	f         *os.File
	n, limit  int
	truncated bool
}

func (w *jobWriter) Write(p []byte) (int, error) {
	n := len(p)
	if w.n >= w.limit {
		w.truncated = true
		return n, nil
	}
	take := len(p)
	if take > w.limit-w.n {
		take = w.limit - w.n
		w.truncated = true
	}
	if take > 0 {
		if _, err := w.f.Write(p[:take]); err != nil {
			return 0, err
		}
		w.n += take
		_ = w.f.Sync()
	}
	return n, nil
}
func saveJob(dir string, rec JobRecord) error {
	jobMu.Lock()
	defer jobMu.Unlock()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, rec.ID+".json.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, rec.ID+".json"))
}
func loadJob(dir, id string) (JobRecord, error) {
	if id == "" || strings.ContainsAny(id, "/\\") {
		return JobRecord{}, errors.New("invalid job ID")
	}
	b, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		return JobRecord{}, err
	}
	var r JobRecord
	err = json.Unmarshal(b, &r)
	return r, err
}
func (s *OperationServer) jobStatus(frame Frame, req OpMessage, send func(Frame) error) error {
	r, e := loadJob(s.jobDir(), req.JobID)
	if e != nil {
		return s.respond(frame, send, OpMessage{Action: "job_result", Error: e.Error()})
	}
	return s.respond(frame, send, jobMessage(r))
}
func (s *OperationServer) jobLogs(frame Frame, req OpMessage, send func(Frame) error) error {
	r, e := loadJob(s.jobDir(), req.JobID)
	if e != nil {
		return s.respond(frame, send, OpMessage{Action: "job_result", Error: e.Error()})
	}
	b, e := os.ReadFile(r.Log)
	if e != nil && !os.IsNotExist(e) {
		return s.respond(frame, send, OpMessage{Action: "job_result", Error: e.Error()})
	}
	max := s.MaxOutput
	if max <= 0 {
		max = 4 << 20
	}
	if len(b) > max {
		b = b[len(b)-max:]
	}
	return s.respond(frame, send, OpMessage{Action: "job_result", OK: true, JobID: r.ID, JobState: r.State, JobLogs: string(b), Truncated: r.Truncated})
}
func (s *OperationServer) jobCancel(frame Frame, req OpMessage, send func(Frame) error) error {
	s.mu.Lock()
	cancel := s.jobCancels[req.JobID]
	s.mu.Unlock()
	if cancel == nil {
		return s.respond(frame, send, OpMessage{Action: "job_result", Error: "job is not running or was already completed"})
	}
	cancel()
	return s.respond(frame, send, OpMessage{Action: "job_result", OK: true, JobID: req.JobID, JobState: "cancelling"})
}
func (s *OperationServer) jobList(frame Frame, send func(Frame) error) error {
	ents, e := os.ReadDir(s.jobDir())
	if e != nil && !os.IsNotExist(e) {
		return s.respond(frame, send, OpMessage{Action: "job_result", Error: e.Error()})
	}
	var ids []string
	for _, ent := range ents {
		if strings.HasSuffix(ent.Name(), ".json") {
			ids = append(ids, strings.TrimSuffix(ent.Name(), ".json"))
		}
	}
	return s.respond(frame, send, OpMessage{Action: "job_result", OK: true, JobIDs: ids})
}
func jobMessage(r JobRecord) OpMessage {
	return OpMessage{Action: "job_result", OK: true, JobID: r.ID, JobState: r.State, ExitCode: r.ExitCode, Error: r.Error, Truncated: r.Truncated}
}
