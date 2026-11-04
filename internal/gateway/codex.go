package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ai-relay/ai-relay/internal/agentcore"
	"github.com/ai-relay/ai-relay/internal/security"
)

const (
	maxCodexPrompt = 32 * 1024
	maxCodexTail   = 1024 * 1024
)

type codexManager struct {
	server  *Server
	mu      sync.Mutex
	running map[string]context.CancelFunc
}

func newCodexManager(s *Server) *codexManager {
	m := &codexManager{server: s, running: map[string]context.CancelFunc{}}
	s.mu.Lock()
	changed := false
	for _, j := range s.codexJobs {
		if j.Status == "running" || j.Status == "cancel_requested" {
			j.Status = "interrupted"
			j.Error = "gateway restarted while the process was running"
			j.Updated = time.Now().Unix()
			changed = true
		}
	}
	if changed {
		_ = s.saveStateLocked()
	}
	s.mu.Unlock()
	return m
}

func codexSandbox() (string, error) {
	mode := strings.TrimSpace(os.Getenv("AI_RELAY_CODEX_SANDBOX"))
	if mode == "" {
		mode = "read-only"
	}
	if mode != "read-only" && mode != "workspace-write" {
		return "", errors.New("AI_RELAY_CODEX_SANDBOX must be read-only or workspace-write")
	}
	return mode, nil
}

func (m *codexManager) submit(owner, prompt, workdir string) (*CodexJobRecord, error) {
	if _, err := codexSandbox(); err != nil {
		return nil, err
	}
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return nil, errors.New("prompt is required")
	}
	if len(prompt) > maxCodexPrompt {
		return nil, fmt.Errorf("prompt exceeds %d bytes", maxCodexPrompt)
	}
	if workdir == "" {
		workdir = m.server.state
	}
	workdir, err := filepath.Abs(workdir)
	if err != nil {
		return nil, fmt.Errorf("invalid workdir: %w", err)
	}
	st, err := os.Stat(workdir)
	if err != nil || !st.IsDir() {
		return nil, errors.New("workdir must be an existing directory")
	}
	id, err := security.Token(18)
	if err != nil {
		return nil, err
	}
	logDir := filepath.Join(m.server.state, "codex-jobs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return nil, err
	}
	logPath := filepath.Join(logDir, id+".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	now := time.Now().Unix()
	j := &CodexJobRecord{ID: id, Owner: owner, Prompt: prompt, Workdir: workdir, Status: "queued", LogPath: logPath, Created: now, Updated: now}
	m.server.mu.Lock()
	m.server.codexJobs[id] = j
	err = m.server.saveStateLocked()
	m.server.mu.Unlock()
	if err != nil {
		return nil, err
	}
	m.server.mu.Lock()
	result := copyCodexJob(j)
	m.server.mu.Unlock()
	go m.run(j.ID)
	return publicCodexJob(result), nil
}

func (m *codexManager) run(id string) {
	sandbox, err := codexSandbox()
	if err != nil {
		m.finish(id, "failed", -1, err.Error())
		return
	}
	bin := strings.TrimSpace(os.Getenv("AI_RELAY_CODEX_BIN"))
	if bin == "" {
		bin = strings.TrimSpace(os.Getenv("RLI_CODEX_BIN"))
	}
	if bin == "" {
		bin = "codex"
	}
	if !filepath.IsAbs(bin) {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			m.finish(id, "failed", 0, "codex executable not found")
			return
		}
		bin = resolved
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.mu.Lock()
	m.running[id] = cancel
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.running, id); m.mu.Unlock() }()
	m.server.mu.Lock()
	j := m.server.codexJobs[id]
	if j == nil || j.Status == "canceled" {
		m.server.mu.Unlock()
		return
	}
	logPath, workdir, prompt := j.LogPath, j.Workdir, j.Prompt
	j.Status = "running"
	j.Updated = time.Now().Unix()
	_ = m.server.saveStateLocked()
	m.server.mu.Unlock()
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		m.finish(id, "failed", 0, err.Error())
		return
	}
	defer f.Close()
	_, _ = io.WriteString(f, fmt.Sprintf("[ai-relay] codex job %s started %s\n", id, time.Now().UTC().Format(time.RFC3339Nano)))
	cmd := exec.CommandContext(ctx, bin, "--ask-for-approval", "never", "exec", "--sandbox", sandbox, "--skip-git-repo-check", "-")
	agentcore.ConfigureProcess(cmd)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.Dir = workdir
	cmd.Stdout = f
	cmd.Stderr = f
	err = cmd.Start()
	if err == nil {
		m.server.mu.Lock()
		if j := m.server.codexJobs[id]; j != nil {
			j.PID = cmd.Process.Pid
			j.Updated = time.Now().Unix()
			_ = m.server.saveStateLocked()
		}
		m.server.mu.Unlock()
		err = cmd.Wait()
	}
	status := "completed"
	exit := 0
	msg := ""
	if err != nil {
		status = "failed"
		msg = err.Error()
		if ctx.Err() != nil {
			status = "canceled"
			msg = "canceled by controller"
		}
		if x, ok := err.(*exec.ExitError); ok {
			exit = x.ExitCode()
		} else {
			exit = -1
		}
	}
	_, _ = io.WriteString(f, fmt.Sprintf("[ai-relay] codex job %s finished status=%s exit=%d\n", id, status, exit))
	m.finish(id, status, exit, msg)
}

func (m *codexManager) finish(id, status string, exit int, msg string) {
	m.server.mu.Lock()
	defer m.server.mu.Unlock()
	if j := m.server.codexJobs[id]; j != nil {
		j.Status = status
		j.PID = 0
		j.ExitCode = &exit
		j.Error = msg
		j.Updated = time.Now().Unix()
		_ = m.server.saveStateLocked()
	}
}

func (m *codexManager) owned(owner, id string) (*CodexJobRecord, error) {
	m.server.mu.Lock()
	defer m.server.mu.Unlock()
	j := m.server.codexJobs[id]
	if j == nil {
		return nil, errors.New("codex job not found")
	}
	if j.Owner != owner {
		return nil, errors.New("codex job belongs to another controller")
	}
	return copyCodexJob(j), nil
}
func (m *codexManager) status(owner, id string) (*CodexJobRecord, error) { return m.owned(owner, id) }
func (m *codexManager) log(owner, id string, tail int) (string, error) {
	j, err := m.owned(owner, id)
	if err != nil {
		return "", err
	}
	if tail < 1 {
		tail = 1
	}
	if tail > maxCodexTail {
		tail = maxCodexTail
	}
	f, err := os.Open(j.LogPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	start := st.Size() - int64(tail)
	if start < 0 {
		start = 0
	}
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(tail)))
	return string(b), err
}
func (m *codexManager) cancel(owner, id string) (*CodexJobRecord, error) {
	j, err := m.owned(owner, id)
	if err != nil {
		return nil, err
	}
	if j.Status == "completed" || j.Status == "failed" || j.Status == "canceled" || j.Status == "interrupted" {
		return j, nil
	}
	m.mu.Lock()
	cancel := m.running[id]
	m.mu.Unlock()
	if cancel == nil {
		m.server.mu.Lock()
		current := m.server.codexJobs[id]
		if current != nil && current.Status == "queued" {
			current.Status = "canceled"
			current.Updated = time.Now().Unix()
			_ = m.server.saveStateLocked()
			j = publicCodexJob(current)
			m.server.mu.Unlock()
			return j, nil
		}
		m.server.mu.Unlock()
		return j, errors.New("codex job is not running")
	}
	cancel()
	m.server.mu.Lock()
	if current := m.server.codexJobs[id]; current != nil && (current.Status == "running" || current.Status == "queued") {
		current.Status = "cancel_requested"
		current.Updated = time.Now().Unix()
		_ = m.server.saveStateLocked()
		j = publicCodexJob(current)
	}
	m.server.mu.Unlock()
	return j, nil
}
func publicCodexJob(j *CodexJobRecord) *CodexJobRecord {
	c := copyCodexJob(j)
	c.LogPath = ""
	return c
}
func copyCodexJob(j *CodexJobRecord) *CodexJobRecord {
	if j == nil {
		return nil
	}
	c := *j
	if j.ExitCode != nil {
		x := *j.ExitCode
		c.ExitCode = &x
	}
	return &c
}
