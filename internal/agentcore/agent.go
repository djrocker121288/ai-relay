package agentcore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Job struct {
	ID              string    `json:"id"`
	Command         string    `json:"command"`
	Args            []string  `json:"args"`
	Started         time.Time `json:"started"`
	Exit            *int      `json:"exit,omitempty"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	Finished        bool      `json:"finished"`
	StdoutTruncated bool      `json:"stdout_truncated"`
	StderrTruncated bool      `json:"stderr_truncated"`
	cmd             *exec.Cmd
	stdin           io.WriteCloser
	mu              sync.Mutex
}
type Core struct {
	mu         sync.Mutex
	jobs       map[string]*Job
	privileged func(*exec.Cmd)
}

func New() *Core { return &Core{jobs: map[string]*Job{}} }
func (c *Core) Capabilities() []string {
	return PlatformCapabilities()
}
func (c *Core) Run(ctx context.Context, id string, command string, args []string, cwd string, env map[string]string, priv bool) (map[string]any, error) {
	if command == "" || strings.Contains(command, "\x00") {
		return nil, fmt.Errorf("invalid command")
	}
	if cwd == "" {
		cwd = "."
	}
	cmd := exec.CommandContext(ctx, command, args...)
	ConfigureProcess(cmd)
	cmd.Dir = cwd
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if priv && runtime.GOOS == "windows" {
		return nil, fmt.Errorf("privileged execution requires an unavailable Windows elevation helper")
	}
	if priv {
		if disabled, _ := os.Stat("/etc/ai-relay/disabled"); disabled == nil {
			return nil, fmt.Errorf("privileged execution disabled")
		}
		if disabled, _ := os.Stat("/etc/rli-remote/disabled"); disabled == nil {
			return nil, fmt.Errorf("privileged execution disabled")
		}
		argv := append([]string{"-n", command}, args...)
		cmd = exec.CommandContext(ctx, "sudo", argv...)
		ConfigureProcess(cmd)
		cmd.Dir = cwd
		cmd.Env = os.Environ()
	}
	var stdout, stderr tailWriter
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	er := cmd.Run()
	stdout.mu.Lock()
	stdoutData, stdoutTruncated := stdout.data, stdout.truncated
	stdout.mu.Unlock()
	stderr.mu.Lock()
	stderrData, stderrTruncated := stderr.data, stderr.truncated
	stderr.mu.Unlock()
	return map[string]any{"exit_code": exitCode(er), "stdout": stdoutData, "stderr": stderrData, "stdout_truncated": stdoutTruncated, "stderr_truncated": stderrTruncated, "privileged": priv}, er
}
func exitCode(e error) int {
	if e == nil {
		return 0
	}
	if x, ok := e.(*exec.ExitError); ok {
		return x.ExitCode()
	}
	return -1
}
func (c *Core) Start(ctx context.Context, id, command string, args []string, cwd string, env map[string]string) (*Job, error) {
	return c.StartWithEvents(ctx, id, command, args, cwd, env, nil)
}

// StartWithEvents starts a durable, independently cancellable job. The event
// callback is invoked for each stdout/stderr chunk and the terminal event.
func (c *Core) StartWithEvents(ctx context.Context, id, command string, args []string, cwd string, env map[string]string, event func(string, string, bool, *int)) (*Job, error) {
	if command == "" || strings.Contains(command, "\x00") {
		return nil, fmt.Errorf("invalid command")
	}
	if cwd == "" {
		cwd = "."
	}
	cmd := exec.CommandContext(ctx, command, args...)
	ConfigureProcess(cmd)
	cmd.Dir = cwd
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	errp, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if e := cmd.Start(); e != nil {
		return nil, e
	}
	j := &Job{ID: id, Command: command, Args: args, Started: time.Now(), cmd: cmd, stdin: in}
	c.mu.Lock()
	c.jobs[id] = j
	c.mu.Unlock()
	go c.capture(j, out, errp, event)
	return j, nil
}
func (c *Core) capture(j *Job, o, e io.Reader, event func(string, string, bool, *int)) {
	var wg sync.WaitGroup
	read := func(stream string, r io.Reader) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, er := r.Read(buf)
			if n > 0 {
				data := string(buf[:n])
				j.mu.Lock()
				if stream == "stdout" {
					tail, truncated := outputTail(j.Stdout, data)
					j.Stdout, j.StdoutTruncated = tail, j.StdoutTruncated || truncated
				} else {
					tail, truncated := outputTail(j.Stderr, data)
					j.Stderr, j.StderrTruncated = tail, j.StderrTruncated || truncated
				}
				j.mu.Unlock()
				if event != nil {
					event(stream, data, false, nil)
				}
			}
			if er != nil {
				return
			}
		}
	}
	wg.Add(2)
	go read("stdout", o)
	go read("stderr", e)
	wg.Wait()
	x := j.cmd.Wait()
	v := exitCode(x)
	j.mu.Lock()
	j.Exit = &v
	j.Finished = true
	j.mu.Unlock()
	c.pruneFinished()
	if event != nil {
		event("", "", true, &v)
	}
}
func (c *Core) WriteStdin(id string, data []byte) error {
	c.mu.Lock()
	j := c.jobs[id]
	c.mu.Unlock()
	if j == nil {
		return os.ErrNotExist
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.Finished || j.stdin == nil {
		return fmt.Errorf("job is finished")
	}
	_, e := j.stdin.Write(data)
	return e
}
func (c *Core) Cancel(id string) error {
	c.mu.Lock()
	j := c.jobs[id]
	c.mu.Unlock()
	if j == nil {
		return os.ErrNotExist
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.Finished {
		return nil
	}
	return KillProcess(j.cmd)
}

// Snapshot remains available even after a completed job leaves the core cache.
func (j *Job) Snapshot() *Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	return &Job{ID: j.ID, Command: j.Command, Args: append([]string(nil), j.Args...), Started: j.Started, Exit: j.Exit, Stdout: j.Stdout, Stderr: j.Stderr, Finished: j.Finished, StdoutTruncated: j.StdoutTruncated, StderrTruncated: j.StderrTruncated}
}
func (c *Core) Jobs() []*Job {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]*Job, 0, len(c.jobs))
	for _, job := range c.jobs {
		result = append(result, job.Snapshot())
	}
	return result
}

// Only the portable agent's transient completed cache is pruned. Durable
// gateway results and pending delivery outboxes remain intact.
func (c *Core) pruneFinished() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		count := 0
		var oldest *Job
		for _, job := range c.jobs {
			snapshot := job.Snapshot()
			if !snapshot.Finished {
				continue
			}
			count++
			if oldest == nil || job.Started.Before(oldest.Started) {
				oldest = job
			}
		}
		if count <= MaxFinishedJobs {
			return
		}
		delete(c.jobs, oldest.ID)
	}
}
func FileOp(op string, p string, data []byte) (any, error) {
	switch op {
	case "read":
		return os.ReadFile(p)
	case "write":
		return nil, os.WriteFile(p, data, 0600)
	case "list":
		x, e := os.ReadDir(p)
		if e != nil {
			return nil, e
		}
		r := []string{}
		for _, v := range x {
			r = append(r, v.Name())
		}
		return r, nil
	case "stat":
		return os.Stat(p)
	case "delete":
		return nil, os.RemoveAll(p)
	case "mkdir":
		return nil, os.MkdirAll(p, 0700)
	case "move":
		return nil, os.Rename(p, string(data))
	case "copy":
		b, e := os.ReadFile(p)
		if e != nil {
			return nil, e
		}
		return nil, os.WriteFile(string(data), b, 0600)
	case "search":
		var r []string
		e := filepath.Walk(p, func(x string, i os.FileInfo, z error) error {
			if z == nil && strings.Contains(i.Name(), string(data)) {
				r = append(r, x)
			}
			return nil
		})
		return r, e
	}
	return nil, fmt.Errorf("unsupported file op")
}
func JSON(v any) string { b, _ := json.Marshal(v); return string(b) }
