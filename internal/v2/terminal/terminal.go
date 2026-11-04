// Package terminal provides the bounded local action surface for the 2.0
// controller. It deliberately does not expose a shell or privilege helper.
package terminal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ai-relay/ai-relay/internal/agentcore"
)

type ApprovalClass string

const (
	ApprovalRead    ApprovalClass = "read"
	ApprovalWrite   ApprovalClass = "write"
	ApprovalExecute ApprovalClass = "execute"
)

type Request struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args,omitempty"`
	WorkingDir  string            `json:"working_dir"`
	Approval    ApprovalClass     `json:"approval"`
	Approved    bool              `json:"approved"`
	Timeout     time.Duration     `json:"timeout"`
	MaxOutput   int               `json:"max_output_bytes"`
	Environment map[string]string `json:"environment,omitempty"`
}

// Executor binds all requests to a repository root selected by the trusted
// supervisor. The request itself cannot enlarge that boundary.
type Executor struct {
	RepositoryRoot string
}

type Result struct {
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	OutputTruncated bool   `json:"output_truncated"`
	Canceled        bool   `json:"canceled"`
}

const (
	DefaultTimeout    = 2 * time.Minute
	DefaultMaxOutput  = 256 * 1024
	AbsoluteMaxOutput = 1024 * 1024
)

var (
	ErrApprovalRequired  = errors.New("explicit approval is required for this action")
	ErrOutsideRepository = errors.New("working directory is outside the repository")
	ErrShellForbidden    = errors.New("shell commands are not permitted")
)

func (e Executor) Run(ctx context.Context, req Request) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("context is required")
	}
	root, err := repositoryRoot(e.RepositoryRoot)
	if err != nil {
		return Result{}, err
	}
	workdir, err := repositoryRoot(req.WorkingDir)
	if err != nil || !within(root, workdir) {
		return Result{}, ErrOutsideRepository
	}
	if err := validate(req, root, workdir); err != nil {
		return Result{}, err
	}
	if req.Approval == ApprovalRead {
		resolved, err := exec.LookPath(req.Command)
		if err != nil {
			return Result{}, err
		}
		realExecutable, err := filepath.EvalSymlinks(resolved)
		if err != nil || within(root, realExecutable) {
			return Result{}, errors.New("read command must resolve outside the repository")
		}
		req.Command = realExecutable
	}
	if req.Timeout <= 0 {
		req.Timeout = DefaultTimeout
	}
	if req.Timeout > 10*time.Minute {
		return Result{}, fmt.Errorf("timeout exceeds 10 minutes")
	}
	if req.MaxOutput <= 0 {
		req.MaxOutput = DefaultMaxOutput
	}
	if req.MaxOutput > AbsoluteMaxOutput {
		return Result{}, fmt.Errorf("max output exceeds %d bytes", AbsoluteMaxOutput)
	}

	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, req.Command, req.Args...)
	agentcore.ConfigureProcess(cmd)
	cmd.Dir = workdir
	cmd.Env = trustedBaseEnvironment()
	for key, value := range req.Environment {
		if !safeEnvKey(key) || strings.ContainsRune(value, '\x00') {
			return Result{}, fmt.Errorf("invalid environment key %q", key)
		}
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	stdout, stderr := &limitedWriter{limit: req.MaxOutput}, &limitedWriter{limit: req.MaxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	result := Result{ExitCode: exitCode(err), Stdout: stdout.String(), Stderr: stderr.String(), OutputTruncated: stdout.truncated || stderr.truncated}
	if ctx.Err() != nil {
		result.Canceled = true
		return result, ctx.Err()
	}
	return result, err
}

func repositoryRoot(dir string) (string, error) {
	if dir == "" {
		return "", ErrOutsideRepository
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", ErrOutsideRepository
	}
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return "", ErrOutsideRepository
	}
	return root, nil
}

func validate(req Request, root, workdir string) error {
	if req.Command == "" || strings.ContainsRune(req.Command, '\x00') {
		return errors.New("command is required")
	}
	base := strings.ToLower(filepath.Base(req.Command))
	for _, shell := range []string{"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"} {
		if base == shell {
			return ErrShellForbidden
		}
	}
	if req.Approval != ApprovalRead && req.Approval != ApprovalWrite && req.Approval != ApprovalExecute {
		return errors.New("invalid approval class")
	}
	if req.Approval != ApprovalRead && !req.Approved {
		return ErrApprovalRequired
	}
	if req.Approval == ApprovalRead && !readOnlyCommand(root, workdir, req.Command, req.Args) {
		return errors.New("command is not allowed for an unapproved read action")
	}
	return nil
}

func readOnlyCommand(root, workdir, command string, args []string) bool {
	if command != filepath.Base(command) {
		return false
	}
	base := strings.ToLower(command)
	if runtime.GOOS == "windows" && strings.HasSuffix(base, ".exe") {
		base = strings.TrimSuffix(base, ".exe")
	}
	switch base {
	case "pwd", "true", "false":
		return len(args) == 0
	case "cat":
		if len(args) == 0 {
			return false
		}
		for _, arg := range args {
			if arg == "--" {
				continue
			}
			if strings.HasPrefix(arg, "-") || !existingPathWithin(root, workdir, arg) {
				return false
			}
		}
		return true
	case "ls":
		for _, arg := range args {
			if arg == "--" || arg == "-a" || arg == "-l" || arg == "-la" || arg == "-al" {
				continue
			}
			if strings.HasPrefix(arg, "-") || !existingPathWithin(root, workdir, arg) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func existingPathWithin(root, workdir, arg string) bool {
	if arg == "" || filepath.IsAbs(arg) {
		return false
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(workdir, arg))
	return err == nil && within(root, resolved)
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func safeEnvKey(k string) bool {
	if k == "NO_COLOR" || k == "TERM" || strings.HasPrefix(k, "AI_RELAY_BENCH_") {
		return !strings.ContainsAny(k, "=\x00")
	}
	return false
}

func trustedBaseEnvironment() []string {
	environment := []string{"PATH=" + os.Getenv("PATH"), "LANG=C"}
	for _, key := range []string{"HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR"} {
		if value := os.Getenv(key); value != "" && !strings.ContainsRune(value, '\x00') {
			environment = append(environment, key+"="+value)
		}
	}
	return environment
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var x *exec.ExitError
	if errors.As(err, &x) {
		return x.ExitCode()
	}
	return -1
}

type limitedWriter struct {
	data      []byte
	limit     int
	truncated bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(w.data)+len(p) > w.limit {
		keep := w.limit - len(w.data)
		if keep > 0 {
			w.data = append(w.data, p[:keep]...)
		}
		w.truncated = true
		return len(p), nil
	}
	w.data = append(w.data, p...)
	return len(p), nil
}
func (w *limitedWriter) String() string { return string(w.data) }

var _ io.Writer = (*limitedWriter)(nil)
