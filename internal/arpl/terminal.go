package arpl

import (
	"context"
	"errors"
	"os/exec"
)

var ErrPTYUnavailable = errors.New("ARPL native PTY backend is unavailable in this build")

// Terminal is a deliberate platform seam. Exec uses an argv vector and never
// constructs a shell command string.
type Terminal interface {
	Start(context.Context, []string, string) (TerminalProcess, error)
}
type TerminalProcess interface {
	Wait() error
	Close() error
}

type ExecTerminal struct{}
type execProcess struct{ cmd *exec.Cmd }

func (ExecTerminal) Start(ctx context.Context, argv []string, dir string) (TerminalProcess, error) {
	if len(argv) == 0 {
		return nil, errors.New("terminal argv is empty")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execProcess{cmd}, nil
}
func (p execProcess) Wait() error { return p.cmd.Wait() }
func (p execProcess) Close() error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Kill()
}

// PTYTerminal is the explicit native adapter seam. Unix PTY support needs a
// platform dependency (not present in this repository's stdlib-only core).
// Windows maps this seam to ConPTY in a future native helper; Android callers
// can supply a Termux/app-sandbox implementation.
type PTYTerminal struct{}

func (PTYTerminal) Start(context.Context, []string, string) (TerminalProcess, error) {
	return nil, ErrPTYUnavailable
}
