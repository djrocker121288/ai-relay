//go:build !windows

package arpl

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/creack/pty"
)

type unixTerminalSession struct {
	cmd  *exec.Cmd
	ptmx *os.File
	once sync.Once
}

func newTerminalSession(ctx context.Context, argv []string, cwd string, rows, cols uint16) (terminalSession, error) {
	if err := validateArgv(argv); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(terminalCommandContext(ctx), argv[0], argv[1:]...)
	cmd.Env = terminalEnvironment()
	if cwd != "" {
		cmd.Dir = cwd
	}
	ws := &pty.Winsize{Rows: rows, Cols: cols}
	ptmx, err := pty.StartWithSize(cmd, ws)
	if err != nil {
		return nil, err
	}
	return &unixTerminalSession{cmd: cmd, ptmx: ptmx}, nil
}

func terminalEnvironment() []string {
	env := os.Environ()
	found := false
	for i, value := range env {
		if !strings.HasPrefix(value, "TERM=") {
			continue
		}
		found = true
		term := strings.TrimPrefix(value, "TERM=")
		if term == "" || strings.EqualFold(term, "dumb") {
			env[i] = "TERM=xterm-256color"
		}
		break
	}
	if !found {
		env = append(env, "TERM=xterm-256color")
	}
	return env
}

func (s *unixTerminalSession) Write(p []byte) (int, error) {
	if s == nil || s.ptmx == nil {
		return 0, io.ErrClosedPipe
	}
	return s.ptmx.Write(p)
}

func (s *unixTerminalSession) Resize(rows, cols uint16) error {
	if s == nil || s.ptmx == nil {
		return io.ErrClosedPipe
	}
	return pty.Setsize(s.ptmx, &pty.Winsize{Rows: rows, Cols: cols})
}

func (s *unixTerminalSession) Close() error {
	if s == nil {
		return nil
	}
	var out error
	s.once.Do(func() {
		if s.ptmx != nil {
			_ = s.ptmx.Close()
		}
		if s.cmd != nil && s.cmd.Process != nil {
			if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				out = err
			}
		}
	})
	return out
}

func (s *unixTerminalSession) Run(onData func([]byte) error) (int, error) {
	if s == nil || s.ptmx == nil || s.cmd == nil {
		return -1, io.ErrClosedPipe
	}
	buf := make([]byte, 32<<10)
	var streamErr error
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 && onData != nil {
			chunk := append([]byte(nil), buf[:n]...)
			if e := onData(chunk); e != nil {
				streamErr = e
				_ = s.Close()
				break
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				// PTYs commonly return EIO when the slave side exits. cmd.Wait
				// below is the authoritative process result.
			}
			break
		}
	}
	waitErr := s.cmd.Wait()
	_ = s.ptmx.Close()
	if streamErr != nil {
		return -1, streamErr
	}
	if waitErr == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		return ee.ExitCode(), waitErr
	}
	return -1, waitErr
}
