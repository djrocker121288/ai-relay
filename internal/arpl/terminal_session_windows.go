//go:build windows

package arpl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// conPTYSession is the native Windows 10 1809+ pseudoconsole adapter.
type conPTYSession struct {
	mu        sync.Mutex
	proc, pty windows.Handle
	in, out   *os.File
	done      chan struct{}
	exitCode  uint32
	waitErr   error
	once      sync.Once
}

func newTerminalSession(ctx context.Context, argv []string, cwd string, rows, cols uint16) (terminalSession, error) {
	if err := validateArgv(argv); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	inR, inW, err := makeConPTYPipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := makeConPTYPipe()
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		return nil, err
	}
	var pty windows.Handle
	if err = windows.CreatePseudoConsole(windows.Coord{X: int16(cols), Y: int16(rows)}, windows.Handle(inR.Fd()), windows.Handle(outW.Fd()), 0, &pty); err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, err
	}
	_ = windows.SetHandleInformation(windows.Handle(inW.Fd()), windows.HANDLE_FLAG_INHERIT, 0)
	_ = windows.SetHandleInformation(windows.Handle(outR.Fd()), windows.HANDLE_FLAG_INHERIT, 0)
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		windows.ClosePseudoConsole(pty)
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, err
	}
	defer attrs.Delete()
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, unsafe.Pointer(pty), unsafe.Sizeof(pty)); err != nil {
		windows.ClosePseudoConsole(pty)
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, err
	}
	cmdline, err := windows.UTF16FromString(joinWindowsCommandLine(argv))
	if err != nil {
		return nil, err
	}
	var dir *uint16
	if cwd != "" {
		dir, err = windows.UTF16PtrFromString(cwd)
		if err != nil {
			return nil, err
		}
	}
	si := windows.StartupInfoEx{}
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(si))
	si.ProcThreadAttributeList = attrs.List()
	pi := windows.ProcessInformation{}
	err = windows.CreateProcess(nil, &cmdline[0], nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT, nil, dir, &si.StartupInfo, &pi)
	inR.Close()
	outW.Close()
	if err != nil {
		windows.ClosePseudoConsole(pty)
		inW.Close()
		outR.Close()
		return nil, err
	}
	windows.CloseHandle(pi.Thread)
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pi.ProcessId)
	windows.CloseHandle(pi.Process)
	if err != nil {
		windows.ClosePseudoConsole(pty)
		inW.Close()
		outR.Close()
		return nil, err
	}
	s := &conPTYSession{proc: proc, pty: pty, in: inW, out: outR, done: make(chan struct{})}
	go s.waitProcess()
	go func() { <-ctx.Done(); _ = s.Close() }()
	return s, nil
}

func makeConPTYPipe() (*os.File, *os.File, error) {
	var r, w windows.Handle
	if err := windows.CreatePipe(&r, &w, nil, 0); err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(r), "arpl-conpty-r"), os.NewFile(uintptr(w), "arpl-conpty-w"), nil
}
func (s *conPTYSession) waitProcess() {
	_, err := windows.WaitForSingleObject(s.proc, windows.INFINITE)
	var code uint32
	if err == nil {
		err = windows.GetExitCodeProcess(s.proc, &code)
	}
	s.mu.Lock()
	s.exitCode = code
	s.waitErr = err
	if s.pty != 0 {
		windows.ClosePseudoConsole(s.pty)
		s.pty = 0
	}
	s.mu.Unlock()
	close(s.done)
}

func (s *conPTYSession) Write(p []byte) (int, error) {
	if s == nil {
		return 0, io.ErrClosedPipe
	}
	s.mu.Lock()
	in := s.in
	s.mu.Unlock()
	if in == nil {
		return 0, io.ErrClosedPipe
	}
	return in.Write(p)
}
func (s *conPTYSession) Resize(rows, cols uint16) error {
	if s == nil {
		return io.ErrClosedPipe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pty == 0 {
		return io.ErrClosedPipe
	}
	return windows.ResizePseudoConsole(s.pty, windows.Coord{X: int16(cols), Y: int16(rows)})
}
func (s *conPTYSession) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.once.Do(func() {
		s.mu.Lock()
		in := s.in
		proc := s.proc
		s.in = nil
		s.mu.Unlock()
		if in != nil {
			_ = in.Close()
		}
		if proc != 0 {
			_ = windows.TerminateProcess(proc, 1)
		}
		if s.done != nil {
			<-s.done
		}
		s.mu.Lock()
		if s.proc != 0 {
			closeErr = windows.CloseHandle(s.proc)
			s.proc = 0
		}
		if s.out != nil {
			_ = s.out.Close()
			s.out = nil
		}
		s.mu.Unlock()
	})
	return closeErr
}
func (s *conPTYSession) Run(onData func([]byte) error) (int, error) {
	if s == nil {
		return -1, io.ErrClosedPipe
	}
	s.mu.Lock()
	out := s.out
	done := s.done
	s.mu.Unlock()
	if out == nil {
		return -1, io.ErrClosedPipe
	}
	buf := make([]byte, 32<<10)
	var readErr error
	for {
		n, err := out.Read(buf)
		if n > 0 && onData != nil {
			if e := onData(append([]byte(nil), buf[:n]...)); e != nil {
				_ = s.Close()
				return -1, e
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				readErr = err
			}
			break
		}
	}
	if done != nil {
		<-done
	}
	s.mu.Lock()
	code := s.exitCode
	waitErr := s.waitErr
	s.mu.Unlock()
	if readErr != nil {
		return -1, readErr
	}
	if waitErr != nil {
		return -1, waitErr
	}
	if code == 0 {
		return 0, nil
	}
	return int(code), errors.New("ConPTY process exited")
}
func joinWindowsCommandLine(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == "" {
			out[i] = "\"\""
			continue
		}
		if !strings.ContainsAny(a, " \t\"") {
			out[i] = a
			continue
		}
		out[i] = "\"" + strings.ReplaceAll(a, "\"", "\\\"") + "\""
	}
	return strings.Join(out, " ")
}

// RunConPTYAcceptance is used by the release gate on a Windows host. It
// verifies create/input/output/resize/exit without involving production peers.
func RunConPTYAcceptance() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := newTerminalSession(ctx, []string{"cmd.exe", "/d", "/q"}, "", 24, 80)
	if err != nil {
		return err
	}
	defer s.Close()
	if err = s.Resize(30, 100); err != nil {
		return err
	}
	if _, err = s.Write([]byte("echo ARPL_CONPTY:accept\r\nexit\r\n")); err != nil {
		return err
	}
	var out strings.Builder
	_, err = s.Run(func(p []byte) error { _, _ = out.Write(p); return nil })
	if err != nil {
		return err
	}
	if !strings.Contains(out.String(), "ARPL_CONPTY:accept") {
		return fmt.Errorf("ConPTY output did not contain acceptance marker")
	}
	return nil
}
