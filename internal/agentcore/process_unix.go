//go:build !windows

package agentcore

import (
	"os"
	"os/exec"
	"syscall"
)

// ConfigureProcess gives each command its own group so cancellation also stops
// children launched by a shell or Codex.
func ConfigureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return KillProcess(cmd) }
}
func KillProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err == syscall.ESRCH {
		return os.ErrProcessDone
	}
	return err
}
