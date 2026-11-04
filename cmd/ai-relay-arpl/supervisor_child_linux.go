//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

// configureSupervisedChild makes the kernel send SIGTERM to a child when the
// supervisor dies, including an unhandled SIGKILL. This prevents stale lock
// recovery from creating duplicate orphan hosts/clients.
func configureSupervisedChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
