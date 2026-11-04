//go:build windows

package agentcore

import "os/exec"

// Windows child process containment requires a native Job Object helper.
func ConfigureProcess(cmd *exec.Cmd)  {}
func KillProcess(cmd *exec.Cmd) error { return cmd.Process.Kill() }
