//go:build !linux && !windows

package main

import "os/exec"

func configureSupervisedChild(*exec.Cmd) {}
