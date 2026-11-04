//go:build windows

package main

import "os/exec"

func configureSupervisedChild(*exec.Cmd) {}
