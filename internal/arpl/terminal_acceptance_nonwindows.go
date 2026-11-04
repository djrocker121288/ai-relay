//go:build !windows

package arpl

import "errors"

func RunConPTYAcceptance() error { return errors.New("ConPTY acceptance requires Windows") }
