//go:build linux || darwin

package lifecycle

import (
	"fmt"
	"os"
	"syscall"
)

func acquireLifecycleLock(f *os.File) error {
	if !lifecycleFileReady(f) {
		return ErrClosed
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("%w: state directory is already open", ErrConflict)
	}
	return nil
}

func releaseLifecycleLock(f *os.File) error {
	if !lifecycleFileReady(f) {
		return ErrClosed
	}
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
