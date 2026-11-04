//go:build linux || darwin

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func ensureLifecycleLockCapability() error { return nil }

// openLifecycleLock opens the ownership boundary without following a
// replaceable path. The state root is private, but a stale or tampered lock
// symlink must still fail closed rather than chmod or lock an unrelated file.
func openLifecycleLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not open lifecycle lock")
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("lifecycle lock must be a regular file")
	}
	// A hard-linked lock path could make Open chmod or lock an unrelated
	// inode outside the lifecycle state directory. The state root is private,
	// but a malformed or operator-provided checkpoint must not redirect this
	// ownership boundary through another directory entry.
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		_ = f.Close()
		return nil, fmt.Errorf("%w: lifecycle lock must not be hard-linked", ErrInvalid)
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := acquireLifecycleLock(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
