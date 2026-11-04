//go:build linux || darwin

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// validateLifecycleLockIdentity opens the path without following a symlink
// and compares the opened inode with the descriptor captured by Open. The
// extra descriptor is closed immediately; the original lock descriptor keeps
// the ownership boundary alive.
func validateLifecycleLockIdentity(path string, expected os.FileInfo) error {
	if isNilLifecycleFileInfo(expected) {
		return ErrClosed
	}
	fd, err := syscall.Open(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("%w: lifecycle lock path must not be a symlink", ErrInvalid)
		}
		return fmt.Errorf("%w: lifecycle lock path is unavailable", ErrConflict)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("%w: lifecycle lock handle is unavailable", ErrConflict)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat lifecycle lock path: %v", ErrConflict, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: lifecycle lock path is not a regular file", ErrInvalid)
	}
	if info.Mode().Perm() != 0600 {
		return fmt.Errorf("%w: lifecycle lock path is not private", ErrInvalid)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("%w: lifecycle lock path must not be hard-linked", ErrInvalid)
	}
	if !os.SameFile(info, expected) {
		return fmt.Errorf("%w: lifecycle lock path changed", ErrConflict)
	}
	return nil
}
