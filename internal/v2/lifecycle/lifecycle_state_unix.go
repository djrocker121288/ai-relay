//go:build linux || darwin

package lifecycle

import (
	"errors"
	"os"
	"syscall"
)

func validateLifecycleStateInfo(info os.FileInfo) error {
	if isNilLifecycleFileInfo(info) {
		return errors.New("lifecycle state observation is unavailable")
	}
	if !info.Mode().IsRegular() {
		return errors.New("lifecycle state must be a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("lifecycle state is not private")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("lifecycle state must not be hard-linked")
	}
	return nil
}

// openLifecycleState opens the replaceable checkpoint without following a
// symlink, then validates the descriptor that will actually be read. The
// directory is private, but the check closes the path-replacement window at
// the state-file boundary as well as the existing state-root boundary.
func openLifecycleState(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not open lifecycle state")
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := validateLifecycleStateInfo(info); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
