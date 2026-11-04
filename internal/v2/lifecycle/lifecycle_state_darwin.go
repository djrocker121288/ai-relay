//go:build darwin

package lifecycle

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// readBoundedFromLifecycleRoot binds the checkpoint lookup to an opened,
// identity-checked directory. A parent rename after this point cannot make
// Openat resolve lifecycle.json under a different pathname target.
func readBoundedFromLifecycleRoot(root string, expected os.FileInfo, limit int64) ([]byte, error) {
	directory, err := openLifecycleRootDirectory(root, expected)
	if err != nil {
		return nil, err
	}
	defer directory.Close()

	state, err := openLifecycleStateAt(directory)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	return readBoundedFile(state, limit)
}

func openLifecycleRootDirectory(path string, expected os.FileInfo) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("could not open lifecycle state root")
	}
	info, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	if expected != nil && isNilLifecycleFileInfo(expected) {
		_ = directory.Close()
		return nil, fmt.Errorf("%w: lifecycle state root expected observation is unavailable", ErrInvalid)
	}
	if expected != nil && !os.SameFile(expected, info) {
		_ = directory.Close()
		return nil, fmt.Errorf("%w: lifecycle state root changed while reading", ErrConflict)
	}
	if err := validateLifecycleRoot(info); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func openLifecycleStateAt(directory *os.File) (*os.File, error) {
	if !lifecycleFileReady(directory) {
		return nil, ErrClosed
	}
	fd, err := unix.Openat(int(directory.Fd()), "lifecycle.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	state := os.NewFile(uintptr(fd), "lifecycle.json")
	if state == nil {
		_ = unix.Close(fd)
		return nil, errors.New("could not open lifecycle state")
	}
	info, err := state.Stat()
	if err != nil {
		_ = state.Close()
		return nil, err
	}
	if err := validateLifecycleStateInfo(info); err != nil {
		_ = state.Close()
		return nil, err
	}
	return state, nil
}
