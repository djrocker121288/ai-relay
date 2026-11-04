//go:build linux || darwin

package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// openProtectedRead opens a configured secret file without following a
// symlinked path component or blocking on a swapped-in FIFO/device, then
// validates the opened descriptor. Each existing ancestor is bound through a
// directory descriptor before the final open, so a path replacement cannot
// redirect the read through a different ancestor after preflight.
func openProtectedRead(path string) (*os.File, error) {
	parent, name, err := openProtectedReadParent(path)
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("could not open protected file")
	}
	var stat syscall.Stat_t
	if err = syscall.Fstat(fd, &stat); err != nil {
		_ = f.Close()
		return nil, err
	}
	mode := uint32(stat.Mode)
	if mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = f.Close()
		return nil, errors.New("vault file must be regular")
	}
	if mode&0077 != 0 {
		_ = f.Close()
		return nil, errors.New("vault file is not private")
	}
	return f, nil
}

// openProtectedReadParent walks the absolute parent path through descriptors
// opened with O_NOFOLLOW. Keeping the parent descriptor alive until the final
// open closes the ancestor check/use gap that a pathname-only preflight leaves.
func openProtectedReadParent(path string) (*os.File, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	absolute = filepath.Clean(absolute)
	parentPath := filepath.Dir(absolute)
	name := filepath.Base(absolute)

	fd, err := unix.Openat(unix.AT_FDCWD, string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, "", err
	}
	parent := os.NewFile(uintptr(fd), string(filepath.Separator))
	if parent == nil {
		_ = unix.Close(fd)
		return nil, "", errors.New("could not open protected parent")
	}
	if err := validateProtectedDirectoryDescriptor(parent, string(filepath.Separator)); err != nil {
		_ = parent.Close()
		return nil, "", err
	}

	components := strings.Split(strings.TrimPrefix(parentPath, string(filepath.Separator)), string(filepath.Separator))
	currentPath := string(filepath.Separator)
	for _, component := range components {
		if component == "" {
			continue
		}
		currentPath = filepath.Join(currentPath, component)
		childFD, openErr := unix.Openat(int(parent.Fd()), component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if openErr != nil {
			_ = parent.Close()
			return nil, "", normalizeProtectedParentError(currentPath, openErr)
		}
		child := os.NewFile(uintptr(childFD), currentPath)
		if child == nil {
			_ = unix.Close(childFD)
			_ = parent.Close()
			return nil, "", errors.New("could not open protected parent")
		}
		if err := validateProtectedDirectoryDescriptor(child, currentPath); err != nil {
			_ = child.Close()
			_ = parent.Close()
			return nil, "", err
		}
		if err := parent.Close(); err != nil {
			_ = child.Close()
			return nil, "", err
		}
		parent = child
	}
	return parent, name, nil
}

func validateProtectedDirectoryDescriptor(directory *os.File, path string) error {
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	if err := validateProtectedDirectory(path, info); err != nil {
		return err
	}
	return nil
}

func normalizeProtectedParentError(path string, err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("vault parent must not be a symlink")
		}
		if errors.Is(err, unix.ENOTDIR) {
			return fmt.Errorf("vault parent %q must be a directory", path)
		}
	}
	return err
}
