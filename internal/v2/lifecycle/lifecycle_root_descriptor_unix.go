//go:build linux || darwin

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ensureLifecycleRootDirectory walks the absolute path through directory
// descriptors. Every component is opened with O_NOFOLLOW, and missing
// components are created with mkdirat relative to the already-open parent.
// This keeps an existing ancestor replacement from redirecting creation
// between a pathname check and Mkdir.
func ensureLifecycleRootDirectory(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	absolute = filepath.Clean(absolute)

	parent, err := openLifecycleDirectoryAt(unix.AT_FDCWD, string(filepath.Separator), absolute)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()

	components := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	currentPath := string(filepath.Separator)
	for _, component := range components {
		if component == "" {
			continue
		}
		currentPath = filepath.Join(currentPath, component)
		child, openErr := openLifecycleDirectoryAt(int(parent.Fd()), component, currentPath)
		if errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(int(parent.Fd()), component, 0700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				return fmt.Errorf("create lifecycle state root component %q: %w", component, mkdirErr)
			}
			child, openErr = openLifecycleDirectoryAt(int(parent.Fd()), component, currentPath)
		}
		if openErr != nil {
			return normalizeLifecycleRootComponentError(currentPath, openErr)
		}
		if err := parent.Close(); err != nil {
			_ = child.Close()
			return err
		}
		parent = child
	}
	return nil
}

func openLifecycleDirectoryAt(parentFD int, name, path string) (*os.File, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("could not open lifecycle state root component")
	}
	info, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	if err := validateLifecycleRootAncestor(path, info); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func normalizeLifecycleRootComponentError(path string, err error) error {
	if errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("%w: lifecycle state root parent must not be a symlink", ErrInvalid)
	}
	if errors.Is(err, unix.ENOTDIR) {
		// Linux may report O_NOFOLLOW plus O_DIRECTORY against a symlink as
		// ENOTDIR rather than ELOOP. The descriptor operation already failed
		// closed; classify the path for a stable, truthful diagnostic only.
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: lifecycle state root parent must not be a symlink", ErrInvalid)
		}
		return fmt.Errorf("%w: lifecycle state root parent must be a directory", ErrInvalid)
	}
	return err
}
