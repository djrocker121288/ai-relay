//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openEvidenceNoFollow binds every existing ancestor and the final evidence
// path without following a symlink. The caller still rechecks the path
// identity after the bounded read so replacement of the directory entry
// remains a rejected handoff.
func openEvidenceNoFollow(path string) (*os.File, error) {
	parent, name, err := openEvidenceParent(path)
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("could not open evidence file")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("evidence path is not a regular file")
	}
	return file, nil
}

// openEvidenceParent keeps the parent descriptor alive until the final open.
// This closes the preflight/use gap where an ancestor could otherwise be
// replaced with a symlink after lstat but before opening the evidence file.
// Evidence is non-secret, so unlike the vault fallback this helper does not
// impose private-directory mode checks.
func openEvidenceParent(path string) (*os.File, string, error) {
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
		return nil, "", errors.New("could not open evidence parent")
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
			return nil, "", openErr
		}
		child := os.NewFile(uintptr(childFD), currentPath)
		if child == nil {
			_ = unix.Close(childFD)
			_ = parent.Close()
			return nil, "", errors.New("could not open evidence parent")
		}
		if err := parent.Close(); err != nil {
			_ = child.Close()
			return nil, "", err
		}
		parent = child
	}
	return parent, name, nil
}
