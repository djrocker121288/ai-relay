//go:build windows

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// openLifecycleState reads the replaceable checkpoint through a handle opened
// with FILE_FLAG_OPEN_REPARSE_POINT. A reparse-point or directory is rejected
// before JSON parsing, so a path replacement cannot redirect the read to an
// unrelated object. Native Windows ACL verification remains a supervisor gate.
func openLifecycleState(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		_ = syscall.CloseHandle(handle)
		return nil, os.ErrInvalid
	}
	if err := validateWindowsHandle(handle, "lifecycle state"); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func readBoundedFromLifecycleRoot(root string, expected os.FileInfo, limit int64) ([]byte, error) {
	directory, err := openLifecycleRootDirectory(root, expected)
	if err != nil {
		return nil, err
	}
	defer directory.Close()

	state, err := openLifecycleState(filepath.Join(root, "lifecycle.json"))
	if err != nil {
		return nil, err
	}
	defer state.Close()
	// Windows has no openat equivalent in the standard syscall surface. Keep
	// the validated directory handle open while the child is opened, then
	// repeat the identity check before reading so a root-path replacement is
	// rejected instead of being treated as the locked state directory.
	if check, err := openLifecycleRootDirectory(root, expected); err != nil {
		return nil, fmt.Errorf("validate lifecycle state root after state open: %w", err)
	} else {
		_ = check.Close()
	}
	return readBoundedFile(state, limit)
}

func openLifecycleRootDirectory(path string, expected os.FileInfo) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(handle), path)
	if directory == nil {
		_ = syscall.CloseHandle(handle)
		return nil, errors.New("could not open lifecycle state root")
	}
	if err := validateWindowsDirectoryHandle(handle, "lifecycle state root"); err != nil {
		_ = directory.Close()
		return nil, err
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

func validateWindowsDirectoryHandle(handle syscall.Handle, label string) error {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s must not be a reparse point", label)
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s must be a directory", label)
	}
	return nil
}
