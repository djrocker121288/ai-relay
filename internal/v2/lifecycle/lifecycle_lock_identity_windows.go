//go:build windows

package lifecycle

import (
	"fmt"
	"os"
	"syscall"
)

// validateLifecycleLockIdentity reopens the lock with the same no-reparse
// boundary used by the opener and compares its file identity with the handle
// captured by Open. Windows ACL verification remains a native supervisor gate.
func validateLifecycleLockIdentity(path string, expected os.FileInfo) error {
	if isNilLifecycleFileInfo(expected) {
		return ErrClosed
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
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
		return fmt.Errorf("%w: lifecycle lock path is unavailable", ErrConflict)
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		_ = syscall.CloseHandle(handle)
		return fmt.Errorf("%w: lifecycle lock handle is unavailable", ErrConflict)
	}
	defer f.Close()
	if err := validateWindowsHandle(handle, "lifecycle lock"); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat lifecycle lock path: %v", ErrConflict, err)
	}
	if !os.SameFile(info, expected) {
		return fmt.Errorf("%w: lifecycle lock path changed", ErrConflict)
	}
	return nil
}
