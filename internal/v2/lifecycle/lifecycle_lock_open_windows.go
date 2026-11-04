//go:build windows

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func ensureLifecycleLockCapability() error { return nil }

// openLifecycleLock opens the ownership boundary without following a Windows
// reparse point. FILE_FLAG_OPEN_REPARSE_POINT makes an existing link open as
// the link itself; the handle attributes are then checked before it can be
// chmodded or locked. ACL validation remains a native supervisor gate.
func openLifecycleLock(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		_ = syscall.CloseHandle(handle)
		return nil, errors.New("could not open lifecycle lock")
	}
	if err := validateWindowsHandle(handle, "lifecycle lock"); err != nil {
		_ = f.Close()
		return nil, err
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

func validateWindowsHandle(handle syscall.Handle, label string) error {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s must not be a reparse point", label)
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fmt.Errorf("%s must be a regular file", label)
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("%s must not be hard-linked", label)
	}
	return nil
}
