//go:build windows

package vault

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openProtectedRead opens a fallback file without following a Windows reparse
// point, then validates the handle before any secret bytes are read. ACL
// validation remains a native supervisor gate; portable mode bits cannot
// represent Windows ACLs.
func openProtectedRead(path string) (*os.File, error) {
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
		return nil, errors.New("could not open protected file")
	}
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("vault file must not be a reparse point")
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = f.Close()
		return nil, errors.New("vault file must be regular")
	}
	return f, nil
}
