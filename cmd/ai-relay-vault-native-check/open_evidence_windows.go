//go:build windows

package main

import (
	"errors"
	"os"
	"syscall"
)

// openEvidenceNoFollow uses a reparse-point handle so offline replay cannot
// follow a Windows symlink or junction between the path check and the read.
func openEvidenceNoFollow(path string) (*os.File, error) {
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
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, errors.New("could not open evidence file")
	}
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = file.Close()
		return nil, errors.New("evidence path is a reparse point")
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = file.Close()
		return nil, errors.New("evidence path is not a regular file")
	}
	return file, nil
}
