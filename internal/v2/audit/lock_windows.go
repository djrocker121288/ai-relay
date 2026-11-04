//go:build windows

package audit

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	auditLockExclusive = 0x00000002
	auditLockFailFast  = 0x00000001
)

var (
	auditKernel32   = syscall.NewLazyDLL("kernel32.dll")
	auditLockProc   = auditKernel32.NewProc("LockFileEx")
	auditUnlockProc = auditKernel32.NewProc("UnlockFileEx")
)

func openAuditLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit writer lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat audit writer lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: audit writer lock must be a regular file", ErrInvalid)
	}
	var overlapped syscall.Overlapped
	result, _, callErr := auditLockProc.Call(file.Fd(), auditLockExclusive|auditLockFailFast, 0, uintptr(^uint32(0)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %v", ErrWriterBusy, callErr)
	}
	return file, nil
}

func closeAuditLock(file *os.File) error {
	if file == nil {
		return nil
	}
	var overlapped syscall.Overlapped
	result, _, callErr := auditUnlockProc.Call(file.Fd(), 0, uintptr(^uint32(0)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		_ = file.Close()
		return callErr
	}
	return file.Close()
}
