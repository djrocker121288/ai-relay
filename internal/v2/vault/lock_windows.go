//go:build windows

package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	vaultLockExclusive = 0x00000002
	vaultLockFailFast  = 0x00000001
)

var (
	vaultKernel32   = syscall.NewLazyDLL("kernel32.dll")
	vaultLockProc   = vaultKernel32.NewProc("LockFileEx")
	vaultUnlockProc = vaultKernel32.NewProc("UnlockFileEx")
)

func openVaultLock(path string) (*os.File, error) {
	if err := ensureProtectedDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := requireProtectedParent(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open vault lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat vault lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("vault lock must be a regular file")
	}
	var overlapped syscall.Overlapped
	result, _, callErr := vaultLockProc.Call(file.Fd(), vaultLockExclusive|vaultLockFailFast, 0, uintptr(^uint32(0)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %v", ErrVaultBusy, callErr)
	}
	return file, nil
}

func closeVaultLock(file *os.File) error {
	if file == nil {
		return nil
	}
	var overlapped syscall.Overlapped
	result, _, callErr := vaultUnlockProc.Call(file.Fd(), 0, uintptr(^uint32(0)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		_ = file.Close()
		return callErr
	}
	return file.Close()
}
