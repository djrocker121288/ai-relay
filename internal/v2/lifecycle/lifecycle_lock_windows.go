//go:build windows

package lifecycle

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	lockfileExclusiveLock   = 0x00000002
	lockfileFailImmediately = 0x00000001
)

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	lockFileExProc = kernel32.NewProc("LockFileEx")
	unlockFileProc = kernel32.NewProc("UnlockFileEx")
)

func acquireLifecycleLock(f *os.File) error {
	if !lifecycleFileReady(f) {
		return ErrClosed
	}
	var overlapped syscall.Overlapped
	r, _, err := lockFileExProc.Call(f.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, uintptr(^uint32(0)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&overlapped)))
	if r == 0 {
		return fmt.Errorf("%w: state directory is already open: %v", ErrConflict, err)
	}
	return nil
}

func releaseLifecycleLock(f *os.File) error {
	if !lifecycleFileReady(f) {
		return ErrClosed
	}
	var overlapped syscall.Overlapped
	r, _, err := unlockFileProc.Call(f.Fd(), 0, uintptr(^uint32(0)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&overlapped)))
	if r == 0 {
		return err
	}
	return nil
}
