//go:build windows

package vault

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x00000001
	moveFileWriteThrough    = 0x00000008
)

var vaultMoveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func createProtectedTemp(dir string) (file *os.File, path string, cleanup func(), err error) {
	file, err = os.CreateTemp(dir, ".vault-*")
	if err != nil {
		return nil, "", nil, err
	}
	path = file.Name()
	cleanup = func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	return file, path, cleanup, nil
}

// replaceProtectedFile preserves atomic replacement on Windows. os.Rename
// maps to MoveFileW there, which refuses an existing destination.
func replaceProtectedFile(from, to string) (*os.File, error) {
	fromPtr, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return nil, err
	}
	toPtr, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return nil, err
	}
	result, _, callErr := vaultMoveFileEx.Call(
		uintptr(unsafe.Pointer(fromPtr)),
		uintptr(unsafe.Pointer(toPtr)),
		moveFileReplaceExisting|moveFileWriteThrough,
	)
	if result == 0 {
		if callErr == syscall.Errno(0) {
			return nil, syscall.EINVAL
		}
		return nil, callErr
	}
	return nil, nil
}
