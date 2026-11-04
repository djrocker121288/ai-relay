//go:build windows

package lifecycle

import (
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x00000001
	moveFileWriteThrough    = 0x00000008
)

var lifecycleMoveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

// os.Rename maps to MoveFileW on Windows, which does not replace an existing
// destination. MoveFileExW with REPLACE_EXISTING preserves the atomic
// checkpoint contract for every update after the initial state write, while
// WRITE_THROUGH supplies the native flush boundary used instead of Unix
// directory fsync.
func replaceLifecycleFile(from, to string) error {
	fromPtr, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	result, _, callErr := lifecycleMoveFileEx.Call(
		uintptr(unsafe.Pointer(fromPtr)),
		uintptr(unsafe.Pointer(toPtr)),
		moveFileReplaceExisting|moveFileWriteThrough,
	)
	if result == 0 {
		if callErr == syscall.Errno(0) {
			return syscall.EINVAL
		}
		return callErr
	}
	return nil
}

// MoveFileExW with MOVEFILE_WRITE_THROUGH is the Windows durability boundary;
// Windows does not provide the Unix directory-fd fsync operation used here.
func syncLifecycleDirectory(string) error { return nil }
