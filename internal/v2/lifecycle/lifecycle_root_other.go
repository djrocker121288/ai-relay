//go:build !linux && !darwin

package lifecycle

import (
	"fmt"
	"os"
)

// Windows ACLs are not represented by os.FileMode permission bits. The
// supervisor/native installer owns ACL verification on that platform.
func validateLifecycleRoot(info os.FileInfo) error {
	if isNilLifecycleFileInfo(info) {
		return fmt.Errorf("%w: state root observation is unavailable", ErrInvalid)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: state root must be a directory", ErrInvalid)
	}
	return nil
}

// Windows ACLs are a supervisor-host boundary. Keep directory creation on
// the native path so the trusted supervisor can verify the resulting ACL.
func ensureLifecycleRootDirectory(path string) error {
	return os.MkdirAll(path, 0700)
}
