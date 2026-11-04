//go:build linux || darwin

package lifecycle

import (
	"fmt"
	"os"
)

// validateLifecycleRoot protects the directory that contains the lock and
// replaceable checkpoint. File mode 0600 alone is insufficient when another
// local user can write or rename entries in the state directory.
func validateLifecycleRoot(info os.FileInfo) error {
	if isNilLifecycleFileInfo(info) {
		return fmt.Errorf("%w: state root observation is unavailable", ErrInvalid)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: state root must be a directory", ErrInvalid)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%w: Unix state root must not be group/other accessible", ErrInvalid)
	}
	return nil
}

func validateLifecycleRootAncestor(path string, info os.FileInfo) error {
	if isNilLifecycleFileInfo(info) {
		return fmt.Errorf("%w: lifecycle state root parent observation is unavailable", ErrInvalid)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: lifecycle state root parent must not be a symlink", ErrInvalid)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: lifecycle state root parent must be a directory", ErrInvalid)
	}
	if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("%w: lifecycle state root parent %q is writable by group or other", ErrInvalid, path)
	}
	return nil
}
