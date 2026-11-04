package vault

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

// withVaultLock serializes fallback opens and lifecycle operations across
// processes. The sidecar contains no secret data; it is only an advisory
// ownership handle for the configured ciphertext path.
func withVaultLock(path string, fn func(*os.File) error) error {
	if fn == nil {
		return errors.New("vault lock operation is nil")
	}
	lockPath := path + ".lock"
	lock, err := openVaultLock(lockPath)
	if err != nil {
		return err
	}
	if err := validateVaultLockFile(lockPath, lock); err != nil {
		_ = closeVaultLock(lock)
		return err
	}
	operationErr := fn(lock)
	// A callback may perform a read, create a first-run key, or otherwise
	// complete work after the initial identity check. Recheck before reporting
	// success so a lock-path replacement during that callback cannot be
	// mistaken for an operation still owned by this descriptor.
	if operationErr == nil {
		operationErr = validateVaultLockFile(lockPath, lock)
	}
	closeErr := closeVaultLock(lock)
	if operationErr != nil && closeErr != nil {
		return errors.Join(operationErr, fmt.Errorf("close vault lock: %w", closeErr))
	}
	if operationErr != nil {
		return operationErr
	}
	return closeErr
}

// validateVaultLockFile confirms that the pathname still names the inode
// whose descriptor owns the advisory lock. An attacker or damaged integration
// can replace a lock pathname after acquisition; a new process could then lock
// the replacement while this process continues using the old descriptor. The
// fallback must fail closed at that split ownership boundary.
func validateVaultLockFile(path string, lock *os.File) error {
	if lock == nil {
		// Unsupported targets intentionally have no native lock primitive. Their
		// portability limitation is documented rather than represented as a
		// false identity check against a nil descriptor.
		return nil
	}
	expected, err := lock.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat vault lock: %v", ErrVaultBusy, err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: inspect vault lock path: %v", ErrVaultBusy, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: vault lock path is a symlink", ErrVaultBusy)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: stat vault lock path: %v", ErrVaultBusy, err)
	}
	currentPathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: recheck vault lock path: %v", ErrVaultBusy, err)
	}
	if currentPathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathInfo, currentPathInfo) || !os.SameFile(expected, info) || !os.SameFile(info, currentPathInfo) {
		return fmt.Errorf("%w: vault lock path changed after acquisition", ErrVaultBusy)
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return fmt.Errorf("%w: vault lock is not a private regular file", ErrVaultBusy)
	}
	return nil
}

// withLocked keeps zero-value/in-memory FileVault fixtures usable for unit
// tests while production instances take the sidecar lock and refresh from the
// latest authenticated checkpoint before the operation runs.
func (v *FileVault) withLocked(fn func() error) error {
	if fn == nil {
		return errors.New("vault locked operation is nil")
	}
	if v == nil || v.path == "" {
		return fn()
	}
	return withVaultLock(v.path, func(lock *os.File) error {
		previousLockValidation := v.lockValidation
		v.lockValidation = func() error { return validateVaultLockFile(v.path+".lock", lock) }
		defer func() { v.lockValidation = previousLockValidation }()
		if err := v.load(); err != nil {
			return err
		}
		if v.beforeLockedOperation != nil {
			if err := v.beforeLockedOperation(); err != nil {
				return err
			}
		}
		if err := validateVaultLockFile(v.path+".lock", lock); err != nil {
			return err
		}
		return fn()
	})
}
