//go:build linux || darwin

package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func openVaultLock(path string) (*os.File, error) {
	if err := ensureProtectedDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := requireProtectedParent(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open vault lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat vault lock: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		_ = file.Close()
		return nil, errors.New("vault lock must be a private regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %v", ErrVaultBusy, err)
	}
	return file, nil
}

func closeVaultLock(file *os.File) error {
	if file == nil {
		return nil
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
