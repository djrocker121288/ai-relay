//go:build linux || darwin

package audit

import (
	"fmt"
	"os"
	"syscall"
)

func openAuditLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit writer lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat audit writer lock: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("%w: audit writer lock must be a private regular file", ErrInvalid)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %v", ErrWriterBusy, err)
	}
	return file, nil
}

func closeAuditLock(file *os.File) error {
	if file == nil {
		return nil
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
