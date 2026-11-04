package audit

import (
	"errors"
	"fmt"
)

func withAuditWriteLock(path string, fn func() error) error {
	lock, err := openAuditLock(path + ".lock")
	if err != nil {
		return err
	}
	operationErr := fn()
	closeErr := closeAuditLock(lock)
	if operationErr != nil && closeErr != nil {
		return errors.Join(operationErr, fmt.Errorf("close audit writer lock: %w", closeErr))
	}
	if operationErr != nil {
		return operationErr
	}
	return closeErr
}

func withAuditReadLock(path string, fn func() error) error {
	// Reads use the same exclusive lock so refresh and inspection are one
	// operation with respect to other readers and writers.
	return withAuditWriteLock(path, fn)
}
