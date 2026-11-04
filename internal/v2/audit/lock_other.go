//go:build !linux && !darwin && !windows

package audit

import (
	"errors"
	"os"
)

func openAuditLock(string) (*os.File, error) {
	return nil, errors.New("audit writer locking is unavailable on this platform")
}

func closeAuditLock(*os.File) error { return nil }
