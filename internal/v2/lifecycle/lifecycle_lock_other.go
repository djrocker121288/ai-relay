//go:build !linux && !darwin && !windows

package lifecycle

import (
	"fmt"
	"os"
)

func acquireLifecycleLock(*os.File) error {
	return fmt.Errorf("%w: cross-process lifecycle locking is unavailable on this platform", ErrUnavailable)
}

func releaseLifecycleLock(*os.File) error { return nil }
