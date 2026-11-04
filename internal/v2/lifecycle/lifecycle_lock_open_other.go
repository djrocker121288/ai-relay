//go:build !linux && !darwin && !windows

package lifecycle

import (
	"fmt"
	"os"
)

func ensureLifecycleLockCapability() error {
	return fmt.Errorf("%w: cross-process lifecycle locking is unavailable on this platform", ErrUnavailable)
}

// Unsupported platforms fail before opening the caller-provided path. They do
// not have a lifecycle lock primitive, and touching the path first could
// follow a symlink and chmod an unrelated inode before returning that fact.
func openLifecycleLock(string) (*os.File, error) {
	return nil, fmt.Errorf("%w: cross-process lifecycle locking is unavailable on this platform", ErrUnavailable)
}
