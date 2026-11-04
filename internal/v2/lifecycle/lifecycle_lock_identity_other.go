//go:build !linux && !darwin && !windows

package lifecycle

import "os"

func validateLifecycleLockIdentity(string, os.FileInfo) error {
	return ErrUnavailable
}
