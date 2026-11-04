//go:build !windows

package security

import (
	"fmt"
	"os"
)

func CheckProtectedFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("credential file %s must be a regular 0600-or-more-restrictive file", path)
	}
	return nil
}
func ProtectFile(path string) error { return os.Chmod(path, 0600) }
