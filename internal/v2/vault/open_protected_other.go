//go:build !linux && !darwin && !windows

package vault

import "os"

// Unsupported platforms retain the existing portable behavior. Windows uses
// a native no-follow handle in open_protected_windows.go.
func openProtectedRead(path string) (*os.File, error) { return os.Open(path) }
