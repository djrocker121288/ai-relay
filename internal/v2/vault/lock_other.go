//go:build !linux && !darwin && !windows

package vault

import "os"

// Unsupported targets retain the previous in-process behavior until a native
// advisory-lock primitive is added for that platform. The file vault remains
// usable there, but its cross-process limit is explicit in the documentation.
func openVaultLock(string) (*os.File, error) { return nil, nil }

func closeVaultLock(*os.File) error { return nil }
