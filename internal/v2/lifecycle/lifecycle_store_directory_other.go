//go:build !linux && !darwin

package lifecycle

import "os"

func openLifecycleStoreDirectory(string, os.FileInfo) (*os.File, error) {
	return nil, nil
}

func closeLifecycleStoreDirectory(*os.File) error { return nil }

// Other platforms retain the portable path-based mutation implementation.
func lifecycleStoreDirectoryReady(*os.File) bool { return true }
