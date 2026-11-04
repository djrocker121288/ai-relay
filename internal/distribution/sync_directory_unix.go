//go:build !windows

package distribution

import "os"

// syncUpdateDirectory is replaceable in Unix tests so directory-sync failure
// recovery can be exercised without changing state outside a test directory.
var syncUpdateDirectory = syncUpdateDirectoryImpl

// syncUpdateDirectoryImpl persists rename metadata after an update. The
// temporary artifact is synced separately; syncing its parent closes the
// rename durability gap on Unix-like systems.
func syncUpdateDirectoryImpl(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
