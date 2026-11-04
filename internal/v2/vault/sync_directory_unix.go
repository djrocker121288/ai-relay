//go:build !windows

package vault

import "os"

// syncVaultDirectory is a variable so Unix tests can exercise the
// post-rename durability recovery path without changing filesystem state
// outside the test directory. When directory is non-nil it is the descriptor
// retained by replaceProtectedFile; path is only the portable fallback.
var syncVaultDirectory = syncVaultDirectoryImpl

// syncVaultDirectoryImpl persists the rename metadata on Unix-like hosts. The
// file sync above protects the contents; syncing the directory closes the
// crash-consistency gap between rename and directory-entry persistence. The
// descriptor argument keeps that sync bound to the directory used by rename.
func syncVaultDirectoryImpl(path string, directory *os.File) error {
	if directory != nil {
		return directory.Sync()
	}
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
