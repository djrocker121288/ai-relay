//go:build linux || darwin

package lifecycle

import "os"

func openLifecycleStoreDirectory(root string, expected os.FileInfo) (*os.File, error) {
	return openLifecycleRootDirectory(root, expected)
}

func closeLifecycleStoreDirectory(directory *os.File) error {
	if directory == nil {
		return nil
	}
	if !lifecycleStoreDirectoryReady(directory) {
		return ErrClosed
	}
	return directory.Close()
}

// lifecycleStoreDirectoryReady is the store-level guard for the descriptor
// relative mutation boundary. The atomic writer retains a path-based fallback
// for direct helper callers and platforms without descriptor-relative APIs,
// but an opened Unix store must never reach that fallback after its captured
// root descriptor has been removed by a malformed in-process integration.
func lifecycleStoreDirectoryReady(directory *os.File) bool {
	return lifecycleFileReady(directory)
}
