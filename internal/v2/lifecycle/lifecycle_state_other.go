//go:build !linux && !darwin && !windows

package lifecycle

import (
	"os"
	"path/filepath"
)

// Windows ACL validation remains a native installer/supervisor boundary;
// portable mode bits cannot prove the security of a persisted checkpoint.
func openLifecycleState(path string) (*os.File, error) {
	return os.Open(path)
}

func readBoundedFromLifecycleRoot(root string, expected os.FileInfo, limit int64) ([]byte, error) {
	return readBounded(filepath.Join(root, "lifecycle.json"), limit)
}
