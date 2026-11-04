//go:build !linux && !darwin

package lifecycle

import "os"

func atomicWriteLifecycleState(_ *os.File, path string, b []byte, preflight func() error, syncDirectory func(string) error) error {
	if syncDirectory == nil {
		syncDirectory = syncLifecycleDirectory
	}
	return atomicWriteWithPreflightAndSync(path, b, preflight, syncDirectory)
}
