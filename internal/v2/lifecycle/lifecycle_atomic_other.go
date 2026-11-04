//go:build !linux && !darwin && !windows

package lifecycle

import "os"

// Other platforms retain the portable atomic replacement primitive. They do
// not claim the Unix directory-fsync or Windows write-through guarantees.
func replaceLifecycleFile(from, to string) error {
	return os.Rename(from, to)
}

func syncLifecycleDirectory(string) error { return nil }
