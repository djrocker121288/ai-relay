//go:build !windows && !linux && !darwin

package vault

import "os"

func createProtectedTemp(dir string) (file *os.File, path string, cleanup func(), err error) {
	file, err = os.CreateTemp(dir, ".vault-*")
	if err != nil {
		return nil, "", nil, err
	}
	path = file.Name()
	cleanup = func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	return file, path, cleanup, nil
}

func replaceProtectedFile(from, to string) (*os.File, error) { return nil, os.Rename(from, to) }
