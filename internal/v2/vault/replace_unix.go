//go:build linux || darwin

package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const protectedTempAttempts = 128

// createProtectedTemp creates a replacement file relative to a descriptor for
// its parent. The returned cleanup function removes the temporary entry through
// that same descriptor, so a later pathname redirection cannot create or remove
// a file outside the directory that was bound here.
func createProtectedTemp(dir string) (file *os.File, path string, cleanup func(), err error) {
	absoluteDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", nil, err
	}
	parent, _, err := openProtectedReadParent(filepath.Join(absoluteDir, ".vault-temp-parent"))
	if err != nil {
		return nil, "", nil, err
	}

	cleanup = func() {
		if file != nil {
			_ = file.Close()
		}
		if parent != nil {
			_ = unix.Unlinkat(int(parent.Fd()), filepath.Base(path), 0)
			_ = parent.Close()
		}
	}
	for attempt := 0; attempt < protectedTempAttempts; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			cleanup()
			return nil, "", nil, err
		}
		name := ".vault-" + hex.EncodeToString(random[:])
		fd, openErr := unix.Openat(int(parent.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if errors.Is(openErr, unix.EEXIST) {
			continue
		}
		if openErr != nil {
			cleanup()
			return nil, "", nil, openErr
		}
		file = os.NewFile(uintptr(fd), filepath.Join(absoluteDir, name))
		if file == nil {
			_ = unix.Close(fd)
			cleanup()
			return nil, "", nil, errors.New("could not create protected temporary file")
		}
		return file, filepath.Join(absoluteDir, name), cleanup, nil
	}
	cleanup()
	return nil, "", nil, errors.New("could not create protected temporary file")
}

// replaceProtectedFile performs the final replacement relative to descriptors
// for the source and destination parents. The temporary file is created by
// path for compatibility with the existing bounded writer, but the rename
// itself cannot be redirected by replacing an ancestor after the parent walk.
// Both names must resolve in the same protected directory; cross-directory
// replacement is not part of the fallback contract.
func replaceProtectedFile(from, to string) (*os.File, error) {
	fromParent, fromName, err := openProtectedReadParent(from)
	if err != nil {
		return nil, err
	}
	toParent, toName, err := openProtectedReadParent(to)
	if err != nil {
		_ = fromParent.Close()
		return nil, err
	}

	fromInfo, err := fromParent.Stat()
	if err != nil {
		_ = fromParent.Close()
		_ = toParent.Close()
		return nil, err
	}
	toInfo, err := toParent.Stat()
	if err != nil {
		_ = fromParent.Close()
		_ = toParent.Close()
		return nil, err
	}
	if !os.SameFile(fromInfo, toInfo) {
		_ = fromParent.Close()
		_ = toParent.Close()
		return nil, errors.New("protected replacement paths must share a directory")
	}
	if filepath.Base(from) != fromName || filepath.Base(to) != toName {
		_ = fromParent.Close()
		_ = toParent.Close()
		return nil, errors.New("protected replacement path has an invalid final name")
	}
	if err := unix.Renameat(int(fromParent.Fd()), fromName, int(toParent.Fd()), toName); err != nil {
		_ = fromParent.Close()
		_ = toParent.Close()
		return nil, err
	}
	// The source and destination descriptors are the same directory, so retain
	// the already-validated source descriptor through the directory sync. The
	// destination descriptor is no longer needed after Renameat.
	_ = toParent.Close()
	return fromParent, nil
}
