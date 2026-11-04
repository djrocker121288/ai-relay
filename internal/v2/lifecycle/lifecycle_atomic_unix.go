//go:build linux || darwin

package lifecycle

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"golang.org/x/sys/unix"
)

type lifecycleDirectoryHandle interface {
	Sync() error
	Close() error
}

// Unix rename replaces the destination atomically. The directory sync makes
// the replacement durable across a crash after the file contents were synced.
func replaceLifecycleFile(from, to string) error {
	return os.Rename(from, to)
}

// atomicWriteLifecycleState writes through the directory descriptor captured
// when the store acquired its lock. The path-based preflight remains useful
// for detecting a root replacement before work begins, but the actual temp
// creation and rename cannot be redirected to a replacement directory after
// the final preflight.
func atomicWriteLifecycleState(directory *os.File, path string, b []byte, preflight func() error, syncDirectory func(string) error) error {
	if directory == nil {
		if syncDirectory == nil {
			syncDirectory = syncLifecycleDirectory
		}
		return atomicWriteWithPreflightAndSync(path, b, preflight, syncDirectory)
	}
	fail := func(err error, installed bool) error {
		if err == nil {
			return nil
		}
		return &atomicWriteError{err: err, installed: installed}
	}
	// A captured descriptor is part of the Unix ownership boundary. A direct
	// helper caller can retain a non-nil *os.File after it has been closed;
	// reject that malformed handle before descriptor-relative syscalls rather
	// than leaking an implementation-specific bad-descriptor error.
	if !lifecycleFileReady(directory) {
		return fail(ErrClosed, false)
	}
	if preflight != nil {
		if err := preflight(); err != nil {
			return fail(err, false)
		}
	}
	tmp, name, err := createLifecycleTempAt(directory)
	if err != nil {
		return fail(err, false)
	}
	defer func() { _ = unix.Unlinkat(int(directory.Fd()), name, 0) }()
	if written, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fail(err, false)
	} else if written != len(b) {
		_ = tmp.Close()
		return fail(io.ErrShortWrite, false)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fail(err, false)
	}
	if err := tmp.Close(); err != nil {
		return fail(err, false)
	}
	if preflight != nil {
		if err := preflight(); err != nil {
			return fail(err, false)
		}
	}
	if err := unix.Renameat(int(directory.Fd()), name, int(directory.Fd()), "lifecycle.json"); err != nil {
		return fail(err, false)
	}
	if syncDirectory != nil {
		if err := callLifecycleDirectorySync(syncDirectory, filepath.Dir(path)); err != nil {
			return fail(err, true)
		}
	} else if err := syncLifecycleDirectoryHandle(directory); err != nil {
		return fail(err, true)
	}
	return nil
}

func createLifecycleTempAt(directory *os.File) (*os.File, string, error) {
	if directory == nil {
		return nil, "", errors.New("lifecycle state root directory is nil")
	}
	for attempt := 0; attempt < 16; attempt++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate lifecycle temporary name: %w", err)
		}
		name := ".lifecycle-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create lifecycle temporary file: %w", err)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
			return nil, "", errors.New("create lifecycle temporary file returned nil")
		}
		return file, name, nil
	}
	return nil, "", errors.New("create lifecycle temporary file: too many name collisions")
}

func syncLifecycleDirectoryHandle(directory *os.File) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("lifecycle directory sync panicked")
		}
	}()
	if directory == nil {
		return errors.New("lifecycle directory handle is nil")
	}
	return directory.Sync()
}

func syncLifecycleDirectory(path string) error {
	return syncLifecycleDirectoryWithOpen(path, func(path string) (lifecycleDirectoryHandle, error) {
		return os.Open(path)
	})
}

func syncLifecycleDirectoryWithOpen(path string, open func(string) (lifecycleDirectoryHandle, error)) (err error) {
	defer func() {
		if recover() != nil {
			// This helper is the platform durability seam as well as a test
			// seam. Keep malformed or future handle implementations from
			// leaking a panic value to a direct caller; the atomic writer still
			// classifies the returned error as a post-install failure.
			err = errors.New("lifecycle directory sync panicked")
		}
	}()
	dir, err := open(path)
	if err != nil {
		return err
	}
	if isNilLifecycleDirectoryHandle(dir) {
		return errors.New("lifecycle directory handle is nil")
	}
	defer func() {
		closeErr := dir.Close()
		if err == nil {
			err = closeErr
		}
	}()
	return dir.Sync()
}

// isNilLifecycleDirectoryHandle also rejects a typed nil stored in the
// interface. Calling a method on such a value would otherwise cross the
// platform durability seam before the malformed handle is reported.
func isNilLifecycleDirectoryHandle(handle lifecycleDirectoryHandle) bool {
	if handle == nil {
		return true
	}
	value := reflect.ValueOf(handle)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
