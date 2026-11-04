//go:build !linux && !darwin && !windows

package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenLifecycleLockUnsupportedPlatformDoesNotTouchPath(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "unrelated.lock")
	if err := os.WriteFile(target, []byte("untouched"), 0640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, ".lifecycle.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := openLifecycleLock(link); err == nil {
		t.Fatal("unsupported platform lock unexpectedly opened")
	} else if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsupported platform lock error = %v, want ErrUnavailable", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0640 {
		t.Fatalf("unrelated symlink target mode = %o, want 0640", got)
	}
}

func TestOpenUnsupportedPlatformDoesNotCreateStateRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "lifecycle-state")
	if _, err := Open(root); err == nil {
		t.Fatal("unsupported platform lifecycle open unexpectedly succeeded")
	} else if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsupported platform lifecycle open error = %v, want ErrUnavailable", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported platform lifecycle open changed state root: %v", err)
	}
}
