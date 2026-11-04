//go:build windows

package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsProtectedReadRejectsReparsePoints(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("reparse-point fixture unavailable: %v", err)
	}
	if f, err := openProtectedRead(link); err == nil {
		_ = f.Close()
		t.Fatal("openProtectedRead followed a reparse point")
	} else if !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("openProtectedRead error = %v, want reparse-point rejection", err)
	}
}

func TestWindowsProtectedReadAcceptsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openProtectedRead(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
