//go:build windows

package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsAtomicProtectedWriteReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	if err := atomicProtectedWrite(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := atomicProtectedWrite(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("replacement contents = %q, want second", got)
	}
}
