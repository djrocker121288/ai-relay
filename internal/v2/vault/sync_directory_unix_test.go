//go:build linux || darwin

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicProtectedWriteRestoresAfterDirectorySyncFailure(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "checkpoint")
	if err := atomicProtectedWrite(path, []byte("original")); err != nil {
		t.Fatal(err)
	}

	originalSync := syncVaultDirectory
	t.Cleanup(func() { syncVaultDirectory = originalSync })
	var calls int
	syncVaultDirectory = func(path string, directory *os.File) error {
		calls++
		if calls == 1 {
			return errors.New("injected directory sync failure")
		}
		return originalSync(path, directory)
	}

	if err := atomicProtectedWrite(path, []byte("replacement")); err == nil {
		t.Fatal("atomicProtectedWrite unexpectedly succeeded after directory sync failure")
	}
	if calls != 2 {
		t.Fatalf("directory sync calls = %d, want initial failure plus restoration", calls)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("checkpoint after failed replacement = %q, want original", got)
	}
}

func TestDirectorySyncUsesReplacementDescriptorAfterAncestorMove(t *testing.T) {
	root := privateTempDir(t)
	dir := filepath.Join(root, "vault")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "checkpoint")
	temporary, temporaryPath, cleanup, err := createProtectedTemp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := temporary.Write([]byte("checkpoint")); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	directory, err := replaceProtectedFile(temporaryPath, path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	moved := filepath.Join(root, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := syncVaultDirectoryImpl(dir, directory); err != nil {
		t.Fatalf("descriptor-bound directory sync after ancestor move: %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, "checkpoint")); err != nil {
		t.Fatalf("moved checkpoint unavailable after descriptor-bound sync: %v", err)
	}
}

func TestProtectedReplacementRecoveryRechecksUnsafeParent(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "checkpoint")
	if err := atomicProtectedWrite(path, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0775); err != nil {
		t.Fatal(err)
	}

	err := restoreProtectedReplacement(dir, path, []byte("replacement"), true)
	if err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("unsafe recovery parent accepted: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "original" {
		t.Fatalf("unsafe recovery changed checkpoint = %q, want original", got)
	}
}

func TestProtectedReplacementRemovalRecoveryRechecksUnsafeParent(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "checkpoint")
	if err := os.WriteFile(path, []byte("new checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0775); err != nil {
		t.Fatal(err)
	}

	err := restoreProtectedReplacement(dir, path, nil, false)
	if err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("unsafe removal recovery accepted: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "new checkpoint" {
		t.Fatalf("unsafe removal recovery changed checkpoint = %q, want new checkpoint", got)
	}
}

func TestReplaceProtectedFileRejectsDifferentParent(t *testing.T) {
	root := privateTempDir(t)
	fromDir := filepath.Join(root, "from")
	toDir := filepath.Join(root, "to")
	if err := os.Mkdir(fromDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(toDir, 0700); err != nil {
		t.Fatal(err)
	}
	from := filepath.Join(fromDir, "temporary")
	to := filepath.Join(toDir, "checkpoint")
	if err := os.WriteFile(from, []byte("temporary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := replaceProtectedFile(from, to); err == nil {
		t.Fatal("replaceProtectedFile accepted different parent directories")
	}
	for path, want := range map[string]string{from: "temporary", to: "original"} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s after rejected replacement = %q, want %q", path, got, want)
		}
	}
}

func TestProtectedTempCleanupStaysBoundToOriginalDirectory(t *testing.T) {
	root := privateTempDir(t)
	dir := filepath.Join(root, "vault")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file, path, cleanup, err := createProtectedTemp(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("temporary")); err != nil {
		cleanup()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		t.Fatal(err)
	}

	moved := filepath.Join(root, "moved")
	if err := os.Rename(dir, moved); err != nil {
		cleanup()
		t.Fatal(err)
	}
	if err := cleanupAndCheckProtectedTemp(cleanup, path, moved); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(moved, filepath.Base(path))); !os.IsNotExist(err) {
		t.Fatalf("descriptor-bound cleanup left original temporary file: %v", err)
	}
}

func cleanupAndCheckProtectedTemp(cleanup func(), path, moved string) error {
	if _, err := os.Stat(path); err == nil {
		return errors.New("temporary path unexpectedly remained reachable after ancestor move")
	}
	if _, err := os.Stat(filepath.Join(moved, filepath.Base(path))); err != nil {
		return err
	}
	cleanup()
	if _, err := os.Lstat(filepath.Join(moved, filepath.Base(path))); err == nil {
		return errors.New("descriptor-bound cleanup did not remove original temporary file")
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}
