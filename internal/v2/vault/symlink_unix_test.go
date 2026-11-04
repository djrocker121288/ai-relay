//go:build !windows

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFileVaultRejectsExistingSymlinks(t *testing.T) {
	d := privateTempDir(t)
	keyTarget := filepath.Join(d, "real.key")
	vaultTarget := filepath.Join(d, "real.vault")
	if err := os.WriteFile(keyTarget, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keyTarget, filepath.Join(d, "vault.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("accepted key symlink: %v", err)
	}

	if err := os.WriteFile(vaultTarget, []byte("placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "vault.key"), make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(vaultTarget, filepath.Join(d, "vault.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("accepted vault symlink: %v", err)
	}
}

func TestFileVaultRejectsVaultSymlinkBeforeCreatingKey(t *testing.T) {
	d := privateTempDir(t)
	target := filepath.Join(d, "real.vault")
	path := filepath.Join(d, "vault.json")
	key := filepath.Join(d, "vault.key")
	if err := os.WriteFile(target, []byte("placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("accepted vault symlink: %v", err)
	}
	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Fatalf("key path side effect after rejected vault path: %v", err)
	}
}

func TestFileVaultRejectsKeySymlinkBeforeReadingTarget(t *testing.T) {
	d := privateTempDir(t)
	path := filepath.Join(d, "vault.json")
	key := filepath.Join(d, "vault.key")
	target := filepath.Join(d, "key-directory")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, key); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("key symlink target was read before rejection: %v", err)
	}
}

func TestMigrationRejectsLegacySymlinkBeforeReadingTarget(t *testing.T) {
	d := privateTempDir(t)
	path := filepath.Join(d, "vault.json")
	key := filepath.Join(d, "vault.key")
	target := filepath.Join(d, "legacy.json")
	legacy := filepath.Join(d, "legacy-link.json")
	if err := os.WriteFile(target, []byte(`{"controller/chatgpt":"secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, legacy); err != nil {
		t.Fatal(err)
	}
	v, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Migrate(legacy); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("accepted legacy symlink: %v", err)
	}
	if _, err := v.Get("controller/chatgpt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("migration changed vault after rejected source: %v", err)
	}
}

func TestOpenProtectedReadRejectsSymlinkAtOpen(t *testing.T) {
	d := privateTempDir(t)
	target := filepath.Join(d, "target")
	link := filepath.Join(d, "link")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openProtectedRead(link); err == nil {
		_ = f.Close()
		t.Fatal("openProtectedRead followed a symlink")
	}
}

func TestOpenProtectedReadRejectsSymlinkedAncestorAtOpen(t *testing.T) {
	d := privateTempDir(t)
	target := filepath.Join(d, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "secret"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "ancestor-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if f, err := openProtectedRead(filepath.Join(link, "secret")); err == nil {
		_ = f.Close()
		t.Fatal("openProtectedRead followed a symlinked ancestor")
	} else if !strings.Contains(err.Error(), "parent must not be a symlink") {
		t.Fatalf("openProtectedRead error = %v, want symlinked-ancestor rejection", err)
	}
}

func TestOpenProtectedReadDoesNotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "secret")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := openProtectedRead(path); err == nil {
		_ = f.Close()
		t.Fatal("openProtectedRead accepted a FIFO")
	}
}

func TestOpenProtectedReadRejectsDescriptorPermissionChange(t *testing.T) {
	d := privateTempDir(t)
	path := filepath.Join(d, "secret")
	if err := os.WriteFile(path, []byte("secret"), 0640); err != nil {
		t.Fatal(err)
	}
	if f, err := openProtectedRead(path); err == nil {
		_ = f.Close()
		t.Fatal("openProtectedRead accepted a non-private descriptor")
	}
}

func TestFileVaultRejectsUnsafeExistingParent(t *testing.T) {
	d := privateTempDir(t)
	parent := filepath.Join(d, "shared")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "vault.json")
	key := filepath.Join(parent, "vault.key")
	if err := os.Chmod(parent, 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("accepted writable parent: %v", err)
	}
	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Fatalf("created key after rejected parent: %v", err)
	}
}

func TestFileVaultRejectsSymlinkedParent(t *testing.T) {
	d := privateTempDir(t)
	target := filepath.Join(d, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(d, "parent-link")
	if err := os.Symlink(target, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(filepath.Join(parent, "vault.json"), filepath.Join(parent, "vault.key")); err == nil || !strings.Contains(err.Error(), "parent must be a directory") {
		t.Fatalf("accepted symlinked parent: %v", err)
	}
}

func TestFileVaultRejectsSymlinkedAncestorBeforeCreatingKey(t *testing.T) {
	d := privateTempDir(t)
	target := filepath.Join(d, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(target, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "ancestor-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(link, "nested", "vault.json")
	key := filepath.Join(link, "nested", "vault.key")

	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "parent must not be a symlink") {
		t.Fatalf("accepted symlinked ancestor: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "nested", "vault.key")); !os.IsNotExist(err) {
		t.Fatalf("created key after rejecting symlinked ancestor: %v", err)
	}
}

func TestAtomicProtectedWriteDoesNotCreateThroughSymlinkedAncestor(t *testing.T) {
	d := privateTempDir(t)
	target := filepath.Join(d, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "ancestor-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(link, "missing", "checkpoint")

	if err := atomicProtectedWrite(path, []byte("secret")); err == nil || !strings.Contains(err.Error(), "parent must not be a symlink") {
		t.Fatalf("accepted symlinked ancestor: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "missing")); !os.IsNotExist(err) {
		t.Fatalf("created descendant through symlinked ancestor: %v", err)
	}
}
