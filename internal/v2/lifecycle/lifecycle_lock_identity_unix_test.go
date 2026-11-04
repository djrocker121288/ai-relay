//go:build linux || darwin

package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRejectsReplacedLifecycleLockBeforeServingState(t *testing.T) {
	root := privateTempDir(t)
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	lockPath := filepath.Join(root, ".lifecycle.lock")
	replacedPath := filepath.Join(root, ".lifecycle.lock.replaced")
	if err := os.Rename(lockPath, replacedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Project("missing"); !errors.Is(err, ErrConflict) {
		t.Fatalf("Project after lock replacement = %v, want ErrConflict", err)
	}
	if _, err := os.Stat(filepath.Join(root, "lifecycle.json")); !os.IsNotExist(err) {
		t.Fatalf("replaced-lock read created state: %v", err)
	}

	other, err := Open(root)
	if err != nil {
		t.Fatalf("replacement lock did not admit an independently checked store: %v", err)
	}
	defer other.Close()
}

func TestStoreRejectsWeakenedLifecycleLockPermissionsBeforeServingState(t *testing.T) {
	root := privateTempDir(t)
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	lockPath := filepath.Join(root, ".lifecycle.lock")
	if err := os.Chmod(lockPath, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Project("missing"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Project after lock permission weakening = %v, want ErrInvalid", err)
	}
	if _, err := os.Stat(filepath.Join(root, "lifecycle.json")); !os.IsNotExist(err) {
		t.Fatalf("weakened-lock read created state: %v", err)
	}
}

func TestOpenRevalidatesLockIdentityImmediatelyAfterAcquisition(t *testing.T) {
	root := privateTempDir(t)
	_, err := Open(root, Options{afterLock: func(lockPath string, _ *os.File) error {
		replacedPath := lockPath + ".replaced"
		if err := os.Rename(lockPath, replacedPath); err != nil {
			return err
		}
		return os.WriteFile(lockPath, nil, 0600)
	}})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Open after lock replacement = %v, want ErrConflict", err)
	}
	if _, err := os.Stat(filepath.Join(root, "lifecycle.json")); !os.IsNotExist(err) {
		t.Fatalf("replaced-lock admission created state: %v", err)
	}
}
