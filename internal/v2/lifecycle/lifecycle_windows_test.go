//go:build windows

package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsLifecycleOpensRegularFilesWithoutFollowingReparsePoints(t *testing.T) {
	root := t.TempDir()
	lockPath := filepath.Join(root, ".lifecycle.lock")
	lock, err := openLifecycleLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := closeLifecycleLock(lock); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(root, "lifecycle.json")
	if err := os.WriteFile(statePath, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := openLifecycleState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("reparse-point fixture unavailable: %v", err)
	}
	if _, err := openLifecycleLock(link); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("openLifecycleLock(reparse point) error = %v", err)
	}
	if _, err := openLifecycleState(link); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("openLifecycleState(reparse point) error = %v", err)
	}
}

func TestWindowsLifecycleRejectsHardLinkedRegularFiles(t *testing.T) {
	root := t.TempDir()

	lockTarget := filepath.Join(root, "lock-target")
	if err := os.WriteFile(lockTarget, nil, 0600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, ".lifecycle.lock")
	if err := os.Link(lockTarget, lockPath); err != nil {
		t.Skipf("hard-link fixture unavailable: %v", err)
	}
	if _, err := openLifecycleLock(lockPath); err == nil || !strings.Contains(err.Error(), "hard-linked") {
		t.Fatalf("openLifecycleLock(hard link) error = %v", err)
	}

	stateTarget := filepath.Join(root, "state-target")
	if err := os.WriteFile(stateTarget, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "lifecycle.json")
	if err := os.Link(stateTarget, statePath); err != nil {
		t.Skipf("hard-link state fixture unavailable: %v", err)
	}
	if _, err := openLifecycleState(statePath); err == nil || !strings.Contains(err.Error(), "hard-linked") {
		t.Fatalf("openLifecycleState(hard link) error = %v", err)
	}
}

func TestWindowsLifecycleRootReadRejectsReparsePoint(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "lifecycle.json")
	if err := os.Symlink(target, state); err != nil {
		t.Skipf("reparse-point fixture unavailable: %v", err)
	}
	if _, err := readBoundedFromLifecycleRoot(root, nil, maxStateBytes); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("readBoundedFromLifecycleRoot(reparse point) error = %v", err)
	}
}

func TestWindowsLifecycleRootReadRequiresExpectedIdentity(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "lifecycle.json")
	if err := os.WriteFile(state, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}

	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "lifecycle.json"), []byte(`{"version":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFromLifecycleRoot(other, expected, maxStateBytes); err == nil || !strings.Contains(err.Error(), "lifecycle state root changed") {
		t.Fatalf("readBoundedFromLifecycleRoot(different root) error = %v", err)
	}
}
