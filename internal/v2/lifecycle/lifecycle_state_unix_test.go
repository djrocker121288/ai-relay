//go:build linux || darwin

package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type lifecycleDirectoryHandleStub struct {
	syncErr  error
	closeErr error
}

func (stub lifecycleDirectoryHandleStub) Sync() error  { return stub.syncErr }
func (stub lifecycleDirectoryHandleStub) Close() error { return stub.closeErr }

type typedNilLifecycleDirectoryHandle struct {
	syncCalled  *bool
	closeCalled *bool
}

func (handle *typedNilLifecycleDirectoryHandle) Sync() error {
	*handle.syncCalled = true
	return nil
}

func (handle *typedNilLifecycleDirectoryHandle) Close() error {
	*handle.closeCalled = true
	return nil
}

type panicLifecycleDirectoryHandle struct {
	panicOnSync  bool
	panicOnClose bool
}

func (handle panicLifecycleDirectoryHandle) Sync() error {
	if handle.panicOnSync {
		panic("untrusted directory sync diagnostic")
	}
	return nil
}

func (handle panicLifecycleDirectoryHandle) Close() error {
	if handle.panicOnClose {
		panic("untrusted directory close diagnostic")
	}
	return nil
}

func TestSyncLifecycleDirectoryReportsCloseFailureAfterSuccessfulSync(t *testing.T) {
	closeErr := errors.New("directory close failed")
	err := syncLifecycleDirectoryWithOpen("ignored", func(string) (lifecycleDirectoryHandle, error) {
		return lifecycleDirectoryHandleStub{closeErr: closeErr}, nil
	})
	if !errors.Is(err, closeErr) {
		t.Fatalf("directory close error = %v, want %v", err, closeErr)
	}
}

func TestValidateLifecycleRootAncestorRejectsUnavailableObservation(t *testing.T) {
	if err := validateLifecycleRootAncestor("parent", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("validateLifecycleRootAncestor(nil) = %v, want ErrInvalid", err)
	}
}

func TestValidateLifecycleStateInfoRejectsUnavailableObservation(t *testing.T) {
	if err := validateLifecycleStateInfo(nil); err == nil || err.Error() != "lifecycle state observation is unavailable" {
		t.Fatalf("validateLifecycleStateInfo(nil) = %v, want unavailable-observation error", err)
	}
}

func TestValidateLifecycleStateInfoRejectsTypedNilBeforeMethodDispatch(t *testing.T) {
	var typed *typedNilLifecycleFileInfo
	if err := validateLifecycleStateInfo(typed); err == nil || err.Error() != "lifecycle state observation is unavailable" {
		t.Fatalf("validateLifecycleStateInfo(typed nil) = %v, want unavailable-observation error", err)
	}
}

func TestAtomicWriteLifecycleStateUsesCapturedDirectory(t *testing.T) {
	root := privateTempDir(t)
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openLifecycleRootDirectory(root, info)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(root, "lifecycle.json")
	if err := atomicWriteLifecycleState(directory, path, []byte("descriptor-bound"), nil, nil); err != nil {
		t.Fatalf("descriptor-bound lifecycle write = %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(moved, "lifecycle.json")); err != nil || string(got) != "descriptor-bound" {
		t.Fatalf("captured directory state = %q, %v; want descriptor-bound in moved root", got, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("replacement path received lifecycle state: %v", err)
	}
}

func TestAtomicWriteLifecycleStateRejectsClosedDirectory(t *testing.T) {
	root := privateTempDir(t)
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openLifecycleRootDirectory(root, info)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}

	err = atomicWriteLifecycleState(directory, filepath.Join(root, "lifecycle.json"), []byte("closed"), nil, nil)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("closed directory write error = %v, want ErrClosed", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "lifecycle.json")); !os.IsNotExist(statErr) {
		t.Fatalf("closed directory write created checkpoint: %v", statErr)
	}
}

func TestOpenLifecycleStateAtRejectsClosedDirectory(t *testing.T) {
	root := privateTempDir(t)
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openLifecycleRootDirectory(root, info)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}

	state, err := openLifecycleStateAt(directory)
	if state != nil {
		_ = state.Close()
		t.Fatal("closed directory unexpectedly opened lifecycle state")
	}
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("closed directory state read error = %v, want ErrClosed", err)
	}
}

func TestSyncLifecycleDirectoryRejectsNilHandle(t *testing.T) {
	err := syncLifecycleDirectoryWithOpen("ignored", func(string) (lifecycleDirectoryHandle, error) {
		return nil, nil
	})
	if err == nil || err.Error() != "lifecycle directory handle is nil" {
		t.Fatalf("nil directory handle error = %v, want explicit failure", err)
	}
}

func TestSyncLifecycleDirectoryRejectsTypedNilHandleBeforeMethodDispatch(t *testing.T) {
	var syncCalled, closeCalled bool
	var handle *typedNilLifecycleDirectoryHandle
	err := syncLifecycleDirectoryWithOpen("ignored", func(string) (lifecycleDirectoryHandle, error) {
		return handle, nil
	})
	if err == nil || err.Error() != "lifecycle directory handle is nil" {
		t.Fatalf("typed-nil directory handle error = %v, want explicit failure", err)
	}
	if syncCalled || closeCalled {
		t.Fatalf("typed-nil directory handle dispatched methods: sync=%t close=%t", syncCalled, closeCalled)
	}
}

func TestSyncLifecycleDirectoryPreservesSyncFailureOverCloseFailure(t *testing.T) {
	syncErr := errors.New("directory sync failed")
	closeErr := errors.New("directory close failed")
	err := syncLifecycleDirectoryWithOpen("ignored", func(string) (lifecycleDirectoryHandle, error) {
		return lifecycleDirectoryHandleStub{syncErr: syncErr, closeErr: closeErr}, nil
	})
	if !errors.Is(err, syncErr) {
		t.Fatalf("directory sync error = %v, want %v", err, syncErr)
	}
	if errors.Is(err, closeErr) {
		t.Fatalf("directory sync error was replaced by close error: %v", err)
	}
}

func TestSyncLifecycleDirectoryContainsHandlePanics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		handle lifecycleDirectoryHandle
	}{
		{name: "sync", handle: panicLifecycleDirectoryHandle{panicOnSync: true}},
		{name: "close", handle: panicLifecycleDirectoryHandle{panicOnClose: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := syncLifecycleDirectoryWithOpen("ignored", func(string) (lifecycleDirectoryHandle, error) {
				return tc.handle, nil
			})
			if err == nil || err.Error() != "lifecycle directory sync panicked" {
				t.Fatalf("directory %s panic error = %v, want generic classification", tc.name, err)
			}
			if strings.Contains(err.Error(), "untrusted directory") {
				t.Fatalf("directory %s panic value escaped into error: %v", tc.name, err)
			}
		})
	}
}

func TestReadBoundedRejectsSymlinkedStateFile(t *testing.T) {
	root := privateTempDir(t)
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "lifecycle.json")
	if err := os.Symlink(target, state); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readBounded(state, maxStateBytes); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("symlinked state error = %v, want ELOOP", err)
	}
}

func TestReadBoundedRejectsNonPrivateStateFile(t *testing.T) {
	root := privateTempDir(t)
	state := filepath.Join(root, "lifecycle.json")
	if err := os.WriteFile(state, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	// A restrictive process umask can silently narrow the creation mode, so
	// explicitly make this file group-readable before exercising the rejection.
	if err := os.Chmod(state, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(state, maxStateBytes); err == nil {
		t.Fatal("group-readable state file was accepted")
	}
}

func TestReadBoundedFromLifecycleRootRequiresExpectedIdentity(t *testing.T) {
	root := privateTempDir(t)
	statePath := filepath.Join(root, "lifecycle.json")
	if err := os.WriteFile(statePath, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := validateLifecycleRootPath(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := readBoundedFromLifecycleRoot(root, info, maxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"version":1}` {
		t.Fatalf("state data = %q, want checkpoint bytes", data)
	}

	other := privateTempDir(t)
	if _, err := readBoundedFromLifecycleRoot(other, info, maxStateBytes); !errors.Is(err, ErrConflict) {
		t.Fatalf("different root identity error = %v, want ErrConflict", err)
	}
}

func TestReadBoundedFromLifecycleRootRejectsSymlinkedStateFile(t *testing.T) {
	root := privateTempDir(t)
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "lifecycle.json")
	if err := os.Symlink(target, statePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	info, err := validateLifecycleRootPath(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFromLifecycleRoot(root, info, maxStateBytes); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("descriptor-bound symlink error = %v, want ELOOP", err)
	}
}

func TestReadBoundedFromLifecycleRootRejectsHardLinkedStateFile(t *testing.T) {
	root := privateTempDir(t)
	target := filepath.Join(t.TempDir(), "unrelated.json")
	if err := os.WriteFile(target, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "lifecycle.json")
	if err := os.Link(target, statePath); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	info, err := validateLifecycleRootPath(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFromLifecycleRoot(root, info, maxStateBytes); err == nil || !strings.Contains(err.Error(), "hard-linked") {
		t.Fatalf("hard-linked state error = %v, want explicit rejection", err)
	}
}

func TestOpenRejectsSymlinkedLifecycleLock(t *testing.T) {
	root := privateTempDir(t)
	target := filepath.Join(root, "unrelated.lock")
	if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(root, ".lifecycle.lock")
	if err := os.Symlink(target, lock); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("symlinked lifecycle lock was accepted")
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "untouched" {
		t.Fatalf("symlink target changed to %q", b)
	}
}

func TestOpenRejectsSymlinkedAncestorBeforeCreatingStateRoot(t *testing.T) {
	base := privateTempDir(t)
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "ancestor-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	root := filepath.Join(link, "new-state")

	if _, err := Open(root); err == nil || !strings.Contains(err.Error(), "parent must not be a symlink") {
		t.Fatalf("Open accepted symlinked ancestor: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "new-state")); !os.IsNotExist(err) {
		t.Fatalf("created state root through symlinked ancestor: stat error = %v", err)
	}
}

func TestOpenRejectsWritableAncestorBeforeCreatingStateRoot(t *testing.T) {
	base := privateTempDir(t)
	parent := filepath.Join(base, "shared")
	if err := os.Mkdir(parent, 0770); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "new-state")

	if _, err := Open(root); err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("Open accepted writable ancestor: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("created state root below writable ancestor: stat error = %v", err)
	}
}

func TestOpenAllowsStickyWritableAncestor(t *testing.T) {
	base := privateTempDir(t)
	parent := filepath.Join(base, "shared")
	if err := os.Mkdir(parent, os.ModeSticky|0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, os.ModeSticky|0770); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "new-state")

	store, err := Open(root)
	if err != nil {
		t.Fatalf("Open below sticky writable ancestor = %v", err)
	}
	defer store.Close()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got&0077 != 0 {
		t.Fatalf("created state root permissions = %o, want no group/other bits", got)
	}
}
