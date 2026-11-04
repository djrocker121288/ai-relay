package lifecycle

import (
	"errors"
	"testing"
	"time"
)

func TestNewControllerRejectsOversizedOwnerBeforeStoreValidation(t *testing.T) {
	store, _ := newTestStore(t)
	defer store.Close()
	store.state.Tasks = nil

	_, err := NewController(store, string(make([]byte, maxIDLength+1)))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized owner with malformed store = %v, want ErrInvalid", err)
	}
}

func TestControllerRejectsMalformedInputBeforeStoreValidation(t *testing.T) {
	store, _ := newTestStore(t)
	defer store.Close()
	controller, err := NewController(store, "owner")
	if err != nil {
		t.Fatal(err)
	}
	// The controller was admitted while the store was valid. Corrupt the live
	// state afterward and prove each direct operation still rejects malformed
	// caller input before spending full state-validation work.
	store.state.Tasks = nil
	overlongID := string(make([]byte, maxIDLength+1))
	operations := map[string]func() error{
		"create project": func() error {
			_, err := controller.CreateProject(overlongID, "Project")
			return err
		},
		"archive project": func() error {
			_, err := controller.ArchiveProject(overlongID)
			return err
		},
		"read project": func() error {
			_, err := controller.Project(overlongID)
			return err
		},
		"create task": func() error {
			_, err := controller.CreateTask(TaskSpec{ID: "task", ProjectID: overlongID})
			return err
		},
		"ready": func() error {
			_, err := controller.Ready(overlongID)
			return err
		},
		"tasks": func() error {
			_, err := controller.Tasks(overlongID)
			return err
		},
		"read task": func() error {
			_, err := controller.Task(overlongID)
			return err
		},
		"acquire": func() error {
			_, err := controller.Acquire(overlongID, time.Minute)
			return err
		},
		"heartbeat": func() error {
			_, err := controller.Heartbeat(Lease{TaskID: overlongID, Owner: "owner", Version: 1}, time.Minute)
			return err
		},
		"checkpoint": func() error {
			_, err := controller.Checkpoint(Lease{TaskID: overlongID, Owner: "owner", Version: 1}, TaskRunning, nil)
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("malformed input error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestControllerRejectsOversizedLeaseOwnerBeforeStoreValidation(t *testing.T) {
	store, _ := newTestStore(t)
	defer store.Close()
	controller, err := NewController(store, "owner")
	if err != nil {
		t.Fatal(err)
	}
	store.state.Tasks = nil
	overlongOwner := string(make([]byte, maxIDLength+1))

	if _, err := controller.Heartbeat(Lease{TaskID: "task", Owner: overlongOwner, Version: 1}, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized heartbeat owner error = %v, want ErrInvalid", err)
	}
	if _, err := controller.Checkpoint(Lease{TaskID: "task", Owner: overlongOwner, Version: 1}, TaskRunning, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized checkpoint owner error = %v, want ErrInvalid", err)
	}
}

func TestControllerBindsLeaseOwnership(t *testing.T) {
	store, clock := newTestStore(t)
	defer store.Close()
	if _, err := store.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateTask(TaskSpec{ID: "task", ProjectID: "p"}); err != nil {
		t.Fatal(err)
	}
	controller, err := NewController(store, "controller-a")
	if err != nil {
		t.Fatal(err)
	}
	if controller.Owner() != "controller-a" {
		t.Fatalf("owner = %q", controller.Owner())
	}
	lease, err := controller.Acquire("task", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Checkpoint(Lease{TaskID: lease.TaskID, Owner: "controller-b", Version: lease.Version}, TaskCompleted, []byte("spoof")); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("spoofed checkpoint = %v, want ErrNotOwner", err)
	}
	clock.Add(time.Minute / 2)
	if _, err := controller.Heartbeat(lease, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Checkpoint(lease, TaskCompleted, []byte("done")); err != nil {
		t.Fatal(err)
	}
}

func TestControllerRejectsInvalidOrClosedBinding(t *testing.T) {
	if _, err := NewController(nil, "owner"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil store = %v, want ErrInvalid", err)
	}
	var zero Store
	if _, err := NewController(&zero, "owner"); !errors.Is(err, ErrClosed) {
		t.Fatalf("zero-value store = %v, want ErrClosed", err)
	}
	store, _ := newTestStore(t)
	if _, err := NewController(store, " owner "); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid owner = %v, want ErrInvalid", err)
	}
	controller, err := NewController(store, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if got := controller.Owner(); got != "" {
		t.Fatalf("closed adapter owner = %q, want empty", got)
	}
	if _, err := controller.Project("missing"); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed adapter read = %v, want ErrClosed", err)
	}
	if _, err := NewController(store, "owner"); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed store rebinding = %v, want ErrClosed", err)
	}
}

func TestControllerRejectsMalformedInternalOwnerBinding(t *testing.T) {
	store, _ := newTestStore(t)
	defer store.Close()
	if _, err := store.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}

	// Constructors reject this value, but an in-process integration can still
	// hand an exported adapter a malformed value from inside this package. The
	// adapter must not retain any lifecycle authority in that state.
	controller := &Controller{store: store, owner: " owner "}
	if got := controller.Owner(); got != "" {
		t.Fatalf("malformed owner accessor = %q, want empty", got)
	}

	operations := map[string]func() error{
		"create project": func() error {
			_, err := controller.CreateProject("other", "Other")
			return err
		},
		"archive project": func() error {
			_, err := controller.ArchiveProject("p")
			return err
		},
		"read project": func() error {
			_, err := controller.Project("p")
			return err
		},
		"create task": func() error {
			_, err := controller.CreateTask(TaskSpec{ID: "task", ProjectID: "p"})
			return err
		},
		"ready": func() error {
			_, err := controller.Ready("p")
			return err
		},
		"tasks": func() error {
			_, err := controller.Tasks("p")
			return err
		},
		"read task": func() error {
			_, err := controller.Task("task")
			return err
		},
		"acquire": func() error {
			_, err := controller.Acquire("task", time.Minute)
			return err
		},
		"heartbeat": func() error {
			_, err := controller.Heartbeat(Lease{TaskID: "task", Version: 1}, time.Minute)
			return err
		},
		"checkpoint": func() error {
			_, err := controller.Checkpoint(Lease{TaskID: "task", Version: 1}, TaskRunning, nil)
			return err
		},
		"recover expired": func() error {
			_, err := controller.RecoverExpired()
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, ErrClosed) {
				t.Fatalf("malformed owner operation error = %v, want ErrClosed", err)
			}
		})
	}
	if _, err := store.Project("other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed owner created project: %v", err)
	}
	if _, err := store.Task("task"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed owner created task: %v", err)
	}
	project, err := store.Project("p")
	if err != nil {
		t.Fatal(err)
	}
	if project.Archived {
		t.Fatal("malformed owner archived project")
	}
}

func TestControllerRejectsValidOwnerSubstitution(t *testing.T) {
	store, _ := newTestStore(t)
	defer store.Close()

	controller, err := NewController(store, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	// An in-package integration can mutate unexported fields after construction.
	// A different valid ID is still an ownership substitution and must not turn
	// the adapter into a new principal.
	controller.owner = "owner-b"
	if got := controller.Owner(); got != "" {
		t.Fatalf("substituted owner accessor = %q, want empty", got)
	}
	if _, err := controller.Project("missing"); !errors.Is(err, ErrClosed) {
		t.Fatalf("substituted owner read = %v, want ErrClosed", err)
	}
}
