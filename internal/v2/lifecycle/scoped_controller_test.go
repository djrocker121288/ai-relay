package lifecycle

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestScopedControllerValidatesAndCopiesPrincipalScopes(t *testing.T) {
	store, _ := newTestStore(t)
	defer store.Close()

	scopes := []string{ScopeTaskLease, ScopeProjectRead}
	controller, err := NewScopedController(store, Principal{ID: "agent-a", Scopes: scopes})
	if err != nil {
		t.Fatal(err)
	}
	scopes[0] = ScopeTaskRecover
	if got, want := controller.Owner(), "agent-a"; got != want {
		t.Fatalf("owner = %q, want %q", got, want)
	}
	want := []string{ScopeProjectRead, ScopeTaskLease}
	if got := controller.Scopes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("scopes = %#v, want %#v", got, want)
	}
	returned := controller.Scopes()
	returned[0] = ScopeTaskRecover
	if got := controller.Scopes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("scope copy was mutable: %#v", got)
	}

	for _, principal := range []Principal{
		{ID: "agent-a"},
		{ID: "agent-a", Scopes: []string{"lifecycle.unknown"}},
		{ID: "agent-a", Scopes: []string{ScopeTaskRead, ScopeTaskRead}},
		{ID: "agent-a", Scopes: make([]string, len(lifecycleScopes)+1)},
		{ID: "agent-a", Scopes: []string{string(make([]byte, maxLifecycleScopeBytes+1))}},
	} {
		if _, err := NewScopedController(store, principal); !errors.Is(err, ErrInvalid) {
			t.Fatalf("principal %#v error = %v, want ErrInvalid", principal, err)
		}
	}
}

func TestNewScopedControllerRejectsOversizedScopesBeforeStoreValidation(t *testing.T) {
	store, _ := newTestStore(t)
	defer store.Close()
	store.state.Tasks = nil

	_, err := NewScopedController(store, Principal{
		ID:     "agent-a",
		Scopes: make([]string, len(lifecycleScopes)+1),
	})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "too many lifecycle scopes") {
		t.Fatalf("oversized scopes with malformed store = %v, want bounded scope rejection", err)
	}
}

func TestScopedControllerChecksScopeBeforeMalformedStoreValidation(t *testing.T) {
	store, _ := newTestStore(t)
	defer store.Close()
	controller, err := NewScopedController(store, Principal{
		ID:     "agent-a",
		Scopes: []string{ScopeProjectRead},
	})
	if err != nil {
		t.Fatal(err)
	}
	store.state.Tasks = nil

	if _, err := controller.CreateTask(TaskSpec{ID: "task", ProjectID: "project"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ungranted task write with malformed store = %v, want ErrForbidden", err)
	}
}

func TestScopedControllerEnforcesScopesAndOwnerBinding(t *testing.T) {
	store, clock := newTestStore(t)
	defer store.Close()
	writer, err := NewScopedController(store, Principal{ID: "agent-a", Scopes: []string{ScopeProjectWrite, ScopeTaskWrite, ScopeTaskLease}})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewScopedController(store, Principal{ID: "agent-b", Scopes: []string{ScopeProjectRead, ScopeTaskRead}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.CreateProject("project", "Project"); err != nil {
		t.Fatal(err)
	}
	task, err := writer.CreateTask(TaskSpec{ID: "task", ProjectID: "project"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Project("project"); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.CreateTask(TaskSpec{ID: "other", ProjectID: "project"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("read-only task creation = %v, want ErrForbidden", err)
	}
	lease, err := writer.Acquire(task.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Task(task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Heartbeat(lease, time.Minute); !errors.Is(err, ErrForbidden) {
		t.Fatalf("read-only heartbeat = %v, want ErrForbidden", err)
	}
	clock.Add(time.Second)
	if _, err := writer.Checkpoint(Lease{TaskID: lease.TaskID, Owner: "agent-b", Version: lease.Version}, TaskCompleted, []byte("spoof")); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("spoofed checkpoint = %v, want ErrNotOwner", err)
	}
	if _, err := writer.Checkpoint(lease, TaskCompleted, []byte("done")); err != nil {
		t.Fatal(err)
	}
}

func TestScopedControllerRequiresRecoveryScopeAndFailsClosedAfterClose(t *testing.T) {
	store, clock := newTestStore(t)
	controller, err := NewScopedController(store, Principal{ID: "supervisor", Scopes: []string{ScopeProjectWrite, ScopeTaskWrite, ScopeTaskLease}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.RecoverExpired(); !errors.Is(err, ErrForbidden) {
		t.Fatalf("recovery without scope = %v, want ErrForbidden", err)
	}
	if _, err := controller.CreateProject("project", "Project"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.CreateTask(TaskSpec{ID: "task", ProjectID: "project"}); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Acquire("task", time.Second); err != nil {
		t.Fatal(err)
	}
	clock.Add(2 * time.Second)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if got := controller.Owner(); got != "" {
		t.Fatalf("closed scoped owner = %q, want empty", got)
	}
	if got := controller.Scopes(); got != nil {
		t.Fatalf("closed scoped scopes = %#v, want nil", got)
	}
	if controller.allows(ScopeProjectWrite) {
		t.Fatal("closed scoped binding retained scope authority")
	}
	if _, err := controller.Project("missing"); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed scoped read = %v, want ErrClosed", err)
	}
	if _, err := controller.CreateProject("closed", "Closed"); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed write = %v, want ErrClosed", err)
	}
}

func TestScopedControllerFailsClosedForMalformedInternalBinding(t *testing.T) {
	store, _ := newTestStore(t)
	defer store.Close()

	for _, tc := range []struct {
		name   string
		scopes map[string]struct{}
		owner  string
	}{
		{name: "nil scopes", scopes: nil, owner: "agent-a"},
		{name: "empty scopes", scopes: map[string]struct{}{}, owner: "agent-a"},
		{name: "unknown scope", scopes: map[string]struct{}{"lifecycle.unknown": {}}, owner: "agent-a"},
		{name: "overlong scope", scopes: map[string]struct{}{strings.Repeat("x", maxLifecycleScopeBytes+1): {}}, owner: "agent-a"},
		{name: "widened scopes", scopes: map[string]struct{}{
			ScopeProjectRead: {}, ScopeProjectWrite: {}, ScopeTaskRead: {}, ScopeTaskWrite: {},
			ScopeTaskLease: {}, ScopeTaskRecover: {}, "lifecycle.extra": {},
		}, owner: "agent-a"},
		{name: "invalid owner", scopes: map[string]struct{}{ScopeProjectRead: {}}, owner: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := &ScopedController{
				controller: &Controller{store: store, owner: tc.owner},
				scopes:     tc.scopes,
			}
			if got := controller.Owner(); got != "" {
				t.Fatalf("malformed owner = %q, want empty", got)
			}
			if got := controller.Scopes(); got != nil {
				t.Fatalf("malformed scopes = %#v, want nil", got)
			}
			if controller.allows(ScopeProjectRead) {
				t.Fatal("malformed binding retained scope authority")
			}
			if _, err := controller.Project("missing"); !errors.Is(err, ErrClosed) {
				t.Fatalf("malformed read error = %v, want ErrClosed", err)
			}
			if _, err := controller.CreateProject("p", "Project"); !errors.Is(err, ErrClosed) {
				t.Fatalf("malformed write error = %v, want ErrClosed", err)
			}
			if _, err := store.Project("p"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("malformed binding mutated state: %v", err)
			}
		})
	}
}
