package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// typedNilLifecycleFileInfo deliberately panics if a validator dispatches a
// method before recognizing the typed-nil interface value.
type typedNilLifecycleFileInfo struct{}

func (*typedNilLifecycleFileInfo) Name() string       { panic("typed-nil FileInfo Name called") }
func (*typedNilLifecycleFileInfo) Size() int64        { panic("typed-nil FileInfo Size called") }
func (*typedNilLifecycleFileInfo) Mode() os.FileMode  { panic("typed-nil FileInfo Mode called") }
func (*typedNilLifecycleFileInfo) ModTime() time.Time { panic("typed-nil FileInfo ModTime called") }
func (*typedNilLifecycleFileInfo) IsDir() bool        { panic("typed-nil FileInfo IsDir called") }
func (*typedNilLifecycleFileInfo) Sys() any           { panic("typed-nil FileInfo Sys called") }

func (c *testClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }
func (c *testClock) Set(now time.Time)   { c.mu.Lock(); c.now = now; c.mu.Unlock() }

func newTestStore(t *testing.T) (*Store, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	root := privateTempDir(t)
	s, err := Open(root, Options{Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return s, clock
}

func TestNilStoreOperationsFailClosed(t *testing.T) {
	var store *Store
	if _, err := store.CreateProject("project", "Project"); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil CreateProject = %v, want ErrClosed", err)
	}
	if _, err := store.ArchiveProject("project"); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil ArchiveProject = %v, want ErrClosed", err)
	}
	if _, err := store.Project("project"); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Project = %v, want ErrClosed", err)
	}
	if _, err := store.CreateTask(TaskSpec{ProjectID: "project"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil CreateTask = %v, want ErrClosed", err)
	}
	if _, err := store.Ready("project"); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Ready = %v, want ErrClosed", err)
	}
	if _, err := store.Tasks("project"); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Tasks = %v, want ErrClosed", err)
	}
	if _, err := store.Task("task"); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Task = %v, want ErrClosed", err)
	}
	if _, err := store.Acquire("task", "owner", time.Second); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Acquire = %v, want ErrClosed", err)
	}
	if _, err := store.Heartbeat("task", "owner", 1, time.Second); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Heartbeat = %v, want ErrClosed", err)
	}
	if _, err := store.Checkpoint("task", "owner", 1, TaskRunning, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Checkpoint = %v, want ErrClosed", err)
	}
	if _, err := store.RecoverExpired(); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil RecoverExpired = %v, want ErrClosed", err)
	}
}

func TestMalformedStoreOperationsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Store)
	}{
		{name: "lock", mutate: func(store *Store) { store.lockFile = nil }},
		{name: "root", mutate: func(store *Store) { store.root = "" }},
		{name: "relative root", mutate: func(store *Store) { store.root = "." }},
		{name: "root identity", mutate: func(store *Store) { store.rootInfo = nil }},
		{name: "root directory", mutate: func(store *Store) { store.rootDir = nil }},
		{name: "state", mutate: func(store *Store) { store.state = nil }},
		{name: "clock", mutate: func(store *Store) { store.now = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := newTestStore(t)
			t.Cleanup(func() { _ = store.Close() })
			tc.mutate(store)
			if _, err := store.Project("missing"); !errors.Is(err, ErrClosed) {
				t.Fatalf("malformed store Project = %v, want ErrClosed", err)
			}
		})
	}
}

func TestStoreRejectsMissingUnixRootDescriptorBeforeMutation(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix store descriptor boundary")
	}
	store, _ := newTestStore(t)
	t.Cleanup(func() { _ = store.Close() })
	store.rootDir = nil

	if _, err := store.CreateProject("project", "Project"); !errors.Is(err, ErrClosed) {
		t.Fatalf("CreateProject with missing root descriptor = %v, want ErrClosed", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, "lifecycle.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing root descriptor created a checkpoint: stat error = %v", err)
	}
}

func TestStoreRejectsClosedCapturedDescriptorsBeforeMutation(t *testing.T) {
	store, _ := newTestStore(t)
	t.Cleanup(func() { _ = store.Close() })
	if err := store.lockFile.Close(); err != nil {
		t.Fatalf("close captured lock descriptor: %v", err)
	}

	if _, err := store.CreateProject("project", "Project"); !errors.Is(err, ErrClosed) {
		t.Fatalf("CreateProject with closed lock descriptor = %v, want ErrClosed", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, "lifecycle.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed lock descriptor created a checkpoint: stat error = %v", err)
	}
}

func TestStoreRejectsClosedUnixRootDescriptorBeforeMutation(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix store descriptor boundary")
	}
	store, _ := newTestStore(t)
	t.Cleanup(func() { _ = store.Close() })
	if err := store.rootDir.Close(); err != nil {
		t.Fatalf("close captured root descriptor: %v", err)
	}

	if _, err := store.CreateProject("project", "Project"); !errors.Is(err, ErrClosed) {
		t.Fatalf("CreateProject with closed root descriptor = %v, want ErrClosed", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, "lifecycle.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed root descriptor created a checkpoint: stat error = %v", err)
	}
}

func TestOpenRejectsMultipleOptionsBeforeCreatingStateRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "lifecycle-state")
	if _, err := Open(root, Options{}, Options{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Open with multiple options = %v, want ErrInvalid", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open with multiple options created state root: stat error = %v", err)
	}
}

func TestOpenCanonicalizesRelativeRootBeforeLock(t *testing.T) {
	working := privateTempDir(t)
	t.Chdir(working)
	relativeRoot := "relative-lifecycle-state"
	absoluteRoot := filepath.Join(working, relativeRoot)

	store, err := Open(relativeRoot)
	if err != nil {
		t.Fatalf("Open(relative root) = %v", err)
	}
	defer store.Close()
	if !filepath.IsAbs(store.root) || store.root != absoluteRoot {
		t.Fatalf("stored root = %q, want absolute %q", store.root, absoluteRoot)
	}

	t.Chdir(t.TempDir())
	if _, err := store.CreateProject("project", "Project"); err != nil {
		t.Fatalf("CreateProject after cwd change = %v", err)
	}
	if _, err := os.Stat(filepath.Join(absoluteRoot, "lifecycle.json")); err != nil {
		t.Fatalf("canonical state checkpoint = %v", err)
	}
}

func TestReadLifecycleStateRejectsMissingRootAsConflict(t *testing.T) {
	root := privateTempDir(t)
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}

	if _, err := readLifecycleState(root, info); !errors.Is(err, ErrConflict) {
		t.Fatalf("readLifecycleState(missing root) = %v, want ErrConflict", err)
	}
}

func TestReadBoundedFileRejectsInvalidLimits(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "bounded-read-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := io.WriteString(file, "checkpoint"); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{-1, maxStateBytes + 1, int64(^uint64(0) >> 1)} {
		if _, err := readBoundedFile(file, limit); !errors.Is(err, ErrInvalid) {
			t.Fatalf("readBoundedFile limit %d error = %v, want ErrInvalid", limit, err)
		}
	}
}

func TestReadBoundedFileRejectsClosedHandle(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "bounded-read-closed-")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(file, maxStateBytes); !errors.Is(err, ErrClosed) {
		t.Fatalf("readBoundedFile(closed handle) = %v, want ErrClosed", err)
	}
}

func TestReadSelectorsRejectInvalidIDsBeforeLookup(t *testing.T) {
	s, _ := newTestStore(t)
	defer s.Close()

	invalid := string(make([]byte, maxIDLength+1))
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{name: "project", call: func() error { _, err := s.Project(invalid); return err }},
		{name: "ready", call: func() error { _, err := s.Ready(invalid); return err }},
		{name: "tasks", call: func() error { _, err := s.Tasks(invalid); return err }},
		{name: "task", call: func() error { _, err := s.Task(invalid); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid selector error = %v, want ErrInvalid", err)
			}
		})
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLifecycleDAGLeasesAndDeterministicResume(t *testing.T) {
	s, clock := newTestStore(t)
	if _, err := s.CreateProject("project-a", "Project A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task-b", ProjectID: "project-a", Dependencies: []string{"task-a"}, IdempotencyKey: "b-v1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("forward dependency error = %v", err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task-a", ProjectID: "project-a", IdempotencyKey: "a-v1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task-b", ProjectID: "project-a", Dependencies: []string{"task-a"}, IdempotencyKey: "b-v1"}); err != nil {
		t.Fatal(err)
	}
	if ready, err := s.Ready("project-a"); err != nil || len(ready) != 1 || ready[0].ID != "task-a" {
		t.Fatalf("initial ready = %#v, %v", ready, err)
	}
	lease, err := s.Acquire("task-a", "agent-1", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Acquire("task-a", "agent-2", time.Minute); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("cross-owner acquire = %v", err)
	}
	if _, err := s.Checkpoint("task-a", "agent-2", lease.Version, TaskCompleted, []byte("wrong owner")); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("cross-owner checkpoint = %v", err)
	}
	if _, err := s.Checkpoint("task-a", "agent-1", lease.Version, TaskCompleted, []byte("done")); err != nil {
		t.Fatal(err)
	}
	ready, err := s.Ready("project-a")
	if err != nil || len(ready) != 1 || ready[0].ID != "task-b" {
		t.Fatalf("post-completion ready = %#v, %v", ready, err)
	}
	if _, err := s.Acquire("task-b", "agent-1", time.Minute); err != nil {
		t.Fatal(err)
	}
	clock.Add(2 * time.Minute)
	recovered, err := s.RecoverExpired()
	if err != nil || len(recovered) != 1 || recovered[0].ID != "task-b" || recovered[0].State != TaskPending {
		t.Fatalf("recovered = %#v, %v", recovered, err)
	}
	if ready, err := s.Ready("project-a"); err != nil || len(ready) != 1 || ready[0].ID != "task-b" {
		t.Fatalf("resume ready = %#v, %v", ready, err)
	}
}

func TestReadyRejectsMalformedUnrelatedTaskBeforeSelectingCandidates(t *testing.T) {
	s, _ := newTestStore(t)
	t.Cleanup(func() { _ = s.Close() })
	project, err := s.CreateProject("project", "Project")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "ready", ProjectID: project.ID}); err != nil {
		t.Fatal(err)
	}

	// Keep the injected entry valid for the durable validator while making it
	// impossible for Acquire to advance its retry/lease counters. Ready must
	// preflight the whole snapshot and must not select the otherwise-ready task.
	s.state.Tasks["broken"] = Task{
		ID:           "broken",
		ProjectID:    project.ID,
		RequestHash:  taskHash(project.ID, nil),
		State:        TaskPending,
		Attempt:      ^uint64(0),
		LeaseVersion: ^uint64(0),
		CreatedAt:    project.CreatedAt,
		UpdatedAt:    project.CreatedAt,
	}

	ready, err := s.Ready(project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 0 {
		t.Fatalf("Ready() returned malformed-snapshot candidates: %#v", ready)
	}
}

func TestLifecycleRejectsInvalidUTF8BeforeMutation(t *testing.T) {
	s, _ := newTestStore(t)
	defer s.Close()

	invalid := string([]byte{0xff})
	format := "project\u202ename"
	layoutSeparator := "project\u2028name"
	c1Control := "project\u0085name"
	if _, err := s.CreateProject("bad-id", invalid); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid project name error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateProject("control-name", "Project\nName"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control-character project name error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateProject("format-name", format); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Unicode format project name error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateProject("layout-name", layoutSeparator); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Unicode line-separator project name error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateProject("c1-name", c1Control); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Unicode control project name error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateProject(invalid, "Project"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid project ID error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateProject(format, "Project"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Unicode format project ID error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateProject(layoutSeparator, "Project"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Unicode line-separator project ID error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateProject("project", "Project"); err != nil {
		t.Fatal(err)
	}

	tests := []TaskSpec{
		{ID: invalid, ProjectID: "project"},
		{ID: "task", ProjectID: invalid},
		{ID: "task", ProjectID: "project", IdempotencyKey: invalid},
	}
	for _, spec := range tests {
		if _, err := s.CreateTask(spec); !errors.Is(err, ErrInvalid) {
			t.Fatalf("CreateTask(%#v) error = %v, want ErrInvalid", spec, err)
		}
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task-control-key", ProjectID: "project", IdempotencyKey: "key\x00suffix"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control-character idempotency key error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task-format-key", ProjectID: "project", IdempotencyKey: format}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Unicode format idempotency key error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task-layout-key", ProjectID: "project", IdempotencyKey: layoutSeparator}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Unicode line-separator idempotency key error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task-c1-key", ProjectID: "project", IdempotencyKey: c1Control}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Unicode control idempotency key error = %v, want ErrInvalid", err)
	}
	if _, err := s.CreateProject("unicode-project", "Próject"); err != nil {
		t.Fatalf("ordinary Unicode project name rejected: %v", err)
	}
	dependencies := make([]string, maxTaskDependencies+1)
	for index := range dependencies {
		dependencies[index] = "dependency-" + strconv.Itoa(index)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "too-many-dependencies", ProjectID: "project", Dependencies: dependencies}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized dependency list error = %v, want ErrInvalid", err)
	}
	if tasks, err := s.Tasks("project"); err != nil {
		t.Fatal(err)
	} else if len(tasks) != 0 {
		t.Fatalf("invalid input created tasks: %#v", tasks)
	}
}

func TestNormalizeDependenciesRejectsOversizedIdentifierBeforeOrdering(t *testing.T) {
	oversized := strings.Repeat("d", maxIDLength+1)
	if _, err := normalizeDependencies([]string{"valid", oversized}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("normalizeDependencies() error = %v, want ErrInvalid", err)
	}
}

func TestValidateStateRejectsOversizedDependencyBeforeHashing(t *testing.T) {
	created := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	oversized := strings.Repeat("d", maxIDLength+1)
	state := &durableState{
		Version: stateVersion,
		Projects: map[string]Project{
			"project": {ID: "project", Name: "Project", CreatedAt: created, UpdatedAt: created},
		},
		Tasks: map[string]Task{
			"task": {
				ID:           "task",
				ProjectID:    "project",
				Dependencies: []string{oversized},
				RequestHash:  "placeholder",
				State:        TaskPending,
				CreatedAt:    created,
				UpdatedAt:    created,
			},
		},
		Idempotency: map[string]string{},
	}

	err := validateState(state)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "dependencies for") {
		t.Fatalf("validateState() = %v, want bounded dependency rejection before request-hash validation", err)
	}
}

func TestValidateStateRejectsAggregateVariableBytesBeforeHashing(t *testing.T) {
	created := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	const historyTasks = 9
	state := &durableState{
		Version:      stateVersion,
		Projects:     map[string]Project{"project": {ID: "project", Name: "Project", CreatedAt: created, UpdatedAt: created}},
		Tasks:        make(map[string]Task, historyTasks),
		Idempotency:  map[string]string{},
		NextSequence: historyTasks,
	}
	for index := 0; index < historyTasks; index++ {
		id := fmt.Sprintf("history-%d", index)
		state.Tasks[id] = Task{
			ID: id, ProjectID: "project", RequestHash: taskHash("project", nil),
			State: TaskCompleted, Attempt: 1, LeaseVersion: 1,
			CreatedAt: created, UpdatedAt: created,
			Checkpoint: &Checkpoint{
				TaskID: id, Owner: "agent", LeaseVersion: 1,
				Sequence: uint64(index + 1), State: TaskCompleted,
				Payload: make([]byte, maxPayloadBytes), CreatedAt: created,
			},
		}
	}

	err := validateState(state)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "variable data exceeds") {
		t.Fatalf("validateState() = %v, want aggregate state-variable rejection before hashing", err)
	}
}

func TestStateVariableBudgetRejectsAggregateMetadataBeforeHashing(t *testing.T) {
	created := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	projectID := "project-" + strings.Repeat("p", maxIDLength-len("project-"))
	state := &durableState{
		Version:     stateVersion,
		Projects:    map[string]Project{projectID: {ID: projectID, Name: "Project", CreatedAt: created, UpdatedAt: created}},
		Tasks:       make(map[string]Task, maxTasks),
		Idempotency: make(map[string]string, maxTasks),
	}
	for index := 0; index < maxTasks; index++ {
		idPrefix := fmt.Sprintf("task-%05d-", index)
		id := idPrefix + strings.Repeat("t", maxIDLength-len(idPrefix))
		keyPrefix := fmt.Sprintf("key-%05d-", index)
		key := keyPrefix + strings.Repeat("k", maxIDLength-len(keyPrefix))
		task := Task{
			ID: id, ProjectID: projectID, IdempotencyKey: key,
			RequestHash: taskHash(projectID, nil), State: TaskPending,
			CreatedAt: created, UpdatedAt: created,
		}
		state.Tasks[id] = task
		state.Idempotency[idempotencyKey(projectID, key)] = id
	}

	err := validateState(state)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "variable data exceeds") {
		t.Fatalf("validateState() = %v, want aggregate metadata rejection before hashing", err)
	}
	if stateVariableBudgetWithin(state) {
		t.Fatal("stateVariableBudgetWithin() accepted oversized aggregate metadata")
	}
	if validReadinessStateMapShape(state) {
		t.Fatal("validReadinessStateMapShape() accepted oversized aggregate metadata")
	}
}

func TestStateVariableBudgetRejectsOversizedDependencySlice(t *testing.T) {
	state := &durableState{
		Projects: map[string]Project{},
		Tasks: map[string]Task{
			"task": {Dependencies: make([]string, maxTaskDependencies+1)},
		},
		Idempotency: map[string]string{},
	}

	if stateVariableBudgetWithin(state) {
		t.Fatal("stateVariableBudgetWithin() accepted an oversized dependency slice of empty strings")
	}
}

func TestStateVariableBudgetRejectsOversizedMapsBeforeScanningEntries(t *testing.T) {
	tests := []struct {
		name  string
		state *durableState
	}{
		{
			name: "projects",
			state: &durableState{
				Projects:    make(map[string]Project, maxProjects+1),
				Tasks:       map[string]Task{},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "tasks",
			state: &durableState{
				Projects:    map[string]Project{},
				Tasks:       make(map[string]Task, maxTasks+1),
				Idempotency: map[string]string{},
			},
		},
		{
			name: "idempotency",
			state: &durableState{
				Projects:    map[string]Project{},
				Tasks:       map[string]Task{},
				Idempotency: make(map[string]string, maxTasks+1),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			switch test.name {
			case "projects":
				for index := 0; index <= maxProjects; index++ {
					test.state.Projects[fmt.Sprintf("project-%d", index)] = Project{}
				}
			case "tasks":
				for index := 0; index <= maxTasks; index++ {
					test.state.Tasks[fmt.Sprintf("task-%d", index)] = Task{}
				}
			case "idempotency":
				for index := 0; index <= maxTasks; index++ {
					test.state.Idempotency[fmt.Sprintf("key-%d", index)] = ""
				}
			}
			if stateVariableBudgetWithin(test.state) {
				t.Fatalf("stateVariableBudgetWithin() accepted oversized %s map", test.name)
			}
		})
	}
}

func TestStateSerializedBudgetRejectsOversizedMapsBeforeEncoding(t *testing.T) {
	state := &durableState{
		Projects:    make(map[string]Project, maxProjects+1),
		Tasks:       map[string]Task{},
		Idempotency: map[string]string{},
	}
	for index := 0; index <= maxProjects; index++ {
		state.Projects[fmt.Sprintf("project-%d", index)] = Project{}
	}

	if stateSerializedWithinBudget(state) {
		t.Fatal("stateSerializedWithinBudget() accepted an oversized project map")
	}
}

func TestCompletedDependencyReadinessRejectsMalformedIdentityBeforeCompletion(t *testing.T) {
	state := &durableState{
		Tasks:       map[string]Task{},
		Idempotency: map[string]string{},
	}
	dependency := Task{
		ID:          "dependency",
		ProjectID:   "project",
		RequestHash: "substituted-request-hash",
		State:       TaskCompleted,
	}
	state.Tasks[dependency.ID] = dependency

	if validCompletedDependencyForReadiness(state, dependency.ID, dependency, "project") {
		t.Fatal("validCompletedDependencyForReadiness() accepted a substituted request fingerprint")
	}

	dependency.RequestHash = ""
	dependency.Dependencies = make([]string, maxTaskDependencies+1)
	if validCompletedDependencyForReadiness(state, dependency.ID, dependency, "project") {
		t.Fatal("validCompletedDependencyForReadiness() accepted an oversized dependency list")
	}
}

func TestCompletedDependencyReadinessRejectsSubstitutedCanonicalSnapshot(t *testing.T) {
	state := &durableState{
		Tasks:       map[string]Task{},
		Idempotency: map[string]string{},
	}
	canonical := Task{ID: "dependency", ProjectID: "project", State: TaskCompleted}
	state.Tasks[canonical.ID] = canonical

	substituted := canonical
	substituted.UpdatedAt = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	if validCompletedDependencyForReadiness(state, canonical.ID, substituted, canonical.ProjectID) {
		t.Fatal("validCompletedDependencyForReadiness() accepted a substituted completed-task snapshot")
	}
}

func TestValidateStateRejectsOversizedIdentifiersBeforeDiagnostics(t *testing.T) {
	created := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	tooLongProjectID := strings.Repeat("p", maxIDLength+1)
	tooLongTaskID := strings.Repeat("t", maxIDLength+1)
	tooLongTaskProjectID := strings.Repeat("r", maxIDLength+1)

	tests := []struct {
		name  string
		state *durableState
		want  string
	}{
		{
			name: "project map key",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{tooLongProjectID: {}},
				Tasks:       map[string]Task{},
				Idempotency: map[string]string{},
			},
			want: "project identifier exceeds",
		},
		{
			name: "task map key",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{"project": {ID: "project", Name: "Project", CreatedAt: created, UpdatedAt: created}},
				Tasks:       map[string]Task{tooLongTaskID: {}},
				Idempotency: map[string]string{},
			},
			want: "task identifier exceeds",
		},
		{
			name: "task project reference",
			state: &durableState{
				Version:  stateVersion,
				Projects: map[string]Project{"project": {ID: "project", Name: "Project", CreatedAt: created, UpdatedAt: created}},
				Tasks: map[string]Task{
					"task": {ID: "task", ProjectID: tooLongTaskProjectID, RequestHash: "placeholder", State: TaskPending, CreatedAt: created, UpdatedAt: created},
				},
				Idempotency: map[string]string{},
			},
			want: "task project identifier exceeds",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateState(test.state)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateState() = %v, want ErrInvalid containing %q", err, test.want)
			}
			if len(err.Error()) > 256 {
				t.Fatalf("validateState() error length = %d, want bounded diagnostic", len(err.Error()))
			}
		})
	}
}

func TestOpenRejectsOversizedPersistedDependencyList(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	dependencies := make([]string, 0, maxTaskDependencies+1)
	for index := 0; index < maxTaskDependencies+1; index++ {
		id := "dependency-" + strconv.Itoa(index)
		dependencies = append(dependencies, id)
		if _, err := s.CreateTask(TaskSpec{ID: id, ProjectID: "p"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateTask(TaskSpec{ID: "target", ProjectID: "p"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.root, "lifecycle.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state durableState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	target := state.Tasks["target"]
	target.Dependencies = dependencies
	target.RequestHash = taskHash(target.ProjectID, target.Dependencies)
	state.Tasks["target"] = target
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Dir(path)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("reopen oversized dependency list error = %v, want bounded ErrInvalid", err)
	}
}

func TestOpenRejectsOversizedPersistedIdempotencyIndex(t *testing.T) {
	root := privateTempDir(t)
	state := durableState{
		Version:     stateVersion,
		Projects:    map[string]Project{},
		Tasks:       map[string]Task{},
		Idempotency: make(map[string]string, maxTasks+1),
	}
	for i := 0; i <= maxTasks; i++ {
		state.Idempotency[fmt.Sprintf("project-%d\x00key", i)] = "missing-task"
	}
	b, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "lifecycle.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized persisted idempotency index error = %v, want ErrInvalid", err)
	}
}

func TestOpenRejectsMalformedPersistedIdempotencyIndexEntryBeforeLookup(t *testing.T) {
	tests := []struct {
		name string
		key  string
		id   string
	}{
		{name: "oversized key", key: strings.Repeat("k", maxIdempotencyIndexKeyLength+1), id: "task"},
		{name: "oversized task id", key: "project\x00key", id: strings.Repeat("t", maxIDLength+1)},
		{name: "missing separator", key: "project-key", id: "task"},
		{name: "empty idempotency key", key: "project\x00", id: "task"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := privateTempDir(t)
			state := durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{},
				Tasks:       map[string]Task{},
				Idempotency: map[string]string{tc.key: tc.id},
			}
			b, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "lifecycle.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(root); !errors.Is(err, ErrInvalid) {
				t.Fatalf("malformed persisted idempotency entry error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestOpenRejectsInvalidPersistedLeaseOwner(t *testing.T) {
	tests := []struct {
		name  string
		owner string
	}{
		{name: "oversized", owner: strings.Repeat("o", maxIDLength+1)},
		{name: "control character", owner: "agent\x00owner"},
		{name: "line separator", owner: "agent\u2028owner"},
		{name: "paragraph separator", owner: "agent\u2029owner"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			if _, err := s.CreateProject("project", "Project"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "project"}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Acquire("task", "valid-owner", time.Minute); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.root, "lifecycle.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var state durableState
			if err := json.Unmarshal(data, &state); err != nil {
				t.Fatal(err)
			}
			task := state.Tasks["task"]
			task.LeaseOwner = tc.owner
			state.Tasks["task"] = task
			data, err = json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(filepath.Dir(path)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid persisted lease owner error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestOpenRejectsTerminalCheckpointFromOlderLease(t *testing.T) {
	s, clock := newTestStore(t)
	if _, err := s.CreateProject("project", "Project"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "project"}); err != nil {
		t.Fatal(err)
	}
	lease, err := s.Acquire("task", "owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(2 * time.Minute)
	if _, err := s.RecoverExpired(); err != nil {
		t.Fatal(err)
	}
	lease, err = s.Acquire("task", "owner-2", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Checkpoint("task", lease.Owner, lease.Version, TaskCompleted, []byte("done")); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(s.root, "lifecycle.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state durableState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	task := state.Tasks["task"]
	task.Checkpoint.LeaseVersion = task.LeaseVersion - 1
	state.Tasks["task"] = task
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Dir(path)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "terminal checkpoint lease version") {
		t.Fatalf("older terminal checkpoint lease version error = %v, want bounded ErrInvalid", err)
	}
}

func TestRecoveredCheckpointCanBeReacquiredAndReopened(t *testing.T) {
	s, clock := newTestStore(t)
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "one", ProjectID: "p"}); err != nil {
		t.Fatal(err)
	}
	first, err := s.Acquire("one", "agent-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Checkpoint("one", "agent-a", first.Version, TaskRunning, []byte("resume-here")); err != nil {
		t.Fatal(err)
	}

	clock.Add(2 * time.Minute)
	if _, err := s.Acquire("one", "agent-b", time.Minute); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired lease was reacquired without explicit recovery: %v", err)
	}
	stillRunning, err := s.Task("one")
	if err != nil {
		t.Fatal(err)
	}
	if stillRunning.State != TaskRunning || stillRunning.LeaseOwner != "agent-a" || stillRunning.LeaseVersion != first.Version {
		t.Fatalf("expired acquire changed lease state: %#v", stillRunning)
	}
	recovered, err := s.RecoverExpired()
	if err != nil || len(recovered) != 1 || recovered[0].Checkpoint == nil {
		t.Fatalf("recovered task = %#v, error = %v", recovered, err)
	}
	second, err := s.Acquire("one", "agent-b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if second.Version != 2 {
		t.Fatalf("reacquired lease version = %d, want 2", second.Version)
	}
	resumed, err := s.Task("one")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Checkpoint == nil || string(resumed.Checkpoint.Payload) != "resume-here" || resumed.Checkpoint.LeaseVersion != 1 {
		t.Fatalf("reacquired checkpoint = %#v, want retained version-1 payload", resumed.Checkpoint)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filepath.Dir(filepath.Join(s.root, "lifecycle.json")))
	if err != nil {
		t.Fatalf("reopen after reacquire = %v", err)
	}
	defer reopened.Close()
	loaded, err := reopened.Task("one")
	if err != nil || loaded.State != TaskRunning || loaded.LeaseOwner != "agent-b" {
		t.Fatalf("reopened resumed task = %#v, error = %v", loaded, err)
	}
}

func TestIdempotencyAndArchive(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	first, err := s.CreateTask(TaskSpec{ID: "one", ProjectID: "p", IdempotencyKey: "same"})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := s.CreateTask(TaskSpec{ID: "different", ProjectID: "p", IdempotencyKey: "same"})
	if err != nil || retry.ID != first.ID {
		t.Fatalf("idempotent retry = %#v, %v", retry, err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "two", ProjectID: "p", Dependencies: []string{"one"}, IdempotencyKey: "same"}); !errors.Is(err, ErrIdempotency) {
		t.Fatalf("idempotency conflict = %v", err)
	}
	if _, err := s.ArchiveProject("p"); err != nil {
		t.Fatal(err)
	}
	archivedRetry, err := s.CreateTask(TaskSpec{ID: "different-after-archive", ProjectID: "p", IdempotencyKey: "same"})
	if err != nil || archivedRetry.ID != first.ID {
		t.Fatalf("idempotent retry after archive = %#v, %v", archivedRetry, err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "new-after-archive", ProjectID: "p", IdempotencyKey: "new"}); !errors.Is(err, ErrArchived) {
		t.Fatalf("new archived-project task error = %v, want ErrArchived", err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "three", ProjectID: "p"}); !errors.Is(err, ErrArchived) {
		t.Fatalf("archived create = %v", err)
	}
}

func TestCreateTaskRejectsMalformedLiveIdempotencyIndex(t *testing.T) {
	s, _ := newTestStore(t)
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}

	key := idempotencyKey("p", "same")
	s.state.Idempotency[key] = ""
	if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "p", IdempotencyKey: "same"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty live idempotency index error = %v, want ErrInvalid", err)
	}
	if _, exists := s.state.Tasks["task"]; exists {
		t.Fatal("malformed live idempotency index allowed task creation")
	}

	s.state.Idempotency[key] = strings.Repeat("t", maxIDLength+1)
	if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "p", IdempotencyKey: "same"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized live idempotency index error = %v, want ErrInvalid", err)
	}
	if _, exists := s.state.Tasks["task"]; exists {
		t.Fatal("oversized live idempotency index allowed task creation")
	}
}

func TestCreateTaskRejectsLiveIdempotencyIndexTaskMismatch(t *testing.T) {
	s, _ := newTestStore(t)
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "existing", ProjectID: "p", IdempotencyKey: "other"}); err != nil {
		t.Fatal(err)
	}

	// The task has a valid ID and matching request hash, but it does not own
	// the requested reverse-index key. A live integration must fail closed
	// instead of returning this unrelated task as a successful retry.
	key := idempotencyKey("p", "same")
	s.state.Idempotency[key] = "existing"
	if _, err := s.CreateTask(TaskSpec{ID: "new", ProjectID: "p", IdempotencyKey: "same"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched live idempotency task error = %v, want ErrInvalid", err)
	}
	if _, exists := s.state.Tasks["new"]; exists {
		t.Fatal("mismatched live idempotency index allowed task creation")
	}
}

func TestLiveStateMutationFailsClosedBeforePersistence(t *testing.T) {
	s, _ := newTestStore(t)
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "p"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(s.root, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}

	// This models a malformed in-process integration after the durable state
	// was already accepted by Open. Any later operation must stop before it
	// serves the damaged task or derives a replacement checkpoint.
	task := s.state.Tasks["task"]
	task.RequestHash = "tampered"
	s.state.Tasks["task"] = task
	if _, err := s.CreateProject("rejected", "Rejected"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("live malformed-state mutation error = %v, want ErrInvalid", err)
	}
	if _, exists := s.state.Projects["rejected"]; exists {
		t.Fatal("malformed live state allowed a new project")
	}
	after, err := os.ReadFile(filepath.Join(s.root, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("malformed live state changed the durable checkpoint")
	}
}

func TestValidateStateRejectsNilState(t *testing.T) {
	if err := validateState(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("validateState(nil) = %v, want ErrInvalid", err)
	}
}

func TestValidateLifecycleRootRejectsUnavailableObservation(t *testing.T) {
	if err := validateLifecycleRoot(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("validateLifecycleRoot(nil) = %v, want ErrInvalid", err)
	}
}

func TestLifecycleFileInfoValidatorsRejectTypedNilBeforeMethodDispatch(t *testing.T) {
	var typed *typedNilLifecycleFileInfo
	info := os.FileInfo(typed)
	if !isNilLifecycleFileInfo(info) {
		t.Fatal("typed-nil FileInfo was not classified as unavailable")
	}
	if err := validateLifecycleRoot(info); !errors.Is(err, ErrInvalid) {
		t.Fatalf("validateLifecycleRoot(typed nil) = %v, want ErrInvalid", err)
	}
	if err := validateLifecycleRootObservation(info, info, info, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("validateLifecycleRootObservation(typed nil) = %v, want ErrInvalid", err)
	}

	root := privateTempDir(t)
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLifecycleRootObservation(rootInfo, rootInfo, rootInfo, info); !errors.Is(err, ErrInvalid) {
		t.Fatalf("validateLifecycleRootObservation(typed-nil expected) = %v, want ErrInvalid", err)
	}
}

func TestLatestStateTimeHandlesUnavailableState(t *testing.T) {
	if latest := latestStateTime(nil); !latest.IsZero() {
		t.Fatalf("latestStateTime(nil) = %v, want zero time", latest)
	}
}

func TestLatestStateTimeRejectsUnsupportedStateVersion(t *testing.T) {
	state := &durableState{
		Version: stateVersion + 1,
		Projects: map[string]Project{
			"project": {UpdatedAt: time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)},
		},
		Tasks:       map[string]Task{},
		Idempotency: map[string]string{},
	}
	if latest := latestStateTime(state); !latest.IsZero() {
		t.Fatalf("latestStateTime(unsupported state version) = %v, want zero time", latest)
	}
}

func TestLatestStateTimeRejectsOversizedStateBeforeTimestampSeeding(t *testing.T) {
	oversizedTasks := make(map[string]Task, maxTasks+1)
	for i := 0; i <= maxTasks; i++ {
		oversizedTasks[strconv.Itoa(i)] = Task{UpdatedAt: time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)}
	}
	state := &durableState{
		Projects:    map[string]Project{},
		Tasks:       oversizedTasks,
		Idempotency: map[string]string{},
	}
	if latest := latestStateTime(state); !latest.IsZero() {
		t.Fatalf("latestStateTime(oversized task map) = %v, want zero time", latest)
	}
}

func TestLatestStateTimeRejectsOversizedSerializedStateBeforeTimestampSeeding(t *testing.T) {
	const historyTasks = 7
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	state := &durableState{
		Version:     stateVersion,
		Projects:    map[string]Project{},
		Tasks:       make(map[string]Task, historyTasks),
		Idempotency: map[string]string{},
	}
	for index := 0; index < historyTasks; index++ {
		id := fmt.Sprintf("history-%d", index)
		state.Tasks[id] = Task{
			ID:        id,
			UpdatedAt: now,
			Checkpoint: &Checkpoint{
				TaskID:    id,
				Payload:   make([]byte, maxPayloadBytes),
				CreatedAt: now,
			},
		}
	}

	if !stateVariableBudgetWithin(state) {
		t.Fatal("test state exceeded the raw variable budget unexpectedly")
	}
	if stateSerializedWithinBudget(state) {
		t.Fatal("test state fit the serialized state budget unexpectedly")
	}
	if latest := latestStateTime(state); !latest.IsZero() {
		t.Fatalf("latestStateTime(oversized serialized state) = %v, want zero time", latest)
	}
}

func TestLatestStateTimeRejectsUnrepresentableTimestamp(t *testing.T) {
	state := &durableState{
		Projects: map[string]Project{
			"project": {UpdatedAt: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
		},
		Tasks:       map[string]Task{},
		Idempotency: map[string]string{},
	}
	if latest := latestStateTime(state); !latest.IsZero() {
		t.Fatalf("latestStateTime(unrepresentable project timestamp) = %v, want zero time", latest)
	}
}

func TestLatestStateTimeRejectsUnrepresentableLeaseHorizon(t *testing.T) {
	state := &durableState{
		Projects: map[string]Project{
			"project": {UpdatedAt: time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)},
		},
		Tasks:       map[string]Task{},
		Idempotency: map[string]string{},
	}
	if latest := latestStateTime(state); !latest.IsZero() {
		t.Fatalf("latestStateTime(project timestamp with overflowing lease horizon) = %v, want zero time", latest)
	}
}

func TestLatestStateTimeRejectsMalformedLifetimeEndpoints(t *testing.T) {
	valid := time.Date(2026, time.October, 17, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		state *durableState
	}{
		{
			name: "project creation timestamp omitted",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{"project": {ID: "project", UpdatedAt: valid}},
				Tasks:       map[string]Task{},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "task creation timestamp omitted",
			state: &durableState{
				Version:  stateVersion,
				Projects: map[string]Project{"project": {ID: "project", CreatedAt: valid, UpdatedAt: valid}},
				Tasks: map[string]Task{
					"task": {ID: "task", ProjectID: "project", CreatedAt: time.Time{}, UpdatedAt: valid},
				},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "project lifetime reversed",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{"project": {ID: "project", CreatedAt: valid.Add(time.Minute), UpdatedAt: valid}},
				Tasks:       map[string]Task{},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "checkpoint outside task lifetime",
			state: &durableState{
				Version:  stateVersion,
				Projects: map[string]Project{"project": {ID: "project", CreatedAt: valid, UpdatedAt: valid}},
				Tasks: map[string]Task{
					"task": {
						ID:        "task",
						ProjectID: "project",
						CreatedAt: valid.Add(time.Minute),
						UpdatedAt: valid.Add(2 * time.Minute),
						Checkpoint: &Checkpoint{
							CreatedAt: valid,
						},
					},
				},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "task references missing project",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{"project": {ID: "project", CreatedAt: valid, UpdatedAt: valid}},
				Tasks:       map[string]Task{"task": {ID: "task", ProjectID: "missing", CreatedAt: valid, UpdatedAt: valid}},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "task predates project",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{"project": {ID: "project", CreatedAt: valid, UpdatedAt: valid}},
				Tasks:       map[string]Task{"task": {ID: "task", ProjectID: "project", CreatedAt: valid.Add(-time.Minute), UpdatedAt: valid}},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "checkpoint identity does not match task",
			state: &durableState{
				Version:  stateVersion,
				Projects: map[string]Project{"project": {ID: "project", CreatedAt: valid, UpdatedAt: valid}},
				Tasks: map[string]Task{"task": {
					ID: "task", ProjectID: "project", CreatedAt: valid, UpdatedAt: valid,
					Checkpoint: &Checkpoint{TaskID: "other", CreatedAt: valid},
				}},
				Idempotency: map[string]string{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if latest := latestStateTime(test.state); !latest.IsZero() {
				t.Fatalf("latestStateTime() = %v, want zero time", latest)
			}
		})
	}
}

func TestDurableStateCloneHandlesUnavailableState(t *testing.T) {
	var state *durableState
	if clone := state.clone(); clone != nil {
		t.Fatalf("durableState.clone(nil) = %#v, want nil", clone)
	}
}

func TestDurableStateCloneRejectsUnsupportedStateVersion(t *testing.T) {
	state := &durableState{
		Version:     stateVersion + 1,
		Projects:    map[string]Project{},
		Tasks:       map[string]Task{},
		Idempotency: map[string]string{},
	}
	if clone := state.clone(); clone != nil {
		t.Fatalf("durableState.clone(unsupported state version) = %#v, want nil", clone)
	}
}

func TestDurableStateCloneRejectsOversizedShapeBeforeCopying(t *testing.T) {
	oversizedTasks := make(map[string]Task, maxTasks+1)
	for i := 0; i <= maxTasks; i++ {
		oversizedTasks[strconv.Itoa(i)] = Task{}
	}
	state := &durableState{
		Version:     stateVersion,
		Projects:    map[string]Project{},
		Tasks:       oversizedTasks,
		Idempotency: map[string]string{},
	}
	if clone := state.clone(); clone != nil {
		t.Fatalf("durableState.clone(oversized task map) = non-nil, want nil")
	}
}

func TestDurableStateCloneRejectsOversizedIdentityBeforeCopying(t *testing.T) {
	tooLong := strings.Repeat("x", maxIDLength+1)
	tests := []struct {
		name  string
		state *durableState
	}{
		{
			name: "project map key",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{tooLong: {ID: tooLong}},
				Tasks:       map[string]Task{},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "dependency",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{},
				Tasks:       map[string]Task{"task": {ID: "task", Dependencies: []string{tooLong}}},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "idempotency index key",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{},
				Tasks:       map[string]Task{},
				Idempotency: map[string]string{strings.Repeat("k", maxIdempotencyIndexKeyLength+1): "task"},
			},
		},
		{
			name: "request hash",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{},
				Tasks:       map[string]Task{"task": {ID: "task", RequestHash: tooLong}},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "task state",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{},
				Tasks:       map[string]Task{"task": {ID: "task", State: TaskState(tooLong)}},
				Idempotency: map[string]string{},
			},
		},
		{
			name: "checkpoint state",
			state: &durableState{
				Version:     stateVersion,
				Projects:    map[string]Project{},
				Tasks:       map[string]Task{"task": {ID: "task", Checkpoint: &Checkpoint{State: TaskState(tooLong)}}},
				Idempotency: map[string]string{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !stateVariableBudgetWithin(test.state) {
				t.Fatal("test state exceeded the aggregate raw-variable budget unexpectedly")
			}
			if !stateSerializedWithinBudget(test.state) {
				t.Fatal("test state exceeded the serialized state budget unexpectedly")
			}
			if clone := test.state.clone(); clone != nil {
				t.Fatalf("durableState.clone(%s) = non-nil, want nil", test.name)
			}
		})
	}
}

func TestDurableStateCloneRejectsOversizedCheckpointBeforeCopying(t *testing.T) {
	state := &durableState{
		Version:  stateVersion,
		Projects: map[string]Project{},
		Tasks: map[string]Task{
			"task": {
				ID:         "task",
				Checkpoint: &Checkpoint{Payload: make([]byte, maxPayloadBytes+1)},
			},
		},
		Idempotency: map[string]string{},
	}
	if clone := state.clone(); clone != nil {
		t.Fatalf("durableState.clone(oversized checkpoint) = non-nil, want nil")
	}
}

func TestDurableStateCloneRejectsOversizedSerializedStateBeforeCopying(t *testing.T) {
	const historyTasks = 7
	state := &durableState{
		Version:     stateVersion,
		Projects:    map[string]Project{},
		Tasks:       make(map[string]Task, historyTasks),
		Idempotency: map[string]string{},
	}
	for index := 0; index < historyTasks; index++ {
		id := fmt.Sprintf("history-%d", index)
		state.Tasks[id] = Task{
			ID: id,
			Checkpoint: &Checkpoint{
				TaskID:  id,
				Payload: make([]byte, maxPayloadBytes),
			},
		}
	}

	if !stateVariableBudgetWithin(state) {
		t.Fatal("test state exceeded the raw variable budget unexpectedly")
	}
	if stateSerializedWithinBudget(state) {
		t.Fatal("test state fit the serialized state budget unexpectedly")
	}
	if clone := state.clone(); clone != nil {
		t.Fatalf("durableState.clone(oversized serialized state) = non-nil, want nil")
	}
}

func TestCloneTaskRejectsOversizedNestedDataBeforeCopying(t *testing.T) {
	tooManyDependencies := make([]string, maxTaskDependencies+1)
	tooLong := strings.Repeat("x", maxIDLength+1)
	tests := []struct {
		name string
		task Task
	}{
		{
			name: "dependencies",
			task: Task{ID: "task", Dependencies: tooManyDependencies},
		},
		{
			name: "checkpoint payload",
			task: Task{ID: "task", Checkpoint: &Checkpoint{Payload: make([]byte, maxPayloadBytes+1)}},
		},
		{
			name: "task identity",
			task: Task{ID: tooLong},
		},
		{
			name: "project identity",
			task: Task{ID: "task", ProjectID: tooLong},
		},
		{
			name: "dependency identity",
			task: Task{ID: "task", Dependencies: []string{tooLong}},
		},
		{
			name: "checkpoint owner identity",
			task: Task{ID: "task", Checkpoint: &Checkpoint{Owner: tooLong}},
		},
		{
			name: "task state",
			task: Task{ID: "task", State: TaskState(tooLong)},
		},
		{
			name: "checkpoint state",
			task: Task{ID: "task", Checkpoint: &Checkpoint{State: TaskState(tooLong)}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cloneTask(test.task); !reflect.DeepEqual(got, Task{}) {
				t.Fatalf("cloneTask(%s) = %#v, want zero task", test.name, got)
			}
		})
	}
}

func TestLiveStateTimestampMutationFailsClosedBeforePersistence(t *testing.T) {
	s, clock := newTestStore(t)
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "p"}); err != nil {
		t.Fatal(err)
	}
	lease, err := s.Acquire("task", "agent", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(s.root, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}

	// MarshalJSON rejects years outside its wire range. This models an
	// integration mutating live state after Open and proves reads stop before
	// returning the malformed task or persisting a derived checkpoint.
	task := s.state.Tasks["task"]
	task.LeaseUntil = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	s.state.Tasks["task"] = task
	if _, err := s.Task("task"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unrepresentable live timestamp read error = %v, want ErrInvalid", err)
	}
	if _, err := s.Checkpoint("task", "agent", lease.Version, TaskCompleted, []byte("done")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unrepresentable live timestamp mutation error = %v, want ErrInvalid", err)
	}
	if s.state.Tasks["task"].Checkpoint != nil {
		t.Fatal("unrepresentable live timestamp allowed a checkpoint")
	}
	if !clock.Now().Equal(time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("test clock unexpectedly changed")
	}
	after, err := os.ReadFile(filepath.Join(s.root, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("unrepresentable live timestamp changed durable state")
	}
}

func TestClockRegressionDoesNotCreateNonCanonicalTimestamps(t *testing.T) {
	s, clock := newTestStore(t)
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "p"}); err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	lease, err := s.Acquire("task", "agent", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clock.Set(time.Date(2026, 10, 17, 11, 0, 0, 0, time.UTC))
	if _, err := s.Checkpoint("task", "agent", lease.Version, TaskCompleted, []byte("done")); err != nil {
		t.Fatalf("checkpoint after clock regression = %v", err)
	}
	task, err := s.Task("task")
	if err != nil {
		t.Fatal(err)
	}
	if task.UpdatedAt.Before(task.CreatedAt) || task.Checkpoint == nil || task.Checkpoint.CreatedAt.Before(task.CreatedAt) {
		t.Fatalf("clock regression produced non-monotonic state: %#v", task)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.root, Options{Now: clock.Now})
	if err != nil {
		t.Fatalf("reopen after clock regression = %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.Task("task"); err != nil {
		t.Fatalf("reopened task after clock regression = %v", err)
	}
}

func TestMalformedLifecycleClockFailsClosedBeforeMutation(t *testing.T) {
	tests := []struct {
		name string
		now  func() time.Time
	}{
		{name: "zero", now: func() time.Time { return time.Time{} }},
		{name: "panic", now: func() time.Time { panic("clock detail must not escape") }},
		{name: "year outside JSON range", now: func() time.Time {
			return time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
		}},
		{name: "lease horizon outside JSON range", now: func() time.Time {
			return time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := newTestStore(t)
			defer store.Close()
			if _, err := store.CreateProject("stable", "Stable"); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(store.root, "lifecycle.json"))
			if err != nil {
				t.Fatal(err)
			}
			lastNow := store.lastNow
			store.now = tc.now
			if _, err := store.CreateProject("rejected", "Rejected"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("malformed clock mutation error = %v, want ErrInvalid", err)
			} else if strings.Contains(err.Error(), "clock detail") {
				t.Fatalf("malformed clock panic detail escaped: %v", err)
			}
			if _, ok := store.state.Projects["rejected"]; ok {
				t.Fatal("malformed clock mutation changed in-memory state")
			}
			if !store.lastNow.Equal(lastNow) {
				t.Fatalf("malformed clock changed timestamp floor: got %v, want %v", store.lastNow, lastNow)
			}
			after, err := os.ReadFile(filepath.Join(store.root, "lifecycle.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("malformed clock mutation changed durable state")
			}
		})
	}
}

func TestMutationRejectsStateCloneFailureAfterAdmission(t *testing.T) {
	store, clock := newTestStore(t)
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateProject("stable", "Stable"); err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(store.root, "lifecycle.json")
	before, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}

	// The public operation validates the live state before calling Now. Model a
	// direct in-process integration that damages the state during that callback;
	// the mutation clone must return ErrInvalid instead of being dereferenced as
	// nil. Keep the clock result valid so the clone boundary is the observed
	// failure.
	store.now = func() time.Time {
		store.state.Tasks["malformed"] = Task{
			ID:          "malformed",
			ProjectID:   "stable",
			RequestHash: strings.Repeat("x", maxStateBytes+1),
			State:       TaskPending,
		}
		return clock.Now()
	}

	var mutationErr error
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		_, mutationErr = store.CreateProject("rejected", "Rejected")
	}()
	if panicked {
		t.Fatal("mutation panicked after state clone rejection")
	}
	if !errors.Is(mutationErr, ErrInvalid) {
		t.Fatalf("mutation error = %v, want ErrInvalid", mutationErr)
	}
	if _, ok := store.state.Projects["rejected"]; ok {
		t.Fatal("state clone rejection installed the candidate project")
	}
	after, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("state clone rejection changed the durable checkpoint")
	}
}

func TestCurrentTimeRejectsUnavailableReceiver(t *testing.T) {
	var nilStore *Store
	if _, err := nilStore.currentTime(); !errors.Is(err, ErrClosed) {
		t.Fatalf("currentTime() on nil store = %v, want ErrClosed", err)
	}

	var zeroStore Store
	if _, err := zeroStore.currentTime(); !errors.Is(err, ErrClosed) {
		t.Fatalf("currentTime() on zero store = %v, want ErrClosed", err)
	}
}

func TestCurrentTimeRejectsMalformedClockFloor(t *testing.T) {
	store, _ := newTestStore(t)
	t.Cleanup(func() { _ = store.Close() })

	floor := time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	store.lastNow = floor
	now, err := store.currentTime()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("currentTime() with malformed floor = %v, want ErrInvalid", err)
	}
	if !now.IsZero() {
		t.Fatalf("currentTime() with malformed floor returned %v, want zero time", now)
	}
	if !store.lastNow.Equal(floor) {
		t.Fatalf("malformed floor changed during rejection: got %v, want %v", store.lastNow, floor)
	}
}

func TestCommitRejectsInvalidCandidateBeforePersistence(t *testing.T) {
	store, clock := newTestStore(t)
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateProject("project", "Project"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(store.root, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}

	// The timestamp floor normally prevents a regressed clock from producing
	// this candidate. Clear the private floor to model a malformed in-process
	// integration and prove the commit boundary still rejects the result.
	store.lastNow = time.Time{}
	clock.Set(time.Date(2026, 10, 17, 11, 0, 0, 0, time.UTC))
	if _, err := store.CreateTask(TaskSpec{ID: "task", ProjectID: "project"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid candidate error = %v, want ErrInvalid", err)
	}
	if _, exists := store.state.Tasks["task"]; exists {
		t.Fatal("invalid candidate changed live state")
	}
	after, err := os.ReadFile(filepath.Join(store.root, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("invalid candidate changed durable state")
	}
}

func TestAtomicCheckpointFailureLeavesPriorState(t *testing.T) {
	s, _ := newTestStore(t)
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "one", ProjectID: "p"}); err != nil {
		t.Fatal(err)
	}
	lease, err := s.Acquire("one", "agent", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.persistHook = func([]byte) error { return errors.New("injected persistence failure") }
	if _, err := s.Checkpoint("one", "agent", lease.Version, TaskCompleted, []byte("not durable")); err == nil {
		t.Fatal("checkpoint unexpectedly succeeded")
	}
	s.persistHook = nil
	task, err := s.Task("one")
	if err != nil {
		t.Fatal(err)
	}
	if task.State != TaskRunning || task.Checkpoint != nil {
		t.Fatalf("failed checkpoint mutated state: %#v", task)
	}
	if _, err := s.Checkpoint("one", "agent", lease.Version, TaskCompleted, []byte("durable")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filepath.Dir(filepath.Join(s.root, "lifecycle.json")))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, err := reopened.Task("one")
	if err != nil || loaded.State != TaskCompleted || string(loaded.Checkpoint.Payload) != "durable" {
		t.Fatalf("reopened = %#v, %v", loaded, err)
	}
}

func TestLifecycleWriteRejectsReplacedStateRoot(t *testing.T) {
	root := privateTempDir(t)
	clock := &testClock{now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	s, err := Open(root, Options{Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject("initial", "Initial"); err != nil {
		t.Fatal(err)
	}

	moved := root + "-moved"
	redirect := privateTempDir(t)
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(redirect, root); err != nil {
		_ = os.Rename(moved, root)
		t.Fatal(err)
	}
	defer func() {
		_ = s.Close()
		_ = os.Remove(root)
		_ = os.Rename(moved, root)
	}()

	if _, err := s.CreateProject("redirected", "Redirected"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replaced-root mutation error = %v, want ErrInvalid", err)
	}
	if _, err := os.Stat(filepath.Join(redirect, "lifecycle.json")); !os.IsNotExist(err) {
		t.Fatalf("redirected state path exists with error = %v", err)
	}
	if _, err := s.Project("redirected"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replaced-root read error = %v, want ErrInvalid", err)
	}
	if _, err := NewController(s, "owner"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replaced-root adapter binding error = %v, want ErrInvalid", err)
	}
}

func TestLifecycleReadRejectsMissingStateRoot(t *testing.T) {
	root := privateTempDir(t)
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateProject("initial", "Initial"); err != nil {
		t.Fatal(err)
	}

	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(moved, root)

	if _, err := store.Project("initial"); !errors.Is(err, ErrConflict) {
		t.Fatalf("missing-root read error = %v, want ErrConflict", err)
	}
	if _, err := NewController(store, "owner"); !errors.Is(err, ErrConflict) {
		t.Fatalf("missing-root adapter binding error = %v, want ErrConflict", err)
	}
}

func TestAtomicWriteReplacesExistingCheckpoint(t *testing.T) {
	root := privateTempDir(t)
	path := filepath.Join(root, "lifecycle.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, []byte("new")); err != nil {
		t.Fatalf("atomic replacement failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("checkpoint contents = %q, want %q", got, "new")
	}
}

func TestAtomicWritePreflightRunsBeforeReplacementCreation(t *testing.T) {
	root := privateTempDir(t)
	path := filepath.Join(root, "lifecycle.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	preflightErr := errors.New("root changed")
	if err := atomicWriteWithPreflight(path, []byte("new"), func() error {
		return preflightErr
	}); !errors.Is(err, preflightErr) {
		t.Fatalf("preflight error = %v, want %v", err, preflightErr)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("checkpoint contents = %q, want unchanged old checkpoint", got)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".lifecycle-") {
			t.Fatalf("preflight created temporary replacement %q", entry.Name())
		}
	}
}

func TestAtomicWritePreflightRunsBeforeReplacementInstall(t *testing.T) {
	root := privateTempDir(t)
	path := filepath.Join(root, "lifecycle.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	preflightErr := errors.New("root changed during replacement write")
	calls := 0
	err := atomicWriteWithPreflight(path, []byte("new"), func() error {
		calls++
		if calls == 2 {
			return preflightErr
		}
		return nil
	})
	if !errors.Is(err, preflightErr) {
		t.Fatalf("preflight error = %v, want %v", err, preflightErr)
	}
	if calls != 2 {
		t.Fatalf("preflight calls = %d, want 2", calls)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("checkpoint contents = %q, want unchanged old checkpoint", got)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".lifecycle-") {
			t.Fatalf("failed final preflight left temporary replacement %q", entry.Name())
		}
	}
}

func TestAtomicWriteDirectorySyncFailureReportsInstalledReplacement(t *testing.T) {
	root := privateTempDir(t)
	path := filepath.Join(root, "lifecycle.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	syncErr := errors.New("directory sync failed")
	err := atomicWriteWithPreflightAndSync(path, []byte("new"), nil, func(string) error {
		return syncErr
	})
	if !errors.Is(err, syncErr) {
		t.Fatalf("directory sync error = %v, want %v", err, syncErr)
	}
	var writeErr *atomicWriteError
	if !errors.As(err, &writeErr) || !writeErr.installed {
		t.Fatalf("directory sync error = %#v, want installed atomic write error", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("installed checkpoint contents = %q, want %q", got, "new")
	}
}

func TestAtomicWriteDirectorySyncPanicReportsInstalledReplacement(t *testing.T) {
	root := privateTempDir(t)
	path := filepath.Join(root, "lifecycle.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	err := atomicWriteWithPreflightAndSync(path, []byte("new"), nil, func(string) error {
		panic("untrusted sync diagnostic")
	})
	if err == nil || !strings.Contains(err.Error(), "directory sync panicked") {
		t.Fatalf("directory sync panic error = %v, want generic panic classification", err)
	}
	var writeErr *atomicWriteError
	if !errors.As(err, &writeErr) || !writeErr.installed {
		t.Fatalf("directory sync panic error = %#v, want installed atomic write error", err)
	}
	if strings.Contains(err.Error(), "untrusted sync diagnostic") {
		t.Fatalf("directory sync panic value escaped into error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("installed checkpoint contents = %q, want %q", got, "new")
	}
}

func TestInstalledCheckpointSyncPanicQuarantinesStore(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.CreateProject("p", "Project"); err != nil {
		t.Fatal(err)
	}
	s.syncDirectoryHook = func(string) error { panic("untrusted sync diagnostic") }
	if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "p"}); err == nil || !strings.Contains(err.Error(), "directory sync panicked") {
		t.Fatalf("checkpoint sync panic error = %v, want generic panic classification", err)
	}
	if _, err := s.Project("p"); !errors.Is(err, ErrClosed) {
		t.Fatalf("quarantined store read = %v, want ErrClosed", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.root)
	if err != nil {
		t.Fatalf("reopen after installed checkpoint panic = %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.Task("task"); err != nil {
		t.Fatalf("reopened installed checkpoint task = %v", err)
	}
}

func TestInstalledCheckpointSyncFailureQuarantinesStore(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.CreateProject("p", "Project"); err != nil {
		t.Fatal(err)
	}
	syncErr := errors.New("directory sync failed")
	s.syncDirectoryHook = func(string) error { return syncErr }
	if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "p"}); !errors.Is(err, syncErr) {
		t.Fatalf("checkpoint sync error = %v, want %v", err, syncErr)
	}
	if _, err := s.Project("p"); !errors.Is(err, ErrClosed) {
		t.Fatalf("quarantined store read = %v, want ErrClosed", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.root)
	if err != nil {
		t.Fatalf("reopen after installed checkpoint = %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.Task("task"); err != nil {
		t.Fatalf("reopened installed checkpoint task = %v", err)
	}
}

func TestCheckpointSequenceExhaustionLeavesStateUnchanged(t *testing.T) {
	s, _ := newTestStore(t)
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateProject("p", "Project"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "p"}); err != nil {
		t.Fatal(err)
	}
	lease, err := s.Acquire("task", "agent", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	checkpointBefore, err := os.ReadFile(filepath.Join(s.root, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.state.NextSequence = ^uint64(0)

	if _, err := s.Checkpoint("task", "agent", lease.Version, TaskRunning, []byte("resume")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("sequence exhaustion error = %v, want ErrInvalid", err)
	}
	if s.state.NextSequence != ^uint64(0) {
		t.Fatalf("sequence changed after rejected checkpoint: %d", s.state.NextSequence)
	}
	checkpointAfter, err := os.ReadFile(filepath.Join(s.root, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(checkpointBefore, checkpointAfter) {
		t.Fatal("rejected checkpoint changed the durable state")
	}
	task, err := s.Task("task")
	if err != nil {
		t.Fatal(err)
	}
	if task.Checkpoint != nil || task.State != TaskRunning {
		t.Fatalf("rejected checkpoint changed task: %#v", task)
	}
}

func TestAcquireRejectsLeaseCounterExhaustion(t *testing.T) {
	s, _ := newTestStore(t)
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateProject("p", "Project"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "task", ProjectID: "p"}); err != nil {
		t.Fatal(err)
	}
	durableBefore, err := os.ReadFile(filepath.Join(s.root, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}
	task := s.state.Tasks["task"]
	task.Attempt = ^uint64(0)
	task.LeaseVersion = ^uint64(0)
	s.state.Tasks["task"] = task

	if _, err := s.Acquire("task", "agent", time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("counter exhaustion error = %v, want ErrInvalid", err)
	}
	after := s.state.Tasks["task"]
	if after.Attempt != ^uint64(0) || after.LeaseVersion != ^uint64(0) || after.State != TaskPending || after.LeaseOwner != "" {
		t.Fatalf("rejected acquire mutated in-memory task: %#v", after)
	}
	durableAfter, err := os.ReadFile(filepath.Join(s.root, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(durableBefore, durableAfter) {
		t.Fatal("rejected acquire changed durable state")
	}
}

func TestCrossProcessWriterLockAndClose(t *testing.T) {
	root := privateTempDir(t)
	first, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); !errors.Is(err, ErrConflict) {
		t.Fatalf("competing open error = %v, want ErrConflict", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLifecycleLockHelper$")
	cmd.Env = append(os.Environ(), "AI_RELAY_LIFECYCLE_LOCK_ROOT="+root)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-process competing open = %v: %s", err, output)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Project("missing"); !errors.Is(err, ErrClosed) {
		t.Fatalf("read after close = %v, want ErrClosed", err)
	}
	second, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := second.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleLockHelper(t *testing.T) {
	root := os.Getenv("AI_RELAY_LIFECYCLE_LOCK_ROOT")
	if root == "" {
		return
	}
	if _, err := Open(root); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-process open error = %v, want ErrConflict", err)
	}
}

func TestCloseLifecycleLockRejectsUnavailableHandle(t *testing.T) {
	if err := closeLifecycleLock(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("closeLifecycleLock(nil) = %v, want ErrClosed", err)
	}

	file, err := os.CreateTemp(t.TempDir(), ".lifecycle-lock-closed-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closeLifecycleLock(file); !errors.Is(err, ErrClosed) {
		t.Fatalf("closeLifecycleLock(closed file) = %v, want ErrClosed", err)
	}
}

func TestLifecycleLockPrimitivesRejectUnavailableHandle(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("native lifecycle lock primitive boundary")
	}

	for _, tc := range []struct {
		name string
		file *os.File
	}{
		{name: "nil", file: nil},
	} {
		if err := acquireLifecycleLock(tc.file); !errors.Is(err, ErrClosed) {
			t.Fatalf("acquireLifecycleLock(%s) = %v, want ErrClosed", tc.name, err)
		}
		if err := releaseLifecycleLock(tc.file); !errors.Is(err, ErrClosed) {
			t.Fatalf("releaseLifecycleLock(%s) = %v, want ErrClosed", tc.name, err)
		}
	}

	file, err := os.CreateTemp(t.TempDir(), ".lifecycle-lock-primitive-closed-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := acquireLifecycleLock(file); !errors.Is(err, ErrClosed) {
		t.Fatalf("acquireLifecycleLock(closed file) = %v, want ErrClosed", err)
	}
	if err := releaseLifecycleLock(file); !errors.Is(err, ErrClosed) {
		t.Fatalf("releaseLifecycleLock(closed file) = %v, want ErrClosed", err)
	}
}

func TestCloseLifecycleStoreDirectoryRejectsClosedHandle(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix store-directory cleanup boundary")
	}

	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closeLifecycleStoreDirectory(directory); !errors.Is(err, ErrClosed) {
		t.Fatalf("closeLifecycleStoreDirectory(closed directory) = %v, want ErrClosed", err)
	}
}

func TestConcurrentLeaseRaceHasOneOwner(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "one", ProjectID: "p"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.Acquire("one", "agent-"+string(rune('a'+i)), time.Minute); err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("lease winners = %d, want 1", winners)
	}
}

func TestOpenRejectsOversizedStateAndSymlinkRoot(t *testing.T) {
	root := privateTempDir(t)
	if err := os.WriteFile(filepath.Join(root, "lifecycle.json"), make([]byte, maxStateBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("oversized state was accepted")
	}
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("symlink root was accepted")
	}
}

func TestOpenRejectsHardLinkedLifecycleLock(t *testing.T) {
	root := privateTempDir(t)
	outside := filepath.Join(t.TempDir(), "shared-lock")
	if err := os.WriteFile(outside, []byte("lock"), 0640); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, ".lifecycle.lock")
	if err := os.Link(outside, lockPath); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(root); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "hard-linked") {
		t.Fatalf("hard-linked lifecycle lock error = %v, want ErrInvalid hard-link rejection", err)
	}
	if info, err := os.Stat(outside); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0640 {
		t.Fatalf("unrelated hard-linked lock mode = %o, want 0640", info.Mode().Perm())
	}
}

func TestValidateLifecycleRootPathRechecksNoFollowAndIdentity(t *testing.T) {
	root := privateTempDir(t)
	info, err := validateLifecycleRootPath(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateLifecycleRootPath(root, info); err != nil {
		t.Fatalf("stable root revalidation = %v", err)
	}
	other := privateTempDir(t)
	if _, err := validateLifecycleRootPath(other, info); !errors.Is(err, ErrConflict) {
		t.Fatalf("different root identity error = %v, want ErrConflict", err)
	}

	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := validateLifecycleRootPath(link, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink root validation error = %v, want ErrInvalid", err)
	}
}

func TestValidateLifecycleRootObservationRejectsChangedPath(t *testing.T) {
	root := privateTempDir(t)
	other := privateTempDir(t)
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	otherInfo, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLifecycleRootObservation(rootInfo, rootInfo, otherInfo, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed root observation error = %v, want ErrConflict", err)
	}

	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLifecycleRootObservation(rootInfo, rootInfo, linkInfo, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink root observation error = %v, want ErrInvalid", err)
	}
}

func TestValidateLifecycleRootObservationRejectsUnavailableObservations(t *testing.T) {
	root := privateTempDir(t)
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name            string
		pathInfo        os.FileInfo
		resolvedInfo    os.FileInfo
		currentPathInfo os.FileInfo
	}{
		{name: "missing path observation", pathInfo: nil, resolvedInfo: info, currentPathInfo: info},
		{name: "missing resolved observation", pathInfo: info, resolvedInfo: nil, currentPathInfo: info},
		{name: "missing current observation", pathInfo: info, resolvedInfo: info, currentPathInfo: nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := validateLifecycleRootObservation(test.pathInfo, test.resolvedInfo, test.currentPathInfo, nil); !errors.Is(err, ErrInvalid) {
				t.Fatalf("unavailable root observation error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestReadLifecycleStateRechecksRootIdentityBeforeOpeningCheckpoint(t *testing.T) {
	root := privateTempDir(t)
	info, err := validateLifecycleRootPath(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	other := privateTempDir(t)
	if err := os.WriteFile(filepath.Join(other, "lifecycle.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := readLifecycleState(other, info); !errors.Is(err, ErrConflict) {
		t.Fatalf("state read with replaced root = %v, want ErrConflict", err)
	}
}

func TestDurableCommitRejectsReplacedLifecycleLockBeforeInstall(t *testing.T) {
	store, _ := newTestStore(t)
	lockPath := filepath.Join(store.root, ".lifecycle.lock")
	replacedPath := lockPath + ".replaced"
	store.beforeAtomicWrite = func() error {
		if err := os.Rename(lockPath, replacedPath); err != nil {
			return err
		}
		return os.WriteFile(lockPath, nil, 0600)
	}

	if _, err := store.CreateProject("project", "name"); !errors.Is(err, ErrConflict) {
		t.Fatalf("commit after lock replacement = %v, want ErrConflict", err)
	}
	if _, err := os.Stat(filepath.Join(store.root, "lifecycle.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock replacement created a checkpoint: stat error = %v", err)
	}
	if _, ok := store.state.Projects["project"]; ok {
		t.Fatal("failed commit changed in-memory state")
	}
}

func TestOpenRejectsAmbiguousOrUnknownPersistedJSON(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "duplicate top-level field",
			data: `{"version":1,"version":1,"projects":{},"tasks":{},"idempotency":{},"next_sequence":0}`,
		},
		{
			name: "unknown top-level field",
			data: `{"version":1,"projects":{},"tasks":{},"idempotency":{},"next_sequence":0,"unexpected":true}`,
		},
		{
			name: "trailing value",
			data: `{"version":1,"projects":{},"tasks":{},"idempotency":{},"next_sequence":0} null`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := privateTempDir(t)
			if err := os.WriteFile(filepath.Join(root, "lifecycle.json"), []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(root); err == nil || !strings.Contains(err.Error(), "decode lifecycle state") {
				t.Fatalf("Open error = %v, want strict decode failure", err)
			}
		})
	}
}

func TestOpenRejectsExcessivePersistedJSONNesting(t *testing.T) {
	root := privateTempDir(t)
	nested := strings.Repeat("[", maxMCPJSONDepth+1) + "0" + strings.Repeat("]", maxMCPJSONDepth+1)
	data := `{"version":1,"projects":{},"tasks":{},"idempotency":{},"next_sequence":0,"unexpected":` + nested + `}`
	if err := os.WriteFile(filepath.Join(root, "lifecycle.json"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil || !strings.Contains(err.Error(), "JSON nesting exceeds limit") {
		t.Fatalf("Open error = %v, want nesting-bound failure", err)
	}
}

func TestOpenRejectsInsecureUnixStateRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs are verified by the native supervisor")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); !errors.Is(err, ErrInvalid) {
		t.Fatalf("insecure state root error = %v, want ErrInvalid", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".lifecycle.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("insecure root created lock = %v", err)
	}
}

func TestOpenRejectsNonCanonicalPersistedState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*durableState)
	}{
		{
			name: "idempotency mapping",
			mutate: func(state *durableState) {
				state.Idempotency["wrong-project\x00same"] = state.Idempotency["p\x00same"]
				delete(state.Idempotency, "p\x00same")
			},
		},
		{
			name: "dependency order",
			mutate: func(state *durableState) {
				task := state.Tasks["two"]
				task.Dependencies = []string{"zero", "one"}
				state.Tasks["two"] = task
			},
		},
		{
			name: "missing idempotency reverse index",
			mutate: func(state *durableState) {
				delete(state.Idempotency, "p\x00same")
			},
		},
		{
			name: "malformed checkpoint metadata",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.State = TaskCompleted
				task.LeaseVersion = 1
				task.Checkpoint = &Checkpoint{TaskID: "one", Owner: "agent\x00spoof", LeaseVersion: 1, Sequence: 1, State: TaskPending}
				state.NextSequence = 1
				state.Tasks["one"] = task
			},
		},
		{
			name: "checkpoint state mismatch",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.Checkpoint = &Checkpoint{
					TaskID: "one", Owner: "agent", LeaseVersion: 1, Sequence: 1,
					State: TaskCompleted, CreatedAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC),
				}
				state.NextSequence = 1
				state.Tasks["one"] = task
			},
		},
		{
			name: "terminal task without checkpoint",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.State = TaskCompleted
				task.LeaseVersion = 1
				state.Tasks["one"] = task
			},
		},
		{
			name: "running checkpoint owner mismatch",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.State = TaskRunning
				task.LeaseOwner = "agent"
				task.LeaseVersion = 1
				task.LeaseUntil = time.Date(2026, 10, 17, 12, 10, 0, 0, time.UTC)
				task.Checkpoint = &Checkpoint{
					TaskID: "one", Owner: "other-agent", LeaseVersion: 1, Sequence: 1,
					State: TaskRunning, CreatedAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC),
				}
				state.NextSequence = 1
				state.Tasks["one"] = task
			},
		},
		{
			name: "running checkpoint version mismatch",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.State = TaskRunning
				task.LeaseOwner = "agent"
				task.LeaseVersion = 1
				task.LeaseUntil = time.Date(2026, 10, 17, 12, 10, 0, 0, time.UTC)
				task.Checkpoint = &Checkpoint{
					TaskID: "one", Owner: "other-agent", LeaseVersion: 1, Sequence: 1,
					State: TaskRunning, CreatedAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC),
				}
				state.NextSequence = 1
				state.Tasks["one"] = task
			},
		},
		{
			name: "request hash mismatch",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.RequestHash = "tampered"
				state.Tasks["one"] = task
			},
		},
		{
			name: "project timestamp order",
			mutate: func(state *durableState) {
				project := state.Projects["p"]
				project.UpdatedAt = project.CreatedAt.Add(-time.Second)
				state.Projects["p"] = project
			},
		},
		{
			name: "task timestamp order",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.UpdatedAt = task.CreatedAt.Add(-time.Second)
				state.Tasks["one"] = task
			},
		},
		{
			name: "task predates project",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.CreatedAt = state.Projects["p"].CreatedAt.Add(-time.Second)
				state.Tasks["one"] = task
			},
		},
		{
			name: "checkpoint outside task lifetime",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.State = TaskCompleted
				task.LeaseVersion = 1
				task.Checkpoint = &Checkpoint{
					TaskID: "one", Owner: "agent", LeaseVersion: 1, Sequence: 1,
					State: TaskCompleted, CreatedAt: task.CreatedAt.Add(-time.Second),
				}
				state.NextSequence = 1
				state.Tasks["one"] = task
			},
		},
		{
			name: "attempt and lease version mismatch",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.Attempt = 1
				state.Tasks["one"] = task
			},
		},
		{
			name: "running lease does not outlive update",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.State = TaskRunning
				task.Attempt = 1
				task.LeaseOwner = "agent"
				task.LeaseVersion = 1
				task.LeaseUntil = task.UpdatedAt
				state.Tasks["one"] = task
			},
		},
		{
			name: "running lease exceeds maximum duration",
			mutate: func(state *durableState) {
				task := state.Tasks["one"]
				task.State = TaskRunning
				task.Attempt = 1
				task.LeaseOwner = "agent"
				task.LeaseVersion = 1
				task.LeaseUntil = task.UpdatedAt.Add(maxLease + time.Nanosecond)
				state.Tasks["one"] = task
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := privateTempDir(t)
			s, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.CreateProject("p", "P"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.CreateTask(TaskSpec{ID: "one", ProjectID: "p", IdempotencyKey: "same"}); err != nil {
				t.Fatal(err)
			}
			if tc.name == "dependency order" {
				if _, err := s.CreateTask(TaskSpec{ID: "zero", ProjectID: "p"}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.CreateTask(TaskSpec{ID: "two", ProjectID: "p", Dependencies: []string{"one", "zero"}}); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(root, "lifecycle.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var state durableState
			if err := json.Unmarshal(data, &state); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&state)
			data, err = json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(root); !errors.Is(err, ErrInvalid) {
				t.Fatalf("reopen error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestOpenRejectsInvalidUTF8PersistedJSON(t *testing.T) {
	root := privateTempDir(t)
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTask(TaskSpec{ID: "one", ProjectID: "p", IdempotencyKey: "same"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "lifecycle.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	invalid := bytes.Replace(data, []byte(`"same"`), []byte{'"', 's', 'a', 0xff, 'e', '"'}, 1)
	if bytes.Equal(data, invalid) {
		t.Fatal("test fixture did not inject invalid UTF-8")
	}
	if err := os.WriteFile(path, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil || !strings.Contains(err.Error(), "JSON is not valid UTF-8") {
		t.Fatalf("reopen error = %v, want invalid UTF-8 rejection", err)
	}
}

func TestOpenRejectsDuplicateCheckpointSequence(t *testing.T) {
	root := privateTempDir(t)
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"one", "two"} {
		if _, err := s.CreateTask(TaskSpec{ID: id, ProjectID: "p"}); err != nil {
			t.Fatal(err)
		}
		lease, err := s.Acquire(id, "agent", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Checkpoint(id, "agent", lease.Version, TaskRunning, []byte(id)); err != nil {
			t.Fatal(err)
		}
	}

	path := filepath.Join(root, "lifecycle.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state durableState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	second := state.Tasks["two"]
	second.Checkpoint.Sequence = state.Tasks["one"].Checkpoint.Sequence
	state.Tasks["two"] = second
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reopen error = %v, want ErrInvalid for duplicate checkpoint sequence", err)
	}
}

func TestOpenRejectsPersistedDependencyCycle(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.CreateProject("p", "P"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"one", "two"} {
		if _, err := s.CreateTask(TaskSpec{ID: id, ProjectID: "p"}); err != nil {
			t.Fatal(err)
		}
	}

	path := filepath.Join(s.root, "lifecycle.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state durableState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	one := state.Tasks["one"]
	one.Dependencies = []string{"two"}
	one.RequestHash = taskHash(one.ProjectID, one.Dependencies)
	state.Tasks["one"] = one
	two := state.Tasks["two"]
	two.Dependencies = []string{"one"}
	two.RequestHash = taskHash(two.ProjectID, two.Dependencies)
	state.Tasks["two"] = two
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Dir(path)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "dependency cycle") {
		t.Fatalf("reopen error = %v, want deterministic dependency-cycle rejection", err)
	}
}

func TestValidateTaskDAGBoundsTraversalStackForDeepPersistedGraph(t *testing.T) {
	state := &durableState{Tasks: make(map[string]Task, maxTasks)}
	for index := 0; index < maxTasks; index++ {
		id := fmt.Sprintf("task-%05d", index)
		dependencies := []string(nil)
		if index > 0 {
			dependencies = []string{fmt.Sprintf("task-%05d", index-1)}
		}
		state.Tasks[id] = Task{ID: id, Dependencies: dependencies}
	}
	first := state.Tasks["task-00000"]
	first.Dependencies = []string{"task-09999"}
	state.Tasks[first.ID] = first

	err := validateTaskDAG(state)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `dependency cycle includes task "task-00000"`) {
		t.Fatalf("deep dependency graph error = %v, want bounded deterministic cycle rejection", err)
	}
}

func TestValidateTaskDAGRejectsUnavailableOrIncompleteGraph(t *testing.T) {
	tests := []struct {
		name  string
		state *durableState
		want  string
	}{
		{name: "nil state", state: nil, want: "task graph is unavailable"},
		{name: "nil task map", state: &durableState{}, want: "task graph is unavailable"},
		{
			name: "missing dependency",
			state: &durableState{Tasks: map[string]Task{
				"task": {ID: "task", Dependencies: []string{"missing"}},
			}},
			want: `dependency task "missing" is missing`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateTaskDAG(test.state); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateTaskDAG() = %v, want ErrInvalid containing %q", err, test.want)
			}
		})
	}
}

func TestDependenciesCompleteRejectsOversizedDirectInput(t *testing.T) {
	completed := Task{ID: "done", ProjectID: "project", State: TaskCompleted}
	state := &durableState{Tasks: map[string]Task{"done": completed}}

	tooMany := make([]string, maxTaskDependencies+1)
	for index := range tooMany {
		tooMany[index] = "done"
	}
	if (&Store{}).dependenciesCompleteFrom(state, &Task{Dependencies: tooMany}) {
		t.Fatal("dependenciesCompleteFrom() accepted oversized dependency list")
	}

	tooLong := strings.Repeat("d", maxIDLength+1)
	if (&Store{}).dependenciesCompleteFrom(state, &Task{Dependencies: []string{tooLong}}) {
		t.Fatal("dependenciesCompleteFrom() accepted oversized dependency identifier")
	}
}

func TestDependenciesCompleteRejectsOversizedStateMaps(t *testing.T) {
	tasks := make(map[string]Task, maxTasks+1)
	for index := 0; index < maxTasks; index++ {
		id := fmt.Sprintf("completed-%05d", index)
		tasks[id] = Task{ID: id, ProjectID: "project", State: TaskCompleted}
	}
	candidate := Task{ID: "candidate", ProjectID: "project", State: TaskPending}
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	tasks[candidate.ID] = candidate

	state := &durableState{Tasks: tasks}
	if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() accepted an otherwise-ready task from an oversized task map")
	}

	state = &durableState{
		Tasks:       map[string]Task{candidate.ID: candidate},
		Idempotency: make(map[string]string, maxTasks+1),
	}
	for index := 0; index <= maxTasks; index++ {
		state.Idempotency[fmt.Sprintf("project\x00key-%05d", index)] = candidate.ID
	}
	if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() accepted an otherwise-ready task from an oversized idempotency map")
	}
}

func TestDependenciesCompleteRejectsUnsupportedReadinessStateVersion(t *testing.T) {
	candidate := Task{ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}}
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state := &durableState{
		Projects: map[string]Project{"project": {ID: "project"}},
		Tasks: map[string]Task{
			"done":       candidateDependency("done", "project"),
			candidate.ID: candidate,
		},
		Idempotency: map[string]string{},
	}

	for _, version := range []int{0, stateVersion, stateVersion + 1, -1} {
		t.Run(fmt.Sprintf("version-%d", version), func(t *testing.T) {
			state.Version = version
			ready := (&Store{}).dependenciesCompleteFrom(state, &candidate)
			if want := version == 0 || version == stateVersion; ready != want {
				t.Fatalf("dependenciesCompleteFrom() with version %d = %v, want %v", version, ready, want)
			}
		})
	}
}

func TestValidReadinessStateMapShapeEnforcesDirectMapBounds(t *testing.T) {
	projectOverflow := make(map[string]Project, maxProjects+1)
	for index := 0; index <= maxProjects; index++ {
		id := fmt.Sprintf("project-%04d", index)
		projectOverflow[id] = Project{ID: id}
	}
	if validReadinessStateMapShape(&durableState{
		Projects:    projectOverflow,
		Tasks:       map[string]Task{},
		Idempotency: map[string]string{},
	}) {
		t.Fatal("validReadinessStateMapShape() accepted an oversized project map")
	}

	idempotencyOverflow := make(map[string]string, maxTasks+1)
	for index := 0; index <= maxTasks; index++ {
		idempotencyOverflow[fmt.Sprintf("project\x00key-%05d", index)] = "task"
	}
	if validReadinessStateMapShape(&durableState{
		Projects:    map[string]Project{},
		Tasks:       map[string]Task{},
		Idempotency: idempotencyOverflow,
	}) {
		t.Fatal("validReadinessStateMapShape() accepted an oversized idempotency map")
	}

	if validReadinessStateMapShape(&durableState{
		Tasks:       map[string]Task{},
		Idempotency: map[string]string{},
	}) {
		t.Fatal("validReadinessStateMapShape() accepted a missing project map")
	}
}

func TestDependenciesCompleteRejectsMalformedUnrelatedStateMapEntries(t *testing.T) {
	base := func() *durableState {
		candidate := Task{ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}}
		candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
		return &durableState{
			Projects: map[string]Project{"project": {ID: "project"}},
			Tasks: map[string]Task{
				"done":       candidateDependency("done", "project"),
				candidate.ID: candidate,
			},
			Idempotency: map[string]string{},
		}
	}

	tests := []struct {
		name   string
		mutate func(*durableState)
	}{
		{name: "malformed unrelated project name", mutate: func(state *durableState) {
			state.Projects["other"] = Project{ID: "other", Name: "bad\nname"}
		}},
		{name: "project identity", mutate: func(state *durableState) {
			state.Projects["other"] = Project{ID: "replaced"}
		}},
		{name: "task identity", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "replaced", ProjectID: "project", State: TaskCompleted}
		}},
		{name: "task state", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskState("corrupt")}
		}},
		{name: "orphan task project", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "missing", State: TaskCompleted}
		}},
		{name: "non-canonical dependencies", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Dependencies: []string{"z", "a"}}
		}},
		{name: "mismatched unrelated request fingerprint", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, RequestHash: "tampered"}
		}},
		{name: "oversized unrelated dependency before request fingerprint", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{
				ID: "other", ProjectID: "project", State: TaskCompleted,
				Dependencies: []string{strings.Repeat("d", maxIDLength+1)}, RequestHash: "tampered",
			}
		}},
		{name: "unrepresentable unrelated project timestamp", mutate: func(state *durableState) {
			project := state.Projects["project"]
			project.UpdatedAt = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
			state.Projects["project"] = project
		}},
		{name: "unrelated project missing paired lifetime timestamp", mutate: func(state *durableState) {
			state.Projects["other"] = Project{ID: "other", CreatedAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
		}},
		{name: "unrepresentable unrelated task timestamp", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, CreatedAt: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)}
		}},
		{name: "unrelated task missing paired lifetime timestamp", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskPending, UpdatedAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
		}},
		{name: "durable unrelated task missing request fingerprint", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskPending, CreatedAt: now, UpdatedAt: now}
		}},
		{name: "durable unrelated terminal task missing request fingerprint", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.NextSequence = 1
			state.Tasks["other"] = Task{
				ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1,
				CreatedAt: now, UpdatedAt: now,
				Checkpoint: &Checkpoint{TaskID: "other", Owner: "agent", LeaseVersion: 1, Sequence: 1, State: TaskCompleted, CreatedAt: now},
			}
		}},
		{name: "unrepresentable unrelated lease timestamp", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskRunning, Attempt: 1, LeaseVersion: 1, LeaseOwner: "agent", LeaseUntil: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)}
		}},
		{name: "unrepresentable unrelated checkpoint timestamp", mutate: func(state *durableState) {
			state.NextSequence = 1
			state.Tasks["other"] = Task{
				ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1,
				Checkpoint: &Checkpoint{TaskID: "other", Owner: "agent", LeaseVersion: 1, Sequence: 1, State: TaskCompleted, CreatedAt: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
			}
		}},
		{name: "task predates unrelated project", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.Projects["project"] = Project{ID: "project", CreatedAt: now, UpdatedAt: now}
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, CreatedAt: now.Add(-time.Minute), UpdatedAt: now}
		}},
		{name: "running lease does not outlive update", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskRunning, Attempt: 1, LeaseVersion: 1, LeaseOwner: "agent", CreatedAt: now, UpdatedAt: now, LeaseUntil: now}
		}},
		{name: "running lease missing task timestamps", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskRunning, Attempt: 1, LeaseVersion: 1, LeaseOwner: "agent", LeaseUntil: time.Date(2026, 10, 17, 12, 1, 0, 0, time.UTC)}
		}},
		{name: "running lease exceeds horizon", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskRunning, Attempt: 1, LeaseVersion: 1, LeaseOwner: "agent", CreatedAt: now, UpdatedAt: now, LeaseUntil: now.Add(maxLease + time.Nanosecond)}
		}},
		{name: "checkpoint version exceeds unrelated task", mutate: func(state *durableState) {
			state.NextSequence = 1
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1, Checkpoint: &Checkpoint{TaskID: "other", Owner: "agent", LeaseVersion: 2, Sequence: 1, State: TaskCompleted}}
		}},
		{name: "checkpoint state mismatches unrelated task", mutate: func(state *durableState) {
			state.NextSequence = 1
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1, Checkpoint: &Checkpoint{TaskID: "other", Owner: "agent", LeaseVersion: 1, Sequence: 1, State: TaskRunning}}
		}},
		{name: "checkpoint falls outside unrelated task lifetime", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.NextSequence = 1
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1, CreatedAt: now, UpdatedAt: now.Add(time.Minute), Checkpoint: &Checkpoint{TaskID: "other", Owner: "agent", LeaseVersion: 1, Sequence: 1, State: TaskCompleted, CreatedAt: now.Add(2 * time.Minute)}}
		}},
		{name: "checkpoint predates supplied task creation", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.NextSequence = 1
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1, CreatedAt: now, Checkpoint: &Checkpoint{TaskID: "other", Owner: "agent", LeaseVersion: 1, Sequence: 1, State: TaskCompleted, CreatedAt: now.Add(-time.Second)}}
		}},
		{name: "checkpoint follows supplied task update", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.NextSequence = 1
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1, UpdatedAt: now, Checkpoint: &Checkpoint{TaskID: "other", Owner: "agent", LeaseVersion: 1, Sequence: 1, State: TaskCompleted, CreatedAt: now.Add(time.Second)}}
		}},
		{name: "missing unrelated dependency", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Dependencies: []string{"missing"}}
		}},
		{name: "cross-project unrelated dependency", mutate: func(state *durableState) {
			state.Projects["other-project"] = Project{ID: "other-project"}
			state.Tasks["other-dependency"] = Task{ID: "other-dependency", ProjectID: "other-project", State: TaskCompleted}
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Dependencies: []string{"other-dependency"}}
		}},
		{name: "unrelated dependency cycle", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Dependencies: []string{"other-two"}}
			state.Tasks["other-two"] = Task{ID: "other-two", ProjectID: "project", State: TaskCompleted, Dependencies: []string{"other"}}
		}},
		{name: "inconsistent unrelated retry counters", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1}
		}},
		{name: "exhausted unrelated pending retry counters", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskPending, Attempt: ^uint64(0), LeaseVersion: ^uint64(0)}
		}},
		{name: "non-running unrelated lease", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, LeaseOwner: "agent", LeaseUntil: time.Unix(1, 0).UTC()}
		}},
		{name: "malformed running unrelated lease", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskRunning, Attempt: 1, LeaseVersion: 1}
		}},
		{name: "terminal task missing checkpoint", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1, CreatedAt: now, UpdatedAt: now}
		}},
		{name: "checkpoint missing creation timestamp", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.NextSequence = 1
			state.Tasks["other"] = Task{
				ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1,
				CreatedAt: now, UpdatedAt: now,
				Checkpoint: &Checkpoint{TaskID: "other", Owner: "agent", LeaseVersion: 1, Sequence: 1, State: TaskCompleted},
			}
		}},
		{name: "checkpoint missing task lifetime timestamps", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.NextSequence = 1
			state.Tasks["other"] = Task{
				ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1,
				Checkpoint: &Checkpoint{TaskID: "other", Owner: "agent", LeaseVersion: 1, Sequence: 1, State: TaskCompleted, CreatedAt: now},
			}
		}},
		{name: "impossible checkpoint shell", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Checkpoint: &Checkpoint{TaskID: "other", State: TaskPending}}
		}},
		{name: "checkpoint sequence beyond state", mutate: func(state *durableState) {
			state.NextSequence = 1
			state.Tasks["other"] = Task{
				ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1,
				Checkpoint: &Checkpoint{TaskID: "other", Owner: "agent", LeaseVersion: 1, Sequence: 2, State: TaskCompleted},
			}
		}},
		{name: "duplicate checkpoint sequence in unrelated tasks", mutate: func(state *durableState) {
			state.NextSequence = 1
			checkpoint := func(id string) *Checkpoint {
				return &Checkpoint{TaskID: id, Owner: "agent", LeaseVersion: 1, Sequence: 1, State: TaskCompleted}
			}
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1, Checkpoint: checkpoint("other")}
			state.Tasks["other-two"] = Task{ID: "other-two", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1, Checkpoint: checkpoint("other-two")}
		}},
		{name: "oversized checkpoint payload", mutate: func(state *durableState) {
			state.NextSequence = 1
			state.Tasks["other"] = Task{
				ID: "other", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1,
				Checkpoint: &Checkpoint{
					TaskID: "other", Owner: "agent", LeaseVersion: 1, Sequence: 1,
					State: TaskCompleted, Payload: make([]byte, maxPayloadBytes+1),
				},
			}
		}},
		{name: "aggregate checkpoint payload exceeds state budget", mutate: func(state *durableState) {
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			const historyTasks = 9
			state.NextSequence = historyTasks
			for index := 0; index < historyTasks; index++ {
				id := fmt.Sprintf("history-%d", index)
				state.Tasks[id] = Task{
					ID: id, ProjectID: "project", RequestHash: taskHash("project", nil),
					State: TaskCompleted, Attempt: 1, LeaseVersion: 1,
					CreatedAt: now, UpdatedAt: now,
					Checkpoint: &Checkpoint{
						TaskID: id, Owner: "agent", LeaseVersion: 1,
						Sequence: uint64(index + 1), State: TaskCompleted,
						Payload: make([]byte, maxPayloadBytes), CreatedAt: now,
					},
				}
			}
		}},
		{name: "aggregate dependency text exceeds state budget", mutate: func(state *durableState) {
			const dependencyTasks = 2049
			dependencies := make([]string, maxTaskDependencies)
			for index := range dependencies {
				dependencies[index] = strings.Repeat("d", maxIDLength)
			}
			for index := 0; index < dependencyTasks; index++ {
				id := fmt.Sprintf("dependency-history-%d", index)
				state.Tasks[id] = Task{ID: id, ProjectID: "project", State: TaskCompleted, Dependencies: dependencies}
			}
		}},
		{name: "combined readiness variable bytes exceed state budget", mutate: func(state *durableState) {
			// Keep dependency text and checkpoint payloads individually below the
			// durable ceiling while exceeding it in combination. This models a
			// direct in-process snapshot that cannot be serialized as an 8 MiB
			// lifecycle checkpoint, even though each variable field family is
			// independently bounded.
			const dependencyTasks = 1793
			dependencies := make([]string, maxTaskDependencies)
			for index := range dependencies {
				prefix := fmt.Sprintf("base-%02d-", index)
				id := prefix + strings.Repeat("b", maxIDLength-len(prefix))
				dependencies[index] = id
				state.Tasks[id] = Task{ID: id, ProjectID: "project", State: TaskCompleted}
			}
			for index := 0; index < dependencyTasks; index++ {
				id := fmt.Sprintf("dependency-pending-%04d", index)
				state.Tasks[id] = Task{
					ID: id, ProjectID: "project", RequestHash: taskHash("project", dependencies),
					State: TaskPending, Dependencies: append([]string(nil), dependencies...),
				}
			}
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.NextSequence = 1
			state.Tasks["payload-pending"] = Task{
				ID: "payload-pending", ProjectID: "project", RequestHash: taskHash("project", nil),
				State: TaskPending, Attempt: 1, LeaseVersion: 1,
				CreatedAt: now, UpdatedAt: now,
				Checkpoint: &Checkpoint{
					TaskID: "payload-pending", Owner: "agent", LeaseVersion: 1,
					Sequence: 1, State: TaskRunning, Payload: make([]byte, maxPayloadBytes), CreatedAt: now,
				},
			}
		}},
		{name: "serialized readiness state exceeds state budget", mutate: func(state *durableState) {
			// Raw payload bytes remain below the shared variable budget, but JSON
			// encodes checkpoint payloads as base64 and adds map/field overhead.
			// The direct readiness snapshot must still fit the persisted ceiling.
			const historyTasks = 7
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
			state.NextSequence = historyTasks
			for index := 0; index < historyTasks; index++ {
				id := fmt.Sprintf("encoded-history-%d", index)
				state.Tasks[id] = Task{
					ID: id, ProjectID: "project", RequestHash: taskHash("project", nil),
					State: TaskCompleted, Attempt: 1, LeaseVersion: 1,
					CreatedAt: now, UpdatedAt: now,
					Checkpoint: &Checkpoint{
						TaskID: id, Owner: "agent", LeaseVersion: 1,
						Sequence: uint64(index + 1), State: TaskCompleted,
						Payload: make([]byte, maxPayloadBytes), CreatedAt: now,
					},
				}
			}
		}},
		{name: "idempotency reverse index", mutate: func(state *durableState) {
			state.Idempotency[idempotencyKey("project", "orphan")] = "missing"
		}},
		{name: "keyed task missing reverse index", mutate: func(state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", IdempotencyKey: "orphan", State: TaskCompleted}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := base()
			candidate := state.Tasks["task"]
			test.mutate(state)
			if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
				t.Fatal("dependenciesCompleteFrom() accepted malformed unrelated state map entry")
			}
		})
	}
}

func TestCheckpointPayloadReturnsIndependentCopy(t *testing.T) {
	task := Task{Checkpoint: &Checkpoint{Payload: []byte("checkpoint")}}

	payload := task.CheckpointPayload()
	if string(payload) != "checkpoint" {
		t.Fatalf("CheckpointPayload() = %q, want checkpoint", payload)
	}
	payload[0] = 'X'
	if got := string(task.Checkpoint.Payload); got != "checkpoint" {
		t.Fatalf("CheckpointPayload() mutation changed task payload to %q", got)
	}

	if got := (Task{}).CheckpointPayload(); got != nil {
		t.Fatalf("CheckpointPayload() without checkpoint = %#v, want nil", got)
	}
}

func TestCheckpointPayloadRejectsOversizedInProcessPayload(t *testing.T) {
	task := Task{Checkpoint: &Checkpoint{Payload: make([]byte, maxPayloadBytes+1)}}
	if got := task.CheckpointPayload(); got != nil {
		t.Fatalf("CheckpointPayload() oversized payload = %d bytes, want nil", len(got))
	}
}

func candidateDependency(id, projectID string) Task {
	return Task{ID: id, ProjectID: projectID, State: TaskCompleted}
}

func TestDependenciesCompleteRejectsMissingOrMismatchedProject(t *testing.T) {
	completed := Task{ID: "done", ProjectID: "project", State: TaskCompleted}
	candidate := Task{ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}}
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state := &durableState{
		Projects: map[string]Project{"project": {ID: "project"}},
		Tasks:    map[string]Task{"done": completed, "task": candidate},
	}

	delete(state.Projects, "project")
	if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() accepted a task without a canonical project")
	}

	state.Projects["project"] = Project{ID: "replaced"}
	if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() accepted a project with mismatched embedded identity")
	}

	state.Projects["project"] = Project{ID: "project"}
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected a task with a canonical project")
	}
}

func TestDependenciesCompleteRejectsOversizedBoundCandidate(t *testing.T) {
	dependencies := make([]string, maxTaskDependencies+1)
	tasks := make(map[string]Task, len(dependencies)+1)
	for index := range dependencies {
		dependency := fmt.Sprintf("dependency-%02d", index)
		dependencies[index] = dependency
		tasks[dependency] = Task{ID: dependency, ProjectID: "project", State: TaskCompleted}
	}
	candidate := Task{
		ID:           "task",
		ProjectID:    "project",
		Dependencies: dependencies,
		State:        TaskPending,
	}
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	tasks[candidate.ID] = candidate
	state := &durableState{Tasks: tasks}

	if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() accepted an oversized bound candidate")
	}
}

func TestDependenciesCompleteRejectsMalformedDirectIdentifier(t *testing.T) {
	completed := Task{ID: "", ProjectID: "project", State: TaskCompleted}
	state := &durableState{Tasks: map[string]Task{"": completed}}

	if (&Store{}).dependenciesCompleteFrom(state, &Task{Dependencies: []string{""}}) {
		t.Fatal("dependenciesCompleteFrom() accepted an empty dependency identifier")
	}

	control := "done\x00"
	state.Tasks[control] = Task{ID: control, ProjectID: "project", State: TaskCompleted}
	if (&Store{}).dependenciesCompleteFrom(state, &Task{Dependencies: []string{control}}) {
		t.Fatal("dependenciesCompleteFrom() accepted a control-character dependency identifier")
	}

	state = &durableState{Tasks: map[string]Task{
		"done": {ID: "replaced", ProjectID: "project", State: TaskCompleted},
	}}
	if (&Store{}).dependenciesCompleteFrom(state, &Task{Dependencies: []string{"done"}}) {
		t.Fatal("dependenciesCompleteFrom() accepted a completed task whose map key and embedded ID differ")
	}
}

func TestDependenciesCompleteRejectsUnboundOrCrossProjectTask(t *testing.T) {
	state := &durableState{Tasks: map[string]Task{
		"done":  {ID: "done", ProjectID: "project-a", State: TaskCompleted},
		"task":  {ID: "task", ProjectID: "project-a", State: TaskPending},
		"other": {ID: "other", ProjectID: "project-b", State: TaskCompleted},
	}}

	tests := []struct {
		name string
		task *Task
	}{
		{name: "unbound task", task: &Task{ID: "missing", ProjectID: "project-a", Dependencies: []string{"done"}}},
		{name: "project mismatch", task: &Task{ID: "task", ProjectID: "project-b", Dependencies: []string{"done"}}},
		{name: "cross-project dependency", task: &Task{ID: "task", ProjectID: "project-a", Dependencies: []string{"other"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if (&Store{}).dependenciesCompleteFrom(state, test.task) {
				t.Fatal("dependenciesCompleteFrom() accepted an unbound or cross-project task")
			}
		})
	}
}

func TestDependenciesCompleteRejectsMalformedCompletedDependency(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	for _, mutate := range []struct {
		name  string
		apply func(*Task)
	}{
		{name: "stale owner", apply: func(task *Task) { task.LeaseOwner = "stale-owner" }},
		{name: "stale expiry", apply: func(task *Task) { task.LeaseUntil = time.Date(2026, 10, 17, 12, 1, 0, 0, time.UTC) }},
		{name: "running checkpoint", apply: func(task *Task) {
			task.Checkpoint = &Checkpoint{TaskID: "done", Owner: "agent", LeaseVersion: 1, Sequence: 1, State: TaskRunning}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			malformed := state.Tasks["done"]
			mutate.apply(&malformed)
			state.Tasks["done"] = malformed
			if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
				t.Fatal("dependenciesCompleteFrom() accepted malformed completed dependency")
			}
			state.Tasks["done"] = Task{ID: "done", ProjectID: "project", State: TaskCompleted}
		})
	}

	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected a well-shaped completed dependency")
	}
}

func TestDependenciesCompleteRejectsMalformedCompletedDependencyCheckpoint(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	checkpoint := &Checkpoint{
		TaskID: "done", Owner: "agent", LeaseVersion: 1, Sequence: 1,
		State: TaskCompleted, Payload: []byte("result"), CreatedAt: now.Add(30 * time.Second),
	}
	state := &durableState{
		Projects:     map[string]Project{"project": {ID: "project", CreatedAt: now, UpdatedAt: now.Add(2 * time.Minute)}},
		NextSequence: 1,
		Tasks: map[string]Task{
			"done": {ID: "done", ProjectID: "project", RequestHash: taskHash("project", nil), State: TaskCompleted, Attempt: 1, LeaseVersion: 1, CreatedAt: now, UpdatedAt: now.Add(time.Minute), Checkpoint: checkpoint},
			"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
		},
	}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected a valid completed dependency checkpoint")
	}

	for _, mutate := range []struct {
		name  string
		apply func(*Task, *durableState)
	}{
		{name: "zero timestamp", apply: func(task *Task, _ *durableState) { task.Checkpoint.CreatedAt = time.Time{} }},
		{name: "outside task lifetime", apply: func(task *Task, _ *durableState) { task.Checkpoint.CreatedAt = now.Add(2 * time.Minute) }},
		{name: "duplicate sequence", apply: func(task *Task, state *durableState) {
			state.Tasks["other"] = Task{ID: "other", ProjectID: "project", Checkpoint: &Checkpoint{Sequence: task.Checkpoint.Sequence}}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			malformed := state.Tasks["done"]
			malformed.Checkpoint = &Checkpoint{
				TaskID: checkpoint.TaskID, Owner: checkpoint.Owner, LeaseVersion: checkpoint.LeaseVersion,
				Sequence: checkpoint.Sequence, State: checkpoint.State, Payload: append([]byte(nil), checkpoint.Payload...), CreatedAt: checkpoint.CreatedAt,
			}
			mutate.apply(&malformed, state)
			state.Tasks["done"] = malformed
			if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
				t.Fatal("dependenciesCompleteFrom() accepted malformed completed dependency checkpoint")
			}
			delete(state.Tasks, "other")
			state.Tasks["done"] = Task{ID: "done", ProjectID: "project", State: TaskCompleted, Attempt: 1, LeaseVersion: 1, CreatedAt: now, UpdatedAt: now.Add(time.Minute), Checkpoint: checkpoint}
		})
	}
}

func TestDependenciesCompleteRejectsUnboundDependencyDefinitions(t *testing.T) {
	state := &durableState{Tasks: map[string]Task{
		"done":  {ID: "done", ProjectID: "project", State: TaskCompleted},
		"other": {ID: "other", ProjectID: "project", State: TaskCompleted},
		"task":  {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}}

	tests := []struct {
		name         string
		dependencies []string
	}{
		{name: "omitted dependency", dependencies: nil},
		{name: "substituted dependency", dependencies: []string{"other"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := state.Tasks["task"]
			candidate.Dependencies = test.dependencies
			if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
				t.Fatal("dependenciesCompleteFrom() accepted a caller-supplied dependency definition")
			}
		})
	}
}

func TestDependenciesCompleteRejectsNonCanonicalDependencyDefinitions(t *testing.T) {
	state := &durableState{Tasks: map[string]Task{
		"done":  {ID: "done", ProjectID: "project", State: TaskCompleted},
		"other": {ID: "other", ProjectID: "project", State: TaskCompleted},
		"task":  {ID: "task", ProjectID: "project", State: TaskPending},
	}}
	tests := []struct {
		name         string
		dependencies []string
	}{
		{name: "duplicate dependency", dependencies: []string{"done", "done"}},
		{name: "unsorted dependencies", dependencies: []string{"other", "done"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := state.Tasks["task"]
			candidate.Dependencies = test.dependencies
			state.Tasks["task"] = candidate
			if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
				t.Fatal("dependenciesCompleteFrom() accepted a non-canonical dependency definition")
			}
		})
	}
}

func TestDependenciesCompleteRejectsMismatchedRequestFingerprint(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = "tampered"
	state.Tasks["task"] = candidate
	if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() accepted a mismatched request fingerprint")
	}

	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected the canonical request fingerprint")
	}
}

func TestDependenciesCompleteRejectsCallerRequestFingerprintMismatch(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	caller := candidate
	caller.RequestHash = "tampered"
	if (&Store{}).dependenciesCompleteFrom(state, &caller) {
		t.Fatal("dependenciesCompleteFrom() accepted a caller-supplied request fingerprint")
	}
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected the canonical caller request fingerprint")
	}
}

func TestDependenciesCompleteRejectsCallerIdempotencyKeyMismatch(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", IdempotencyKey: "original", State: TaskPending, Dependencies: []string{"done"}},
	}, Idempotency: map[string]string{idempotencyKey("project", "original"): "task"}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	caller := candidate
	caller.IdempotencyKey = "substituted"
	if (&Store{}).dependenciesCompleteFrom(state, &caller) {
		t.Fatal("dependenciesCompleteFrom() accepted a caller-supplied idempotency key")
	}
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected the canonical idempotency key")
	}
}

func TestDependenciesCompleteRejectsMalformedIdempotencyReverseIndex(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", IdempotencyKey: "original", State: TaskPending, Dependencies: []string{"done"}},
	}, Idempotency: map[string]string{}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	for _, indexedID := range []string{"", "other"} {
		t.Run(fmt.Sprintf("indexed-task-%q", indexedID), func(t *testing.T) {
			state.Idempotency[idempotencyKey("project", "original")] = indexedID
			if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
				t.Fatal("dependenciesCompleteFrom() accepted malformed idempotency reverse index")
			}
			delete(state.Idempotency, idempotencyKey("project", "original"))
		})
	}

	state.Idempotency[idempotencyKey("project", "original")] = candidate.ID
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected a valid idempotency reverse index")
	}
}

func TestDependenciesCompleteRejectsMalformedIdempotencyKey(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	for _, key := range []string{"invalid\x00key", string([]byte{0xff})} {
		key := key
		t.Run(fmt.Sprintf("canonical-%x", []byte(key)), func(t *testing.T) {
			malformed := state.Tasks["task"]
			malformed.IdempotencyKey = key
			state.Tasks["task"] = malformed
			if (&Store{}).dependenciesCompleteFrom(state, &malformed) {
				t.Fatal("dependenciesCompleteFrom() accepted malformed canonical idempotency key")
			}
			state.Tasks["task"] = candidate
		})
	}

	caller := candidate
	caller.IdempotencyKey = "invalid\x00key"
	if (&Store{}).dependenciesCompleteFrom(state, &caller) {
		t.Fatal("dependenciesCompleteFrom() accepted malformed caller idempotency key")
	}
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected the canonical empty idempotency key")
	}
}

func TestDependenciesCompleteRejectsNonPendingTask(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}}
	task := state.Tasks["task"]
	task.RequestHash = taskHash(task.ProjectID, task.Dependencies)
	state.Tasks["task"] = task

	for _, stateValue := range []TaskState{TaskRunning, TaskCompleted, TaskFailed, TaskCancelled} {
		t.Run(string(stateValue), func(t *testing.T) {
			candidate := state.Tasks["task"]
			candidate.State = stateValue
			state.Tasks["task"] = candidate
			if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
				t.Fatalf("dependenciesCompleteFrom() accepted %s task as ready", stateValue)
			}
		})
	}

	candidate := state.Tasks["task"]
	candidate.State = TaskPending
	state.Tasks["task"] = candidate
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected pending task with complete dependencies")
	}
}

func TestDependenciesCompleteRejectsPendingTaskWithActiveLease(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	for _, mutate := range []struct {
		name  string
		apply func(*Task)
	}{
		{name: "canonical owner", apply: func(task *Task) { task.LeaseOwner = "stale-owner" }},
		{name: "canonical expiry", apply: func(task *Task) { task.LeaseUntil = time.Date(2026, 10, 17, 12, 1, 0, 0, time.UTC) }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			malformed := state.Tasks["task"]
			mutate.apply(&malformed)
			state.Tasks["task"] = malformed
			if (&Store{}).dependenciesCompleteFrom(state, &malformed) {
				t.Fatal("dependenciesCompleteFrom() accepted pending task with an active lease")
			}
			state.Tasks["task"] = candidate
		})
	}

	caller := candidate
	caller.LeaseOwner = "stale-owner"
	if (&Store{}).dependenciesCompleteFrom(state, &caller) {
		t.Fatal("dependenciesCompleteFrom() accepted caller candidate with an active lease")
	}
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected canonical pending task without an active lease")
	}
}

func TestDependenciesCompleteRejectsInconsistentAttemptAndLeaseVersion(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	for _, mutate := range []struct {
		name  string
		apply func(*Task)
	}{
		{name: "canonical attempt", apply: func(task *Task) { task.Attempt = 1 }},
		{name: "canonical lease version", apply: func(task *Task) { task.LeaseVersion = 1 }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			malformed := state.Tasks["task"]
			mutate.apply(&malformed)
			state.Tasks["task"] = malformed
			if (&Store{}).dependenciesCompleteFrom(state, &malformed) {
				t.Fatal("dependenciesCompleteFrom() accepted a task with inconsistent retry counters")
			}
			state.Tasks["task"] = candidate
		})
	}

	caller := candidate
	caller.Attempt = 1
	if (&Store{}).dependenciesCompleteFrom(state, &caller) {
		t.Fatal("dependenciesCompleteFrom() accepted a caller candidate with inconsistent retry counters")
	}
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected canonical pending task with consistent retry counters")
	}
}

func TestDependenciesCompleteRejectsCallerCounterMismatch(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	caller := candidate
	caller.Attempt = 1
	caller.LeaseVersion = 1
	if (&Store{}).dependenciesCompleteFrom(state, &caller) {
		t.Fatal("dependenciesCompleteFrom() accepted caller counters that differ from the canonical task")
	}
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected canonical pending task with matching counters")
	}
}

func TestDependenciesCompleteRejectsExhaustedCounters(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	malformed := candidate
	malformed.Attempt = ^uint64(0)
	malformed.LeaseVersion = ^uint64(0)
	state.Tasks["task"] = malformed
	if (&Store{}).dependenciesCompleteFrom(state, &malformed) {
		t.Fatal("dependenciesCompleteFrom() accepted canonical task with exhausted retry counters")
	}

	state.Tasks["task"] = candidate
	caller := candidate
	caller.Attempt = ^uint64(0)
	caller.LeaseVersion = ^uint64(0)
	if (&Store{}).dependenciesCompleteFrom(state, &caller) {
		t.Fatal("dependenciesCompleteFrom() accepted caller task with exhausted retry counters")
	}
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected actionable pending task")
	}
}

func TestDependenciesCompleteRejectsCheckpointSubstitution(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, NextSequence: 1, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {
			ID: "task", ProjectID: "project", State: TaskPending, Attempt: 1,
			LeaseVersion: 1, Dependencies: []string{"done"}, CreatedAt: now,
			UpdatedAt: now.Add(time.Minute), Checkpoint: &Checkpoint{
				TaskID: "task", Owner: "agent", LeaseVersion: 1, Sequence: 1,
				State: TaskRunning, Payload: []byte("resume"), CreatedAt: now.Add(30 * time.Second),
			},
		},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected a valid resumable checkpoint")
	}

	caller := candidate
	caller.Checkpoint = &Checkpoint{
		TaskID: "task", Owner: "agent", LeaseVersion: 1, Sequence: 1,
		State: TaskRunning, Payload: []byte("substituted"), CreatedAt: now.Add(30 * time.Second),
	}
	if (&Store{}).dependenciesCompleteFrom(state, &caller) {
		t.Fatal("dependenciesCompleteFrom() accepted a caller-substituted checkpoint")
	}

	malformed := candidate
	malformed.Checkpoint = &Checkpoint{
		TaskID: "task", Owner: "agent", LeaseVersion: 1, Sequence: 1,
		State: TaskCompleted, Payload: []byte("resume"), CreatedAt: now.Add(30 * time.Second),
	}
	state.Tasks["task"] = malformed
	if (&Store{}).dependenciesCompleteFrom(state, &malformed) {
		t.Fatal("dependenciesCompleteFrom() accepted a non-running pending checkpoint")
	}
}

func TestDependenciesCompleteRejectsCheckpointSequenceOutsideState(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, NextSequence: 0, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {
			ID: "task", ProjectID: "project", State: TaskPending, Attempt: 1,
			LeaseVersion: 1, Dependencies: []string{"done"}, CreatedAt: now,
			UpdatedAt: now.Add(time.Minute), Checkpoint: &Checkpoint{
				TaskID: "task", Owner: "agent", LeaseVersion: 1, Sequence: 1,
				State: TaskRunning, Payload: []byte("resume"), CreatedAt: now.Add(30 * time.Second),
			},
		},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() accepted a checkpoint sequence beyond state.NextSequence")
	}

	state.NextSequence = 1
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected a checkpoint sequence within state.NextSequence")
	}
}

func TestDependenciesCompleteRejectsCheckpointSequenceExhaustion(t *testing.T) {
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, NextSequence: ^uint64(0), Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {ID: "task", ProjectID: "project", State: TaskPending, Dependencies: []string{"done"}},
	}, Idempotency: map[string]string{}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() advertised work after checkpoint sequence exhaustion")
	}
}

func TestDependenciesCompleteRejectsDuplicateCheckpointSequence(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	state := &durableState{Projects: map[string]Project{"project": {ID: "project"}}, NextSequence: 1, Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {
			ID: "task", ProjectID: "project", State: TaskPending, Attempt: 1,
			LeaseVersion: 1, Dependencies: []string{"done"}, CreatedAt: now,
			UpdatedAt: now.Add(time.Minute), Checkpoint: &Checkpoint{
				TaskID: "task", Owner: "agent", LeaseVersion: 1, Sequence: 1,
				State: TaskRunning, Payload: []byte("resume"), CreatedAt: now.Add(30 * time.Second),
			},
		},
		"other": {ID: "other", ProjectID: "project", Checkpoint: &Checkpoint{Sequence: 1}},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	if (&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() accepted a checkpoint sequence shared by another task")
	}

	delete(state.Tasks, "other")
	if !(&Store{}).dependenciesCompleteFrom(state, &candidate) {
		t.Fatal("dependenciesCompleteFrom() rejected a unique checkpoint sequence")
	}
}

func TestDependenciesCompleteRejectsOversizedCheckpointBeforeComparison(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	state := &durableState{Tasks: map[string]Task{
		"done": {ID: "done", ProjectID: "project", State: TaskCompleted},
		"task": {
			ID: "task", ProjectID: "project", State: TaskPending, Attempt: 1,
			LeaseVersion: 1, Dependencies: []string{"done"}, CreatedAt: now,
			UpdatedAt: now.Add(time.Minute), Checkpoint: &Checkpoint{
				TaskID: "task", Owner: "agent", LeaseVersion: 1, Sequence: 1,
				State: TaskRunning, Payload: []byte("resume"), CreatedAt: now.Add(30 * time.Second),
			},
		},
	}}
	candidate := state.Tasks["task"]
	candidate.RequestHash = taskHash(candidate.ProjectID, candidate.Dependencies)
	state.Tasks["task"] = candidate

	caller := candidate
	caller.Checkpoint = &Checkpoint{
		TaskID: "task", Owner: "agent", LeaseVersion: 1, Sequence: 1,
		State: TaskRunning, Payload: make([]byte, maxPayloadBytes+1), CreatedAt: now.Add(30 * time.Second),
	}
	if (&Store{}).dependenciesCompleteFrom(state, &caller) {
		t.Fatal("dependenciesCompleteFrom() accepted an oversized caller checkpoint")
	}
}

func TestValidateTaskDAGRejectsOversizedInputs(t *testing.T) {
	tooManyTasks := &durableState{Tasks: make(map[string]Task, maxTasks+1)}
	for index := 0; index <= maxTasks; index++ {
		id := fmt.Sprintf("task-%05d", index)
		tooManyTasks.Tasks[id] = Task{ID: id}
	}
	tooManyDependencies := &durableState{Tasks: map[string]Task{
		"task": {ID: "task", Dependencies: make([]string, maxTaskDependencies+1)},
	}}
	tooLongTaskID := strings.Repeat("t", maxIDLength+1)
	tooLongTaskIdentifier := &durableState{Tasks: map[string]Task{
		tooLongTaskID: {ID: tooLongTaskID},
	}}
	tooLongDependencyID := strings.Repeat("d", maxIDLength+1)
	tooLongDependencyIdentifier := &durableState{Tasks: map[string]Task{
		"task": {ID: "task", Dependencies: []string{tooLongDependencyID}},
	}}

	tests := []struct {
		name  string
		state *durableState
		want  string
	}{
		{name: "too many tasks", state: tooManyTasks, want: "task graph exceeds"},
		{name: "too many dependencies", state: tooManyDependencies, want: `dependencies for "task" exceed`},
		{name: "oversized task identifier", state: tooLongTaskIdentifier, want: "task graph identifier exceeds"},
		{name: "oversized dependency identifier", state: tooLongDependencyIdentifier, want: "dependency identifier exceeds"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateTaskDAG(test.state); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateTaskDAG() = %v, want ErrInvalid containing %q", err, test.want)
			}
		})
	}
}

func TestValidateTaskDAGRejectsMalformedIdentifiers(t *testing.T) {
	control := "dependency\x00"
	tests := []struct {
		name  string
		state *durableState
		want  string
	}{
		{
			name: "empty task identifier",
			state: &durableState{Tasks: map[string]Task{
				"": {ID: ""},
			}},
			want: "task graph identifier is invalid",
		},
		{
			name: "control character dependency",
			state: &durableState{Tasks: map[string]Task{
				"task": {ID: "task", Dependencies: []string{control}},
			}},
			want: "dependency identifier is invalid",
		},
		{
			name: "task value identity mismatch",
			state: &durableState{Tasks: map[string]Task{
				"task": {ID: "other"},
			}},
			want: "task graph task identity is invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateTaskDAG(test.state); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateTaskDAG() = %v, want ErrInvalid containing %q", err, test.want)
			}
		})
	}
}

func TestDependenciesCompleteFromRejectsUnavailableInputs(t *testing.T) {
	completed := Task{ID: "dependency", State: TaskCompleted}
	tests := []struct {
		name  string
		state *durableState
		task  *Task
	}{
		{name: "nil state", task: &Task{Dependencies: []string{"dependency"}}},
		{name: "nil task map", state: &durableState{}, task: &Task{Dependencies: []string{"dependency"}}},
		{name: "nil task", state: &durableState{Tasks: map[string]Task{"dependency": completed}}},
		{name: "missing dependency", state: &durableState{Tasks: map[string]Task{}}, task: &Task{Dependencies: []string{"dependency"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if ready := (&Store{}).dependenciesCompleteFrom(test.state, test.task); ready {
				t.Fatal("dependenciesCompleteFrom() = true for unavailable input")
			}
		})
	}
}

func TestDependenciesCompleteRejectsUnavailableReceiver(t *testing.T) {
	var store *Store
	if ready := store.dependenciesComplete(&Task{Dependencies: []string{"dependency"}}); ready {
		t.Fatal("dependenciesComplete() = true for nil store")
	}
}
