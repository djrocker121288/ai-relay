// Package lifecycle contains the isolated 2.0 project/task lifecycle core.
// It has no gateway, agent, scheduler, or 1.x dependencies.
package lifecycle

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	stateVersion                 = 1
	maxStateBytes                = 8 << 20
	maxPayloadBytes              = 1 << 20
	maxProjects                  = 1000
	maxTasks                     = 10000
	maxTaskDependencies          = 32
	maxIDLength                  = 128
	maxIdempotencyIndexKeyLength = maxIDLength + 1 + maxIDLength
	maxNameLength                = 256
	maxLease                     = time.Hour
)

var (
	ErrNotFound     = errors.New("lifecycle object not found")
	ErrConflict     = errors.New("lifecycle conflict")
	ErrArchived     = errors.New("project is archived")
	ErrLeaseHeld    = errors.New("task lease is held by another owner")
	ErrLeaseExpired = errors.New("task lease is missing or expired")
	ErrNotOwner     = errors.New("task is owned by another lease")
	ErrDependencies = errors.New("task dependencies are not complete")
	ErrTerminal     = errors.New("task is terminal")
	ErrIdempotency  = errors.New("idempotency key conflicts with an existing task")
	ErrInvalid      = errors.New("invalid lifecycle request")
	ErrUnavailable  = errors.New("lifecycle capability unavailable")
	ErrClosed       = errors.New("lifecycle store is closed")
)

type TaskState string

const (
	TaskPending   TaskState = "pending"
	TaskRunning   TaskState = "running"
	TaskCompleted TaskState = "completed"
	TaskFailed    TaskState = "failed"
	TaskCancelled TaskState = "cancelled"
)

type Project struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Archived  bool      `json:"archived"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type TaskSpec struct {
	ID             string   `json:"id"`
	ProjectID      string   `json:"project_id"`
	Dependencies   []string `json:"dependencies,omitempty"`
	IdempotencyKey string   `json:"idempotency_key,omitempty"`
}

type Checkpoint struct {
	TaskID       string    `json:"task_id"`
	Owner        string    `json:"owner"`
	LeaseVersion uint64    `json:"lease_version"`
	Sequence     uint64    `json:"sequence"`
	State        TaskState `json:"state"`
	Payload      []byte    `json:"payload,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type Task struct {
	ID             string      `json:"id"`
	ProjectID      string      `json:"project_id"`
	Dependencies   []string    `json:"dependencies,omitempty"`
	IdempotencyKey string      `json:"idempotency_key,omitempty"`
	RequestHash    string      `json:"request_hash"`
	State          TaskState   `json:"state"`
	Attempt        uint64      `json:"attempt"`
	LeaseOwner     string      `json:"lease_owner,omitempty"`
	LeaseVersion   uint64      `json:"lease_version,omitempty"`
	LeaseUntil     time.Time   `json:"lease_until,omitempty"`
	Checkpoint     *Checkpoint `json:"checkpoint,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

type Lease struct {
	TaskID    string    `json:"task_id"`
	Owner     string    `json:"owner"`
	Version   uint64    `json:"version"`
	ExpiresAt time.Time `json:"expires_at"`
	Attempt   uint64    `json:"attempt"`
}

type Options struct {
	// Now is injectable for deterministic recovery tests. Production callers
	// should leave it nil so the store uses UTC wall time.
	Now func() time.Time
	// afterLock is an in-package test seam for replacing the lock pathname
	// between acquisition and the post-acquisition identity check. Production
	// callers cannot set unexported fields; keeping the seam here makes the
	// admission boundary deterministic without weakening the live path.
	afterLock func(string, *os.File) error
}

type Store struct {
	mu          sync.Mutex
	root        string
	rootInfo    os.FileInfo
	rootDir     *os.File
	lockFile    *os.File
	lockInfo    os.FileInfo
	closed      bool
	now         func() time.Time
	lastNow     time.Time
	state       *durableState
	persistHook func([]byte) error
	// beforeAtomicWrite is an in-package test seam for replacing the lock
	// pathname after the initial commit validation and before the atomic
	// writer's final preflight. Production stores leave it nil.
	beforeAtomicWrite func() error
	// syncDirectoryHook is a test seam for the post-install durability
	// boundary. Production stores leave it nil and use the platform-native
	// directory sync implementation.
	syncDirectoryHook func(string) error
}

type durableState struct {
	Version      int                `json:"version"`
	Projects     map[string]Project `json:"projects"`
	Tasks        map[string]Task    `json:"tasks"`
	Idempotency  map[string]string  `json:"idempotency"`
	NextSequence uint64             `json:"next_sequence"`
}

// Open opens or creates an isolated lifecycle state directory. It does not
// recover expired leases implicitly; callers must make that transition
// explicit with RecoverExpired so crash recovery is observable and replayable.
func Open(root string, options ...Options) (*Store, error) {
	if len(options) > 1 {
		return nil, fmt.Errorf("%w: at most one lifecycle options value is allowed", ErrInvalid)
	}
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("%w: state root is required", ErrInvalid)
	}
	// Check the platform capability before creating the state root. An
	// unsupported platform must be an observable no-op for the caller's path,
	// not a late lock failure after filesystem state has been created.
	if err := ensureLifecycleLockCapability(); err != nil {
		return nil, err
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve state root: %w", err)
	}
	root = absoluteRoot
	info, err := validateLifecycleRootPath(root, nil)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := ensureLifecycleRootDirectory(root); err != nil {
		return nil, fmt.Errorf("create state root: %w", err)
	}
	if info == nil {
		info, err = validateLifecycleRootPath(root, nil)
		if err != nil {
			return nil, err
		}
	}
	lockFile, err := openLifecycleLock(filepath.Join(root, ".lifecycle.lock"))
	if err != nil {
		return nil, fmt.Errorf("open lifecycle state lock: %w", err)
	}
	lockInfo, err := lockFile.Stat()
	if err != nil {
		_ = closeLifecycleLock(lockFile)
		return nil, fmt.Errorf("stat lifecycle state lock: %w", err)
	}
	lockPath := filepath.Join(root, ".lifecycle.lock")
	if len(options) > 0 && options[0].afterLock != nil {
		if err := options[0].afterLock(lockPath, lockFile); err != nil {
			_ = closeLifecycleLock(lockFile)
			return nil, fmt.Errorf("post-lock lifecycle test hook: %w", err)
		}
	}
	// The lock descriptor remains held, but its pathname may have been
	// replaced immediately after acquisition. Reject that split ownership
	// boundary before opening or reading the state root; otherwise another
	// process could acquire the replacement pathname while Open still returns
	// a store backed by the old descriptor.
	if err := validateLifecycleLockIdentity(lockPath, lockInfo); err != nil {
		_ = closeLifecycleLock(lockFile)
		return nil, fmt.Errorf("validate locked lifecycle lock: %w", err)
	}
	// Recheck the pathname after taking ownership. A root can be replaced
	// between the initial validation and lock acquisition; following a newly
	// introduced symlink here would make the lock describe one directory while
	// state I/O targets another.
	lockedRootInfo, err := validateLifecycleRootPath(root, info)
	if err != nil {
		_ = closeLifecycleLock(lockFile)
		return nil, fmt.Errorf("validate locked lifecycle root: %w", err)
	}
	rootDir, err := openLifecycleStoreDirectory(root, lockedRootInfo)
	if err != nil {
		_ = closeLifecycleLock(lockFile)
		return nil, fmt.Errorf("open lifecycle state root: %w", err)
	}
	s := &Store{root: root, rootInfo: lockedRootInfo, rootDir: rootDir, lockFile: lockFile, lockInfo: lockInfo, now: func() time.Time { return time.Now().UTC() }, state: emptyState()}
	if len(options) > 0 && options[0].Now != nil {
		s.now = func() time.Time { return options[0].Now().UTC() }
	}
	b, err := readLifecycleState(root, lockedRootInfo)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("read lifecycle state: %w", err)
	}
	var loaded durableState
	// Reopen the durable checkpoint through the same bounded, strict JSON
	// boundary used by the additive MCP adapter. Persisted state is local, but
	// duplicate keys, unknown fields, and trailing values can still create
	// parser differentials between tools that inspect or repair the checkpoint.
	if err := decodeStrictJSON(b, &loaded); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("decode lifecycle state: %w", err)
	}
	if err := validateState(&loaded); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("validate lifecycle state: %w", err)
	}
	s.state = &loaded
	s.lastNow = latestStateTime(s.state)
	return s, nil
}

// readLifecycleState repeats the locked-root identity check immediately before
// opening the replaceable checkpoint. The state-file open still uses the
// platform no-follow/descriptor validation boundary, but this pre-read check
// avoids treating a root pathname replacement observed between lock
// acquisition and checkpoint open as an authorized state directory.
func readLifecycleState(root string, expected os.FileInfo) ([]byte, error) {
	if _, err := validateLifecycleRootPath(root, expected); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: lifecycle state root disappeared before state read", ErrConflict)
		}
		return nil, fmt.Errorf("validate lifecycle root before state read: %w", err)
	}
	b, err := readBoundedFromLifecycleRoot(root, expected, maxStateBytes)
	if !os.IsNotExist(err) {
		return b, err
	}
	// ENOENT is the expected signal for a newly-created store with no
	// lifecycle.json yet, but the platform-specific bounded read can also
	// observe the root disappearing after the pre-read validation. Recheck the
	// root before allowing Open to treat the checkpoint as absent; otherwise an
	// already-locked store could be returned in an unusable state.
	if _, rootErr := validateLifecycleRootPath(root, expected); rootErr != nil {
		return nil, fmt.Errorf("%w: lifecycle state root disappeared while reading state", ErrConflict)
	}
	return b, err
}

// Close releases the state-directory writer lock. A store must be closed
// before another process can open the same state directory. It is idempotent;
// operations after Close return ErrClosed rather than using memory that is no
// longer backed by the durable ownership boundary.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lockFile == nil {
		rootErr := closeLifecycleStoreDirectory(s.rootDir)
		s.rootDir = nil
		return rootErr
	}
	err := closeLifecycleLock(s.lockFile)
	s.lockFile = nil
	rootErr := closeLifecycleStoreDirectory(s.rootDir)
	s.rootDir = nil
	return errors.Join(err, rootErr)
}

func emptyState() *durableState {
	return &durableState{Version: stateVersion, Projects: map[string]Project{}, Tasks: map[string]Task{}, Idempotency: map[string]string{}}
}

func validateLifecycleRootObservation(pathInfo, info, currentPathInfo, expected os.FileInfo) error {
	// The normal path obtains all three observations from Lstat/Stat, but keep
	// this lower comparison helper fail-closed for direct and future
	// in-process callers. A missing observation cannot establish filesystem
	// identity and must not reach FileInfo methods or os.SameFile.
	if isNilLifecycleFileInfo(pathInfo) || isNilLifecycleFileInfo(info) || isNilLifecycleFileInfo(currentPathInfo) {
		return fmt.Errorf("%w: lifecycle state root observation is unavailable", ErrInvalid)
	}
	if expected != nil && isNilLifecycleFileInfo(expected) {
		return fmt.Errorf("%w: lifecycle state root expected observation is unavailable", ErrInvalid)
	}
	if currentPathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: state root must not be a symlink", ErrInvalid)
	}
	if !os.SameFile(pathInfo, currentPathInfo) || !os.SameFile(currentPathInfo, info) {
		return fmt.Errorf("%w: lifecycle state root changed while validating", ErrConflict)
	}
	if expected != nil && !os.SameFile(expected, info) {
		return fmt.Errorf("%w: lifecycle state root changed while opening", ErrConflict)
	}
	return validateLifecycleRoot(info)
}

// validateLifecycleRootPath validates the path and the directory it resolves
// to as one boundary. The path is checked with Lstat both before and after
// Stat: a root replaced with a symlink or different directory during the
// followed lookup cannot pass the platform permission check. When expected is
// supplied, the resolved directory must still be the same filesystem object
// captured before lock acquisition.
func validateLifecycleRootPath(path string, expected os.FileInfo) (os.FileInfo, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: state root must not be a symlink", ErrInvalid)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat state root: %w", err)
	}
	currentPathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validateLifecycleRootObservation(pathInfo, info, currentPathInfo, expected); err != nil {
		return nil, err
	}
	return info, nil
}

func (s *Store) CreateProject(id, name string) (Project, error) {
	if err := s.ensureReceiver(); err != nil {
		return Project{}, err
	}
	if err := validID("project", id); err != nil {
		return Project{}, err
	}
	if err := validName(name); err != nil {
		return Project{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return Project{}, err
	}
	if _, ok := s.state.Projects[id]; ok {
		return Project{}, fmt.Errorf("%w: project %q exists", ErrConflict, id)
	}
	if len(s.state.Projects) >= maxProjects {
		return Project{}, fmt.Errorf("%w: project limit reached", ErrInvalid)
	}
	now, err := s.currentTime()
	if err != nil {
		return Project{}, err
	}
	next, err := s.cloneStateForMutation()
	if err != nil {
		return Project{}, err
	}
	p := Project{ID: id, Name: name, CreatedAt: now, UpdatedAt: now}
	next.Projects[id] = p
	if err := s.commitLocked(next); err != nil {
		return Project{}, err
	}
	return p, nil
}

func (s *Store) ArchiveProject(id string) (Project, error) {
	if err := s.ensureReceiver(); err != nil {
		return Project{}, err
	}
	if err := validID("project", id); err != nil {
		return Project{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return Project{}, err
	}
	p, ok := s.state.Projects[id]
	if !ok {
		return Project{}, ErrNotFound
	}
	if p.Archived {
		return p, nil
	}
	p.Archived = true
	now, err := s.currentTime()
	if err != nil {
		return Project{}, err
	}
	next, err := s.cloneStateForMutation()
	if err != nil {
		return Project{}, err
	}
	p.UpdatedAt = now
	next.Projects[id] = p
	if err := s.commitLocked(next); err != nil {
		return Project{}, err
	}
	return p, nil
}

func (s *Store) Project(id string) (Project, error) {
	if err := s.ensureReceiver(); err != nil {
		return Project{}, err
	}
	if err := validID("project", id); err != nil {
		return Project{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return Project{}, err
	}
	p, ok := s.state.Projects[id]
	if !ok {
		return Project{}, ErrNotFound
	}
	return p, nil
}

func (s *Store) CreateTask(spec TaskSpec) (Task, error) {
	if err := s.ensureReceiver(); err != nil {
		return Task{}, err
	}
	if err := validID("project", spec.ProjectID); err != nil {
		return Task{}, err
	}
	if spec.ID != "" {
		if err := validID("task", spec.ID); err != nil {
			return Task{}, err
		}
	}
	if err := validIdempotencyKey(spec.IdempotencyKey); err != nil {
		return Task{}, err
	}
	deps, err := normalizeDependencies(spec.Dependencies)
	if err != nil {
		return Task{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return Task{}, err
	}
	p, ok := s.state.Projects[spec.ProjectID]
	if !ok {
		return Task{}, ErrNotFound
	}
	hash := taskHash(spec.ProjectID, deps)
	key := idempotencyKey(spec.ProjectID, spec.IdempotencyKey)
	if spec.IdempotencyKey != "" {
		if existingID, indexed := s.state.Idempotency[key]; indexed {
			// A valid durable state cannot contain an empty or malformed task ID,
			// but an in-process integration can still damage the reverse index
			// after Open. Do not treat that present entry as absent: doing so
			// would allow a duplicate idempotency key to be committed while the
			// malformed index remains live.
			if validID("idempotency task", existingID) != nil {
				return Task{}, fmt.Errorf("%w: idempotency index is malformed", ErrInvalid)
			}
			existing, exists := s.state.Tasks[existingID]
			// The mapped task must prove that this reverse-index entry belongs
			// to the requested project and key. A valid task with the same
			// dependency hash but a different (or missing) key must not be
			// returned as an idempotent retry after live state corruption.
			if !exists || existing.ID != existingID || existing.ProjectID != spec.ProjectID || existing.IdempotencyKey != spec.IdempotencyKey || idempotencyKey(existing.ProjectID, existing.IdempotencyKey) != key {
				return Task{}, fmt.Errorf("%w: idempotency index is malformed", ErrInvalid)
			}
			if existing.RequestHash != hash {
				return Task{}, ErrIdempotency
			}
			return cloneTask(existing), nil
		}
	}
	// An idempotent retry must return the task created by the original
	// successful request even if the project was archived afterward. Only a
	// genuinely new task is blocked by the archived-project policy.
	if p.Archived {
		return Task{}, ErrArchived
	}
	for _, dep := range deps {
		d, exists := s.state.Tasks[dep]
		if !exists {
			return Task{}, fmt.Errorf("%w: dependency %q", ErrNotFound, dep)
		}
		if d.ProjectID != spec.ProjectID {
			return Task{}, fmt.Errorf("%w: dependency belongs to another project", ErrInvalid)
		}
	}
	if len(s.state.Tasks) >= maxTasks {
		return Task{}, fmt.Errorf("%w: task limit reached", ErrInvalid)
	}
	id := spec.ID
	if id == "" {
		id, err = newID("task")
		if err != nil {
			return Task{}, err
		}
	}
	if _, exists := s.state.Tasks[id]; exists {
		return Task{}, fmt.Errorf("%w: task %q exists", ErrConflict, id)
	}
	now, err := s.currentTime()
	if err != nil {
		return Task{}, err
	}
	task := Task{ID: id, ProjectID: spec.ProjectID, Dependencies: deps, IdempotencyKey: spec.IdempotencyKey, RequestHash: hash, State: TaskPending, CreatedAt: now, UpdatedAt: now}
	next, err := s.cloneStateForMutation()
	if err != nil {
		return Task{}, err
	}
	next.Tasks[id] = task
	if spec.IdempotencyKey != "" {
		next.Idempotency[key] = id
	}
	if err := s.commitLocked(next); err != nil {
		return Task{}, err
	}
	return cloneTask(task), nil
}

// Ready returns pending tasks whose dependencies are completed, in stable ID
// order. It is a read-only resume plan; Acquire still owns the lease race.
func (s *Store) Ready(projectID string) ([]Task, error) {
	if err := s.ensureReceiver(); err != nil {
		return nil, err
	}
	if err := validID("project", projectID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return nil, err
	}
	if _, ok := s.state.Projects[projectID]; !ok {
		return nil, ErrNotFound
	}
	ready := make([]Task, 0)
	// The map-wide readiness preflight is independent of the candidate task.
	// Run it once for this locked state snapshot rather than once per task;
	// otherwise a bounded state with many tasks would repeat the complete DAG
	// walk and map validation for every candidate.
	if !validReadinessStateMapShape(s.state) {
		return ready, nil
	}
	for _, task := range s.state.Tasks {
		if task.ProjectID == projectID && task.State == TaskPending && dependenciesCompleteFromValidatedState(s.state, &task) {
			ready = append(ready, cloneTask(task))
		}
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].ID < ready[j].ID })
	return ready, nil
}

func (s *Store) Tasks(projectID string) ([]Task, error) {
	if err := s.ensureReceiver(); err != nil {
		return nil, err
	}
	if err := validID("project", projectID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return nil, err
	}
	if _, ok := s.state.Projects[projectID]; !ok {
		return nil, ErrNotFound
	}
	tasks := make([]Task, 0)
	for _, task := range s.state.Tasks {
		if task.ProjectID == projectID {
			tasks = append(tasks, cloneTask(task))
		}
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })
	return tasks, nil
}

func (s *Store) Task(id string) (Task, error) {
	if err := s.ensureReceiver(); err != nil {
		return Task{}, err
	}
	if err := validID("task", id); err != nil {
		return Task{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return Task{}, err
	}
	task, ok := s.state.Tasks[id]
	if !ok {
		return Task{}, ErrNotFound
	}
	return cloneTask(task), nil
}

func (s *Store) Acquire(taskID, owner string, ttl time.Duration) (Lease, error) {
	if err := s.ensureReceiver(); err != nil {
		return Lease{}, err
	}
	if err := validID("task", taskID); err != nil {
		return Lease{}, err
	}
	if err := validID("owner", owner); err != nil {
		return Lease{}, err
	}
	if err := validTTL(ttl); err != nil {
		return Lease{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return Lease{}, err
	}
	task, ok := s.state.Tasks[taskID]
	if !ok {
		return Lease{}, ErrNotFound
	}
	if task.State == TaskCompleted || task.State == TaskFailed || task.State == TaskCancelled {
		return Lease{}, ErrTerminal
	}
	now, err := s.currentTime()
	if err != nil {
		return Lease{}, err
	}
	if task.State == TaskRunning {
		if task.LeaseUntil.After(now) {
			return Lease{}, ErrLeaseHeld
		}
		// Expiry recovery is an explicit supervisor transition. Do not let a
		// caller turn an expired running lease directly into a new attempt;
		// RecoverExpired must first make the pending transition observable.
		return Lease{}, ErrLeaseExpired
	}
	next, err := s.cloneStateForMutation()
	if err != nil {
		return Lease{}, err
	}
	task = next.Tasks[taskID]
	if task.Attempt == ^uint64(0) || task.LeaseVersion == ^uint64(0) {
		return Lease{}, fmt.Errorf("%w: lease attempt counter exhausted", ErrInvalid)
	}
	if !s.dependenciesCompleteFrom(next, &task) {
		return Lease{}, ErrDependencies
	}
	task.State = TaskRunning
	task.Attempt++
	task.LeaseOwner = owner
	task.LeaseVersion++
	task.LeaseUntil = now.Add(ttl)
	task.UpdatedAt = now
	next.Tasks[taskID] = task
	if err := s.commitLocked(next); err != nil {
		return Lease{}, err
	}
	return Lease{TaskID: taskID, Owner: owner, Version: task.LeaseVersion, ExpiresAt: task.LeaseUntil, Attempt: task.Attempt}, nil
}

func (s *Store) Heartbeat(taskID, owner string, version uint64, ttl time.Duration) (Lease, error) {
	if err := s.ensureReceiver(); err != nil {
		return Lease{}, err
	}
	if err := validID("task", taskID); err != nil {
		return Lease{}, err
	}
	if err := validID("owner", owner); err != nil {
		return Lease{}, err
	}
	if err := validTTL(ttl); err != nil {
		return Lease{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return Lease{}, err
	}
	task, ok := s.state.Tasks[taskID]
	if !ok {
		return Lease{}, ErrNotFound
	}
	now, err := s.currentTime()
	if err != nil {
		return Lease{}, err
	}
	if task.State != TaskRunning || task.LeaseOwner != owner || task.LeaseVersion != version {
		return Lease{}, ErrNotOwner
	}
	if !task.LeaseUntil.After(now) {
		return Lease{}, ErrLeaseExpired
	}
	next, err := s.cloneStateForMutation()
	if err != nil {
		return Lease{}, err
	}
	task = next.Tasks[taskID]
	task.LeaseUntil = now.Add(ttl)
	task.UpdatedAt = now
	next.Tasks[taskID] = task
	if err := s.commitLocked(next); err != nil {
		return Lease{}, err
	}
	return Lease{TaskID: taskID, Owner: owner, Version: version, ExpiresAt: task.LeaseUntil, Attempt: task.Attempt}, nil
}

// Checkpoint durably records progress. Terminal checkpoints release the lease
// in the same atomic state transition, so a completed task cannot be resumed.
func (s *Store) Checkpoint(taskID, owner string, version uint64, state TaskState, payload []byte) (Task, error) {
	if err := s.ensureReceiver(); err != nil {
		return Task{}, err
	}
	if err := validID("task", taskID); err != nil {
		return Task{}, err
	}
	if err := validID("owner", owner); err != nil {
		return Task{}, err
	}
	if len(payload) > maxPayloadBytes {
		return Task{}, fmt.Errorf("%w: checkpoint payload exceeds %d bytes", ErrInvalid, maxPayloadBytes)
	}
	if !validTaskState(state) || state == TaskPending {
		return Task{}, fmt.Errorf("%w: checkpoint state %q", ErrInvalid, state)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return Task{}, err
	}
	task, ok := s.state.Tasks[taskID]
	if !ok {
		return Task{}, ErrNotFound
	}
	now, err := s.currentTime()
	if err != nil {
		return Task{}, err
	}
	if task.State != TaskRunning || task.LeaseOwner != owner || task.LeaseVersion != version {
		return Task{}, ErrNotOwner
	}
	if !task.LeaseUntil.After(now) {
		return Task{}, ErrLeaseExpired
	}
	if s.state.NextSequence == ^uint64(0) {
		return Task{}, fmt.Errorf("%w: checkpoint sequence exhausted", ErrInvalid)
	}
	next, err := s.cloneStateForMutation()
	if err != nil {
		return Task{}, err
	}
	task = next.Tasks[taskID]
	next.NextSequence++
	copyPayload := append([]byte(nil), payload...)
	task.Checkpoint = &Checkpoint{TaskID: taskID, Owner: owner, LeaseVersion: version, Sequence: next.NextSequence, State: state, Payload: copyPayload, CreatedAt: now}
	task.State = state
	task.UpdatedAt = now
	if state == TaskCompleted || state == TaskFailed || state == TaskCancelled {
		task.LeaseOwner = ""
		task.LeaseUntil = time.Time{}
	}
	next.Tasks[taskID] = task
	if err := s.commitLocked(next); err != nil {
		return Task{}, err
	}
	return cloneTask(task), nil
}

// RecoverExpired returns tasks whose leases were expired at the supplied
// store time to pending state. It never executes or retries a task.
func (s *Store) RecoverExpired() ([]Task, error) {
	if err := s.ensureReceiver(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return nil, err
	}
	now, err := s.currentTime()
	if err != nil {
		return nil, err
	}
	next, err := s.cloneStateForMutation()
	if err != nil {
		return nil, err
	}
	recovered := make([]Task, 0)
	for id, task := range next.Tasks {
		if task.State != TaskRunning || task.LeaseUntil.After(now) {
			continue
		}
		task.State = TaskPending
		task.LeaseOwner = ""
		task.LeaseUntil = time.Time{}
		task.UpdatedAt = now
		next.Tasks[id] = task
		recovered = append(recovered, cloneTask(task))
	}
	if len(recovered) == 0 {
		return nil, nil
	}
	if err := s.commitLocked(next); err != nil {
		return nil, err
	}
	sort.Slice(recovered, func(i, j int) bool { return recovered[i].ID < recovered[j].ID })
	return recovered, nil
}

// currentTime keeps lifecycle timestamps monotonic within one state store.
// Wall clocks can step backwards after NTP corrections, VM resume, or an
// operator-supplied test clock. Without a floor, a later mutation could make
// UpdatedAt or a checkpoint timestamp precede already durable state and cause
// the next reopen to reject an otherwise recoverable checkpoint. A malformed
// injected clock is also a failed mutation boundary: zero time and callback
// panics are rejected without exposing the panic value or changing the floor.
func (s *Store) currentTime() (now time.Time, err error) {
	// Exported operations validate the complete store before reaching the
	// clock, but keep this lower helper explicit for direct and future
	// in-process callers. An unavailable receiver must not invoke a nil clock
	// through the panic-recovery path or look like a malformed clock value.
	if s == nil || s.now == nil {
		return time.Time{}, ErrClosed
	}
	defer func() {
		if recover() != nil {
			now = time.Time{}
			err = fmt.Errorf("%w: lifecycle clock panicked", ErrInvalid)
		}
	}()
	now = s.now().UTC()
	if err := validateLifecycleTimestamp(now); err != nil {
		return time.Time{}, err
	}
	if !s.lastNow.IsZero() {
		if err := validateLifecycleTimestamp(s.lastNow); err != nil {
			return time.Time{}, fmt.Errorf("%w: lifecycle clock floor is invalid", err)
		}
	}
	if now.Before(s.lastNow) {
		return s.lastNow, nil
	}
	s.lastNow = now
	return now, nil
}

// validateLifecycleTimestamp keeps injected clock values on the same
// representable surface as the JSON checkpoint. A non-zero time outside
// encoding/json's supported year range would otherwise advance lastNow and
// only fail after a candidate had already been cloned for persistence.
func validateLifecycleTimestamp(value time.Time) error {
	if value.IsZero() {
		return fmt.Errorf("%w: lifecycle clock returned zero time", ErrInvalid)
	}
	if _, err := value.MarshalJSON(); err != nil {
		return fmt.Errorf("%w: lifecycle clock returned an unrepresentable time", ErrInvalid)
	}
	// Every lifecycle mutation may be followed by a lease operation. Reject a
	// clock whose maximum supported lease horizon cannot be represented before
	// advancing the monotonic floor, rather than letting Acquire or Heartbeat
	// discover the overflow after cloning a candidate.
	if _, err := value.Add(maxLease).MarshalJSON(); err != nil {
		return fmt.Errorf("%w: lifecycle clock lease horizon is unrepresentable", ErrInvalid)
	}
	return nil
}

func latestStateTime(state *durableState) time.Time {
	// Open validates the decoded state before seeding the clock floor, but keep
	// this lower helper safe for direct and future in-process callers. An
	// unavailable, unsupported-version, oversized, or aggregate-oversized state
	// has no trustworthy timestamp to adopt and must be rejected before walking
	// its maps.
	if state == nil || state.Version != stateVersion || state.Projects == nil || state.Tasks == nil || state.Idempotency == nil || len(state.Projects) > maxProjects || len(state.Tasks) > maxTasks || len(state.Idempotency) > maxTasks || !stateVariableBudgetWithin(state) || !stateSerializedWithinBudget(state) {
		return time.Time{}
	}
	latest := time.Time{}
	for _, project := range state.Projects {
		// The seeded floor is consumed by currentTime before the next lease
		// mutation. Apply the same lease-horizon check here; a timestamp can be
		// valid JSON at the end of year 9999 while its one-hour expiry is not.
		// Both lifetime endpoints are durable state. Do not let a malformed
		// creation timestamp hide behind a valid update timestamp when this
		// lower helper is called directly or by a future reopen seam.
		if validateLifecycleTimestamp(project.CreatedAt) != nil || validateLifecycleTimestamp(project.UpdatedAt) != nil || project.UpdatedAt.Before(project.CreatedAt) {
			return time.Time{}
		}
		if project.UpdatedAt.After(latest) {
			latest = project.UpdatedAt
		}
	}
	for _, task := range state.Tasks {
		// The floor must be seeded only from a task that is still bound to its
		// canonical project snapshot. A direct or future in-process caller must
		// not let an orphaned task, a substituted project identity, or a
		// checkpoint belonging to another task contribute a timestamp before
		// the normal full-state validator gets a chance to reject the state.
		project, ok := state.Projects[task.ProjectID]
		if !ok || project.ID != task.ProjectID || task.CreatedAt.Before(project.CreatedAt) {
			return time.Time{}
		}
		// A task lifetime is also a paired durable boundary. Reject an omitted
		// or reversed creation endpoint before adopting the later update time.
		if validateLifecycleTimestamp(task.CreatedAt) != nil || validateLifecycleTimestamp(task.UpdatedAt) != nil || task.UpdatedAt.Before(task.CreatedAt) || (task.Checkpoint != nil && (task.Checkpoint.TaskID != task.ID || len(task.Checkpoint.Payload) > maxPayloadBytes || validateLifecycleTimestamp(task.Checkpoint.CreatedAt) != nil || task.Checkpoint.CreatedAt.Before(task.CreatedAt) || task.Checkpoint.CreatedAt.After(task.UpdatedAt))) {
			return time.Time{}
		}
		if task.UpdatedAt.After(latest) {
			latest = task.UpdatedAt
		}
		if task.Checkpoint != nil && task.Checkpoint.CreatedAt.After(latest) {
			latest = task.Checkpoint.CreatedAt
		}
	}
	return latest
}

func (s *Store) ensureOpenLocked() error {
	// An opened store is a complete ownership binding, not merely a live lock
	// descriptor. Keep direct callers and malformed in-process integrations
	// from reaching a nil state or clock after the lock check; adapters already
	// perform the same fail-closed validation before binding a principal.
	if s == nil || s.closed || !lifecycleFileReady(s.lockFile) || s.lockInfo == nil || s.root == "" || !filepath.IsAbs(s.root) || s.rootInfo == nil || !lifecycleStoreDirectoryReady(s.rootDir) || s.state == nil || s.now == nil {
		return ErrClosed
	}
	// Reads must not continue serving state after the pathname loses the
	// filesystem identity captured with the writer lock. Writes already repeat
	// this check at each atomic-install boundary; doing it here closes the
	// corresponding stale-read and stale-adapter path.
	if err := s.validateRootIdentity(); err != nil {
		return err
	}
	// The root check protects the state directory, but the lock pathname can
	// also be replaced after Open. Revalidate the exact inode that supplied the
	// cross-process ownership boundary before serving a read or mutation; an
	// old store must fail closed instead of continuing while a replacement lock
	// admits another writer.
	if err := validateLifecycleLockIdentity(filepath.Join(s.root, ".lifecycle.lock"), s.lockInfo); err != nil {
		return err
	}
	// The state is normally validated when it is decoded during Open, but an
	// in-process integration can still mutate the private state after that
	// boundary. Revalidate before every operation so a damaged live checkpoint
	// cannot be read, used to derive a new state, or persisted over the last
	// known-good durable checkpoint.
	if err := validateState(s.state); err != nil {
		return err
	}
	return nil
}

// ensureReceiver keeps the exported core operations fail-closed when a
// malformed adapter or direct caller holds a nil store pointer. Adapter
// constructors reject nil stores earlier, but the core remains safe when used
// directly or after an integration boundary is bypassed.
func (s *Store) ensureReceiver() error {
	if s == nil {
		return ErrClosed
	}
	return nil
}

// ensureAdapterReady validates the store boundary before an owner-bound
// controller captures it. A zero-value or already-closed store must not look
// like a configured lifecycle backend and fail later after transport setup.
// Operations still re-check the live store state, because a valid adapter may
// outlive an explicit Store.Close call.
func (s *Store) ensureAdapterReady() error {
	if s == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return err
	}
	if s.state == nil || s.now == nil {
		return ErrClosed
	}
	return nil
}

func (s *Store) dependenciesComplete(task *Task) bool {
	if s == nil {
		return false
	}
	return s.dependenciesCompleteFrom(s.state, task)
}

func validReadinessStateMapShape(state *durableState) bool {
	if state == nil || state.Projects == nil || state.Tasks == nil || len(state.Projects) > maxProjects || len(state.Tasks) > maxTasks || len(state.Idempotency) > maxTasks {
		return false
	}
	// Every attacker-controlled string and retained payload contributes to the
	// durable JSON snapshot. Apply the same aggregate raw-variable budget before
	// the graph walk, request-fingerprint checks, or candidate comparisons so a
	// direct caller cannot spend bounded-but-large work on a snapshot that the
	// durable validator would reject.
	if !stateVariableBudgetWithin(state) {
		return false
	}
	// Checkpoint allocators reject the maximum sequence before mutation because
	// incrementing it would wrap to zero. Keep direct readiness aligned with
	// that durable boundary: once no representable checkpoint sequence remains,
	// readiness must not advertise any pending work that cannot be checkpointed.
	if state.NextSequence == ^uint64(0) {
		return false
	}
	// Lower readiness callers may provide partial state values, so retain the
	// zero-value compatibility used by direct fixtures. If a schema version is
	// supplied, it must still be the version this lifecycle core understands;
	// otherwise readiness could be reported from a future or incompatible state
	// shape that the durable reopen validator would reject.
	if state.Version != 0 && state.Version != stateVersion {
		return false
	}
	// The durable state file is capped at 8 MiB, but a direct in-process
	// caller can construct a bounded task map whose dependency lists are each
	// individually valid while their aggregate text is much larger. Bound that
	// work before the graph walk or request-fingerprint hashing so an unrelated
	// task cannot turn readiness into an oversized dependency scan.
	// Dependency text and retained checkpoint payloads both occupy the durable
	// state representation. Apply one shared budget before the graph walk or
	// candidate cloning; separate per-field ceilings could otherwise admit a
	// direct snapshot whose combined variable data exceeds maxStateBytes.
	for _, task := range state.Tasks {
		if len(task.Dependencies) > maxTaskDependencies {
			return false
		}
		for _, dependency := range task.Dependencies {
			if len(dependency) > maxIDLength {
				return false
			}
		}
	}
	// Readiness consumes the same bounded task graph as durable recovery. A
	// direct in-process caller must not hide an unrelated dependency cycle
	// behind an otherwise-ready candidate; validate the graph before the
	// map-wide field checks below use any dependency edge.
	if err := validateTaskDAG(state); err != nil {
		return false
	}
	checkpointSequences := make(map[uint64]struct{}, len(state.Tasks))
	for id, project := range state.Projects {
		if validID("project", id) != nil || project.ID != id {
			return false
		}
		// Lower readiness callers may provide partial project values, so retain
		// zero-value compatibility while rejecting any supplied project name that
		// could not cross the normal project-mutation boundary. An unrelated
		// malformed name must not be hidden by an otherwise-ready candidate.
		if project.Name != "" && validName(project.Name) != nil {
			return false
		}
		// Lower readiness callers may provide partial project values, so retain
		// zero-value compatibility while rejecting any supplied timestamp that
		// cannot cross the durable JSON boundary. An unrelated malformed time
		// must not be hidden by an otherwise-ready candidate.
		if !validReadinessLifetime(project.CreatedAt, project.UpdatedAt) {
			return false
		}
	}
	for id, task := range state.Tasks {
		if validID("task", id) != nil || task.ID != id || validID("task project", task.ProjectID) != nil {
			return false
		}
		project, ok := state.Projects[task.ProjectID]
		if !ok || !validTaskState(task.State) || validIdempotencyKey(task.IdempotencyKey) != nil || len(task.Dependencies) > maxTaskDependencies || (task.Checkpoint != nil && len(task.Checkpoint.Payload) > maxPayloadBytes) {
			return false
		}
		if !validReadinessLifetime(task.CreatedAt, task.UpdatedAt) || !validOptionalReadinessTimestamp(task.LeaseUntil) {
			return false
		}
		if !project.CreatedAt.IsZero() && !task.CreatedAt.IsZero() && task.CreatedAt.Before(project.CreatedAt) {
			return false
		}
		if !task.CreatedAt.IsZero() && !task.UpdatedAt.IsZero() && task.UpdatedAt.Before(task.CreatedAt) {
			return false
		}
		if task.State == TaskRunning && !task.UpdatedAt.IsZero() {
			if !task.LeaseUntil.After(task.UpdatedAt) || task.LeaseUntil.Sub(task.UpdatedAt) > maxLease {
				return false
			}
		}
		// A running entry necessarily carries a complete lease, so it is no
		// longer a zero-value partial fixture. Require both task lifetime
		// endpoints before applying the lease relation; otherwise an unrelated
		// fully leased task with omitted timestamps could pass this lower
		// readiness boundary even though durable validation rejects it.
		if task.State == TaskRunning && (task.CreatedAt.IsZero() || task.UpdatedAt.IsZero()) {
			return false
		}
		if task.Checkpoint != nil && !validOptionalReadinessTimestamp(task.Checkpoint.CreatedAt) {
			return false
		}
		// An explicit checkpoint binds progress to the task lifetime. Keep both
		// durable endpoints present before accepting that metadata; otherwise an
		// unrelated checkpoint with omitted lifetime bounds could hide malformed
		// state behind an otherwise-ready candidate.
		if task.Checkpoint != nil && (task.CreatedAt.IsZero() || task.UpdatedAt.IsZero()) {
			return false
		}
		// Validate dependency identifiers and their canonical order before
		// hashing a supplied request fingerprint. A malformed in-process task
		// must not make this lower boundary spend work on unbounded dependency
		// text before the same identifier contract used by durable validation
		// rejects it.
		for index, dependency := range task.Dependencies {
			if validID("dependency", dependency) != nil || (index > 0 && task.Dependencies[index-1] >= dependency) {
				return false
			}
		}
		// Partial in-process task values used by lower-level callers may omit a
		// request fingerprint, but a supplied fingerprint must still be the
		// canonical project/dependency binding. Otherwise an unrelated task can
		// carry a substituted non-empty hash and hide state corruption behind an
		// otherwise-ready candidate.
		if task.RequestHash != "" {
			const requestHashLength = sha256.Size * 2
			if len(task.RequestHash) != requestHashLength || task.RequestHash != taskHash(task.ProjectID, task.Dependencies) {
				return false
			}
		}
		// An actionable task that carries any durable retry, dependency,
		// lifetime, lease, or checkpoint metadata must also retain the request
		// fingerprint that binds that metadata to its project and dependency
		// graph. Zero-value partial fixtures, including established terminal
		// dependency fixtures, remain valid; populated pending or running state
		// with a missing fingerprint must not hide malformed work behind a ready
		// candidate.
		if task.RequestHash == "" && (task.State == TaskPending || task.State == TaskRunning) && hasReadinessTaskMetadata(task) {
			return false
		}
		// A populated terminal task also retains durable work identity through
		// its checkpoint. Require the request fingerprint whenever terminal
		// metadata is present, while keeping zero-value terminal dependency
		// fixtures compatible with lower-level readiness tests.
		if task.RequestHash == "" && isReadinessTerminalState(task.State) && hasReadinessTaskMetadata(task) {
			return false
		}
		// Acquisition advances the retry and lease-version counters together,
		// and only a running task may carry an active lease. Keep this lower
		// map-wide preflight aligned with durable validation so an unrelated
		// malformed task cannot be hidden by an otherwise-ready candidate.
		if task.Attempt != task.LeaseVersion {
			return false
		}
		// A pending task with an exhausted retry counter cannot be acquired:
		// Acquire rejects the counter before incrementing it. Reject that
		// impossible actionable entry map-wide, so unrelated exhausted work
		// cannot be hidden behind a different ready candidate. Running and
		// terminal tasks may legitimately retain the maximum as historical
		// lease state and are checked by their own transition rules.
		if task.State == TaskPending && (task.Attempt == ^uint64(0) || task.LeaseVersion == ^uint64(0)) {
			return false
		}
		switch task.State {
		case TaskRunning:
			if validID("lease owner", task.LeaseOwner) != nil || task.LeaseUntil.IsZero() || task.LeaseVersion == 0 {
				return false
			}
		default:
			if task.LeaseOwner != "" || !task.LeaseUntil.IsZero() {
				return false
			}
		}
		// The persisted validator requires every keyed task to have its
		// project-scoped reverse-index entry. Validate that forward direction
		// here as well; otherwise an unrelated keyed task with a missing index
		// could be hidden by an otherwise-ready candidate.
		if task.IdempotencyKey != "" {
			if state.Idempotency == nil || state.Idempotency[idempotencyKey(task.ProjectID, task.IdempotencyKey)] != id {
				return false
			}
		}
		// Durable terminal tasks always retain the checkpoint that records their
		// terminal transition. Keep zero-value partial fixtures usable for direct
		// readiness tests, but reject a terminal entry that supplies any durable
		// task metadata without that checkpoint; otherwise unrelated corruption
		// could be hidden by an otherwise-ready candidate.
		if task.Checkpoint == nil && isReadinessTerminalState(task.State) && hasReadinessTaskMetadata(task) {
			return false
		}
		for _, dependency := range task.Dependencies {
			// Keep the lower map-shape preflight on the same project-local
			// graph contract as durable validation. A malformed unrelated task
			// must not hide a missing, self, or cross-project dependency behind
			// an otherwise-ready candidate.
			dependencyTask, ok := state.Tasks[dependency]
			if !ok || dependencyTask.ID != dependency || dependencyTask.ProjectID != task.ProjectID || dependency == id {
				return false
			}
		}
		if checkpoint := task.Checkpoint; checkpoint != nil && (checkpoint.TaskID != id || validID("checkpoint owner", checkpoint.Owner) != nil || checkpoint.LeaseVersion == 0 || checkpoint.Sequence == 0 || checkpoint.Sequence > state.NextSequence || !validTaskState(checkpoint.State) || checkpoint.State == TaskPending || checkpoint.LeaseVersion > task.LeaseVersion || checkpoint.CreatedAt.IsZero()) {
			return false
		}
		if checkpoint := task.Checkpoint; checkpoint != nil {
			switch task.State {
			case TaskPending, TaskRunning:
				if checkpoint.State != TaskRunning {
					return false
				}
			case TaskCompleted, TaskFailed, TaskCancelled:
				if checkpoint.State != task.State || checkpoint.LeaseVersion != task.LeaseVersion {
					return false
				}
			}
			// Each supplied task-lifetime endpoint is authoritative even when
			// the other endpoint is omitted by a partial in-process fixture. A
			// malformed checkpoint must not hide behind the zero-value
			// compatibility used by lower-level readiness callers.
			if (!task.CreatedAt.IsZero() && checkpoint.CreatedAt.Before(task.CreatedAt)) || (!task.UpdatedAt.IsZero() && checkpoint.CreatedAt.After(task.UpdatedAt)) {
				return false
			}
			if task.State == TaskRunning && checkpoint.LeaseVersion == task.LeaseVersion && checkpoint.Owner != task.LeaseOwner {
				return false
			}
			if _, exists := checkpointSequences[checkpoint.Sequence]; exists {
				return false
			}
			checkpointSequences[checkpoint.Sequence] = struct{}{}
		}
	}
	for key, id := range state.Idempotency {
		separator := strings.IndexByte(key, 0)
		if len(key) > maxIdempotencyIndexKeyLength || len(id) > maxIDLength || separator <= 0 || separator == len(key)-1 || strings.IndexByte(key[separator+1:], 0) >= 0 || validID("idempotency project", key[:separator]) != nil || validIdempotencyKey(key[separator+1:]) != nil || validID("idempotency task", id) != nil {
			return false
		}
		task, ok := state.Tasks[id]
		if !ok || task.IdempotencyKey == "" || key != idempotencyKey(task.ProjectID, task.IdempotencyKey) {
			return false
		}
	}
	// The durable boundary measures the indented JSON checkpoint, not just the
	// raw variable fields above. Payload base64 expansion and map/field
	// encoding overhead must therefore be checked before a direct readiness
	// caller can retain or clone a state snapshot that commitLocked would reject.
	return stateSerializedWithinBudget(state)
}

// stateSerializedWithinBudget applies the exact durable representation bound
// after the cheaper raw-variable preflight. JSON base64 expansion and field
// overhead can make an otherwise raw-bounded in-process snapshot exceed the
// persisted ceiling, so callers that retain or clone state must check the
// representation before allocating replacement data.
func stateSerializedWithinBudget(state *durableState) bool {
	// Keep this exact-size helper bounded when called directly. Normal callers
	// already perform the cheaper map and raw-variable checks, but a future
	// in-process seam must not make json.MarshalIndent scan or retain an
	// oversized state snapshot merely because it reached this lower helper
	// without that admission path.
	if state == nil || len(state.Projects) > maxProjects || len(state.Tasks) > maxTasks || len(state.Idempotency) > maxTasks || !stateVariableBudgetWithin(state) {
		return false
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	return err == nil && len(encoded) <= maxStateBytes
}

func isReadinessTerminalState(state TaskState) bool {
	switch state {
	case TaskCompleted, TaskFailed, TaskCancelled:
		return true
	default:
		return false
	}
}

func hasReadinessTaskMetadata(task Task) bool {
	return task.RequestHash != "" || task.Attempt != 0 || task.LeaseVersion != 0 || task.IdempotencyKey != "" || task.Dependencies != nil || !task.CreatedAt.IsZero() || !task.UpdatedAt.IsZero() || task.LeaseOwner != "" || !task.LeaseUntil.IsZero() || task.Checkpoint != nil
}

func validOptionalReadinessTimestamp(value time.Time) bool {
	return value.IsZero() || validateStateTimestamp("readiness timestamp", value) == nil
}

func validReadinessLifetime(created, updated time.Time) bool {
	// Lower-level readiness fixtures may omit the optional lifetime entirely,
	// but an explicitly supplied endpoint is durable metadata and therefore
	// must retain its paired endpoint before it can influence readiness.
	if created.IsZero() != updated.IsZero() {
		return false
	}
	if !validOptionalReadinessTimestamp(created) || !validOptionalReadinessTimestamp(updated) {
		return false
	}
	return created.IsZero() || !updated.Before(created)
}

// stateVariableBudgetWithin bounds the raw attacker-controlled portion of a
// durable state snapshot before validation uses any of its values as graph
// edges or request-hash input. JSON escaping and structural field overhead are
// checked later by the exact serialized-size boundary; this lower budget keeps
// aggregate string and payload work bounded before that encoding step.
func stateVariableBudgetWithin(state *durableState) bool {
	// Keep this lower resource helper fail-closed on its own. Callers normally
	// check the map shape first, but a direct or future in-process seam must not
	// scan an oversized zero-byte map merely because its entries contribute no
	// string data to the aggregate budget.
	if state == nil || len(state.Projects) > maxProjects || len(state.Tasks) > maxTasks || len(state.Idempotency) > maxTasks {
		return false
	}
	var total int64
	add := func(size int) bool {
		if size < 0 || int64(size) > int64(maxStateBytes) || total > int64(maxStateBytes)-int64(size) {
			return false
		}
		total += int64(size)
		return true
	}
	addStrings := func(values ...string) bool {
		for _, value := range values {
			if !add(len(value)) {
				return false
			}
		}
		return true
	}
	for id, project := range state.Projects {
		if !addStrings(id, project.ID, project.Name) {
			return false
		}
	}
	for id, task := range state.Tasks {
		if !addStrings(id, task.ID, task.ProjectID, task.IdempotencyKey, task.RequestHash, string(task.State), task.LeaseOwner) {
			return false
		}
		// Enforce the per-task dependency-count ceiling before walking the
		// caller-supplied slice. A malformed in-process task can otherwise carry
		// an arbitrarily large slice of empty strings that contributes no bytes
		// but still makes this aggregate preflight spend unbounded iteration work.
		if len(task.Dependencies) > maxTaskDependencies {
			return false
		}
		for _, dependency := range task.Dependencies {
			if !addStrings(dependency) {
				return false
			}
		}
		if task.Checkpoint != nil {
			if !addStrings(task.Checkpoint.TaskID, task.Checkpoint.Owner, string(task.Checkpoint.State)) || !add(len(task.Checkpoint.Payload)) {
				return false
			}
		}
	}
	for key, id := range state.Idempotency {
		if !addStrings(key, id) {
			return false
		}
	}
	return true
}

func (s *Store) dependenciesCompleteFrom(state *durableState, task *Task) bool {
	// The normal operation path validates the complete live state first, but
	// keep this lower readiness helper fail-closed for direct and future
	// in-process callers. An unavailable graph or task cannot establish that
	// every dependency completed, and must not become a nil-dereference panic.
	if state == nil || state.Projects == nil || len(state.Projects) > maxProjects || state.Tasks == nil || len(state.Tasks) > maxTasks || len(state.Idempotency) > maxTasks || task == nil {
		return false
	}
	// The lower readiness seam may be called with an in-process state that
	// bypassed validateState. Reject malformed map entries before using any
	// caller-controlled key as a lookup or allowing a valid candidate to mask
	// unrelated corruption in the same state snapshot.
	if !validReadinessStateMapShape(state) {
		return false
	}
	return dependenciesCompleteFromValidatedState(state, task)
}

// dependenciesCompleteFromValidatedState evaluates one candidate after the
// complete bounded state map has already passed validReadinessStateMapShape.
// Ready uses this form so the map-wide preflight is snapshot-scoped; direct
// callers continue through dependenciesCompleteFrom and retain the same
// fail-closed preflight.
func dependenciesCompleteFromValidatedState(state *durableState, task *Task) bool {
	if state == nil || task == nil {
		return false
	}
	// Readiness is scoped to the candidate task's validated project. A direct
	// in-process caller must not be able to supply an unbound task value (or a
	// task whose map entry was replaced) and use completed work from another
	// project to establish readiness.
	if validID("task", task.ID) != nil || validID("project", task.ProjectID) != nil {
		return false
	}
	project, ok := state.Projects[task.ProjectID]
	if !ok || project.ID != task.ProjectID {
		return false
	}
	// Keep the optional retry identity on the same bounded UTF-8/control
	// character contract as the persisted task validator. A direct caller must
	// not make an identically malformed key look ready merely because both the
	// map entry and candidate carry it.
	if validIdempotencyKey(task.IdempotencyKey) != nil {
		return false
	}
	candidate, ok := state.Tasks[task.ID]
	if !ok || candidate.ID != task.ID || candidate.ProjectID != task.ProjectID {
		return false
	}
	// Readiness is a plan for a task that can be newly acquired. A direct
	// caller must not use this lower helper to classify an already-running or
	// terminal task as ready merely because its dependencies are complete.
	if candidate.State != TaskPending || task.State != TaskPending || candidate.IdempotencyKey != task.IdempotencyKey || candidate.LeaseOwner != "" || !candidate.LeaseUntil.IsZero() || task.LeaseOwner != "" || !task.LeaseUntil.IsZero() || candidate.Attempt != candidate.LeaseVersion || task.Attempt != task.LeaseVersion || candidate.Attempt != task.Attempt || candidate.LeaseVersion != task.LeaseVersion {
		return false
	}
	// The caller-bound task must describe the same durable retry snapshot as
	// the canonical map entry. Readiness does not use timestamps or checkpoint
	// payloads to decide dependency completion, but accepting a substituted
	// snapshot here would let a direct in-process caller resume a different
	// piece of work under the canonical task identity.
	// Validate both checkpoint snapshots before comparing their payloads. The
	// caller-bound task is an in-process input; a substituted oversized payload
	// must fail closed without making the lower readiness helper scan it first.
	if !validReadinessCheckpoint(state, candidate) || !validReadinessCheckpoint(state, *task) {
		return false
	}
	if !candidate.CreatedAt.Equal(task.CreatedAt) || !candidate.UpdatedAt.Equal(task.UpdatedAt) || !readinessCheckpointsEqual(candidate.Checkpoint, task.Checkpoint) {
		return false
	}
	// Readiness is an acquisition plan, so a retry counter at the maximum
	// representable value is not actionable: Acquire must reject it before
	// incrementing, and Ready must not advertise a task that cannot be leased.
	if candidate.Attempt == ^uint64(0) || candidate.LeaseVersion == ^uint64(0) {
		return false
	}
	// A keyed task is only retryable through the reverse index that points back
	// to this exact task. The normal operation path validates the complete live
	// state first, but a direct in-process caller must not turn a missing or
	// substituted idempotency entry into an affirmative readiness result.
	if candidate.IdempotencyKey != "" {
		indexedID, ok := state.Idempotency[idempotencyKey(candidate.ProjectID, candidate.IdempotencyKey)]
		if !ok || indexedID != candidate.ID {
			return false
		}
	}
	// Enforce the dependency budget before comparing the caller and canonical
	// slices. A direct in-process caller can otherwise provide two equally
	// oversized definitions and make this lower readiness seam scan arbitrary
	// dependency input before it eventually rejects the task.
	if len(candidate.Dependencies) > maxTaskDependencies || len(task.Dependencies) > maxTaskDependencies {
		return false
	}
	// The map entry is the authoritative task definition. A caller-supplied
	// dependency slice that omits a real prerequisite or substitutes another
	// completed task must not turn the same task into a false-ready result.
	if len(candidate.Dependencies) != len(task.Dependencies) {
		return false
	}
	for index, dependency := range candidate.Dependencies {
		if dependency != task.Dependencies[index] {
			return false
		}
		// The persisted state contract stores dependency IDs in strictly
		// increasing order. Keep this lower readiness seam on that same
		// canonical representation so a direct caller cannot make a malformed
		// duplicate or unsorted dependency list appear ready merely because
		// every referenced task is completed.
		if index > 0 && candidate.Dependencies[index-1] >= dependency {
			return false
		}
	}
	// Persisted and exported-operation inputs are already validated, but this
	// lower helper keeps the same dependency identifier budget when called
	// independently.
	for _, dep := range task.Dependencies {
		// Keep direct callers on the complete dependency-ID contract before
		// using malformed text as a task-map key. A bounded but empty or
		// control-character identifier must not make a malformed task appear
		// ready merely because an in-process map contains the same key.
		if validID("dependency", dep) != nil {
			return false
		}
		dependency, ok := state.Tasks[dep]
		// A direct in-process state map can contain a valid key whose embedded
		// task identity was replaced or never initialized. Do not let that
		// malformed entry establish readiness merely because its state says
		// completed; persisted validation requires the same key/identity match.
		if !ok || !validCompletedDependencyForReadiness(state, dep, dependency, task.ProjectID) {
			return false
		}
	}
	// The durable validator binds readiness to the task's request fingerprint
	// as well as its dependency list. Bind the caller's fingerprint to the
	// canonical map entry too: a malformed in-process task must not report
	// ready merely because its dependencies happen to be complete.
	const requestHashLength = sha256.Size * 2
	expectedRequestHash := taskHash(candidate.ProjectID, candidate.Dependencies)
	if len(candidate.RequestHash) != requestHashLength || candidate.RequestHash != expectedRequestHash || len(task.RequestHash) != requestHashLength || task.RequestHash != candidate.RequestHash {
		return false
	}
	return true
}

func validCompletedDependencyForReadiness(state *durableState, id string, dependency Task, projectID string) bool {
	if state == nil || state.Tasks == nil || len(state.Tasks) > maxTasks || dependency.ID != id || dependency.ProjectID != projectID || dependency.State != TaskCompleted || dependency.LeaseOwner != "" || !dependency.LeaseUntil.IsZero() || dependency.Attempt != dependency.LeaseVersion {
		return false
	}
	// The caller normally passes the value read directly from state.Tasks, but
	// this helper is also an in-process lower seam. Bind the supplied completed
	// dependency back to its canonical map entry before inspecting completion;
	// otherwise a substituted same-ID task could attest completion while
	// carrying different retry, timestamp, checkpoint, or dependency metadata.
	canonical, ok := state.Tasks[id]
	if !ok || !readinessTaskSnapshotsEqual(canonical, dependency) {
		return false
	}
	// The map-wide readiness preflight normally validates every task before
	// reaching this helper, but keep the completed-dependency seam safe when it
	// is called directly or by a future in-process integration. A supplied
	// fingerprint must bind the dependency to its project-local graph, and a
	// dependency list must remain bounded and canonical before hashing it. Keep
	// the empty fingerprint/list compatibility used by partial completed-task
	// fixtures.
	if len(dependency.Dependencies) > maxTaskDependencies {
		return false
	}
	for index, dep := range dependency.Dependencies {
		if validID("dependency", dep) != nil || (index > 0 && dependency.Dependencies[index-1] >= dep) {
			return false
		}
	}
	if dependency.RequestHash != "" {
		const requestHashLength = sha256.Size * 2
		if len(dependency.RequestHash) != requestHashLength || dependency.RequestHash != taskHash(projectID, dependency.Dependencies) {
			return false
		}
	}
	if dependency.IdempotencyKey != "" {
		if validIdempotencyKey(dependency.IdempotencyKey) != nil || state.Idempotency == nil || state.Idempotency[idempotencyKey(dependency.ProjectID, dependency.IdempotencyKey)] != id {
			return false
		}
	}
	checkpoint := dependency.Checkpoint
	if checkpoint == nil {
		return true
	}
	// Direct readiness callers may provide a partially modeled completed task,
	// but an explicitly retained checkpoint must still obey the terminal shape
	// before it can attest that a dependency is complete. Its timestamp must
	// also be representable and remain within the task lifetime, and its global
	// sequence must not alias another task's checkpoint.
	if state.Tasks == nil || len(state.Tasks) > maxTasks || checkpoint.TaskID != id || validID("checkpoint owner", checkpoint.Owner) != nil || checkpoint.LeaseVersion == 0 || checkpoint.LeaseVersion != dependency.LeaseVersion || checkpoint.Sequence == 0 || checkpoint.Sequence > state.NextSequence || checkpoint.State != TaskCompleted || len(checkpoint.Payload) > maxPayloadBytes || validateStateTimestamp("checkpoint created_at", checkpoint.CreatedAt) != nil || validateStateTimestamp("dependency created_at", dependency.CreatedAt) != nil || validateStateTimestamp("dependency updated_at", dependency.UpdatedAt) != nil || dependency.UpdatedAt.Before(dependency.CreatedAt) || checkpoint.CreatedAt.Before(dependency.CreatedAt) || checkpoint.CreatedAt.After(dependency.UpdatedAt) {
		return false
	}
	return readinessCheckpointSequenceUnique(state, id, checkpoint.Sequence)
}

func readinessTaskSnapshotsEqual(left, right Task) bool {
	if left.ID != right.ID || left.ProjectID != right.ProjectID || left.IdempotencyKey != right.IdempotencyKey || left.RequestHash != right.RequestHash || left.State != right.State || left.Attempt != right.Attempt || left.LeaseOwner != right.LeaseOwner || left.LeaseVersion != right.LeaseVersion || !left.LeaseUntil.Equal(right.LeaseUntil) || !left.CreatedAt.Equal(right.CreatedAt) || !left.UpdatedAt.Equal(right.UpdatedAt) || !readinessCheckpointsEqual(left.Checkpoint, right.Checkpoint) {
		return false
	}
	if len(left.Dependencies) != len(right.Dependencies) || len(left.Dependencies) > maxTaskDependencies || len(right.Dependencies) > maxTaskDependencies {
		return false
	}
	for index := range left.Dependencies {
		if left.Dependencies[index] != right.Dependencies[index] {
			return false
		}
	}
	return true
}

func validReadinessCheckpoint(state *durableState, task Task) bool {
	checkpoint := task.Checkpoint
	if checkpoint == nil {
		return true
	}
	// Pending tasks may retain only a valid running checkpoint from an earlier
	// or current lease. Keep this lower readiness seam on the same bounded
	// representation as validateState before comparing any caller payload.
	if state == nil || state.Tasks == nil || len(state.Tasks) > maxTasks || checkpoint.TaskID != task.ID || validID("checkpoint owner", checkpoint.Owner) != nil || checkpoint.LeaseVersion == 0 || checkpoint.Sequence == 0 || checkpoint.Sequence > state.NextSequence || checkpoint.State != TaskRunning || len(checkpoint.Payload) > maxPayloadBytes || validateStateTimestamp("checkpoint created_at", checkpoint.CreatedAt) != nil || checkpoint.CreatedAt.Before(task.CreatedAt) || checkpoint.CreatedAt.After(task.UpdatedAt) || checkpoint.LeaseVersion > task.LeaseVersion {
		return false
	}
	// Durable validation assigns each checkpoint sequence to exactly one task.
	// Preserve that invariant at this lower readiness boundary too: a malformed
	// in-process state with a sequence shared by another task must not make a
	// pending candidate appear resumable merely because its own snapshot is
	// otherwise well-shaped.
	return readinessCheckpointSequenceUnique(state, task.ID, checkpoint.Sequence)
}

func readinessCheckpointSequenceUnique(state *durableState, taskID string, sequence uint64) bool {
	if state == nil || state.Tasks == nil || len(state.Tasks) > maxTasks {
		return false
	}
	for id, task := range state.Tasks {
		if id != taskID && task.Checkpoint != nil && task.Checkpoint.Sequence == sequence {
			return false
		}
	}
	return true
}

func readinessCheckpointsEqual(left, right *Checkpoint) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.TaskID == right.TaskID && left.Owner == right.Owner && left.LeaseVersion == right.LeaseVersion && left.Sequence == right.Sequence && left.State == right.State && bytes.Equal(left.Payload, right.Payload) && left.CreatedAt.Equal(right.CreatedAt)
}

func (s *Store) commitLocked(next *durableState) error {
	if err := s.validateRootForWrite(); err != nil {
		return err
	}
	// Revalidate the candidate after the operation has derived it from the
	// live state and before it can replace the durable checkpoint. The live
	// state is checked on admission, but an in-process clock or integration
	// seam can still influence a later mutation; never serialize a candidate
	// that reopen would reject.
	if next == nil {
		return fmt.Errorf("%w: lifecycle candidate state is nil", ErrInvalid)
	}
	if err := validateState(next); err != nil {
		return fmt.Errorf("validate lifecycle candidate state: %w", err)
	}
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode lifecycle state: %w", err)
	}
	if len(b) > maxStateBytes {
		return fmt.Errorf("%w: lifecycle state exceeds %d bytes", ErrInvalid, maxStateBytes)
	}
	if s.persistHook != nil {
		if err := s.persistHook(b); err != nil {
			return fmt.Errorf("persist lifecycle state: %w", err)
		}
	} else {
		if s.beforeAtomicWrite != nil {
			if err := s.beforeAtomicWrite(); err != nil {
				return fmt.Errorf("pre-commit lifecycle test hook: %w", err)
			}
		}
		var syncDirectory func(string) error
		if s.syncDirectoryHook != nil {
			syncDirectory = s.syncDirectoryHook
		}
		if err := atomicWriteLifecycleState(s.rootDir, filepath.Join(s.root, "lifecycle.json"), b, s.validateRootForWrite, syncDirectory); err != nil {
			var writeErr *atomicWriteError
			if errors.As(err, &writeErr) && writeErr.installed {
				// The replacement is visible, but its containing directory did
				// not cross the requested durability boundary. Do not leave an
				// older in-memory state writable: a later mutation could
				// overwrite the newly installed checkpoint. Reopen the store to
				// establish state from disk after the supervisor reviews the
				// durability failure.
				s.quarantineAfterInstalledWriteFailure()
			}
			return fmt.Errorf("persist lifecycle state: %w", err)
		}
	}
	s.state = next
	return nil
}

func (s *Store) quarantineAfterInstalledWriteFailure() {
	s.closed = true
	if s.lockFile == nil {
		return
	}
	lockFile := s.lockFile
	s.lockFile = nil
	_ = closeLifecycleLock(lockFile)
	rootDir := s.rootDir
	s.rootDir = nil
	_ = closeLifecycleStoreDirectory(rootDir)
}

// validateRootForWrite keeps the durable checkpoint attached to the same
// private directory whose lock was acquired at Open time. A pathname can be
// replaced after the lock is opened; following that replacement would allow a
// mutation to write through a symlink or into an unrelated directory. The
// identity check is intentionally repeated immediately before serialization.
func (s *Store) validateRootForWrite() error {
	if s == nil || s.rootInfo == nil || !filepath.IsAbs(s.root) {
		return fmt.Errorf("%w: lifecycle state root identity is unavailable", ErrInvalid)
	}
	if err := s.validateRootIdentity(); err != nil {
		return err
	}
	// The root and lock are one ownership boundary. Recheck the lock at the
	// same final preflight used immediately before temporary-file creation and
	// replacement, so a pathname replacement after operation admission cannot
	// leave the old store writing beside a newly admitted replacement lock.
	return validateLifecycleLockIdentity(filepath.Join(s.root, ".lifecycle.lock"), s.lockInfo)
}

// validateRootIdentity checks that the open store still points at the same
// private directory whose lock was acquired. Both reads and writes use this
// boundary; a stale in-memory read can be just as misleading as a redirected
// durable write after a root pathname is replaced.
func (s *Store) validateRootIdentity() error {
	if s == nil || s.rootInfo == nil || !filepath.IsAbs(s.root) {
		return fmt.Errorf("%w: lifecycle state root identity is unavailable", ErrInvalid)
	}
	// Reuse the complete no-follow observation used while opening the store.
	// A single Lstat/Stat pair is insufficient here: the pathname can become a
	// symlink or another directory between those calls. The before/after
	// observation must remain identical for every live read and write boundary.
	if _, err := validateLifecycleRootPath(s.root, s.rootInfo); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: lifecycle state root is unavailable", ErrConflict)
		}
		return err
	}
	return nil
}

func atomicWrite(path string, b []byte) error {
	return atomicWriteWithPreflight(path, b, nil)
}

type atomicWriteError struct {
	err       error
	installed bool
}

func (e *atomicWriteError) Error() string { return e.err.Error() }
func (e *atomicWriteError) Unwrap() error { return e.err }

// atomicWriteWithPreflight performs caller-supplied boundary checks after the
// parent directory has been selected, both before the temporary replacement is
// created and again immediately before it is installed. Store commits use the
// second check to close the pathname/root-identity gap opened while the
// replacement is being written; direct helper callers retain the historical
// no-preflight behavior.
func atomicWriteWithPreflight(path string, b []byte, preflight func() error) error {
	return atomicWriteWithPreflightAndSync(path, b, preflight, syncLifecycleDirectory)
}

func atomicWriteWithPreflightAndSync(path string, b []byte, preflight func() error, syncDirectory func(string) error) error {
	fail := func(err error, installed bool) error {
		if err == nil {
			return nil
		}
		return &atomicWriteError{err: err, installed: installed}
	}
	dir := filepath.Dir(path)
	if preflight != nil {
		if err := preflight(); err != nil {
			return fail(err, false)
		}
	}
	tmp, err := os.CreateTemp(dir, ".lifecycle-*")
	if err != nil {
		return fail(err, false)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fail(err, false)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fail(err, false)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fail(err, false)
	}
	if err := tmp.Close(); err != nil {
		return fail(err, false)
	}
	if preflight != nil {
		if err := preflight(); err != nil {
			return fail(err, false)
		}
	}
	if err := replaceLifecycleFile(tmpName, path); err != nil {
		return fail(err, false)
	}
	if err := callLifecycleDirectorySync(syncDirectory, dir); err != nil {
		return fail(err, true)
	}
	return nil
}

// callLifecycleDirectorySync contains a malformed or future platform sync
// seam after replacement installation. The replacement is already visible at
// this point, so a panic must become an installed-write failure and let the
// caller quarantine the in-memory store instead of escaping with stale state
// still writable.
func callLifecycleDirectorySync(syncDirectory func(string) error, path string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("lifecycle directory sync panicked")
		}
	}()
	if syncDirectory == nil {
		return errors.New("lifecycle directory sync is nil")
	}
	return syncDirectory(path)
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := openLifecycleState(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readBoundedFile(f, limit)
}

func readBoundedFile(f *os.File, limit int64) ([]byte, error) {
	if f == nil {
		return nil, errors.New("lifecycle state file is nil")
	}
	// A non-nil descriptor can still be closed by a malformed in-process
	// integration. Reject it before handing the handle to io.ReadAll so direct
	// callers receive the same bounded ownership result as the descriptor-
	// relative state reader.
	if !lifecycleFileReady(f) {
		return nil, ErrClosed
	}
	// LimitReader treats a negative limit as an already-exhausted reader, and
	// limit+1 would overflow at MaxInt64. Reject invalid and overlarge bounds
	// before any read so a malformed internal caller cannot turn an unbounded
	// request into a misleading successful empty checkpoint or a large
	// allocation. The helper is specific to the persisted lifecycle state, so
	// its caller cannot widen the documented 8 MiB state ceiling.
	if limit < 0 || limit > maxStateBytes || limit == int64(^uint64(0)>>1) {
		return nil, fmt.Errorf("%w: lifecycle state read limit is invalid", ErrInvalid)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("state exceeds %d bytes", limit)
	}
	return b, nil
}

// cloneStateForMutation converts the lower clone helper's nil rejection into
// an operation error before any mutation path dereferences the candidate. The
// normal admission check already validates the live state, but an in-process
// seam can change it after admission (for example, an injected clock callback)
// and must fail closed rather than turn bounded corruption into a panic.
func (s *Store) cloneStateForMutation() (*durableState, error) {
	if s == nil || s.state == nil {
		return nil, ErrClosed
	}
	next := s.state.clone()
	if next == nil {
		return nil, fmt.Errorf("%w: lifecycle mutation state clone rejected", ErrInvalid)
	}
	return next, nil
}

func (s *durableState) clone() *durableState {
	// Exported operations establish a validated live state before cloning, but
	// keep this lower helper safe for direct and future in-process callers. A
	// missing, unsupported-version, structurally oversized, or aggregate-
	// oversized durable state cannot produce a trustworthy candidate checkpoint,
	// and must be rejected before map allocation or slice/payload copying begins.
	if s == nil || s.Version != stateVersion || s.Projects == nil || s.Tasks == nil || s.Idempotency == nil || len(s.Projects) > maxProjects || len(s.Tasks) > maxTasks || len(s.Idempotency) > maxTasks || !stateVariableBudgetWithin(s) {
		return nil
	}
	// The aggregate byte budget does not replace the narrower identity and
	// project-name ceilings. Reject a single oversized field before allocating
	// replacement maps so a direct caller cannot make clone retain a bounded-
	// aggregate but invalid identifier/name.
	if !stateCloneShapeWithin(s) {
		return nil
	}
	// The aggregate raw-variable budget above does not replace the individual
	// checkpoint ceiling. Reject an oversized payload before allocating the
	// replacement maps or copying any dependency slice/payload; otherwise a
	// malformed lower caller could still make clone copy several MiB that the
	// durable validator would reject as one checkpoint.
	for _, task := range s.Tasks {
		if len(task.Dependencies) > maxTaskDependencies || (task.Checkpoint != nil && len(task.Checkpoint.Payload) > maxPayloadBytes) {
			return nil
		}
	}
	// Raw-variable bounds do not account for checkpoint-payload base64 expansion
	// or JSON field overhead. Reject the exact durable representation before
	// allocating replacement maps or copying nested task data, matching the
	// lower readiness and commit boundaries.
	if !stateSerializedWithinBudget(s) {
		return nil
	}
	next := &durableState{Version: s.Version, NextSequence: s.NextSequence, Projects: make(map[string]Project, len(s.Projects)), Tasks: make(map[string]Task, len(s.Tasks)), Idempotency: make(map[string]string, len(s.Idempotency))}
	for id, project := range s.Projects {
		next.Projects[id] = project
	}
	for id, task := range s.Tasks {
		next.Tasks[id] = cloneTask(task)
	}
	for key, id := range s.Idempotency {
		next.Idempotency[key] = id
	}
	return next
}

// stateCloneShapeWithin applies the length portions of the durable identity
// contract before clone allocates replacement maps or copies nested slices.
// Full UTF-8, character, relationship, timestamp, and state-transition
// validation remains the responsibility of validateState; this lower helper
// only prevents one bounded aggregate field from bypassing its local size
// ceiling and consuming clone work.
func stateCloneShapeWithin(state *durableState) bool {
	if state == nil {
		return false
	}
	for id, project := range state.Projects {
		if len(id) > maxIDLength || len(project.ID) > maxIDLength || len(project.Name) > maxNameLength {
			return false
		}
	}
	for id, task := range state.Tasks {
		if len(id) > maxIDLength || len(task.ID) > maxIDLength || len(task.ProjectID) > maxIDLength || len(task.IdempotencyKey) > maxIDLength || len(task.RequestHash) > maxIDLength || len(string(task.State)) > maxIDLength || len(task.LeaseOwner) > maxIDLength {
			return false
		}
		for _, dependency := range task.Dependencies {
			if len(dependency) > maxIDLength {
				return false
			}
		}
		if task.Checkpoint != nil && (len(task.Checkpoint.TaskID) > maxIDLength || len(task.Checkpoint.Owner) > maxIDLength || len(string(task.Checkpoint.State)) > maxIDLength) {
			return false
		}
	}
	for key, id := range state.Idempotency {
		if len(key) > maxIdempotencyIndexKeyLength || len(id) > maxIDLength {
			return false
		}
	}
	return true
}

func cloneTask(task Task) Task {
	// Store operations validate the complete state before reaching this helper,
	// but keep the lowest task-copy seam fail-closed for direct or future
	// in-process callers. Returning a zero task is the only error-free signal
	// available here; valid store tasks always satisfy these bounds, while an
	// oversized identity, dependency slice, or checkpoint payload must not be
	// copied.
	if !taskCloneShapeWithin(task) {
		return Task{}
	}
	task.Dependencies = append([]string(nil), task.Dependencies...)
	if task.Checkpoint != nil {
		checkpoint := *task.Checkpoint
		checkpoint.Payload = append([]byte(nil), checkpoint.Payload...)
		task.Checkpoint = &checkpoint
	}
	return task
}

// taskCloneShapeWithin applies the local length portions of the durable task
// contract before cloneTask allocates nested copies. Full UTF-8, relationship,
// timestamp, and state-transition validation remains the responsibility of
// validateState; this lower helper only prevents a direct in-process caller
// from making the defensive-copy seam retain oversized identity data.
func taskCloneShapeWithin(task Task) bool {
	if len(task.ID) > maxIDLength || len(task.ProjectID) > maxIDLength || len(task.IdempotencyKey) > maxIDLength || len(task.RequestHash) > maxIDLength || len(task.LeaseOwner) > maxIDLength || len(string(task.State)) > maxIDLength || len(task.Dependencies) > maxTaskDependencies {
		return false
	}
	for _, dependency := range task.Dependencies {
		if len(dependency) > maxIDLength {
			return false
		}
	}
	if task.Checkpoint != nil {
		if len(task.Checkpoint.TaskID) > maxIDLength || len(task.Checkpoint.Owner) > maxIDLength || len(string(task.Checkpoint.State)) > maxIDLength || len(task.Checkpoint.Payload) > maxPayloadBytes {
			return false
		}
	}
	return true
}

func validateState(state *durableState) error {
	if state == nil || state.Version != stateVersion || state.Projects == nil || state.Tasks == nil || state.Idempotency == nil {
		return fmt.Errorf("%w: unsupported or incomplete state", ErrInvalid)
	}
	if len(state.Projects) > maxProjects || len(state.Tasks) > maxTasks || len(state.Idempotency) > maxTasks {
		return fmt.Errorf("%w: state limits exceeded", ErrInvalid)
	}
	// Preserve the established bounded "too large" classification before the
	// shared raw-variable scan. This also ensures a malformed dependency slice
	// is rejected by count without iterating its contents.
	for _, task := range state.Tasks {
		if len(task.Dependencies) > maxTaskDependencies {
			return fmt.Errorf("%w: task is too large: dependencies exceed %d", ErrInvalid, maxTaskDependencies)
		}
	}
	// Run the aggregate raw-variable preflight before any task request hash is
	// recomputed. This keeps direct in-process state mutation on the same
	// resource boundary as persisted JSON and avoids hashing or cloning a
	// snapshot whose attacker-controlled strings and payloads already exceed
	// the durable state budget.
	if !stateVariableBudgetWithin(state) {
		return fmt.Errorf("%w: lifecycle state variable data exceeds %d bytes", ErrInvalid, maxStateBytes)
	}
	checkpointSequences := make(map[uint64]string)
	for id, project := range state.Projects {
		// The normal persisted-state size cap bounds decoded map keys, but a
		// malformed in-process state can still carry an oversized key. Reject it
		// before including the key in a diagnostic.
		if len(id) > maxIDLength {
			return fmt.Errorf("%w: lifecycle project identifier exceeds %d bytes", ErrInvalid, maxIDLength)
		}
		if project.ID != id || validID("project", id) != nil || validName(project.Name) != nil {
			return fmt.Errorf("%w: invalid project %q", ErrInvalid, id)
		}
		if err := validateStateTimestamp("project created_at", project.CreatedAt); err != nil {
			return fmt.Errorf("%w for %q", err, id)
		}
		if err := validateStateTimestamp("project updated_at", project.UpdatedAt); err != nil {
			return fmt.Errorf("%w for %q", err, id)
		}
		if project.UpdatedAt.Before(project.CreatedAt) {
			return fmt.Errorf("%w: invalid project timestamps for %q", ErrInvalid, id)
		}
	}
	for id, task := range state.Tasks {
		// Keep direct callers on the same bounded identifier surface as the
		// persisted graph validator before any task-key diagnostic is formatted.
		if len(id) > maxIDLength {
			return fmt.Errorf("%w: lifecycle task identifier exceeds %d bytes", ErrInvalid, maxIDLength)
		}
		if task.ID != id || validID("task", id) != nil || task.RequestHash == "" || !validTaskState(task.State) {
			return fmt.Errorf("%w: invalid task %q", ErrInvalid, id)
		}
		if err := validateStateTimestamp("task created_at", task.CreatedAt); err != nil {
			return fmt.Errorf("%w for %q", err, id)
		}
		if err := validateStateTimestamp("task updated_at", task.UpdatedAt); err != nil {
			return fmt.Errorf("%w for %q", err, id)
		}
		if task.UpdatedAt.Before(task.CreatedAt) {
			return fmt.Errorf("%w: invalid task timestamps for %q", ErrInvalid, id)
		}
		if err := validIdempotencyKey(task.IdempotencyKey); err != nil {
			return fmt.Errorf("%w for task %q", err, id)
		}
		if len(task.ProjectID) > maxIDLength {
			return fmt.Errorf("%w: lifecycle task project identifier exceeds %d bytes", ErrInvalid, maxIDLength)
		}
		if _, ok := state.Projects[task.ProjectID]; !ok {
			return fmt.Errorf("%w: task project %q missing", ErrInvalid, task.ProjectID)
		}
		project := state.Projects[task.ProjectID]
		if task.CreatedAt.Before(project.CreatedAt) {
			return fmt.Errorf("%w: task %q predates its project", ErrInvalid, id)
		}
		if len(task.Dependencies) > maxTaskDependencies || (task.Checkpoint != nil && len(task.Checkpoint.Payload) > maxPayloadBytes) {
			return fmt.Errorf("%w: task %q is too large", ErrInvalid, id)
		}
		for i, dep := range task.Dependencies {
			if validID("dependency", dep) != nil || (i > 0 && task.Dependencies[i-1] >= dep) {
				return fmt.Errorf("%w: dependencies for %q are not canonical", ErrInvalid, id)
			}
		}
		// Apply the bounded dependency contract before hashing. Persisted input
		// is already capped, but a direct in-process caller can construct a
		// malformed task with oversized dependency text; hashing it first would
		// spend work on data the validator must reject anyway.
		if task.RequestHash != taskHash(task.ProjectID, task.Dependencies) {
			return fmt.Errorf("%w: request hash for %q does not match task dependencies", ErrInvalid, id)
		}
		for _, dep := range task.Dependencies {
			dependency, ok := state.Tasks[dep]
			if !ok || dependency.ProjectID != task.ProjectID || dep == id {
				return fmt.Errorf("%w: invalid dependency for %q", ErrInvalid, id)
			}
		}
		if task.State == TaskRunning && (validID("lease owner", task.LeaseOwner) != nil || task.LeaseUntil.IsZero() || task.LeaseVersion == 0) {
			return fmt.Errorf("%w: running task %q has no lease", ErrInvalid, id)
		}
		if task.State == TaskRunning {
			if err := validateStateTimestamp("task lease_until", task.LeaseUntil); err != nil {
				return fmt.Errorf("%w for %q", err, id)
			}
		}
		// Acquire increments attempt and lease version together, and no other
		// lifecycle operation changes either counter. A persisted mismatch
		// would make retry history disagree with lease ownership history.
		if task.Attempt != task.LeaseVersion {
			return fmt.Errorf("%w: attempt and lease version for %q are inconsistent", ErrInvalid, id)
		}
		if task.State == TaskRunning && !task.LeaseUntil.After(task.UpdatedAt) {
			return fmt.Errorf("%w: running lease for %q does not outlive task update", ErrInvalid, id)
		}
		if task.State == TaskRunning && task.LeaseUntil.Sub(task.UpdatedAt) > maxLease {
			return fmt.Errorf("%w: running lease for %q exceeds maximum duration", ErrInvalid, id)
		}
		if task.State != TaskRunning && (task.LeaseOwner != "" || !task.LeaseUntil.IsZero()) {
			return fmt.Errorf("%w: non-running task %q has a lease", ErrInvalid, id)
		}
		if task.Checkpoint != nil && (task.Checkpoint.TaskID != id || validID("checkpoint owner", task.Checkpoint.Owner) != nil || task.Checkpoint.LeaseVersion == 0 || task.Checkpoint.Sequence == 0 || task.Checkpoint.CreatedAt.IsZero() || !validTaskState(task.Checkpoint.State) || task.Checkpoint.State == TaskPending) {
			return fmt.Errorf("%w: invalid checkpoint for %q", ErrInvalid, id)
		}
		if task.Checkpoint != nil {
			if err := validateStateTimestamp("checkpoint created_at", task.Checkpoint.CreatedAt); err != nil {
				return fmt.Errorf("%w for %q", err, id)
			}
			if task.Checkpoint.CreatedAt.Before(task.CreatedAt) || task.Checkpoint.CreatedAt.After(task.UpdatedAt) {
				return fmt.Errorf("%w: checkpoint timestamp for %q is outside task lifetime", ErrInvalid, id)
			}
			switch task.State {
			case TaskPending, TaskRunning:
				if task.Checkpoint.State != TaskRunning {
					return fmt.Errorf("%w: checkpoint state for %q does not match resumable task", ErrInvalid, id)
				}
			case TaskCompleted, TaskFailed, TaskCancelled:
				if task.Checkpoint.State != task.State {
					return fmt.Errorf("%w: checkpoint state for %q does not match terminal task", ErrInvalid, id)
				}
			}
		}
		if task.State == TaskCompleted || task.State == TaskFailed || task.State == TaskCancelled {
			if task.Checkpoint == nil {
				return fmt.Errorf("%w: terminal task %q has no checkpoint", ErrInvalid, id)
			}
		}
		if task.State == TaskRunning && task.Checkpoint != nil {
			// A recovered task may retain the last running checkpoint from an
			// earlier lease so the next owner can resume from its durable
			// payload. Once the new owner records progress, the checkpoint must
			// match the active lease again; a same-version mismatch is never
			// accepted.
			if task.Checkpoint.LeaseVersion == task.LeaseVersion && task.Checkpoint.Owner != task.LeaseOwner {
				return fmt.Errorf("%w: running task %q checkpoint does not match active lease", ErrInvalid, id)
			}
		}
		if task.Checkpoint != nil && task.Checkpoint.LeaseVersion > task.LeaseVersion {
			return fmt.Errorf("%w: checkpoint lease version for %q exceeds task lease version", ErrInvalid, id)
		}
		if task.Checkpoint != nil && task.State != TaskPending && task.State != TaskRunning && task.Checkpoint.LeaseVersion != task.LeaseVersion {
			return fmt.Errorf("%w: terminal checkpoint lease version for %q does not match task lease version", ErrInvalid, id)
		}
		if task.Checkpoint != nil && task.Checkpoint.Sequence > state.NextSequence {
			return fmt.Errorf("%w: checkpoint sequence for %q exceeds state sequence", ErrInvalid, id)
		}
		if task.Checkpoint != nil {
			if previousTask, exists := checkpointSequences[task.Checkpoint.Sequence]; exists {
				return fmt.Errorf("%w: checkpoint sequence %d is shared by tasks %q and %q", ErrInvalid, task.Checkpoint.Sequence, previousTask, id)
			}
			checkpointSequences[task.Checkpoint.Sequence] = id
		}
		if task.IdempotencyKey != "" {
			key := idempotencyKey(task.ProjectID, task.IdempotencyKey)
			if state.Idempotency[key] != id {
				return fmt.Errorf("%w: missing idempotency mapping for %q", ErrInvalid, id)
			}
		}
	}
	for key, id := range state.Idempotency {
		// Bound and structurally validate both map strings before using the
		// attacker-controlled value as a task-map lookup. The index is derived
		// from a valid project ID and non-empty idempotency key, so accepting a
		// larger or malformed entry would only add parser/repair work without
		// representing a durable mapping.
		separator := strings.IndexByte(key, 0)
		if len(key) > maxIdempotencyIndexKeyLength || len(id) > maxIDLength || separator <= 0 || separator == len(key)-1 || strings.IndexByte(key[separator+1:], 0) >= 0 || validID("idempotency project", key[:separator]) != nil || validIdempotencyKey(key[separator+1:]) != nil || validID("idempotency task", id) != nil {
			return fmt.Errorf("%w: idempotency mapping is malformed or too large", ErrInvalid)
		}
		task, ok := state.Tasks[id]
		if key == "" || !ok || task.IdempotencyKey == "" || key != idempotencyKey(task.ProjectID, task.IdempotencyKey) {
			return fmt.Errorf("%w: invalid idempotency mapping", ErrInvalid)
		}
	}
	if err := validateTaskDAG(state); err != nil {
		return err
	}
	return nil
}

// validateStateTimestamp keeps live and durable state on the same timestamp
// surface as encoding/json. Persisted decoding normally enforces this, but an
// in-process integration can mutate the private state after Open; fail closed
// before a read or a derived candidate serves an unrepresentable timestamp.
func validateStateTimestamp(kind string, value time.Time) error {
	if value.IsZero() {
		return fmt.Errorf("%w: %s is zero", ErrInvalid, kind)
	}
	if _, err := value.MarshalJSON(); err != nil {
		return fmt.Errorf("%w: %s is unrepresentable", ErrInvalid, kind)
	}
	return nil
}

// validateTaskDAG rejects dependency cycles in persisted state. CreateTask
// only accepts dependencies that already exist, so cycles cannot be produced
// through the API; reopen must still fail closed if a state file was tampered
// with or repaired incorrectly. The traversal is iterative so the bounded
// persisted graph consumes explicit heap-backed work rather than growing the
// goroutine call stack for a long dependency chain.
func validateTaskDAG(state *durableState) error {
	// validateState normally establishes this shape before calling the graph
	// walk, but keep the lower helper fail-closed for direct and future
	// in-process callers. A missing dependency must not be treated as an
	// implicit zero-value task: that would make an incomplete graph appear
	// acyclic and could let a readiness/recovery caller proceed from malformed
	// state.
	if state == nil || state.Tasks == nil {
		return fmt.Errorf("%w: lifecycle task graph is unavailable", ErrInvalid)
	}
	if len(state.Tasks) > maxTasks {
		return fmt.Errorf("%w: lifecycle task graph exceeds %d tasks", ErrInvalid, maxTasks)
	}
	const (
		unvisited = uint8(iota)
		visiting
		visited
	)
	type frame struct {
		id      string
		nextDep int
	}
	colors := make(map[string]uint8, len(state.Tasks))
	ids := make([]string, 0, len(state.Tasks))
	for id := range state.Tasks {
		// The full state validator applies the complete task-ID contract before
		// reaching this graph walk, but direct callers can invoke the lower
		// helper with a malformed map key or a value whose embedded identity does
		// not match that key. Reject both before sorting or using the key in an
		// error so graph work and diagnostics remain bounded and malformed task
		// values cannot become graph vertices.
		if len(id) > maxIDLength {
			return fmt.Errorf("%w: lifecycle task graph identifier exceeds %d bytes", ErrInvalid, maxIDLength)
		}
		if validID("task graph", id) != nil {
			return fmt.Errorf("%w: lifecycle task graph identifier is invalid", ErrInvalid)
		}
		if task := state.Tasks[id]; task.ID != id || validID("task graph task", task.ID) != nil {
			return fmt.Errorf("%w: lifecycle task graph task identity is invalid", ErrInvalid)
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		if colors[id] != unvisited {
			continue
		}
		colors[id] = visiting
		stack := []frame{{id: id}}
		for len(stack) > 0 {
			current := &stack[len(stack)-1]
			task, ok := state.Tasks[current.id]
			if !ok {
				return fmt.Errorf("%w: dependency task %q is missing", ErrInvalid, current.id)
			}
			dependencies := task.Dependencies
			if len(dependencies) > maxTaskDependencies {
				return fmt.Errorf("%w: dependencies for %q exceed %d", ErrInvalid, current.id, maxTaskDependencies)
			}
			for _, dependency := range dependencies {
				// A dependency is used as a map key and may appear in a
				// diagnostic below. Keep direct graph callers on the same bounded
				// identifier surface as persisted state before either operation;
				// bounded but malformed text must not become a graph edge.
				if len(dependency) > maxIDLength {
					return fmt.Errorf("%w: lifecycle dependency identifier exceeds %d bytes", ErrInvalid, maxIDLength)
				}
				if validID("dependency", dependency) != nil {
					return fmt.Errorf("%w: lifecycle dependency identifier is invalid", ErrInvalid)
				}
			}
			if current.nextDep >= len(dependencies) {
				colors[current.id] = visited
				stack = stack[:len(stack)-1]
				continue
			}
			dependency := dependencies[current.nextDep]
			current.nextDep++
			switch colors[dependency] {
			case visiting:
				return fmt.Errorf("%w: dependency cycle includes task %q", ErrInvalid, dependency)
			case visited:
				continue
			default:
				if _, ok := state.Tasks[dependency]; !ok {
					return fmt.Errorf("%w: dependency task %q is missing", ErrInvalid, dependency)
				}
				colors[dependency] = visiting
				stack = append(stack, frame{id: dependency})
			}
		}
	}
	return nil
}

func (task Task) CheckpointPayload() []byte {
	if task.Checkpoint == nil {
		return nil
	}
	// Exported Task values can be constructed by an in-process caller without
	// passing through the store's checkpoint validator. Do not copy an
	// oversized payload from that lower seam; the durable checkpoint contract
	// caps payloads at maxPayloadBytes and this accessor has no error return with
	// which to report a malformed value. Valid payloads retain their defensive
	// copy semantics, while an unavailable/oversized payload fails closed as
	// nil.
	if len(task.Checkpoint.Payload) > maxPayloadBytes {
		return nil
	}
	// A Task may be copied while its optional Checkpoint pointer remains
	// shared. Return an independent payload so the convenience accessor cannot
	// mutate checkpoint state through an alias held by another task value.
	return append([]byte(nil), task.Checkpoint.Payload...)
}

func validTaskState(state TaskState) bool {
	switch state {
	case TaskPending, TaskRunning, TaskCompleted, TaskFailed, TaskCancelled:
		return true
	default:
		return false
	}
}

func validID(kind, value string) error {
	if value == "" || len(value) > maxIDLength || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/?#") {
		return fmt.Errorf("%w: %s ID is invalid", ErrInvalid, kind)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s ID is not valid UTF-8", ErrInvalid, kind)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return fmt.Errorf("%w: %s ID contains control characters", ErrInvalid, kind)
		}
	}
	return nil
}

func validName(value string) error {
	if value == "" || len(value) > maxNameLength || strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: project name is invalid", ErrInvalid)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: project name is not valid UTF-8", ErrInvalid)
	}
	if containsControlCharacters(value) {
		return fmt.Errorf("%w: project name contains control characters", ErrInvalid)
	}
	return nil
}

func validIdempotencyKey(value string) error {
	if len(value) > maxIDLength {
		return fmt.Errorf("%w: idempotency key is too long", ErrInvalid)
	}
	if value != "" && !utf8.ValidString(value) {
		return fmt.Errorf("%w: idempotency key is not valid UTF-8", ErrInvalid)
	}
	if containsControlCharacters(value) {
		return fmt.Errorf("%w: idempotency key contains control characters", ErrInvalid)
	}
	return nil
}

func containsControlCharacters(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return true
		}
	}
	return false
}

func validTTL(ttl time.Duration) error {
	if ttl <= 0 || ttl > maxLease {
		return fmt.Errorf("%w: lease TTL must be between 1ns and %s", ErrInvalid, maxLease)
	}
	return nil
}

func normalizeDependencies(dependencies []string) ([]string, error) {
	if len(dependencies) > maxTaskDependencies {
		return nil, fmt.Errorf("%w: task dependencies exceed %d", ErrInvalid, maxTaskDependencies)
	}
	// Validate each identifier before sorting. The normal API path already
	// receives bounded MCP input, but a direct in-process caller can supply very
	// large malformed strings; sorting them first would make the lower helper
	// spend comparison work on data that the lifecycle ID contract will reject.
	for _, dependency := range dependencies {
		if err := validID("dependency", dependency); err != nil {
			return nil, err
		}
	}
	result := append([]string(nil), dependencies...)
	sort.Strings(result)
	for i, dep := range result {
		if i > 0 && result[i-1] == dep {
			return nil, fmt.Errorf("%w: duplicate dependency %q", ErrInvalid, dep)
		}
	}
	return result, nil
}

func idempotencyKey(projectID, key string) string {
	return projectID + "\x00" + key
}

func taskHash(projectID string, dependencies []string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00", projectID)
	for _, dep := range dependencies {
		_, _ = fmt.Fprintf(h, "%s\x00", dep)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func newID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate %s ID: %w", prefix, err)
	}
	return prefix + "-" + hex.EncodeToString(b), nil
}
