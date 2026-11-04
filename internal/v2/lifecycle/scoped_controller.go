package lifecycle

import (
	"fmt"
	"sort"
	"time"
)

const maxLifecycleScopeBytes = 256

// Scope names are deliberately lifecycle-specific. A gateway or agent may
// grant them after authenticating a principal, but this package never
// authenticates tokens or accepts an owner from task input.
const (
	ScopeProjectRead  = "lifecycle.project.read"
	ScopeProjectWrite = "lifecycle.project.write"
	ScopeTaskRead     = "lifecycle.task.read"
	ScopeTaskWrite    = "lifecycle.task.write"
	ScopeTaskLease    = "lifecycle.task.lease"
	ScopeTaskRecover  = "lifecycle.task.recover"
)

var lifecycleScopes = map[string]struct{}{
	ScopeProjectRead:  {},
	ScopeProjectWrite: {},
	ScopeTaskRead:     {},
	ScopeTaskWrite:    {},
	ScopeTaskLease:    {},
	ScopeTaskRecover:  {},
}

// ErrForbidden means the authenticated principal lacks the scope required by
// an operation. It is distinct from ErrNotOwner so callers can audit an
// authorization failure without treating it as a lease race.
var ErrForbidden = fmt.Errorf("lifecycle scope is not granted")

// Principal is the already-authenticated identity and its explicitly granted
// lifecycle scopes. Authentication and token verification stay outside this
// transport-neutral package.
type Principal struct {
	ID     string
	Scopes []string
}

// ScopedController adds a fail-closed scope policy to the owner-bound
// Controller. It intentionally exposes no method that accepts a caller
// supplied owner.
type ScopedController struct {
	controller *Controller
	scopes     map[string]struct{}
}

// NewScopedController binds one authenticated principal to one lifecycle
// store. Unknown or duplicate scopes are rejected so a transport cannot
// silently widen the policy through malformed input.
func NewScopedController(store *Store, principal Principal) (*ScopedController, error) {
	if err := validID("owner", principal.ID); err != nil {
		return nil, err
	}
	scopes, err := validateLifecycleScopes(principal.Scopes)
	if err != nil {
		return nil, err
	}
	controller, err := NewController(store, principal.ID)
	if err != nil {
		return nil, err
	}
	return &ScopedController{controller: controller, scopes: scopes}, nil
}

func validateLifecycleScopes(values []string) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: lifecycle scopes are required", ErrInvalid)
	}
	// There are no more valid scopes than entries in the allowlist. Reject an
	// oversized authenticated claim before store validation, map allocation, or
	// iteration over attacker-controlled input, keeping admission bounded.
	if len(values) > len(lifecycleScopes) {
		return nil, fmt.Errorf("%w: too many lifecycle scopes", ErrInvalid)
	}
	scopes := make(map[string]struct{}, len(values))
	for _, scope := range values {
		// Scope names are authenticated input. Bound each string before the
		// allowlist lookup so one malformed claim cannot force an unbounded
		// hash/compare operation.
		if len(scope) > maxLifecycleScopeBytes {
			return nil, fmt.Errorf("%w: lifecycle scope is too long", ErrInvalid)
		}
		if _, ok := lifecycleScopes[scope]; !ok {
			return nil, fmt.Errorf("%w: unknown lifecycle scope %q", ErrInvalid, scope)
		}
		if _, duplicate := scopes[scope]; duplicate {
			return nil, fmt.Errorf("%w: duplicate lifecycle scope %q", ErrInvalid, scope)
		}
		scopes[scope] = struct{}{}
	}
	return scopes, nil
}

// Owner returns the immutable authenticated principal bound to this adapter.
func (c *ScopedController) Owner() string {
	if !c.bindingValid() {
		return ""
	}
	return c.controller.Owner()
}

// Scopes returns a stable copy suitable for audit or response metadata.
func (c *ScopedController) Scopes() []string {
	if !c.bindingValid() {
		return nil
	}
	out := make([]string, 0, len(c.scopes))
	for scope := range c.scopes {
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

// bindingShapeValid keeps direct/in-process callers on the same fail-closed
// structural scope contract as the MCP adapter. Constructors establish this
// shape, but an in-package integration can still retain a partially
// initialized value. It deliberately does not inspect the live store so an
// authorization check can reject an ungranted operation before state
// validation work.
func (c *ScopedController) bindingShapeValid() bool {
	if c == nil || c.controller == nil || c.controller.validBinding() != nil {
		return false
	}
	if len(c.scopes) == 0 || len(c.scopes) > len(lifecycleScopes) {
		return false
	}
	for scope := range c.scopes {
		if len(scope) > maxLifecycleScopeBytes {
			return false
		}
		if _, ok := lifecycleScopes[scope]; !ok {
			return false
		}
	}
	return true
}

// bindingValid adds the live-store check required by accessors and capability
// discovery. Mutation methods use require first, so a missing scope does not
// spend full state-validation work; an allowed operation is still rechecked
// by the owner-bound controller before it reaches the store.
func (c *ScopedController) bindingValid() bool {
	return c.bindingShapeValid() && c.controller.valid() == nil
}

func (c *ScopedController) storeClosed() bool {
	if c == nil || c.controller == nil || c.controller.store == nil {
		return true
	}
	c.controller.store.mu.Lock()
	defer c.controller.store.mu.Unlock()
	return c.controller.store.closed
}

func (c *ScopedController) allows(scope string) bool {
	if !c.bindingValid() {
		return false
	}
	_, ok := c.scopes[scope]
	return ok
}

func (c *ScopedController) require(scope string) error {
	if !c.bindingShapeValid() || c.storeClosed() {
		return ErrClosed
	}
	if _, ok := c.scopes[scope]; !ok {
		return fmt.Errorf("%w: %s", ErrForbidden, scope)
	}
	return nil
}

func (c *ScopedController) CreateProject(id, name string) (Project, error) {
	if err := c.require(ScopeProjectWrite); err != nil {
		return Project{}, err
	}
	return c.controller.CreateProject(id, name)
}

func (c *ScopedController) ArchiveProject(id string) (Project, error) {
	if err := c.require(ScopeProjectWrite); err != nil {
		return Project{}, err
	}
	return c.controller.ArchiveProject(id)
}

func (c *ScopedController) Project(id string) (Project, error) {
	if err := c.require(ScopeProjectRead); err != nil {
		return Project{}, err
	}
	return c.controller.Project(id)
}

func (c *ScopedController) CreateTask(spec TaskSpec) (Task, error) {
	if err := c.require(ScopeTaskWrite); err != nil {
		return Task{}, err
	}
	return c.controller.CreateTask(spec)
}

func (c *ScopedController) Ready(projectID string) ([]Task, error) {
	if err := c.require(ScopeTaskRead); err != nil {
		return nil, err
	}
	return c.controller.Ready(projectID)
}

func (c *ScopedController) Tasks(projectID string) ([]Task, error) {
	if err := c.require(ScopeTaskRead); err != nil {
		return nil, err
	}
	return c.controller.Tasks(projectID)
}

func (c *ScopedController) Task(taskID string) (Task, error) {
	if err := c.require(ScopeTaskRead); err != nil {
		return Task{}, err
	}
	return c.controller.Task(taskID)
}

func (c *ScopedController) Acquire(taskID string, ttl time.Duration) (Lease, error) {
	if err := c.require(ScopeTaskLease); err != nil {
		return Lease{}, err
	}
	return c.controller.Acquire(taskID, ttl)
}

func (c *ScopedController) Heartbeat(lease Lease, ttl time.Duration) (Lease, error) {
	if err := c.require(ScopeTaskLease); err != nil {
		return Lease{}, err
	}
	return c.controller.Heartbeat(lease, ttl)
}

func (c *ScopedController) Checkpoint(lease Lease, state TaskState, payload []byte) (Task, error) {
	if err := c.require(ScopeTaskLease); err != nil {
		return Task{}, err
	}
	return c.controller.Checkpoint(lease, state, payload)
}

func (c *ScopedController) RecoverExpired() ([]Task, error) {
	if err := c.require(ScopeTaskRecover); err != nil {
		return nil, err
	}
	return c.controller.RecoverExpired()
}
