package lifecycle

import (
	"fmt"
	"time"
)

// APIVersion identifies the additive lifecycle adapter contract. It is kept
// separate from the legacy agent protocol so callers cannot accidentally
// treat lifecycle ownership as command execution authority.
const APIVersion = "ai-relay/lifecycle/v1"

// Controller binds lifecycle mutations to one authenticated caller identity.
// The gateway/agent adapter should construct one controller per request
// principal and must never accept an owner supplied in request parameters.
// Read operations are also bound to the store so a closed or replaced store
// cannot be used through a stale adapter.
type Controller struct {
	store         *Store
	owner         string
	ownerSnapshot string
}

// NewController creates a scoped lifecycle adapter. The owner is the stable
// authenticated principal (controller or agent identity), not a display name.
func NewController(store *Store, owner string) (*Controller, error) {
	// Bound the authenticated owner before inspecting the live store. An
	// invalid principal must fail at the cheapest admission boundary even when
	// a direct in-process caller supplies a malformed store.
	if err := validID("owner", owner); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("%w: lifecycle store is required", ErrInvalid)
	}
	if err := store.ensureAdapterReady(); err != nil {
		return nil, err
	}
	return &Controller{store: store, owner: owner, ownerSnapshot: owner}, nil
}

// Owner returns the immutable principal bound to this adapter.
func (c *Controller) Owner() string {
	if err := c.valid(); err != nil {
		return ""
	}
	return c.owner
}

func (c *Controller) valid() error {
	if err := c.validBinding(); err != nil {
		return err
	}
	return c.store.ensureAdapterReady()
}

func (c *Controller) validBinding() error {
	if c == nil || c.store == nil || validID("owner", c.owner) != nil || validID("owner snapshot", c.ownerSnapshot) != nil || c.owner != c.ownerSnapshot {
		return ErrClosed
	}
	return nil
}

// admitInput keeps direct controller calls on the same cheap input boundary as
// the store and MCP adapter. Structural owner binding is checked first, then
// caller input, and only then is the live store inspected. This prevents a
// malformed request from spending full lifecycle-state validation work.
func (c *Controller) admitInput(validate func() error) error {
	if err := c.validBinding(); err != nil {
		return err
	}
	if validate != nil {
		if err := validate(); err != nil {
			return err
		}
	}
	return c.store.ensureAdapterReady()
}

func (c *Controller) CreateProject(id, name string) (Project, error) {
	if err := c.admitInput(func() error {
		if err := validID("project", id); err != nil {
			return err
		}
		return validName(name)
	}); err != nil {
		return Project{}, err
	}
	return c.store.CreateProject(id, name)
}

func (c *Controller) ArchiveProject(id string) (Project, error) {
	if err := c.admitInput(func() error { return validID("project", id) }); err != nil {
		return Project{}, err
	}
	return c.store.ArchiveProject(id)
}

func (c *Controller) Project(id string) (Project, error) {
	if err := c.admitInput(func() error { return validID("project", id) }); err != nil {
		return Project{}, err
	}
	return c.store.Project(id)
}

func (c *Controller) CreateTask(spec TaskSpec) (Task, error) {
	if err := c.admitInput(func() error {
		if err := validID("project", spec.ProjectID); err != nil {
			return err
		}
		if spec.ID != "" {
			if err := validID("task", spec.ID); err != nil {
				return err
			}
		}
		if err := validIdempotencyKey(spec.IdempotencyKey); err != nil {
			return err
		}
		_, err := normalizeDependencies(spec.Dependencies)
		return err
	}); err != nil {
		return Task{}, err
	}
	return c.store.CreateTask(spec)
}

func (c *Controller) Ready(projectID string) ([]Task, error) {
	if err := c.admitInput(func() error { return validID("project", projectID) }); err != nil {
		return nil, err
	}
	return c.store.Ready(projectID)
}

func (c *Controller) Tasks(projectID string) ([]Task, error) {
	if err := c.admitInput(func() error { return validID("project", projectID) }); err != nil {
		return nil, err
	}
	return c.store.Tasks(projectID)
}

func (c *Controller) Task(taskID string) (Task, error) {
	if err := c.admitInput(func() error { return validID("task", taskID) }); err != nil {
		return Task{}, err
	}
	return c.store.Task(taskID)
}

// Acquire leases a task for the bound principal. Callers cannot substitute a
// different owner, which preserves controller/agent ownership across retries.
func (c *Controller) Acquire(taskID string, ttl time.Duration) (Lease, error) {
	if err := c.admitInput(func() error {
		if err := validID("task", taskID); err != nil {
			return err
		}
		return validTTL(ttl)
	}); err != nil {
		return Lease{}, err
	}
	return c.store.Acquire(taskID, c.owner, ttl)
}

func (c *Controller) Heartbeat(lease Lease, ttl time.Duration) (Lease, error) {
	if err := c.admitInput(func() error {
		if err := validID("lease owner", lease.Owner); err != nil {
			return err
		}
		if lease.Owner != c.owner {
			return ErrNotOwner
		}
		if err := validID("task", lease.TaskID); err != nil {
			return err
		}
		return validTTL(ttl)
	}); err != nil {
		return Lease{}, err
	}
	return c.store.Heartbeat(lease.TaskID, c.owner, lease.Version, ttl)
}

func (c *Controller) Checkpoint(lease Lease, state TaskState, payload []byte) (Task, error) {
	if err := c.admitInput(func() error {
		if err := validID("lease owner", lease.Owner); err != nil {
			return err
		}
		if lease.Owner != c.owner {
			return ErrNotOwner
		}
		if err := validID("task", lease.TaskID); err != nil {
			return err
		}
		if len(payload) > maxPayloadBytes {
			return fmt.Errorf("%w: checkpoint payload exceeds %d bytes", ErrInvalid, maxPayloadBytes)
		}
		if !validTaskState(state) || state == TaskPending {
			return fmt.Errorf("%w: checkpoint state %q", ErrInvalid, state)
		}
		return nil
	}); err != nil {
		return Task{}, err
	}
	return c.store.Checkpoint(lease.TaskID, c.owner, lease.Version, state, payload)
}

// RecoverExpired is intentionally explicit. It does not execute or retry any
// task and is therefore suitable for a supervisor-owned recovery operation.
func (c *Controller) RecoverExpired() ([]Task, error) {
	if err := c.valid(); err != nil {
		return nil, err
	}
	return c.store.RecoverExpired()
}
