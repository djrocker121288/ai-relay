package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

var ErrInsufficientCapacity = errors.New("insufficient capacity")

var ErrProjectQuota = errors.New("project resource quota exceeded")

type Resources struct {
	CPU        int    `json:"cpu"`
	MemoryByte uint64 `json:"memory_bytes"`
	GPU        int    `json:"gpu"`
	VRAMByte   uint64 `json:"vram_bytes"`
}

type Request struct {
	ID          string    `json:"id"`
	Project     string    `json:"project"`
	Priority    int       `json:"priority"`
	Resources   Resources `json:"resources"`
	Reclaimable bool      `json:"reclaimable"`
}

type Allocation struct {
	Request
	Sequence uint64 `json:"sequence"`
}

// ProjectQuota limits the aggregate resources held by one project. A zero
// value means no project-specific limit for that resource.
type ProjectQuota struct {
	Resources Resources `json:"resources"`
}

type PressureLevel string

const (
	PressureNormal      PressureLevel = "normal"
	PressureConstrained PressureLevel = "constrained"
	PressureCritical    PressureLevel = "critical"
)

// Pressure is an observation only. It never stops or evicts a process.
type Pressure struct {
	Level       PressureLevel `json:"level"`
	Available   Resources     `json:"available"`
	Allocated   Resources     `json:"allocated"`
	Reclaimable int           `json:"reclaimable"`
}

type queuedRequest struct {
	request  Request
	sequence uint64
	done     chan struct{}
	result   Allocation
	err      error
}

type Scheduler struct {
	mu             sync.Mutex
	capacity       Resources
	reserve        Resources
	allocations    map[string]Allocation
	quotas         map[string]ProjectQuota
	usage          map[string]Resources
	waiters        []*queuedRequest
	nextProject    string
	sequence       uint64
	fullDemand     bool
	fullDemandAuth bool
}

func New(capacity, reserve Resources) (*Scheduler, error) {
	if err := validateResources("capacity", capacity); err != nil {
		return nil, err
	}
	if err := validateResources("reserve", reserve); err != nil {
		return nil, err
	}
	if !fits(reserve, capacity) {
		return nil, fmt.Errorf("reserve exceeds capacity")
	}
	return &Scheduler{capacity: capacity, reserve: reserve, allocations: make(map[string]Allocation), quotas: make(map[string]ProjectQuota), usage: make(map[string]Resources)}, nil
}

func (s *Scheduler) SetProjectQuota(project string, quota ProjectQuota) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if project == "" {
		return fmt.Errorf("project is required")
	}
	if err := validateResources("project quota", quota.Resources); err != nil {
		return err
	}
	if !fits(quota.Resources, s.capacity) {
		return fmt.Errorf("project quota exceeds capacity")
	}
	s.quotas[project] = quota
	s.dispatchLocked()
	return nil
}

func (s *Scheduler) SetFullDemand(enabled, authorized bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enabled && !authorized {
		return fmt.Errorf("full-demand mode requires explicit policy authorization")
	}
	s.fullDemand, s.fullDemandAuth = enabled, enabled && authorized
	s.dispatchLocked()
	return nil
}

func (s *Scheduler) Acquire(request Request) (Allocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.ID == "" || request.Project == "" {
		return Allocation{}, fmt.Errorf("request ID and project are required")
	}
	if err := validateResources("request", request.Resources); err != nil {
		return Allocation{}, err
	}
	if _, exists := s.allocations[request.ID]; exists || s.queuedIDLocked(request.ID) {
		return Allocation{}, fmt.Errorf("request %q already exists", request.ID)
	}
	if !s.fitsProjectLocked(request.Project, request.Resources) {
		return Allocation{}, ErrProjectQuota
	}
	if !fits(request.Resources, s.availableLocked()) {
		return Allocation{}, ErrInsufficientCapacity
	}
	s.sequence++
	allocation := Allocation{Request: request, Sequence: s.sequence}
	s.allocations[request.ID] = allocation
	s.usage[request.Project] = add(s.usage[request.Project], request.Resources)
	return allocation, nil
}

// AcquireQueued waits for admission when immediate capacity is unavailable.
// Requests are selected fairly across projects; within a project, higher
// priority is selected first and older requests break ties.
func (s *Scheduler) AcquireQueued(ctx context.Context, request Request) (Allocation, error) {
	if ctx == nil {
		return Allocation{}, fmt.Errorf("context is required")
	}
	s.mu.Lock()
	if request.ID == "" || request.Project == "" {
		s.mu.Unlock()
		return Allocation{}, fmt.Errorf("request ID and project are required")
	}
	if err := validateResources("request", request.Resources); err != nil {
		s.mu.Unlock()
		return Allocation{}, err
	}
	if !fits(request.Resources, s.capacity) {
		s.mu.Unlock()
		return Allocation{}, ErrInsufficientCapacity
	}
	if _, exists := s.allocations[request.ID]; exists || s.queuedIDLocked(request.ID) {
		s.mu.Unlock()
		return Allocation{}, fmt.Errorf("request %q already exists", request.ID)
	}
	if !s.requestFitsProjectLimitLocked(request.Project, request.Resources) {
		s.mu.Unlock()
		return Allocation{}, ErrProjectQuota
	}
	s.sequence++
	w := &queuedRequest{request: request, sequence: s.sequence, done: make(chan struct{})}
	s.waiters = append(s.waiters, w)
	s.dispatchLocked()
	s.mu.Unlock()

	select {
	case <-w.done:
		return w.result, w.err
	case <-ctx.Done():
		s.mu.Lock()
		for i, candidate := range s.waiters {
			if candidate == w {
				s.waiters = append(s.waiters[:i], s.waiters[i+1:]...)
				w.err = ctx.Err()
				close(w.done)
				s.mu.Unlock()
				return Allocation{}, ctx.Err()
			}
		}
		s.mu.Unlock()
		<-w.done
		return w.result, w.err
	}
}

func (s *Scheduler) Release(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.allocations[id]; !ok {
		return false
	}
	allocation := s.allocations[id]
	delete(s.allocations, id)
	s.usage[allocation.Project] = subtract(s.usage[allocation.Project], allocation.Resources)
	s.dispatchLocked()
	return true
}

// Pressure returns a read-only signal for supervisors. A critical signal is
// emitted when any non-zero usable resource is exhausted; no owner is killed
// and no allocation is reclaimed by this method.
func (s *Scheduler) Pressure() Pressure {
	s.mu.Lock()
	defer s.mu.Unlock()
	available := s.availableLocked()
	var allocated Resources
	reclaimable := 0
	for _, allocation := range s.allocations {
		allocated = add(allocated, allocation.Resources)
		if allocation.Reclaimable {
			reclaimable++
		}
	}
	usable := s.capacity
	if !(s.fullDemand && s.fullDemandAuth) {
		usable = subtract(usable, s.reserve)
	}
	level := PressureNormal
	for _, pair := range []struct{ capacity, available uint64 }{
		{uint64(maxInt(usable.CPU, 0)), uint64(maxInt(available.CPU, 0))},
		{usable.MemoryByte, available.MemoryByte},
		{uint64(maxInt(usable.GPU, 0)), uint64(maxInt(available.GPU, 0))},
		{usable.VRAMByte, available.VRAMByte},
	} {
		if pair.capacity == 0 {
			continue
		}
		if pair.available == 0 {
			level = PressureCritical
			break
		}
		if lessThanQuarter(pair.available, pair.capacity) && level == PressureNormal {
			level = PressureConstrained
		}
	}
	return Pressure{Level: level, Available: available, Allocated: allocated, Reclaimable: reclaimable}
}

func (s *Scheduler) fitsProjectLocked(project string, request Resources) bool {
	quota, ok := s.quotas[project]
	if !ok {
		return true
	}
	used := s.usage[project]
	return withinQuotaInt(request.CPU, used.CPU, quota.Resources.CPU) &&
		withinQuota(request.MemoryByte, used.MemoryByte, quota.Resources.MemoryByte) &&
		withinQuotaInt(request.GPU, used.GPU, quota.Resources.GPU) &&
		withinQuota(request.VRAMByte, used.VRAMByte, quota.Resources.VRAMByte)
}

func (s *Scheduler) requestFitsProjectLimitLocked(project string, request Resources) bool {
	quota, ok := s.quotas[project]
	if !ok {
		return true
	}
	return withinQuotaInt(request.CPU, 0, quota.Resources.CPU) &&
		withinQuota(request.MemoryByte, 0, quota.Resources.MemoryByte) &&
		withinQuotaInt(request.GPU, 0, quota.Resources.GPU) &&
		withinQuota(request.VRAMByte, 0, quota.Resources.VRAMByte)
}

func withinQuotaInt(request, used, quota int) bool {
	return quota == 0 || (used <= quota && request <= quota-used)
}

func withinQuota(request, used, quota uint64) bool {
	return quota == 0 || (used <= quota && request <= quota-used)
}

func (s *Scheduler) queuedIDLocked(id string) bool {
	for _, waiter := range s.waiters {
		if waiter.request.ID == id {
			return true
		}
	}
	return false
}

func (s *Scheduler) dispatchLocked() {
	for {
		index := s.nextFittableWaiterLocked()
		if index < 0 {
			return
		}
		waiter := s.waiters[index]
		s.waiters = append(s.waiters[:index], s.waiters[index+1:]...)
		allocation := Allocation{Request: waiter.request, Sequence: waiter.sequence}
		s.allocations[allocation.ID] = allocation
		s.usage[allocation.Project] = add(s.usage[allocation.Project], allocation.Resources)
		waiter.result = allocation
		waiter.err = nil
		s.nextProject = allocation.Project
		close(waiter.done)
	}
}

func (s *Scheduler) nextFittableWaiterLocked() int {
	projects := make(map[string]bool)
	for _, waiter := range s.waiters {
		projects[waiter.request.Project] = true
	}
	if len(projects) == 0 {
		return -1
	}
	ordered := make([]string, 0, len(projects))
	for project := range projects {
		ordered = append(ordered, project)
	}
	sort.Strings(ordered)
	start := 0
	if s.nextProject != "" {
		for i, project := range ordered {
			if project == s.nextProject {
				start = (i + 1) % len(ordered)
				break
			}
		}
	}
	for offset := range ordered {
		project := ordered[(start+offset)%len(ordered)]
		best := -1
		for i, waiter := range s.waiters {
			if waiter.request.Project != project ||
				!fits(waiter.request.Resources, s.availableLocked()) ||
				!s.fitsProjectLocked(project, waiter.request.Resources) ||
				(best >= 0 && !higherPriority(waiter, s.waiters[best])) {
				continue
			}
			best = i
		}
		if best >= 0 {
			return best
		}
	}
	return -1
}

func higherPriority(a, b *queuedRequest) bool {
	if a.request.Priority != b.request.Priority {
		return a.request.Priority > b.request.Priority
	}
	return a.sequence < b.sequence
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func lessThanQuarter(available, capacity uint64) bool {
	threshold := capacity / 4
	if capacity%4 != 0 {
		threshold++
	}
	return available < threshold
}

func validateResources(name string, resources Resources) error {
	if resources.CPU < 0 || resources.GPU < 0 {
		return fmt.Errorf("%s cannot contain negative resources", name)
	}
	return nil
}

// ReclamationPlan returns the lowest-priority reclaimable allocations whose
// cooperative release would make target fit. It never terminates a process or
// mutates scheduler state; the supervisor must checkpoint and stop each owner,
// then call Release before retrying Acquire.
func (s *Scheduler) ReclamationPlan(target Resources, minimumPriority int) ([]Allocation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	available := s.availableLocked()
	if fits(target, available) {
		return nil, true
	}
	var candidates []Allocation
	for _, allocation := range s.allocations {
		if allocation.Reclaimable && allocation.Priority < minimumPriority {
			candidates = append(candidates, allocation)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority == candidates[j].Priority {
			return candidates[i].Sequence < candidates[j].Sequence
		}
		return candidates[i].Priority < candidates[j].Priority
	})
	var plan []Allocation
	for _, candidate := range candidates {
		plan = append(plan, candidate)
		available = add(available, candidate.Resources)
		if fits(target, available) {
			return plan, true
		}
	}
	return nil, false
}

func (s *Scheduler) Available() Resources {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.availableLocked()
}

func (s *Scheduler) availableLocked() Resources {
	base := s.capacity
	if !(s.fullDemand && s.fullDemandAuth) {
		base = subtract(base, s.reserve)
	}
	for _, allocation := range s.allocations {
		base = subtract(base, allocation.Resources)
	}
	return base
}

func fits(request, available Resources) bool {
	return request.CPU <= available.CPU && request.MemoryByte <= available.MemoryByte && request.GPU <= available.GPU && request.VRAMByte <= available.VRAMByte
}

func add(a, b Resources) Resources {
	return Resources{CPU: a.CPU + b.CPU, MemoryByte: a.MemoryByte + b.MemoryByte, GPU: a.GPU + b.GPU, VRAMByte: a.VRAMByte + b.VRAMByte}
}

func subtract(a, b Resources) Resources {
	result := Resources{CPU: a.CPU - b.CPU, MemoryByte: a.MemoryByte - b.MemoryByte, GPU: a.GPU - b.GPU, VRAMByte: a.VRAMByte - b.VRAMByte}
	if result.CPU < 0 {
		result.CPU = 0
	}
	if result.GPU < 0 {
		result.GPU = 0
	}
	if b.MemoryByte > a.MemoryByte {
		result.MemoryByte = 0
	}
	if b.VRAMByte > a.VRAMByte {
		result.VRAMByte = 0
	}
	return result
}
