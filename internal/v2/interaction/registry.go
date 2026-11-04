package interaction

import (
	"context"
	"errors"
	"fmt"
)

// errRegistryHandoff is private control flow used to distinguish a registry
// ownership/consent recheck failure from an adapter's own execution error.
// invokeAdapter maps it back to the public unavailable result without
// exposing registry internals to callers.
var errRegistryHandoff = errors.New("interaction registry handoff rejected")

// AdapterRegistry is an immutable, bounded set of supervisor-selected
// interaction adapters. It owns membership and the validated publication
// snapshot; adapter internals remain owned by their implementations and are
// revalidated by Execute before an action starts.
type AdapterRegistry struct {
	adapters     map[Method]Adapter
	capabilities []Capability
}

// boundAdapter keeps an adapter tied to the method under which the registry
// accepted it. A capability method change is an ownership change, not a
// fallback opportunity; report the bound method as unavailable so the shared
// execution boundary fails closed without invoking the adapter.
type boundAdapter struct {
	expected Method
	adapter  Adapter
}

func (a boundAdapter) Capability() Capability {
	capability, err := adapterCapability(a.adapter)
	if err != nil {
		// Capability has no error return, so re-panic the already-contained
		// adapter failure. The outer adapterCapability call in Execute catches
		// this and preserves the generic ErrAdapter boundary.
		panic(err)
	}
	if capability.Method != a.expected {
		return Capability{Method: a.expected, ownershipDrift: true}
	}
	return capability
}

func (a boundAdapter) Execute(ctx context.Context, request Request, plan Plan) (Result, error) {
	if err := a.validateHandoff(plan); err != nil {
		return Result{}, err
	}
	return a.adapter.Execute(ctx, request, plan)
}

// validateHandoff performs the last registry-owned check after the shared
// execution boundary has selected the bound adapter. Keep the plan method in
// this comparison as well as the live capability fields: a malformed internal
// handoff must not turn a registry-owned adapter into an unscoped executor.
func (a boundAdapter) validateHandoff(plan Plan) error {
	capability, err := adapterCapability(a.adapter)
	if err != nil {
		return err
	}
	if err := capability.Validate(); err != nil {
		return err
	}
	if capability.Method != a.expected || capability.Method != plan.Method || !capability.Available || capability.Consent != ConsentGranted || capability.Detail != plan.CapabilityDetail {
		return errRegistryHandoff
	}
	return nil
}

// NewAdapterRegistry validates and snapshots the supplied adapters. The
// registry never discovers, constructs, or probes a platform adapter. Input
// order is not ownership: methods are stored and executed in the fixed
// API/terminal/accessibility/visual order.
func NewAdapterRegistry(adapters ...Adapter) (*AdapterRegistry, error) {
	if len(adapters) > maxCapabilityCount {
		return nil, fmt.Errorf("%w: adapter registry exceeds the bounded limit", ErrInvalid)
	}

	snapshot := make(map[Method]Adapter, len(adapters))
	capabilitySnapshot := make(map[Method]Capability, len(adapters))
	for _, adapter := range adapters {
		if nilAdapter(adapter) {
			return nil, fmt.Errorf("%w: adapter is required", ErrInvalid)
		}
		capability, capabilityErr := adapterCapability(adapter)
		if capabilityErr != nil {
			return nil, fmt.Errorf("%w: adapter capability is unavailable", ErrInvalid)
		}
		if err := capability.Validate(); err != nil {
			return nil, err
		}
		if _, exists := snapshot[capability.Method]; exists {
			return nil, fmt.Errorf("%w: duplicate adapter method", ErrInvalid)
		}
		snapshot[capability.Method] = adapter
		capabilitySnapshot[capability.Method] = capability
	}

	capabilities := make([]Capability, 0, len(snapshot))
	for _, method := range methodOrder {
		capability, ok := capabilitySnapshot[method]
		if !ok {
			continue
		}
		capabilities = append(capabilities, capability)
	}
	if err := ValidateCapabilities(capabilities); err != nil {
		return nil, err
	}

	return &AdapterRegistry{adapters: snapshot, capabilities: capabilities}, nil
}

// Capabilities returns a copy of the bounded publication snapshot. Before
// publishing it, the registry rechecks each adapter's bound method so a
// method-ownership change cannot make the stale registration snapshot appear
// authoritative. Other registration fields remain immutable here; callers
// that need current availability, consent, or detail must use
// CurrentCapabilities. The returned slice can be changed by the caller
// without changing the registry.
func (r *AdapterRegistry) Capabilities() ([]Capability, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: adapter registry is required", ErrInvalid)
	}
	if err := r.validateSnapshot(); err != nil {
		return nil, err
	}
	if err := r.validateBoundMethods(); err != nil {
		return nil, err
	}
	capabilities := make([]Capability, len(r.capabilities))
	copy(capabilities, r.capabilities)
	return capabilities, nil
}

// CurrentCapabilities returns a validated, current capability publication for
// the registry's exact members. Unlike Capabilities, it re-reads adapter
// state, so consent, availability, session detail, and method ownership drift
// cannot be advertised as if they were the registration snapshot.
func (r *AdapterRegistry) CurrentCapabilities() ([]Capability, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: adapter registry is required", ErrInvalid)
	}
	return r.currentCapabilities()
}

// Select returns a current policy plan without invoking an adapter. It keeps
// the registry's exact membership boundary while re-reading each adapter's
// bounded capability publication, so a revoked consent or changed session is
// reflected before a caller presents or records a plan.
func (r *AdapterRegistry) Select(request Request) (Plan, error) {
	if r == nil {
		return Plan{}, fmt.Errorf("%w: adapter registry is required", ErrInvalid)
	}
	if err := validateSelectionRequest(request); err != nil {
		return Plan{}, err
	}
	capabilities, err := r.currentCapabilities()
	if err != nil {
		return Plan{}, err
	}
	return Select(request, capabilities)
}

// Execute delegates to the existing transport-neutral execution boundary
// using only this registry's immutable membership snapshot. Selection,
// cancellation, consent revalidation, output bounds, and visual evidence
// checks remain centralized in Execute.
func (r *AdapterRegistry) Execute(ctx context.Context, request Request) (Plan, Result, error) {
	if r == nil {
		return Plan{}, Result{}, fmt.Errorf("%w: adapter registry is required", ErrInvalid)
	}
	if err := validateExecutionContext(ctx); err != nil {
		return Plan{}, Result{}, err
	}
	if err := validateSelectionRequest(request); err != nil {
		return Plan{}, Result{}, err
	}
	if _, err := r.currentCapabilities(); err != nil {
		return Plan{}, Result{}, err
	}
	adapters := make([]Adapter, 0, len(r.adapters))
	for _, method := range methodOrder {
		if adapter, ok := r.adapters[method]; ok {
			adapters = append(adapters, boundAdapter{expected: method, adapter: adapter})
		}
	}
	return Execute(ctx, request, adapters)
}

func (r *AdapterRegistry) currentCapabilities() ([]Capability, error) {
	if err := r.validateSnapshot(); err != nil {
		return nil, err
	}
	capabilities := make([]Capability, 0, len(r.adapters))
	for _, method := range methodOrder {
		adapter, ok := r.adapters[method]
		if !ok {
			continue
		}
		capability, err := adapterCapability(adapter)
		if err != nil {
			return nil, fmt.Errorf("%w: current adapter capability is unavailable", ErrAdapter)
		}
		if capability.Method != method {
			return nil, fmt.Errorf("%w: adapter method ownership changed", ErrUnavailable)
		}
		capabilities = append(capabilities, capability)
	}
	if err := ValidateCapabilities(capabilities); err != nil {
		return nil, err
	}
	return capabilities, nil
}

// validateBoundMethods keeps the immutable registration publication tied to
// the adapter method accepted at construction. Capability availability,
// consent, and detail are intentionally not checked here because they belong
// to CurrentCapabilities; method ownership is the one field that determines
// whether the registration snapshot still names the same adapter boundary.
func (r *AdapterRegistry) validateBoundMethods() error {
	for method, adapter := range r.adapters {
		capability, err := adapterCapability(adapter)
		if err != nil {
			return fmt.Errorf("%w: registered adapter capability is unavailable", ErrAdapter)
		}
		if capability.Method != method {
			return fmt.Errorf("%w: adapter method ownership changed", ErrUnavailable)
		}
	}
	return nil
}

// validateSnapshot keeps the registry's in-process ownership handoff
// fail-closed. NewAdapterRegistry establishes a non-nil map and a fixed-order
// capability snapshot, but package-local integrations can still construct or
// mutate an AdapterRegistry directly. A malformed snapshot must not become an
// apparently valid publication or a route to current capability inspection.
// Live capability drift remains allowed and is checked separately by
// currentCapabilities and boundAdapter; this helper validates only membership,
// shape, and the registration-time method binding.
func (r *AdapterRegistry) validateSnapshot() error {
	if r == nil || r.adapters == nil || r.capabilities == nil || len(r.adapters) > maxCapabilityCount || len(r.capabilities) > maxCapabilityCount || len(r.adapters) != len(r.capabilities) {
		return fmt.Errorf("%w: adapter registry snapshot is malformed", ErrInvalid)
	}
	if err := ValidateCapabilities(r.capabilities); err != nil {
		return err
	}
	seen := make(map[Method]struct{}, len(r.capabilities))
	lastMethodIndex := -1
	for _, capability := range r.capabilities {
		methodIndex := -1
		for index, method := range methodOrder {
			if capability.Method == method {
				methodIndex = index
				break
			}
		}
		// The snapshot is compacted to registered members. A registry may
		// legitimately start at terminal, accessibility, or visual; only
		// relative fallback-order drift is malformed.
		if methodIndex <= lastMethodIndex {
			return fmt.Errorf("%w: adapter registry capability order is malformed", ErrInvalid)
		}
		lastMethodIndex = methodIndex
		adapter, ok := r.adapters[capability.Method]
		if !ok || nilAdapter(adapter) {
			return fmt.Errorf("%w: adapter registry member is malformed", ErrInvalid)
		}
		seen[capability.Method] = struct{}{}
	}
	for method, adapter := range r.adapters {
		if !isMethod(method) || nilAdapter(adapter) {
			return fmt.Errorf("%w: adapter registry member is malformed", ErrInvalid)
		}
		if _, ok := seen[method]; !ok {
			return fmt.Errorf("%w: adapter registry snapshot is incomplete", ErrInvalid)
		}
	}
	return nil
}
