package interaction

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSelectUsesDeterministicFallbackOrderAndCopiesVisualTarget(t *testing.T) {
	target := &VisualTarget{Label: "button", X: 10, Y: 20, Width: 100, Height: 40, ScreenWidth: 1920, ScreenHeight: 1080}
	plan, err := Select(Request{Operation: "submit", Mutating: true, Target: target}, []Capability{
		{Method: MethodVisual, Available: true, Consent: ConsentGranted},
		{Method: MethodAccessibility, Available: true, Consent: ConsentGranted},
		{Method: MethodTerminal, Available: true, Consent: ConsentGranted},
		{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "local API session"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Method != MethodAPI || plan.RequiresVisualEvidence || plan.Target != nil || plan.CapabilityDetail != "local API session" {
		t.Fatalf("plan = %#v, want API without visual requirements", plan)
	}

	plan, err = Select(Request{Operation: "submit", Mutating: true, Target: target}, []Capability{
		{Method: MethodVisual, Available: true, Consent: ConsentGranted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Method != MethodVisual || !plan.RequiresVisualEvidence || plan.Target == target {
		t.Fatalf("visual plan = %#v, want copied target and evidence requirement", plan)
	}
	target.Label = "changed-after-selection"
	if plan.Target.Label != "button" {
		t.Fatal("visual plan retained caller-owned target pointer")
	}
}

func TestSelectPreservesValidatedCapabilityDetailInPlan(t *testing.T) {
	plan, err := Select(Request{Operation: "read"}, []Capability{{
		Method:    MethodTerminal,
		Available: true,
		Consent:   ConsentGranted,
		Detail:    "pty session A",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.CapabilityDetail != "pty session A" {
		t.Fatalf("capability detail = %q, want validated snapshot", plan.CapabilityDetail)
	}
}

func TestCapabilityValidateIsAnAdditivePublicationBoundary(t *testing.T) {
	valid := Capability{Method: MethodAccessibility, Available: true, Consent: ConsentGranted, Detail: "desktop session"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid capability rejected: %v", err)
	}

	for _, capability := range []Capability{
		{Method: "browser", Consent: ConsentGranted},
		{Method: MethodAPI, Consent: "maybe"},
		{Method: MethodTerminal, Detail: "bad\u202e detail"},
	} {
		if err := capability.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("capability %#v error = %v, want ErrInvalid", capability, err)
		}
	}
}

func TestValidateCapabilitiesChecksWholePublication(t *testing.T) {
	valid := []Capability{
		{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "local API"},
		{Method: MethodTerminal, Available: true, Consent: ConsentRequired, Detail: "operator PTY"},
	}
	if err := ValidateCapabilities(valid); err != nil {
		t.Fatalf("valid capability publication rejected: %v", err)
	}

	cases := []struct {
		name string
		caps []Capability
	}{
		{name: "duplicate method", caps: []Capability{{Method: MethodAPI}, {Method: MethodAPI}}},
		{name: "malformed member", caps: []Capability{{Method: MethodAPI}, {Method: "browser"}}},
		{name: "oversized publication", caps: make([]Capability, maxCapabilityCount+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateCapabilities(tc.caps); !errors.Is(err, ErrInvalid) {
				t.Fatalf("publication error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestNewAdapterRegistrySnapshotsBoundedPublication(t *testing.T) {
	api := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "local API"}}
	terminal := &fakeAdapter{capability: Capability{Method: MethodTerminal, Available: true, Consent: ConsentRequired, Detail: "operator PTY"}}
	input := []Adapter{terminal, api}
	registry, err := NewAdapterRegistry(input...)
	if err != nil {
		t.Fatalf("NewAdapterRegistry() = %v, want success", err)
	}
	input[0] = nil

	capabilities, err := registry.Capabilities()
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities) != 2 || capabilities[0].Method != MethodAPI || capabilities[1].Method != MethodTerminal {
		t.Fatalf("Capabilities() = %#v, want fixed fallback order", capabilities)
	}
	capabilities[0].Detail = "caller mutation"
	capabilities, err = registry.Capabilities()
	if err != nil {
		t.Fatal(err)
	}
	if capabilities[0].Detail != "local API" {
		t.Fatalf("registry capability snapshot changed after caller mutation: %#v", capabilities[0])
	}
}

func TestAdapterRegistrySupportsSparseFallbackOrder(t *testing.T) {
	terminal := &fakeAdapter{
		capability: Capability{Method: MethodTerminal, Available: true, Consent: ConsentGranted, Detail: "operator PTY"},
		result:     Result{Output: "terminal-result"},
	}
	registry, err := NewAdapterRegistry(terminal)
	if err != nil {
		t.Fatalf("NewAdapterRegistry() = %v, want success for terminal-only registry", err)
	}

	capabilities, err := registry.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities() = %v, want compact snapshot", err)
	}
	if len(capabilities) != 1 || capabilities[0].Method != MethodTerminal {
		t.Fatalf("Capabilities() = %#v, want terminal-only snapshot", capabilities)
	}

	current, err := registry.CurrentCapabilities()
	if err != nil {
		t.Fatalf("CurrentCapabilities() = %v, want terminal-only publication", err)
	}
	if len(current) != 1 || current[0] != capabilities[0] {
		t.Fatalf("CurrentCapabilities() = %#v, want %#v", current, capabilities)
	}

	plan, err := registry.Select(Request{Operation: "read"})
	if err != nil {
		t.Fatalf("Select() = %v, want terminal fallback", err)
	}
	if plan.Method != MethodTerminal || plan.CapabilityDetail != "operator PTY" {
		t.Fatalf("Select() = %#v, want terminal plan", plan)
	}

	plan, result, err := registry.Execute(context.Background(), Request{Operation: "read"})
	if err != nil {
		t.Fatalf("Execute() = %v, want terminal execution", err)
	}
	if plan.Method != MethodTerminal || result.Output != "terminal-result" || terminal.calls != 1 {
		t.Fatalf("Execute() = plan %#v, result %#v, calls %d; want one terminal execution", plan, result, terminal.calls)
	}
}

func TestAdapterRegistryCurrentCapabilitiesRefreshesValidatedPublication(t *testing.T) {
	api := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "api-v1"}}
	terminal := &fakeAdapter{capability: Capability{Method: MethodTerminal, Available: true, Consent: ConsentRequired, Detail: "pty-v1"}}
	registry, err := NewAdapterRegistry(api, terminal)
	if err != nil {
		t.Fatal(err)
	}

	api.capability.Detail = "api-v2"
	api.capability.Available = false
	api.capability.Consent = ConsentDenied
	terminal.capability.Consent = ConsentGranted
	terminal.capability.Detail = "pty-v2"

	capabilities, err := registry.CurrentCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities) != 2 || capabilities[0] != api.capability || capabilities[1] != terminal.capability {
		t.Fatalf("CurrentCapabilities() = %#v, want current fixed-order publication", capabilities)
	}
	if api.calls != 0 || terminal.calls != 0 {
		t.Fatalf("current publication invoked adapter execution: %d/%d", api.calls, terminal.calls)
	}

	capabilities[0].Detail = "caller mutation"
	refreshed, err := registry.CurrentCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	if refreshed[0].Detail != "api-v2" {
		t.Fatalf("CurrentCapabilities() returned aliased data: %#v", refreshed[0])
	}
	registered, err := registry.Capabilities()
	if err != nil {
		t.Fatal(err)
	}
	if registered[0].Detail != "api-v1" || registered[1].Consent != ConsentRequired {
		t.Fatalf("Capabilities() lost registration snapshot: %#v", registered)
	}
}

func TestAdapterRegistryCurrentCapabilitiesFailsClosedOnDriftAndPanic(t *testing.T) {
	methodDrift := &fakeAdapter{capabilitySequence: []Capability{
		{Method: MethodAPI, Available: true, Consent: ConsentGranted},
		{Method: MethodTerminal, Available: true, Consent: ConsentGranted},
	}}
	registry, err := NewAdapterRegistry(methodDrift)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Capabilities(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("registration snapshot method drift error = %v, want ErrUnavailable", err)
	}
	if _, err := registry.CurrentCapabilities(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("method drift error = %v, want ErrUnavailable", err)
	}

	panicking := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}}
	registry, err = NewAdapterRegistry(panicking)
	if err != nil {
		t.Fatal(err)
	}
	panicking.panicCapability = true
	if _, err := registry.CurrentCapabilities(); !errors.Is(err, ErrAdapter) {
		t.Fatalf("capability panic error = %v, want ErrAdapter", err)
	}
	if _, err := registry.Capabilities(); !errors.Is(err, ErrAdapter) {
		t.Fatalf("registration snapshot capability panic error = %v, want ErrAdapter", err)
	}

	var nilRegistry *AdapterRegistry
	if _, err := nilRegistry.CurrentCapabilities(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil registry CurrentCapabilities() = %v, want ErrInvalid", err)
	}
}

func TestNewAdapterRegistryRejectsMalformedOwnership(t *testing.T) {
	duplicate := &fakeAdapter{capability: Capability{Method: MethodAPI}}
	tooMany := make([]Adapter, maxCapabilityCount+1)
	for index := range tooMany {
		tooMany[index] = &fakeAdapter{capability: Capability{Method: MethodAPI}}
	}
	var typedNil *typedNilAdapter
	cases := []struct {
		name     string
		adapters []Adapter
	}{
		{name: "typed nil", adapters: []Adapter{typedNil}},
		{name: "duplicate method", adapters: []Adapter{duplicate, duplicate}},
		{name: "too many", adapters: tooMany},
		{name: "panicking capability", adapters: []Adapter{&fakeAdapter{panicCapability: true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAdapterRegistry(tc.adapters...); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewAdapterRegistry() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestAdapterRegistryRejectsMalformedInProcessSnapshot(t *testing.T) {
	valid := func(t *testing.T) *AdapterRegistry {
		t.Helper()
		registry, err := NewAdapterRegistry(&fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}})
		if err != nil {
			t.Fatal(err)
		}
		return registry
	}

	cases := []struct {
		name   string
		mutate func(*AdapterRegistry)
	}{
		{name: "zero value", mutate: func(registry *AdapterRegistry) {}},
		{name: "missing capability snapshot", mutate: func(registry *AdapterRegistry) {
			registry.capabilities = nil
		}},
		{name: "missing member map", mutate: func(registry *AdapterRegistry) {
			registry.adapters = nil
		}},
		{name: "snapshot order drift", mutate: func(registry *AdapterRegistry) {
			registry.capabilities = []Capability{{Method: MethodTerminal, Available: true, Consent: ConsentGranted}}
		}},
		{name: "unbound member", mutate: func(registry *AdapterRegistry) {
			registry.adapters[MethodTerminal] = &fakeAdapter{capability: Capability{Method: MethodTerminal}}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry := &AdapterRegistry{}
			if tc.name != "zero value" {
				registry = valid(t)
			}
			tc.mutate(registry)

			if _, err := registry.Capabilities(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Capabilities() = %v, want ErrInvalid", err)
			}
			if _, err := registry.CurrentCapabilities(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("CurrentCapabilities() = %v, want ErrInvalid", err)
			}
			if _, err := registry.Select(Request{Operation: "read"}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Select() = %v, want ErrInvalid", err)
			}
			if _, _, err := registry.Execute(context.Background(), Request{Operation: "read"}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Execute() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestAdapterRegistryExecutePreservesFallbackOrder(t *testing.T) {
	api := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}, result: Result{Output: "api-result"}}
	terminal := &fakeAdapter{capability: Capability{Method: MethodTerminal, Available: true, Consent: ConsentGranted}, result: Result{Output: "terminal-result"}}
	registry, err := NewAdapterRegistry(terminal, api)
	if err != nil {
		t.Fatal(err)
	}
	plan, result, err := registry.Execute(context.Background(), Request{Operation: "read"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Method != MethodAPI || result.Output != "api-result" || api.calls != 1 || terminal.calls != 0 {
		t.Fatalf("plan/result/calls = %#v/%#v/%d/%d", plan, result, api.calls, terminal.calls)
	}
}

func TestAdapterRegistrySelectRefreshesCurrentCapabilitiesWithoutExecution(t *testing.T) {
	api := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "api-v1"}}
	terminal := &fakeAdapter{capability: Capability{Method: MethodTerminal, Available: true, Consent: ConsentGranted, Detail: "pty-v1"}}
	registry, err := NewAdapterRegistry(api, terminal)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := registry.Select(Request{Operation: "read"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Method != MethodAPI || plan.CapabilityDetail != "api-v1" || api.calls != 0 || terminal.calls != 0 {
		t.Fatalf("initial plan/calls = %#v/%d/%d", plan, api.calls, terminal.calls)
	}

	api.capability = Capability{Method: MethodAPI, Available: false, Consent: ConsentDenied, Detail: "api-revoked"}
	terminal.capability.Detail = "pty-v2"
	plan, err = registry.Select(Request{Operation: "read"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Method != MethodTerminal || plan.CapabilityDetail != "pty-v2" {
		t.Fatalf("refreshed plan = %#v, want terminal with current detail", plan)
	}
	if api.calls != 0 || terminal.calls != 0 {
		t.Fatalf("selection invoked adapter execution: %d/%d", api.calls, terminal.calls)
	}
}

func TestAdapterRegistrySelectContainsCapabilityFailures(t *testing.T) {
	adapter := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}}
	registry, err := NewAdapterRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	adapter.panicCapability = true
	if _, err := registry.Select(Request{Operation: "read"}); !errors.Is(err, ErrAdapter) {
		t.Fatalf("panicking current capability error = %v, want ErrAdapter", err)
	}

	var nilRegistry *AdapterRegistry
	if _, err := nilRegistry.Select(Request{Operation: "read"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil registry Select() = %v, want ErrInvalid", err)
	}
}

func TestAdapterRegistryRejectsMethodOwnershipChanges(t *testing.T) {
	adapter := &fakeAdapter{capabilitySequence: []Capability{
		{Method: MethodAPI, Available: true, Consent: ConsentGranted},
		{Method: MethodTerminal, Available: true, Consent: ConsentGranted},
	}}
	registry, err := NewAdapterRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Select(Request{Operation: "read"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("changed method selection error = %v, want ErrUnavailable", err)
	}
}

func TestAdapterRegistryBindsMethodAcrossExecutionPreflight(t *testing.T) {
	adapter := &fakeAdapter{capabilitySequence: []Capability{
		{Method: MethodAPI, Available: true, Consent: ConsentGranted},
		{Method: MethodAPI, Available: true, Consent: ConsentGranted},
		{Method: MethodTerminal, Available: true, Consent: ConsentGranted},
	}, result: Result{Output: "must-not-run"}}
	registry, err := NewAdapterRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.Execute(context.Background(), Request{Operation: "mutate"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("method drift during execution error = %v, want ErrUnavailable", err)
	}
	if adapter.calls != 0 {
		t.Fatalf("method drift invoked adapter %d times", adapter.calls)
	}
}

func TestAdapterRegistryRevalidatesCapabilityAtInvocationHandoff(t *testing.T) {
	cases := []struct {
		name     string
		sequence []Capability
	}{
		{
			name: "method drift",
			sequence: []Capability{
				{Method: MethodAPI, Available: true, Consent: ConsentGranted},      // registration
				{Method: MethodAPI, Available: true, Consent: ConsentGranted},      // registry refresh
				{Method: MethodAPI, Available: true, Consent: ConsentGranted},      // shared preflight
				{Method: MethodTerminal, Available: true, Consent: ConsentGranted}, // handoff
			},
		},
		{
			name: "consent revoked",
			sequence: []Capability{
				{Method: MethodAPI, Available: true, Consent: ConsentGranted},
				{Method: MethodAPI, Available: true, Consent: ConsentGranted},
				{Method: MethodAPI, Available: true, Consent: ConsentGranted},
				{Method: MethodAPI, Available: true, Consent: ConsentDenied},
			},
		},
		{
			name: "session detail changed",
			sequence: []Capability{
				{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "session-a"},
				{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "session-a"},
				{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "session-a"},
				{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "session-b"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &fakeAdapter{capabilitySequence: tc.sequence, result: Result{Output: "must-not-run"}}
			registry, err := NewAdapterRegistry(adapter)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := registry.Execute(context.Background(), Request{Operation: "mutate"}); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("late capability drift error = %v, want ErrUnavailable", err)
			}
			if adapter.calls != 0 {
				t.Fatalf("late capability drift invoked adapter %d times", adapter.calls)
			}
			if adapter.capabilityCalls != 4 {
				t.Fatalf("capability calls = %d, want registration plus three execution-boundary checks", adapter.capabilityCalls)
			}
		})
	}
}

func TestAdapterRegistryDoesNotFallbackAfterLateOwnershipDrift(t *testing.T) {
	primary := &fakeAdapter{capabilitySequence: []Capability{
		{Method: MethodAPI, Available: true, Consent: ConsentGranted},
		{Method: MethodAPI, Available: true, Consent: ConsentGranted},
		{Method: MethodTerminal, Available: true, Consent: ConsentGranted},
	}, result: Result{Output: "must-not-run"}}
	fallback := &fakeAdapter{
		capability: Capability{Method: MethodTerminal, Available: true, Consent: ConsentGranted},
		result:     Result{Output: "fallback-must-not-run"},
	}
	registry, err := NewAdapterRegistry(primary, fallback)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := registry.Execute(context.Background(), Request{Operation: "mutate"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("late ownership drift error = %v, want ErrUnavailable", err)
	}
	if primary.calls != 0 || fallback.calls != 0 {
		t.Fatalf("ownership drift invoked adapters: primary=%d fallback=%d", primary.calls, fallback.calls)
	}
}

func TestAdapterRegistryRejectsCapabilityDriftAtBoundHandoff(t *testing.T) {
	primary := &fakeAdapter{capabilitySequence: []Capability{
		{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "session-a"},      // registration
		{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "session-a"},      // registry refresh
		{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "session-a"},      // shared selection
		{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "session-a"},      // shared pre-invocation check
		{Method: MethodTerminal, Available: true, Consent: ConsentGranted, Detail: "session-b"}, // bound handoff
	}, result: Result{Output: "must-not-run"}}
	fallback := &fakeAdapter{
		capability: Capability{Method: MethodTerminal, Available: true, Consent: ConsentGranted},
		result:     Result{Output: "fallback-must-not-run"},
	}
	registry, err := NewAdapterRegistry(primary, fallback)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := registry.Execute(context.Background(), Request{Operation: "mutate"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("bound handoff drift error = %v, want ErrUnavailable", err)
	}
	if primary.calls != 0 || fallback.calls != 0 {
		t.Fatalf("bound handoff drift invoked adapters: primary=%d fallback=%d", primary.calls, fallback.calls)
	}
	if primary.capabilityCalls != 5 {
		t.Fatalf("primary capability calls = %d, want registration plus four execution-boundary checks", primary.capabilityCalls)
	}
}

func TestAdapterRegistryExecutionValidatesContextBeforeCapabilityInspection(t *testing.T) {
	adapter := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}}
	registry, err := NewAdapterRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	capabilityCalls := adapter.capabilityCalls

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := registry.Execute(ctx, Request{Operation: "read"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled registry context error = %v, want context.Canceled", err)
	}
	if adapter.capabilityCalls != capabilityCalls {
		t.Fatalf("canceled registry context inspected capabilities: %d -> %d", capabilityCalls, adapter.capabilityCalls)
	}

	adapter.panicCapability = true
	var typedNil *typedNilContext
	if _, _, err := registry.Execute(typedNil, Request{Operation: "read"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed-nil registry context error = %v, want ErrInvalid", err)
	}
	if adapter.capabilityCalls != capabilityCalls {
		t.Fatalf("typed-nil registry context reached capability inspection: %d -> %d", capabilityCalls, adapter.capabilityCalls)
	}

	if _, _, err := registry.Execute(panicContext{}, Request{Operation: "read"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("panicking registry context error = %v, want ErrInvalid", err)
	}
	if adapter.capabilityCalls != capabilityCalls {
		t.Fatalf("panicking registry context reached capability inspection: %d -> %d", capabilityCalls, adapter.capabilityCalls)
	}
}

func TestAdapterRegistryValidatesRequestBeforeCapabilityInspection(t *testing.T) {
	cases := []struct {
		name    string
		request Request
		wantErr error
	}{
		{name: "empty operation", request: Request{}, wantErr: ErrInvalid},
		{name: "security dialog", request: Request{Operation: "click", SecurityDialog: true}, wantErr: ErrSecurityDialog},
		{name: "invalid target", request: Request{
			Operation: "click",
			Target:    &VisualTarget{Label: "outside", X: 9, Y: 0, Width: 2, Height: 1, ScreenWidth: 10, ScreenHeight: 10},
		}, wantErr: ErrVisualTarget},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}}
			registry, err := NewAdapterRegistry(adapter)
			if err != nil {
				t.Fatal(err)
			}
			capabilityCalls := adapter.capabilityCalls
			adapter.panicCapability = true

			if _, err := registry.Select(tc.request); !errors.Is(err, tc.wantErr) {
				t.Fatalf("registry Select() error = %v, want %v", err, tc.wantErr)
			}
			if adapter.capabilityCalls != capabilityCalls {
				t.Fatalf("invalid registry selection inspected capabilities: %d -> %d", capabilityCalls, adapter.capabilityCalls)
			}
			if _, _, err := registry.Execute(context.Background(), tc.request); !errors.Is(err, tc.wantErr) {
				t.Fatalf("registry Execute() error = %v, want %v", err, tc.wantErr)
			}
			if adapter.capabilityCalls != capabilityCalls {
				t.Fatalf("invalid registry execution inspected capabilities: %d -> %d", capabilityCalls, adapter.capabilityCalls)
			}
		})
	}
}

func TestAdapterRegistryRejectsNilReceiver(t *testing.T) {
	var nilRegistry *AdapterRegistry
	if _, err := nilRegistry.Capabilities(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil registry Capabilities() = %v, want ErrInvalid", err)
	}
	if _, _, err := nilRegistry.Execute(context.Background(), Request{Operation: "read"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil registry Execute() = %v, want ErrInvalid", err)
	}
}

func TestSelectRequiresExplicitConsentAndAvailability(t *testing.T) {
	_, err := Select(Request{Operation: "read"}, []Capability{
		{Method: MethodAPI, Available: true, Consent: ConsentRequired},
		{Method: MethodTerminal, Available: false, Consent: ConsentGranted},
		{Method: MethodAccessibility, Available: true, Consent: ConsentDenied},
		{Method: MethodVisual, Available: true, Consent: ConsentUnknown},
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}

	plan, err := Select(Request{Operation: "read"}, []Capability{{Method: MethodTerminal, Available: true, Consent: ConsentGranted}})
	if err != nil || plan.Method != MethodTerminal {
		t.Fatalf("consented terminal plan = %#v, error = %v", plan, err)
	}
}

func TestSelectRejectsMalformedCapabilitiesAndSecurityDialogs(t *testing.T) {
	cases := []struct {
		name string
		caps []Capability
		want error
	}{
		{name: "unknown method", caps: []Capability{{Method: "browser", Consent: ConsentGranted}}, want: ErrInvalid},
		{name: "duplicate method", caps: []Capability{{Method: MethodAPI}, {Method: MethodAPI}}, want: ErrInvalid},
		{name: "unknown consent", caps: []Capability{{Method: MethodAPI, Consent: "maybe"}}, want: ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Select(Request{Operation: "read"}, tc.caps)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}

	_, err := Select(Request{Operation: "approve", SecurityDialog: true}, []Capability{{Method: MethodAPI, Available: true, Consent: ConsentGranted}})
	if !errors.Is(err, ErrSecurityDialog) {
		t.Fatalf("security-dialog error = %v, want ErrSecurityDialog", err)
	}
}

func TestVisualSelectionRequiresBoundedTarget(t *testing.T) {
	cases := []struct {
		name    string
		target  *VisualTarget
		wantErr error
	}{
		{name: "missing", wantErr: ErrVisualTarget},
		{name: "negative coordinate", target: &VisualTarget{X: -1, Y: 0, Width: 1, Height: 1, ScreenWidth: 10, ScreenHeight: 10}, wantErr: ErrVisualTarget},
		{name: "outside screen", target: &VisualTarget{X: 9, Y: 0, Width: 2, Height: 1, ScreenWidth: 10, ScreenHeight: 10}, wantErr: ErrVisualTarget},
		{name: "oversized screen", target: &VisualTarget{X: 0, Y: 0, Width: 1, Height: 1, ScreenWidth: maxScreenDimension + 1, ScreenHeight: 10}, wantErr: ErrVisualTarget},
		{name: "control label", target: &VisualTarget{Label: "bad\nlabel", X: 0, Y: 0, Width: 1, Height: 1, ScreenWidth: 10, ScreenHeight: 10}, wantErr: ErrVisualTarget},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Select(Request{Operation: "click", Target: tc.target}, []Capability{{Method: MethodVisual, Available: true, Consent: ConsentGranted}})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestSelectValidatesSuppliedTargetBeforeNonVisualSelection(t *testing.T) {
	_, err := Select(Request{
		Operation: "read",
		Target:    &VisualTarget{Label: "bad\u202e", X: 0, Y: 0, Width: 1, Height: 1, ScreenWidth: 10, ScreenHeight: 10},
	}, []Capability{{Method: MethodAPI, Available: true, Consent: ConsentGranted}})
	if !errors.Is(err, ErrVisualTarget) {
		t.Fatalf("non-visual target validation error = %v, want ErrVisualTarget", err)
	}
}

func TestVisualEvidenceIsRequiredAndBounded(t *testing.T) {
	plan, err := Select(Request{Operation: "click", Target: &VisualTarget{X: 1, Y: 1, Width: 2, Height: 2, ScreenWidth: 10, ScreenHeight: 10}}, []Capability{{Method: MethodVisual, Available: true, Consent: ConsentGranted}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateVisualEvidence(plan, VisualEvidence{}); !errors.Is(err, ErrVisualEvidence) {
		t.Fatalf("missing evidence error = %v, want ErrVisualEvidence", err)
	}
	if err := ValidateVisualEvidence(plan, VisualEvidence{Before: "before.json", After: "after.json"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateVisualEvidence(plan, VisualEvidence{Before: strings.Repeat("x", maxEvidenceRefBytes+1), After: "after.json"}); !errors.Is(err, ErrVisualEvidence) {
		t.Fatalf("oversized evidence error = %v, want ErrVisualEvidence", err)
	}
	if err := ValidateVisualEvidence(plan, VisualEvidence{Before: "same.json", After: "same.json"}); !errors.Is(err, ErrVisualEvidence) {
		t.Fatalf("reused evidence error = %v, want ErrVisualEvidence", err)
	}
	if err := ValidateVisualEvidence(Plan{Method: MethodAPI}, VisualEvidence{}); err != nil {
		t.Fatalf("non-visual plan unexpectedly requires evidence: %v", err)
	}
	if err := ValidateVisualEvidence(Plan{Method: MethodAPI, RequiresVisualEvidence: true}, VisualEvidence{}); !errors.Is(err, ErrVisualEvidence) {
		t.Fatalf("inconsistent non-visual plan error = %v, want ErrVisualEvidence", err)
	}
	if err := ValidateVisualEvidence(Plan{Method: MethodVisual}, VisualEvidence{}); !errors.Is(err, ErrVisualEvidence) {
		t.Fatalf("malformed visual plan bypassed evidence requirement: %v", err)
	}
}

func TestValidateVisualEvidenceRejectsUnselectableVisualPlans(t *testing.T) {
	validTarget := &VisualTarget{X: 1, Y: 1, Width: 2, Height: 2, ScreenWidth: 10, ScreenHeight: 10}
	cases := []struct {
		name string
		plan Plan
	}{
		{name: "missing operation", plan: Plan{Method: MethodVisual, Consent: ConsentGranted, Target: validTarget}},
		{name: "missing consent", plan: Plan{Method: MethodVisual, Operation: "click", Target: validTarget}},
		{name: "malformed capability detail", plan: Plan{Method: MethodVisual, Operation: "click", Consent: ConsentGranted, CapabilityDetail: "session\u202e", Target: validTarget}},
		{name: "missing target", plan: Plan{Method: MethodVisual, Operation: "click", Consent: ConsentGranted}},
		{name: "invalid target", plan: Plan{Method: MethodVisual, Operation: "click", Consent: ConsentGranted, Target: &VisualTarget{X: 9, Y: 0, Width: 2, Height: 1, ScreenWidth: 10, ScreenHeight: 10}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateVisualEvidence(tc.plan, VisualEvidence{Before: "before", After: "after"}); !errors.Is(err, ErrVisualEvidence) {
				t.Fatalf("ValidateVisualEvidence() = %v, want ErrVisualEvidence", err)
			}
		})
	}

	plan := Plan{Method: MethodVisual, Operation: "click", Consent: ConsentGranted, Target: validTarget}
	if err := ValidateVisualEvidence(plan, VisualEvidence{Before: "before", After: "after"}); err != nil {
		t.Fatalf("valid visual plan rejected: %v", err)
	}
}

func TestRequestAndCapabilityBoundsFailClosed(t *testing.T) {
	if _, err := Select(Request{Operation: ""}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty operation error = %v, want ErrInvalid", err)
	}
	if _, err := Select(Request{Operation: strings.Repeat("x", maxOperationBytes+1)}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized operation error = %v, want ErrInvalid", err)
	}
	tooMany := make([]Capability, maxCapabilityCount+1)
	for i := range tooMany {
		tooMany[i] = Capability{Method: MethodAPI, Consent: ConsentGranted}
	}
	if _, err := Select(Request{Operation: "read"}, tooMany); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized capability list error = %v, want ErrInvalid", err)
	}
}

func TestInteractionMetadataRejectsUnicodeControlsAndFormatCharacters(t *testing.T) {
	validTarget := &VisualTarget{Label: "öffnet", X: 1, Y: 1, Width: 2, Height: 2, ScreenWidth: 10, ScreenHeight: 10}
	if _, err := Select(Request{Operation: "lire", Target: validTarget}, []Capability{{
		Method: MethodVisual, Available: true, Consent: ConsentGranted, Detail: "écran",
	}}); err != nil {
		t.Fatalf("ordinary Unicode metadata rejected: %v", err)
	}

	cases := []struct {
		name string
		call func() error
	}{
		{name: "operation control", call: func() error {
			_, err := Select(Request{Operation: "read\u0085"}, nil)
			return err
		}},
		{name: "capability detail format", call: func() error {
			_, err := Select(Request{Operation: "read"}, []Capability{{Method: MethodAPI, Detail: "api\u202e"}})
			return err
		}},
		{name: "visual label format", call: func() error {
			_, err := Select(Request{Operation: "click", Target: &VisualTarget{Label: "but\u200bton", X: 1, Y: 1, Width: 2, Height: 2, ScreenWidth: 10, ScreenHeight: 10}}, []Capability{{Method: MethodVisual, Available: true, Consent: ConsentGranted}})
			return err
		}},
		{name: "evidence reference format", call: func() error {
			return ValidateVisualEvidence(Plan{Method: MethodVisual}, VisualEvidence{Before: "before\u2066", After: "after"})
		}},
		{name: "operation line separator", call: func() error {
			_, err := Select(Request{Operation: "read\u2028next"}, nil)
			return err
		}},
		{name: "capability detail paragraph separator", call: func() error {
			_, err := Select(Request{Operation: "read"}, []Capability{{Method: MethodAPI, Detail: "api\u2029detail"}})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("metadata with Unicode control/format character was accepted")
			}
			if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrVisualTarget) && !errors.Is(err, ErrVisualEvidence) {
				t.Fatalf("error = %v, want an interaction boundary error", err)
			}
		})
	}
}

func TestExecuteUsesSelectedAdapterAndCopiesRequestTarget(t *testing.T) {
	target := &VisualTarget{Label: "button", X: 1, Y: 1, Width: 2, Height: 2, ScreenWidth: 10, ScreenHeight: 10}
	api := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}, result: Result{Output: "api-result"}}
	terminal := &fakeAdapter{capability: Capability{Method: MethodTerminal, Available: true, Consent: ConsentGranted}, result: Result{Output: "terminal-result"}}
	plan, result, err := Execute(context.Background(), Request{Operation: "read", Target: target}, []Adapter{terminal, api})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Method != MethodAPI || result.Output != "api-result" || api.calls != 1 || terminal.calls != 0 {
		t.Fatalf("plan/result/calls = %#v/%#v/%d/%d", plan, result, api.calls, terminal.calls)
	}
	if api.request.Target == target {
		t.Fatal("adapter received caller-owned target pointer")
	}
	api.request.Target.Label = "adapter-mutated"
	if target.Label != "button" {
		t.Fatal("adapter mutation escaped request copy")
	}
}

func TestExecuteCopiesVisualPlanTargetBeforeAdapterInvocation(t *testing.T) {
	adapter := &fakeAdapter{
		capability:       Capability{Method: MethodVisual, Available: true, Consent: ConsentGranted},
		mutatePlanTarget: true,
		result:           Result{Evidence: VisualEvidence{Before: "before", After: "after"}},
	}

	plan, _, err := Execute(context.Background(), Request{
		Operation: "click",
		Target:    &VisualTarget{Label: "button", X: 1, Y: 1, Width: 2, Height: 2, ScreenWidth: 10, ScreenHeight: 10},
	}, []Adapter{adapter})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Target == nil || plan.Target.Label != "button" {
		t.Fatalf("returned plan target = %#v, want original bounded target", plan.Target)
	}
	if adapter.receivedPlan.Target == nil || adapter.receivedPlan.Target.Label != "adapter-mutated" {
		t.Fatalf("adapter plan target = %#v, want adapter-local mutation", adapter.receivedPlan.Target)
	}
	if adapter.receivedPlan.Target == plan.Target {
		t.Fatal("adapter received caller-owned plan target pointer")
	}
}

func TestExecuteRequiresCancellationAndVisualEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	visual := &fakeAdapter{capability: Capability{Method: MethodVisual, Available: true, Consent: ConsentGranted}, result: Result{Evidence: VisualEvidence{Before: "before", After: "after"}}}
	if _, _, err := Execute(ctx, Request{Operation: "click", Target: &VisualTarget{X: 1, Y: 1, Width: 2, Height: 2, ScreenWidth: 10, ScreenHeight: 10}}, []Adapter{visual}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled execution error = %v, want context.Canceled", err)
	}
	if visual.calls != 0 {
		t.Fatal("cancelled execution invoked adapter")
	}

	visual.result.Evidence = VisualEvidence{}
	if _, _, err := Execute(context.Background(), Request{Operation: "click", Target: &VisualTarget{X: 1, Y: 1, Width: 2, Height: 2, ScreenWidth: 10, ScreenHeight: 10}}, []Adapter{visual}); !errors.Is(err, ErrVisualEvidence) {
		t.Fatalf("missing visual evidence error = %v, want ErrVisualEvidence", err)
	}
}

func TestExecuteRejectsTypedNilContextBeforeAdapterInspection(t *testing.T) {
	var typedNil *typedNilContext
	adapter := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}}
	if _, _, err := Execute(typedNil, Request{Operation: "read"}, []Adapter{adapter}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed-nil context error = %v, want ErrInvalid", err)
	}
	if adapter.calls != 0 {
		t.Fatal("typed-nil context inspected or invoked an adapter")
	}
}

func TestExecuteRejectsTypedNilAdapterBeforeCapabilityInspection(t *testing.T) {
	var typedNil *typedNilAdapter
	if _, _, err := Execute(context.Background(), Request{Operation: "read"}, []Adapter{typedNil}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed-nil adapter error = %v, want ErrInvalid", err)
	}
}

func TestExecuteRechecksContextBeforeAdapterInvocation(t *testing.T) {
	ctx := &cancelAfterContextCheck{cancelAfter: 1}
	adapter := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}}

	if _, _, err := Execute(ctx, Request{Operation: "mutate"}, []Adapter{adapter}); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-selection cancellation error = %v, want context.Canceled", err)
	}
	if adapter.calls != 0 {
		t.Fatalf("post-selection cancellation invoked adapter %d times", adapter.calls)
	}
	if ctx.checks != 2 {
		t.Fatalf("context checks = %d, want initial and pre-invocation checks", ctx.checks)
	}
}

func TestExecuteValidatesRequestBeforeCapabilityInspection(t *testing.T) {
	cases := []struct {
		name    string
		request Request
		wantErr error
	}{
		{name: "empty operation", request: Request{}, wantErr: ErrInvalid},
		{name: "security dialog", request: Request{Operation: "click", SecurityDialog: true}, wantErr: ErrSecurityDialog},
		{name: "invalid target", request: Request{
			Operation: "click",
			Target:    &VisualTarget{Label: "outside", X: 9, Y: 0, Width: 2, Height: 1, ScreenWidth: 10, ScreenHeight: 10},
		}, wantErr: ErrVisualTarget},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &fakeAdapter{panicCapability: true}
			if _, _, err := Execute(context.Background(), tc.request, []Adapter{adapter}); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Execute() error = %v, want %v", err, tc.wantErr)
			}
			if adapter.capabilityCalls != 0 || adapter.calls != 0 {
				t.Fatalf("invalid request reached adapter inspection/execution: %d/%d", adapter.capabilityCalls, adapter.calls)
			}
		})
	}
}

func TestExecuteRevalidatesSelectedAdapterConsentBeforeInvocation(t *testing.T) {
	adapter := &fakeAdapter{capabilitySequence: []Capability{
		{Method: MethodAPI, Available: true, Consent: ConsentGranted},
		{Method: MethodAPI, Available: true, Consent: ConsentDenied},
	}}

	if _, _, err := Execute(context.Background(), Request{Operation: "mutate"}, []Adapter{adapter}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoked-consent error = %v, want ErrUnavailable", err)
	}
	if adapter.calls != 0 {
		t.Fatalf("revoked-consent execution invoked adapter %d times", adapter.calls)
	}
	if adapter.capabilityCalls != 2 {
		t.Fatalf("capability calls = %d, want initial snapshot and pre-invocation revalidation", adapter.capabilityCalls)
	}
}

func TestExecuteRejectsSelectedAdapterCapabilityMutationBeforeInvocation(t *testing.T) {
	adapter := &fakeAdapter{capabilitySequence: []Capability{
		{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "session-a"},
		{Method: MethodAPI, Available: true, Consent: ConsentGranted, Detail: "session-b"},
	}}

	if _, _, err := Execute(context.Background(), Request{Operation: "mutate"}, []Adapter{adapter}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("capability-mutation error = %v, want ErrUnavailable", err)
	}
	if adapter.calls != 0 {
		t.Fatalf("capability-mutation execution invoked adapter %d times", adapter.calls)
	}
	if adapter.capabilityCalls != 2 {
		t.Fatalf("capability calls = %d, want initial snapshot and pre-invocation revalidation", adapter.capabilityCalls)
	}
}

func TestExecuteRejectsResultWhenContextCancelsDuringAdapter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	adapter := &fakeAdapter{
		capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted},
		result:     Result{Output: "stale-result"},
		cancel:     cancel,
	}

	plan, result, err := Execute(ctx, Request{Operation: "mutate"}, []Adapter{adapter})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("post-execution cancellation error = %v, want context.Canceled", err)
	}
	if plan != (Plan{}) || result != (Result{}) {
		t.Fatalf("canceled execution returned plan/result = %#v/%#v, want zero values", plan, result)
	}
	if adapter.calls != 1 {
		t.Fatalf("adapter calls = %d, want 1", adapter.calls)
	}
}

func TestExecuteContainsContextInspectionPanicBeforeAdapterInspection(t *testing.T) {
	adapter := &fakeAdapter{panicCapability: true}
	_, _, err := Execute(panicContext{}, Request{Operation: "read"}, []Adapter{adapter})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("panicking context error = %v, want ErrInvalid", err)
	}
	if strings.Contains(err.Error(), "context panic") {
		t.Fatal("context panic detail crossed the boundary")
	}
	if adapter.calls != 0 {
		t.Fatal("panicking context reached adapter execution")
	}
}

func TestExecuteNormalizesUnsupportedContextErrorsBeforeAdapterInspection(t *testing.T) {
	adapter := &fakeAdapter{panicCapability: true}
	_, _, err := Execute(customErrorContext{err: errors.New("private context detail")}, Request{Operation: "read"}, []Adapter{adapter})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsupported context error = %v, want ErrInvalid", err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unsupported context error was classified as cancellation: %v", err)
	}
	if strings.Contains(err.Error(), "private context detail") {
		t.Fatal("caller-owned context error detail crossed the boundary")
	}
	if adapter.calls != 0 || adapter.capabilityCalls != 0 {
		t.Fatalf("malformed context reached adapter inspection/execution: %d/%d", adapter.capabilityCalls, adapter.calls)
	}
}

func TestExecuteBoundsOutputAndContainsAdapterFailures(t *testing.T) {
	invalidUTF8 := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}, result: Result{Output: string([]byte{'o', 'k', 0xff})}}
	if _, _, err := Execute(context.Background(), Request{Operation: "read"}, []Adapter{invalidUTF8}); !errors.Is(err, ErrAdapter) {
		t.Fatalf("invalid UTF-8 output error = %v, want ErrAdapter", err)
	}

	oversized := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}, result: Result{Output: strings.Repeat("x", maxOutputBytes+1)}}
	if _, _, err := Execute(context.Background(), Request{Operation: "read"}, []Adapter{oversized}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("oversized output error = %v, want ErrOutputTooLarge", err)
	}

	unsafe := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}, result: Result{Output: "ok\x1b[31m"}}
	if _, _, err := Execute(context.Background(), Request{Operation: "read"}, []Adapter{unsafe}); !errors.Is(err, ErrAdapter) {
		t.Fatalf("terminal-control output error = %v, want ErrAdapter", err)
	}

	lineSeparated := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}, result: Result{Output: "before\u2028after"}}
	if _, _, err := Execute(context.Background(), Request{Operation: "read"}, []Adapter{lineSeparated}); !errors.Is(err, ErrAdapter) {
		t.Fatalf("line-separator output error = %v, want ErrAdapter", err)
	}

	unsafeEvidence := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}, result: Result{Evidence: VisualEvidence{Before: "before\u200b", After: "after"}}}
	if _, _, err := Execute(context.Background(), Request{Operation: "read"}, []Adapter{unsafeEvidence}); !errors.Is(err, ErrAdapter) {
		t.Fatalf("unsafe non-visual evidence error = %v, want ErrAdapter", err)
	}

	oversizedEvidence := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}, result: Result{Evidence: VisualEvidence{Before: strings.Repeat("x", maxEvidenceRefBytes+1)}}}
	if _, _, err := Execute(context.Background(), Request{Operation: "read"}, []Adapter{oversizedEvidence}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("oversized non-visual evidence error = %v, want ErrOutputTooLarge", err)
	}

	panicking := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}, panicExecute: true}
	_, _, err := Execute(context.Background(), Request{Operation: "read"}, []Adapter{panicking})
	if !errors.Is(err, ErrAdapter) {
		t.Fatalf("adapter panic error = %v, want ErrAdapter", err)
	}
	if strings.Contains(err.Error(), "test adapter panic") {
		t.Fatal("adapter panic detail crossed the boundary")
	}
}

func TestExecuteRejectsAdapterCapabilityPanicsAndErrors(t *testing.T) {
	panicking := &fakeAdapter{panicCapability: true}
	if _, _, err := Execute(context.Background(), Request{Operation: "read"}, []Adapter{panicking}); !errors.Is(err, ErrAdapter) {
		t.Fatalf("capability panic error = %v, want ErrAdapter", err)
	}
	failing := &fakeAdapter{capability: Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}, executeErr: errors.New("private adapter detail")}
	if _, _, err := Execute(context.Background(), Request{Operation: "read"}, []Adapter{failing}); !errors.Is(err, ErrAdapter) || strings.Contains(err.Error(), "private adapter detail") {
		t.Fatalf("adapter error = %v, want generic ErrAdapter without detail", err)
	}
}

type fakeAdapter struct {
	capability         Capability
	capabilitySequence []Capability
	capabilityCalls    int
	result             Result
	executeErr         error
	panicCapability    bool
	panicExecute       bool
	cancel             context.CancelFunc
	calls              int
	request            Request
	receivedPlan       Plan
	mutatePlanTarget   bool
}

type typedNilContext struct{}

type typedNilAdapter struct{}

func (*typedNilAdapter) Capability() Capability {
	return Capability{Method: MethodAPI, Available: true, Consent: ConsentGranted}
}

func (*typedNilAdapter) Execute(context.Context, Request, Plan) (Result, error) {
	return Result{Output: "unexpected"}, nil
}

type panicContext struct{}

type customErrorContext struct {
	err error
}

type cancelAfterContextCheck struct {
	checks      int
	cancelAfter int
}

func (c *cancelAfterContextCheck) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelAfterContextCheck) Done() <-chan struct{}       { return nil }
func (c *cancelAfterContextCheck) Err() error {
	c.checks++
	if c.checks > c.cancelAfter {
		return context.Canceled
	}
	return nil
}
func (c *cancelAfterContextCheck) Value(any) any { return nil }

func (*typedNilContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*typedNilContext) Done() <-chan struct{}       { return nil }
func (*typedNilContext) Err() error                  { return nil }
func (*typedNilContext) Value(any) any               { return nil }

func (panicContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (panicContext) Done() <-chan struct{}       { return nil }
func (panicContext) Err() error                  { panic("context panic") }
func (panicContext) Value(any) any               { return nil }

func (c customErrorContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c customErrorContext) Done() <-chan struct{}       { return nil }
func (c customErrorContext) Err() error                  { return c.err }
func (c customErrorContext) Value(any) any               { return nil }

func (a *fakeAdapter) Capability() Capability {
	if a.panicCapability {
		panic("test capability panic")
	}
	if len(a.capabilitySequence) > 0 {
		index := a.capabilityCalls
		if index >= len(a.capabilitySequence) {
			index = len(a.capabilitySequence) - 1
		}
		a.capabilityCalls++
		return a.capabilitySequence[index]
	}
	return a.capability
}

func (a *fakeAdapter) Execute(_ context.Context, request Request, plan Plan) (Result, error) {
	a.calls++
	a.request = request
	a.receivedPlan = plan
	if a.mutatePlanTarget && plan.Target != nil {
		plan.Target.Label = "adapter-mutated"
		a.receivedPlan = plan
	}
	if a.cancel != nil {
		a.cancel()
	}
	if a.panicExecute {
		panic("test adapter panic")
	}
	return a.result, a.executeErr
}
