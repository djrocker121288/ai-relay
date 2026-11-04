package tunnel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewProviderRegistrySnapshotsBoundedUniqueProviders(t *testing.T) {
	first := &fakeProvider{report: validHealthReport()}
	second := &namedProvider{name: "other", report: validHealthReport()}
	registry, err := NewProviderRegistry(first, second)
	if err != nil {
		t.Fatalf("NewProviderRegistry() = %v, want success", err)
	}
	provider, err := registry.Lookup("loopback")
	if err != nil || provider != first {
		t.Fatalf("Lookup(loopback) = %v, %v; want first provider", provider, err)
	}
	if _, err := registry.Lookup("other"); err != nil {
		t.Fatalf("Lookup(other) = %v, want success", err)
	}

	first.report.Provider = "mutated-after-registration"
	provider, err = registry.Lookup("loopback")
	if err != nil || provider != first {
		t.Fatalf("registry changed after provider mutation: %v, %v", provider, err)
	}
}

func TestNewProviderRegistryRejectsMalformedOwnership(t *testing.T) {
	duplicate := &fakeProvider{report: validHealthReport()}
	tests := []struct {
		name      string
		providers []Provider
	}{
		{name: "typed nil", providers: []Provider{(*fakeProvider)(nil)}},
		{name: "duplicate", providers: []Provider{duplicate, duplicate}},
		{name: "too many", providers: makeProviders(maxRegisteredProviders + 1)},
		{name: "control name", providers: []Provider{&namedProvider{name: "bad\nname"}}},
		{name: "panicking name", providers: []Provider{&namedProvider{panicName: true}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewProviderRegistry(test.providers...); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewProviderRegistry() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestProviderRegistryCheckUsesExactConfiguredProvider(t *testing.T) {
	first := &fakeProvider{report: validHealthReport()}
	second := &namedProvider{name: "other", report: validHealthReport()}
	registry, err := NewProviderRegistry(first, second)
	if err != nil {
		t.Fatal(err)
	}
	report, err := registry.Check(context.Background(), validTunnelConfig)
	if err != nil || report.Provider != validTunnelConfig.Provider {
		t.Fatalf("registry.Check() = %#v, %v; want loopback report", report, err)
	}
	if first.calls != 1 || second.calls != 0 {
		t.Fatalf("provider calls = (%d, %d), want (1, 0)", first.calls, second.calls)
	}

	if _, err := registry.Check(context.Background(), Config{
		Provider: "missing",
		Endpoint: validTunnelConfig.Endpoint,
		Audience: validTunnelConfig.Audience,
		Resource: validTunnelConfig.Resource,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing provider error = %v, want ErrInvalid", err)
	}
}

func TestProviderRegistryRejectsInvalidLookupAndNilReceiver(t *testing.T) {
	registry, err := NewProviderRegistry(&fakeProvider{report: validHealthReport()})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "bad\nname", strings.Repeat("a", maxProviderBytes+1), "missing"} {
		if _, err := registry.Lookup(name); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Lookup(%q) = %v, want ErrInvalid", name, err)
		}
	}
	var nilRegistry *ProviderRegistry
	if _, err := nilRegistry.Lookup("loopback"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil registry Lookup() = %v, want ErrInvalid", err)
	}
}

func TestProviderRegistryRejectsMalformedInProcessSnapshot(t *testing.T) {
	oversized := make(map[string]Provider, maxRegisteredProviders+1)
	for index, provider := range makeProviders(maxRegisteredProviders + 1) {
		oversized[provider.Name()+string(rune('a'+index))] = provider
	}
	var typedNil *fakeProvider
	tests := []struct {
		name     string
		registry *ProviderRegistry
	}{
		{name: "zero value", registry: &ProviderRegistry{}},
		{name: "nil provider", registry: &ProviderRegistry{providers: map[string]Provider{"loopback": nil}}},
		{name: "typed nil provider", registry: &ProviderRegistry{providers: map[string]Provider{"loopback": typedNil}}},
		{name: "malformed key", registry: &ProviderRegistry{providers: map[string]Provider{"other": &fakeProvider{}}}},
		{name: "panicking provider name", registry: &ProviderRegistry{providers: map[string]Provider{"loopback": &namedProvider{panicName: true}}}},
		{name: "oversized snapshot", registry: &ProviderRegistry{providers: oversized}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.registry.Lookup("loopback"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Lookup() = %v, want ErrInvalid", err)
			}
			if _, err := test.registry.Check(context.Background(), validTunnelConfig); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Check() = %v, want ErrInvalid", err)
			}
		})
	}
}

func validHealthReport() HealthReport {
	return HealthReport{
		Provider:  validTunnelConfig.Provider,
		Endpoint:  validTunnelConfig.Endpoint,
		Audience:  validTunnelConfig.Audience,
		Resource:  validTunnelConfig.Resource,
		Healthy:   true,
		CheckedAt: time.Unix(10, 0),
	}
}

func makeProviders(count int) []Provider {
	providers := make([]Provider, 0, count)
	for index := 0; index < count; index++ {
		providers = append(providers, &namedProvider{name: "provider-" + string(rune('a'+index))})
	}
	return providers
}

type namedProvider struct {
	name      string
	report    HealthReport
	calls     int
	panicName bool
}

func (p *namedProvider) Name() string {
	if p.panicName {
		panic("provider name detail")
	}
	return p.name
}

func (p *namedProvider) Check(context.Context, Config) (HealthReport, error) {
	p.calls++
	return p.report, nil
}
