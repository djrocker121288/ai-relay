package tunnel

import (
	"context"
	"fmt"
)

const maxRegisteredProviders = 16

// ProviderRegistry is an immutable, bounded set of supervisor-selected
// provider implementations. It performs no discovery, network I/O, or
// credential loading; callers must construct it from already-approved
// adapters.
type ProviderRegistry struct {
	providers map[string]Provider
}

// NewProviderRegistry validates and snapshots the supplied provider set. A
// provider name is its stable ownership key, so duplicate or malformed names
// fail closed rather than allowing configuration-dependent replacement.
func NewProviderRegistry(providers ...Provider) (*ProviderRegistry, error) {
	if len(providers) > maxRegisteredProviders {
		return nil, fmt.Errorf("%w: provider registry exceeds the bounded limit", ErrInvalid)
	}
	snapshot := make(map[string]Provider, len(providers))
	for _, provider := range providers {
		if nilProvider(provider) {
			return nil, fmt.Errorf("%w: provider is required", ErrInvalid)
		}
		name, panicked := providerName(provider)
		if panicked {
			return nil, fmt.Errorf("%w: provider name is unavailable", ErrInvalid)
		}
		if err := validText("provider", name, maxProviderBytes); err != nil {
			return nil, err
		}
		if _, exists := snapshot[name]; exists {
			return nil, fmt.Errorf("%w: duplicate provider", ErrInvalid)
		}
		snapshot[name] = provider
	}
	return &ProviderRegistry{providers: snapshot}, nil
}

// validateSnapshot rechecks the private ownership boundary before any
// provider can be published or called. The constructor creates a valid
// snapshot, but package-local construction, future deserialization, or an
// internal refactor must not turn a malformed map into provider authority.
func (r *ProviderRegistry) validateSnapshot() error {
	if r == nil {
		return fmt.Errorf("%w: provider registry is required", ErrInvalid)
	}
	if r.providers == nil {
		return fmt.Errorf("%w: provider registry snapshot is nil", ErrInvalid)
	}
	if len(r.providers) > maxRegisteredProviders {
		return fmt.Errorf("%w: provider registry exceeds the bounded limit", ErrInvalid)
	}
	for key, provider := range r.providers {
		if err := validText("provider", key, maxProviderBytes); err != nil {
			return err
		}
		if nilProvider(provider) {
			return fmt.Errorf("%w: provider is required", ErrInvalid)
		}
		name, panicked := providerName(provider)
		if panicked {
			return fmt.Errorf("%w: provider name is unavailable", ErrInvalid)
		}
		if err := validText("provider", name, maxProviderBytes); err != nil {
			return err
		}
		if name != key {
			return fmt.Errorf("%w: provider registry key does not match provider name", ErrInvalid)
		}
	}
	return nil
}

// Lookup returns the registered provider for name. The registry never
// discovers or constructs a provider, and the returned implementation remains
// owned by its caller.
func (r *ProviderRegistry) Lookup(name string) (Provider, error) {
	if err := r.validateSnapshot(); err != nil {
		return nil, err
	}
	if err := validText("provider", name, maxProviderBytes); err != nil {
		return nil, err
	}
	provider, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("%w: provider is not registered", ErrInvalid)
	}
	return provider, nil
}

// Check selects the exact configured provider and delegates to the existing
// bounded health boundary. It does not retry, fall back, or silently select a
// different provider.
func (r *ProviderRegistry) Check(ctx context.Context, config Config) (HealthReport, error) {
	if err := r.validateSnapshot(); err != nil {
		return HealthReport{}, err
	}
	if err := ValidateConfig(config); err != nil {
		return HealthReport{}, err
	}
	provider, err := r.Lookup(config.Provider)
	if err != nil {
		return HealthReport{}, err
	}
	return Check(ctx, provider, config)
}
