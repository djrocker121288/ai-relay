package tunnel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var validTunnelConfig = Config{
	Provider: "loopback",
	Endpoint: "https://relay.example.test:8443/tunnel",
	Audience: "ai-relay-controller",
	Resource: "https://relay.example.test/resource",
}

func TestValidateConfigRequiresBoundedAuthenticatedHTTPSIdentity(t *testing.T) {
	valid := validTunnelConfig
	if err := ValidateConfig(valid); err != nil {
		t.Fatalf("valid tunnel config rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "http endpoint", mutate: func(c *Config) { c.Endpoint = "http://relay.example.test/tunnel" }},
		{name: "endpoint userinfo", mutate: func(c *Config) { c.Endpoint = "https://user:secret@relay.example.test/tunnel" }},
		{name: "endpoint query", mutate: func(c *Config) { c.Endpoint = "https://relay.example.test/tunnel?token=secret" }},
		{name: "endpoint empty query", mutate: func(c *Config) { c.Endpoint = "https://relay.example.test/tunnel?" }},
		{name: "resource fragment", mutate: func(c *Config) { c.Resource = "https://relay.example.test/resource#secret" }},
		{name: "resource empty query", mutate: func(c *Config) { c.Resource = "https://relay.example.test/resource?" }},
		{name: "invalid port", mutate: func(c *Config) { c.Endpoint = "https://relay.example.test:65536/tunnel" }},
		{name: "control provider", mutate: func(c *Config) { c.Provider = "loopback\n" }},
		{name: "oversized audience", mutate: func(c *Config) { c.Audience = strings.Repeat("a", maxAudienceBytes+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if err := ValidateConfig(config); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ValidateConfig() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestValidateHealthReportRequiresExactConfigIdentity(t *testing.T) {
	report := HealthReport{
		Provider:  validTunnelConfig.Provider,
		Endpoint:  validTunnelConfig.Endpoint,
		Audience:  validTunnelConfig.Audience,
		Resource:  validTunnelConfig.Resource,
		Healthy:   true,
		CheckedAt: time.Unix(10, 0),
	}
	if err := ValidateHealthReport(validTunnelConfig, report); err != nil {
		t.Fatalf("valid health report rejected: %v", err)
	}
	for _, mutate := range []func(*HealthReport){
		func(r *HealthReport) { r.Provider = "other" },
		func(r *HealthReport) { r.Endpoint = "https://other.example.test/tunnel" },
		func(r *HealthReport) { r.Audience = "other-audience" },
		func(r *HealthReport) { r.Resource = "https://other.example.test/resource" },
		func(r *HealthReport) { r.CheckedAt = time.Time{} },
	} {
		candidate := report
		mutate(&candidate)
		if err := ValidateHealthReport(validTunnelConfig, candidate); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ValidateHealthReport() = %v, want ErrInvalid", err)
		}
	}
}

func TestCheckBoundsProviderIdentityCancellationAndPanic(t *testing.T) {
	provider := &fakeProvider{report: HealthReport{
		Provider:  "loopback",
		Endpoint:  validTunnelConfig.Endpoint,
		Audience:  validTunnelConfig.Audience,
		Resource:  validTunnelConfig.Resource,
		Healthy:   false,
		CheckedAt: time.Unix(11, 0),
	}}
	report, err := Check(context.Background(), provider, validTunnelConfig)
	if err != nil || report != provider.report {
		t.Fatalf("Check() = %#v, %v; want provider report", report, err)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider.calls = 0
	if _, err := Check(ctx, provider, validTunnelConfig); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Check() = %v, want context.Canceled", err)
	}
	if provider.calls != 0 {
		t.Fatalf("canceled check called provider %d times", provider.calls)
	}

	provider.panicCheck = true
	if _, err := Check(context.Background(), provider, validTunnelConfig); !errors.Is(err, ErrProvider) {
		t.Fatalf("panicking provider error = %v, want ErrProvider", err)
	}
}

func TestCheckRejectsMismatchedOrMalformedProviderResult(t *testing.T) {
	for _, report := range []HealthReport{
		{Provider: "other", Endpoint: validTunnelConfig.Endpoint, Audience: validTunnelConfig.Audience, Resource: validTunnelConfig.Resource, CheckedAt: time.Unix(1, 0)},
		{Provider: validTunnelConfig.Provider, Endpoint: "https://other.example.test", Audience: validTunnelConfig.Audience, Resource: validTunnelConfig.Resource, CheckedAt: time.Unix(1, 0)},
		{Provider: validTunnelConfig.Provider, Endpoint: validTunnelConfig.Endpoint, Audience: "other-audience", Resource: validTunnelConfig.Resource, CheckedAt: time.Unix(1, 0)},
		{Provider: validTunnelConfig.Provider, Endpoint: validTunnelConfig.Endpoint, Audience: validTunnelConfig.Audience, Resource: "https://other.example.test/resource", CheckedAt: time.Unix(1, 0)},
		{Provider: validTunnelConfig.Provider, Endpoint: validTunnelConfig.Endpoint, Audience: validTunnelConfig.Audience, Resource: validTunnelConfig.Resource},
	} {
		provider := &fakeProvider{report: report}
		if _, err := Check(context.Background(), provider, validTunnelConfig); !errors.Is(err, ErrInvalid) {
			t.Fatalf("malformed provider report %#v error = %v, want ErrInvalid", report, err)
		}
	}
}

type fakeProvider struct {
	report     HealthReport
	calls      int
	panicCheck bool
}

func (p *fakeProvider) Name() string { return "loopback" }

func (p *fakeProvider) Check(context.Context, Config) (HealthReport, error) {
	p.calls++
	if p.panicCheck {
		panic("provider detail")
	}
	return p.report, nil
}
