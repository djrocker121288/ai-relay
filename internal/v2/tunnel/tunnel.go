// Package tunnel contains the side-effect-free P8 tunnel boundary.
//
// It validates authenticated-distribution configuration and the shape of a
// provider health report. It does not open sockets, contact a provider, or
// handle credentials.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxProviderBytes = 128
	maxEndpointBytes = 2048
	maxAudienceBytes = 256
	maxResourceBytes = 2048
)

var (
	ErrInvalid  = errors.New("invalid tunnel configuration")
	ErrProvider = errors.New("tunnel provider failed")
)

// Config is the non-secret configuration needed to identify one authenticated
// tunnel endpoint. Endpoint and Resource must be HTTPS URLs without embedded
// credentials, query state, or fragments. The boundary intentionally carries
// no token, certificate, or provider-specific secret.
type Config struct {
	Provider string
	Endpoint string
	Audience string
	Resource string
}

// HealthReport is the bounded provider result associated with one Config.
// Healthy=false is a valid negative health result; it must still identify the
// exact provider and endpoint that was checked.
type HealthReport struct {
	Provider  string
	Endpoint  string
	Audience  string
	Resource  string
	Healthy   bool
	CheckedAt time.Time
}

// Provider is the narrow provider-neutral health seam. Implementations own
// transport, authentication, and provider-specific checks; callers must pass
// a bounded context and a previously validated Config.
type Provider interface {
	Name() string
	Check(context.Context, Config) (HealthReport, error)
}

// ValidateConfig validates the provider-neutral tunnel identity without doing
// DNS, network, credential, or filesystem work.
func ValidateConfig(config Config) error {
	if err := validText("provider", config.Provider, maxProviderBytes); err != nil {
		return err
	}
	if err := validateHTTPSURL("endpoint", config.Endpoint, maxEndpointBytes); err != nil {
		return err
	}
	if err := validText("audience", config.Audience, maxAudienceBytes); err != nil {
		return err
	}
	if err := validateHTTPSURL("resource", config.Resource, maxResourceBytes); err != nil {
		return err
	}
	return nil
}

// ValidateHealthReport validates a provider result against the configuration
// it claims to describe. It proves consistency only; it does not prove that
// the endpoint was reachable or that an authentication policy was satisfied.
func ValidateHealthReport(config Config, report HealthReport) error {
	if err := ValidateConfig(config); err != nil {
		return err
	}
	if err := validText("health provider", report.Provider, maxProviderBytes); err != nil {
		return err
	}
	if report.Provider != config.Provider {
		return fmt.Errorf("%w: health provider does not match configuration", ErrInvalid)
	}
	if report.Endpoint != config.Endpoint {
		return fmt.Errorf("%w: health endpoint does not match configuration", ErrInvalid)
	}
	if report.Audience != config.Audience {
		return fmt.Errorf("%w: health audience does not match configuration", ErrInvalid)
	}
	if report.Resource != config.Resource {
		return fmt.Errorf("%w: health resource does not match configuration", ErrInvalid)
	}
	if report.CheckedAt.IsZero() {
		return fmt.Errorf("%w: health check time is required", ErrInvalid)
	}
	return nil
}

// Check invokes one already-selected provider and validates its result. It
// contains malformed provider callbacks and rechecks cancellation after the
// callback, but deliberately leaves provider transport and authentication to
// the provider implementation.
func Check(ctx context.Context, provider Provider, config Config) (report HealthReport, err error) {
	if nilContext(ctx) {
		return HealthReport{}, fmt.Errorf("%w: context is required", ErrInvalid)
	}
	if err := safeContextErr(ctx); err != nil {
		return HealthReport{}, err
	}
	if err := ValidateConfig(config); err != nil {
		return HealthReport{}, err
	}
	if nilProvider(provider) {
		return HealthReport{}, fmt.Errorf("%w: provider is required", ErrInvalid)
	}
	name, panicked := providerName(provider)
	if panicked {
		return HealthReport{}, ErrProvider
	}
	if err := validText("provider", name, maxProviderBytes); err != nil || name != config.Provider {
		return HealthReport{}, fmt.Errorf("%w: provider identity mismatch", ErrInvalid)
	}
	if err := safeContextErr(ctx); err != nil {
		return HealthReport{}, err
	}

	defer func() {
		if recover() != nil {
			report = HealthReport{}
			err = ErrProvider
		}
	}()
	report, err = provider.Check(ctx, config)
	if err != nil {
		return HealthReport{}, ErrProvider
	}
	if err := safeContextErr(ctx); err != nil {
		return HealthReport{}, err
	}
	if err := ValidateHealthReport(config, report); err != nil {
		return HealthReport{}, err
	}
	return report, nil
}

func validateHTTPSURL(kind, value string, maxBytes int) error {
	if err := validText(kind, value, maxBytes); err != nil {
		return err
	}
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("%w: %s must be an HTTPS URL without credentials, query, or fragment", ErrInvalid, kind)
	}
	if parsed.Hostname() == "" || strings.HasSuffix(parsed.Host, ":") {
		return fmt.Errorf("%w: %s authority is invalid", ErrInvalid, kind)
	}
	if port := parsed.Port(); port != "" {
		if value, err := strconv.ParseUint(port, 10, 16); err != nil || value == 0 {
			return fmt.Errorf("%w: %s port is invalid", ErrInvalid, kind)
		}
	}
	return nil
}

func validText(kind, value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: %s is empty, oversized, malformed, or padded", ErrInvalid, kind)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%w: %s contains a control or format character", ErrInvalid, kind)
		}
	}
	return nil
}

func nilContext(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func nilProvider(provider Provider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func safeContextErr(ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("%w: context inspection failed", ErrInvalid)
		}
	}()
	return ctx.Err()
}

func providerName(provider Provider) (name string, panicked bool) {
	defer func() {
		if recover() != nil {
			name = ""
			panicked = true
		}
	}()
	return provider.Name(), false
}
