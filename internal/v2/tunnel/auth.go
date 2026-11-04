package tunnel

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxAuthorizationBytes = 4096
	maxSubjectBytes       = 256
	maxScopeBytes         = 128
	maxPrincipalScopes    = 32
	maxRequiredScopes     = 16
)

var ErrUnauthorized = errors.New("unauthorized tunnel distribution")

// Principal is the already-verified identity returned by an Authenticator.
// The authenticator owns token signature, issuer, and key validation. The
// distribution boundary only accepts a principal whose resource, audience,
// expiry, and requested scopes match this tunnel configuration.
type Principal struct {
	Subject   string
	Audience  string
	Resource  string
	Scopes    []string
	ExpiresAt time.Time
}

// Authenticator is the narrow authenticated-distribution seam. Implementers
// must verify the supplied bearer token and may use the complete Config for
// resource-bound validation. Implementations must not return the token.
type Authenticator interface {
	Authorize(context.Context, string, Config) (Principal, error)
}

// ValidatePrincipal applies the distribution-side identity and scope policy
// at the caller-provided time. It does not authenticate the principal or
// persist a grant.
func ValidatePrincipal(config Config, principal Principal, requiredScopes []string, now time.Time) error {
	if err := ValidateConfig(config); err != nil {
		return err
	}
	if err := validText("principal subject", principal.Subject, maxSubjectBytes); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	if principal.Audience != config.Audience || principal.Resource != config.Resource {
		return fmt.Errorf("%w: principal binding does not match configuration", ErrUnauthorized)
	}
	if principal.ExpiresAt.IsZero() || now.IsZero() || !principal.ExpiresAt.After(now) {
		return fmt.Errorf("%w: principal is expired or has no expiry", ErrUnauthorized)
	}
	if len(principal.Scopes) > maxPrincipalScopes {
		return fmt.Errorf("%w: scope list exceeds the bounded limit", ErrUnauthorized)
	}
	if err := validateAuthenticationRequiredScopes(requiredScopes); err != nil {
		return err
	}

	granted := make(map[string]struct{}, len(principal.Scopes))
	for _, scope := range principal.Scopes {
		if err := validText("principal scope", scope, maxScopeBytes); err != nil {
			return fmt.Errorf("%w: %v", ErrUnauthorized, err)
		}
		if _, duplicate := granted[scope]; duplicate {
			return fmt.Errorf("%w: duplicate principal scope", ErrUnauthorized)
		}
		granted[scope] = struct{}{}
	}
	required := make(map[string]struct{}, len(requiredScopes))
	for _, scope := range requiredScopes {
		if err := validText("required scope", scope, maxScopeBytes); err != nil {
			return fmt.Errorf("%w: %v", ErrUnauthorized, err)
		}
		if _, duplicate := required[scope]; duplicate {
			return fmt.Errorf("%w: duplicate required scope", ErrUnauthorized)
		}
		required[scope] = struct{}{}
		if _, present := granted[scope]; !present {
			return fmt.Errorf("%w: required scope is missing", ErrUnauthorized)
		}
	}
	return nil
}

// validateAuthenticationRequiredScopes checks caller-owned policy before any authenticator
// callback. It deliberately returns only the stable unauthorized class so a
// malformed scope policy cannot expose bounded policy text or verifier detail
// across the distribution boundary.
func validateAuthenticationRequiredScopes(requiredScopes []string) error {
	if len(requiredScopes) > maxRequiredScopes {
		return fmt.Errorf("%w: required scope policy is malformed", ErrUnauthorized)
	}
	seen := make(map[string]struct{}, len(requiredScopes))
	for _, scope := range requiredScopes {
		if err := validText("required scope", scope, maxScopeBytes); err != nil {
			return fmt.Errorf("%w: required scope policy is malformed", ErrUnauthorized)
		}
		if _, duplicate := seen[scope]; duplicate {
			return fmt.Errorf("%w: required scope policy is malformed", ErrUnauthorized)
		}
		seen[scope] = struct{}{}
	}
	return nil
}

// Authenticate parses exactly one bounded Bearer header, delegates token
// verification, and applies the resource/audience/expiry/scope boundary. It
// never contacts a provider, opens a listener, or exposes verifier details.
func Authenticate(ctx context.Context, authenticator Authenticator, config Config, authorization []string, requiredScopes []string) (principal Principal, err error) {
	if nilContext(ctx) {
		return Principal{}, fmt.Errorf("%w: context is required", ErrInvalid)
	}
	if err := safeContextErr(ctx); err != nil {
		return Principal{}, err
	}
	if err := ValidateConfig(config); err != nil {
		return Principal{}, err
	}
	if err := validateAuthenticationRequiredScopes(requiredScopes); err != nil {
		return Principal{}, err
	}
	token, err := parseBearerHeaders(authorization)
	if err != nil {
		return Principal{}, err
	}
	if nilAuthenticator(authenticator) {
		return Principal{}, fmt.Errorf("%w: authenticator is required", ErrInvalid)
	}

	var authErr error
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		principal, authErr = authenticator.Authorize(ctx, token, config)
	}()
	if panicked || authErr != nil {
		return Principal{}, ErrUnauthorized
	}
	if err := safeContextErr(ctx); err != nil {
		return Principal{}, err
	}
	if err := ValidatePrincipal(config, principal, requiredScopes, time.Now().UTC()); err != nil {
		if errors.Is(err, ErrInvalid) {
			return Principal{}, err
		}
		return Principal{}, ErrUnauthorized
	}
	principal.Scopes = append([]string(nil), principal.Scopes...)
	return principal, nil
}

func parseBearerHeaders(headers []string) (string, error) {
	if len(headers) != 1 || len(headers[0]) > maxAuthorizationBytes {
		return "", ErrUnauthorized
	}
	const prefix = "Bearer "
	value := headers[0]
	if len(value) <= len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", ErrUnauthorized
	}
	token := value[len(prefix):]
	if !validBearerToken(token) {
		return "", ErrUnauthorized
	}
	return token, nil
}

func validBearerToken(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("-._~+/=", r) {
			return false
		}
	}
	return true
}

func nilAuthenticator(authenticator Authenticator) bool {
	if authenticator == nil {
		return true
	}
	value := reflect.ValueOf(authenticator)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
