package vault

import (
	"context"
	"errors"
	"reflect"
)

func validateOpenContext(ctx context.Context) error {
	if ctx == nil || nilContext(ctx) {
		return errors.New("vault open context is nil")
	}
	return nil
}

// validateActiveOpenContext rejects cancellation before a native-only opener
// can inspect a platform credential store. The plain open-context validator
// intentionally leaves cancellation to its caller because OpenDefault may
// need to pass a live context into a bounded native probe.
func validateActiveOpenContext(ctx context.Context) error {
	if err := validateOpenContext(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

// ValidateContext rejects literal and typed-nil contexts before a caller
// reaches a native backend boundary. It intentionally does not inspect
// cancellation or deadlines; callers decide whether those states are valid
// for their operation.
func ValidateContext(ctx context.Context) error {
	if ctx == nil || nilContext(ctx) {
		return errors.New("vault context is nil")
	}
	return nil
}

// A context is an interface, so a typed-nil pointer can otherwise pass the
// literal nil check and panic when backend selection calls its methods.
func nilContext(ctx context.Context) bool {
	return nilInterface(ctx)
}

// nilInterface detects both a literal nil interface and an interface holding a
// nil pointer (or another nil-capable value). Native adapter seams are
// interfaces so the latter must be rejected before a method call.
func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// rejectTypedNilError keeps malformed native seams from reaching errors.Is or
// errors.As with an interface that contains a nil pointer. Such an error can
// panic when its methods are inspected, and treating it as success would be a
// fail-open result. Native boundaries use this before classifying a returned
// error; the caller receives only stable boundary text.
func rejectTypedNilError(err error) error {
	if err != nil && nilInterface(err) {
		return errors.New("native boundary returned typed-nil error")
	}
	return err
}

// nativeErrorProbeSentinel and nativeErrorProbeType let the shared native
// redaction boundary inspect an error chain without trusting a platform or
// injected implementation. A hostile error can panic from Is, As, or Unwrap;
// retaining that error as a cause would move the panic to the next caller.
var nativeErrorProbeSentinel = errors.New("native error probe")

const maxNativeUnavailableChain = 64

type nativeErrorProbeType struct{}

func (*nativeErrorProbeType) Error() string { return "native error probe" }

func safeNativeErrorIs(err, target error) (matched, panicked bool) {
	if err == nil || target == nil {
		return err == nil && target == nil, false
	}
	matched, valid := walkNativeErrorGraph(err, func(current error) (bool, bool) {
		if _, custom := current.(interface{ Is(error) bool }); custom {
			// Do not invoke an untrusted Is method: it can recurse into the
			// standard errors.Is walker and overflow the stack before recover can
			// run. Native boundaries retain direct identity and ordinary unwrap
			// classification; custom matching is an unclassifiable result.
			return false, false
		}
		return sameNativeError(current, target), true
	})
	return matched, !valid
}

func safeNativeErrorAs(err error, target any) (matched, panicked bool) {
	if err == nil || target == nil {
		return false, false
	}
	targetValue := reflect.ValueOf(target)
	if targetValue.Kind() != reflect.Pointer || targetValue.IsNil() || !targetValue.Elem().CanSet() {
		return false, true
	}
	targetType := targetValue.Elem().Type()
	matched, valid := walkNativeErrorGraph(err, func(current error) (bool, bool) {
		if _, custom := current.(interface{ As(any) bool }); custom {
			// As has the same untrusted recursion and arbitrary-assignment risks
			// as Is. Direct assignability through a bounded ordinary unwrap graph
			// is sufficient for native status carriers.
			return false, false
		}
		currentValue := reflect.ValueOf(current)
		if currentValue.IsValid() && currentValue.Type().AssignableTo(targetType) {
			targetValue.Elem().Set(currentValue)
			return true, true
		}
		return false, true
	})
	return matched, !valid
}

// walkNativeErrorGraph traverses only ordinary unwrap edges. It validates the
// complete bounded graph before returning a match, so a matching sibling cannot
// hide a cyclic, typed-nil, panicking, or overlong branch. Custom Is/As
// methods are rejected by the callback before they can recurse or claim an
// unrelated classification.
func walkNativeErrorGraph(err error, visit func(error) (matched, valid bool)) (matched, valid bool) {
	visited := 0
	var walk func(error, []error) (bool, bool)
	walk = func(current error, ancestors []error) (matched, valid bool) {
		if current == nil {
			return false, true
		}
		if nilInterface(current) {
			return false, false
		}
		for _, ancestor := range ancestors {
			if sameNativeError(current, ancestor) {
				return false, false
			}
		}
		visited++
		if visited > maxNativeUnavailableChain {
			return false, false
		}
		currentMatched, currentValid := visit(current)
		if !currentValid {
			return false, false
		}
		children, panicked := safeNativeErrorUnwrap(current)
		if panicked {
			return false, false
		}
		matched = currentMatched
		ancestors = append(append([]error(nil), ancestors...), current)
		for _, child := range children {
			childMatched, childValid := walk(child, ancestors)
			if !childValid {
				return false, false
			}
			matched = matched || childMatched
		}
		return matched, true
	}
	return walk(err, nil)
}

// hasNativeUnavailableSentinel checks fallback eligibility by identity rather
// than by calling a foreign error's Is method. A malformed adapter can claim
// any target from Is, which would otherwise turn a permission or runtime
// failure into an implicit encrypted-file fallback. The bounded walk still
// accepts ordinary fmt.Errorf wrapping and errors.Join, while panicking or
// cyclic custom unwrap chains fail closed.
func hasNativeUnavailableSentinel(err error) (matched bool) {
	err = rejectTypedNilError(err)
	if err == nil {
		return false
	}
	visited := 0
	var walk func(error, []error) (matched, valid bool)
	walk = func(current error, ancestors []error) (matched, valid bool) {
		if current == nil {
			return false, true
		}
		// A typed-nil child is malformed unwrap data, not an ordinary opaque
		// error. Reject the entire graph so a sibling sentinel cannot turn a
		// partially malformed result into an implicit fallback.
		if nilInterface(current) {
			return false, false
		}
		for _, ancestor := range ancestors {
			if sameNativeError(current, ancestor) {
				return false, false
			}
		}
		visited++
		if visited > maxNativeUnavailableChain {
			return false, false
		}
		if sameNativeError(current, ErrUnavailable) {
			return true, true
		}
		children, panicked := safeNativeErrorUnwrap(current)
		if panicked {
			return false, false
		}
		matched = false
		ancestors = append(append([]error(nil), ancestors...), current)
		for _, child := range children {
			childMatched, childValid := walk(child, ancestors)
			if !childValid {
				return false, false
			}
			matched = matched || childMatched
		}
		return matched, true
	}
	matched, valid := walk(err, nil)
	return valid && matched
}

func sameNativeError(left, right error) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftType := reflect.TypeOf(left)
	rightType := reflect.TypeOf(right)
	if leftType != rightType || !leftType.Comparable() {
		return false
	}
	return left == right
}

func safeNativeErrorUnwrap(err error) (children []error, panicked bool) {
	defer func() {
		if recover() != nil {
			children = nil
			panicked = true
		}
	}()
	switch unwrappable := err.(type) {
	case interface{ Unwrap() []error }:
		return unwrappable.Unwrap(), false
	case interface{ Unwrap() error }:
		return []error{unwrappable.Unwrap()}, false
	default:
		return nil, false
	}
}

// sanitizeNativeErrorChain returns an error that is safe to retain as an
// unwrap cause. Ordinary errors keep their identity for errors.Is/errors.As;
// an error-chain panic is replaced with an opaque boundary error so later
// callers cannot reproduce the panic while inspecting the returned error.
func sanitizeNativeErrorChain(err error) error {
	err = rejectTypedNilError(err)
	if err == nil {
		return nil
	}
	// A custom Is method can claim a match for any target without traversing
	// its own Unwrap chain. Treat a match for the private probe as untrusted as
	// well as a panic; otherwise a malformed error could hide a later hostile
	// chain from this sanitizer and retain it for future callers.
	if matched, panicked := safeNativeErrorIs(err, nativeErrorProbeSentinel); matched || panicked {
		return errors.New("native boundary returned unclassifiable error")
	}
	var probe *nativeErrorProbeType
	if matched, panicked := safeNativeErrorAs(err, &probe); matched || panicked {
		return errors.New("native boundary returned unclassifiable error")
	}
	return err
}

// nativeStoreOpener is kept narrow so backend selection can be tested without
// touching a user keyring or credential profile.
type nativeStoreOpener func() (Store, error)

// safeOpenStore contains malformed or platform-owned opener panics before they
// can terminate a caller or disclose panic text. An unexpected native panic is
// deliberately not translated to ErrUnavailable: only an explicit capability
// result may select the encrypted-file fallback.
func safeOpenStore(kind string, opener nativeStoreOpener) (store Store, err error) {
	defer func() {
		if recover() != nil {
			store = nil
			err = errors.New("vault " + kind + " opener panicked")
		}
	}()
	store, err = opener()
	return store, rejectTypedNilError(err)
}

// openNativeWithContext keeps native-only selection fail-closed when a
// platform constructor returns after its caller has been canceled. Unlike
// the Linux Secret Service probe, macOS and Windows constructors cannot be
// interrupted through this narrow Store API, so a returned backend must be
// rejected before it can be used.
func openNativeWithContext(ctx context.Context, native nativeStoreOpener) (Store, error) {
	if err := validateActiveOpenContext(ctx); err != nil {
		return nil, err
	}
	if native == nil {
		return nil, errors.New("vault native opener is nil")
	}
	store, err := safeOpenStore("native", native)
	if contextErr := validateActiveOpenContext(ctx); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, redactNativeStoreError("open", err)
	}
	if nilStore(store) {
		return nil, errors.New("vault native opener returned nil store")
	}
	return store, nil
}

// chooseStore applies the only implicit fallback allowed by the v2 vault
// boundary: a native backend may fall back when it is unavailable, but native
// lookup, permission, cancellation, and corruption classifications must reach
// callers without exposing platform diagnostics.
func chooseStore(fallback func() (Store, error), native nativeStoreOpener) (Store, error) {
	if fallback == nil {
		return nil, errors.New("vault fallback opener is nil")
	}
	if native == nil {
		return nil, errors.New("vault native opener is nil")
	}
	store, err := safeOpenStore("native", native)
	if err == nil {
		if nilStore(store) {
			return nil, errors.New("vault native opener returned nil store")
		}
		return store, nil
	}
	if !hasNativeUnavailableSentinel(err) {
		return nil, redactNativeStoreError("open", err)
	}
	store, err = safeOpenStore("fallback", fallback)
	if err == nil && nilStore(store) {
		return nil, errors.New("vault fallback opener returned nil store")
	}
	return store, err
}

// chooseStoreWithContext applies the same native-first policy as chooseStore,
// while keeping cancellation authoritative across the selection boundary. A
// native opener may be an injected seam or a platform call that returns after
// its caller has been canceled; that result must not be accepted, and a
// cancellation observed before fallback selection must not create a file
// vault.
func chooseStoreWithContext(ctx context.Context, fallback func() (Store, error), native nativeStoreOpener) (Store, error) {
	if err := validateActiveOpenContext(ctx); err != nil {
		return nil, err
	}
	if fallback == nil {
		return nil, errors.New("vault fallback opener is nil")
	}
	if native == nil {
		return nil, errors.New("vault native opener is nil")
	}
	store, err := safeOpenStore("native", native)
	if contextErr := validateActiveOpenContext(ctx); contextErr != nil {
		return nil, contextErr
	}
	if err == nil {
		if nilStore(store) {
			return nil, errors.New("vault native opener returned nil store")
		}
		return store, nil
	}
	if !hasNativeUnavailableSentinel(err) {
		return nil, redactNativeStoreError("open", err)
	}
	if contextErr := validateActiveOpenContext(ctx); contextErr != nil {
		return nil, contextErr
	}
	store, err = safeOpenStore("fallback", fallback)
	if contextErr := validateActiveOpenContext(ctx); contextErr != nil {
		return nil, contextErr
	}
	if err == nil && nilStore(store) {
		return nil, errors.New("vault fallback opener returned nil store")
	}
	return store, err
}

// openFallbackWithContext applies the same cancellation boundary when a
// platform has no native backend and therefore does not pass through the
// native-first selector. A slow file opener must not be accepted after the
// caller withdraws the request.
func openFallbackWithContext(ctx context.Context, fallback func() (Store, error)) (Store, error) {
	if err := validateActiveOpenContext(ctx); err != nil {
		return nil, err
	}
	if fallback == nil {
		return nil, errors.New("vault fallback opener is nil")
	}
	store, err := safeOpenStore("fallback", fallback)
	if contextErr := validateActiveOpenContext(ctx); contextErr != nil {
		return nil, contextErr
	}
	if err == nil && nilStore(store) {
		return nil, errors.New("vault fallback opener returned nil store")
	}
	return store, err
}

// Store is an interface, so an opener can accidentally return a typed-nil
// pointer with a nil error. Treat every nil-capable dynamic value as absent;
// otherwise backend selection would succeed and defer the construction error
// until the first lifecycle call.
func nilStore(store Store) bool {
	return nilInterface(store)
}
