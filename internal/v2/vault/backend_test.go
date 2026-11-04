package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateOpenContextRejectsNil(t *testing.T) {
	if err := validateOpenContext(nil); err == nil || !strings.Contains(err.Error(), "open context is nil") {
		t.Fatalf("nil context error = %v", err)
	}
	var typedNil *typedNilContext
	if err := validateOpenContext(typedNil); err == nil || !strings.Contains(err.Error(), "open context is nil") {
		t.Fatalf("typed-nil context error = %v", err)
	}
	if err := validateOpenContext(context.Background()); err != nil {
		t.Fatalf("background context rejected: %v", err)
	}
}

func TestOpenDefaultRejectsCanceledContextBeforeBackendAccess(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "vault.json")
	keyPath := filepath.Join(d, "vault.key")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := OpenDefault(ctx, path, keyPath); !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenDefault(canceled) error = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled OpenDefault vault path error = %v, want absent path", err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled OpenDefault key path error = %v, want absent path", err)
	}
}

type backendTestStore struct{}

type backendNilStore struct{}

type typedNilBoundaryError struct{}

func (*typedNilBoundaryError) Error() string { return "typed nil native error" }
func (e *typedNilBoundaryError) Unwrap() error {
	return errors.New("unreachable typed-nil cause")
}

type typedNilContext struct{}

func (*typedNilContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*typedNilContext) Done() <-chan struct{}       { return nil }
func (*typedNilContext) Err() error                  { return nil }
func (*typedNilContext) Value(any) any               { return nil }

type panickingNativeError struct {
	panicIs bool
	panicAs bool
}

func (e panickingNativeError) Error() string { return "secret-bearing native diagnostic" }

func (e panickingNativeError) Is(error) bool {
	if e.panicIs {
		panic("secret-bearing Is diagnostic")
	}
	return false
}

func (e panickingNativeError) As(any) bool {
	if e.panicAs {
		panic("secret-bearing As diagnostic")
	}
	return false
}

type forgingNativeProbeError struct {
	forgeIs bool
	forgeAs bool
}

type forgingUnavailableError struct{}

func (forgingUnavailableError) Error() string        { return "secret-bearing forged unavailable diagnostic" }
func (forgingUnavailableError) Is(target error) bool { return target == ErrUnavailable }

type panickingUnavailableUnwrapError struct{}

func (panickingUnavailableUnwrapError) Error() string {
	return "secret-bearing panicking unavailable diagnostic"
}
func (panickingUnavailableUnwrapError) Unwrap() error { panic("secret-bearing unwrap diagnostic") }

type nonComparableUnavailableError []string

func (nonComparableUnavailableError) Error() string {
	return "secret-bearing non-comparable unavailable diagnostic"
}
func (nonComparableUnavailableError) Is(target error) bool { return target == ErrUnavailable }

type cyclicUnavailableError struct{}

func (cyclicUnavailableError) Error() string   { return "secret-bearing cyclic unavailable diagnostic" }
func (e cyclicUnavailableError) Unwrap() error { return e }

type cyclicUnavailableBranchError struct{}

func (cyclicUnavailableBranchError) Error() string { return "secret-bearing cyclic branch diagnostic" }
func (e cyclicUnavailableBranchError) Unwrap() []error {
	return []error{e, ErrUnavailable}
}

func (e forgingNativeProbeError) Error() string { return "secret-bearing forged native diagnostic" }

func (e forgingNativeProbeError) Is(target error) bool {
	return e.forgeIs && target == nativeErrorProbeSentinel
}

func (e forgingNativeProbeError) As(target any) bool {
	return e.forgeAs && target != nil
}

func (backendTestStore) Get(string) (Record, error)            { return Record{}, nil }
func (backendTestStore) Put(string, string) (Record, error)    { return Record{}, nil }
func (backendTestStore) Rotate(string, string) (Record, error) { return Record{}, nil }
func (backendTestStore) Revoke(string) error                   { return nil }
func (*backendNilStore) Get(string) (Record, error)            { return Record{}, nil }
func (*backendNilStore) Put(string, string) (Record, error)    { return Record{}, nil }
func (*backendNilStore) Rotate(string, string) (Record, error) { return Record{}, nil }
func (*backendNilStore) Revoke(string) error                   { return nil }

func TestChooseStoreFallsBackOnlyWhenUnavailable(t *testing.T) {
	fallback := func() (Store, error) { return backendTestStore{}, nil }
	got, err := chooseStore(fallback, func() (Store, error) { return nil, ErrUnavailable })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(backendTestStore); !ok {
		t.Fatalf("fallback type = %T", got)
	}
}

func TestChooseStoreRequiresUnavailableSentinelIdentity(t *testing.T) {
	fallbackCalled := false
	_, err := chooseStore(func() (Store, error) {
		fallbackCalled = true
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, forgingUnavailableError{}
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("forged unavailable error = %v, want opaque native failure", err)
	}
	if fallbackCalled {
		t.Fatal("fallback opened for a forged ErrUnavailable classification")
	}
}

func TestChooseStoreAcceptsWrappedUnavailableSentinel(t *testing.T) {
	fallbackCalled := false
	got, err := chooseStore(func() (Store, error) {
		fallbackCalled = true
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, fmt.Errorf("helper unavailable: %w", ErrUnavailable)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !fallbackCalled {
		t.Fatal("fallback was not opened for a wrapped ErrUnavailable sentinel")
	}
	if _, ok := got.(backendTestStore); !ok {
		t.Fatalf("fallback type = %T", got)
	}
}

func TestChooseStoreRejectsPanickingUnavailableUnwrap(t *testing.T) {
	fallbackCalled := false
	_, err := chooseStore(func() (Store, error) {
		fallbackCalled = true
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, panickingUnavailableUnwrapError{}
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("panicking unwrap error = %v, want opaque native failure", err)
	}
	if fallbackCalled {
		t.Fatal("fallback opened after a panicking unavailable unwrap")
	}
}

func TestChooseStoreRejectsNonComparableUnavailableError(t *testing.T) {
	fallbackCalled := false
	_, err := chooseStore(func() (Store, error) {
		fallbackCalled = true
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, nonComparableUnavailableError{"secret"}
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("non-comparable unavailable error = %v, want opaque native failure", err)
	}
	if fallbackCalled {
		t.Fatal("fallback opened for a non-comparable forged ErrUnavailable classification")
	}
}

func TestChooseStoreRejectsCyclicUnavailableChain(t *testing.T) {
	fallbackCalled := false
	_, err := chooseStore(func() (Store, error) {
		fallbackCalled = true
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, cyclicUnavailableError{}
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("cyclic unavailable error = %v, want opaque native failure", err)
	}
	if fallbackCalled {
		t.Fatal("fallback opened after a cyclic unavailable chain")
	}
}

func TestChooseStoreRejectsCyclicUnavailableBranchWithSentinel(t *testing.T) {
	fallbackCalled := false
	_, err := chooseStore(func() (Store, error) {
		fallbackCalled = true
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, cyclicUnavailableBranchError{}
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("cyclic branch error = %v, want opaque native failure", err)
	}
	if fallbackCalled {
		t.Fatal("fallback opened after a cyclic branch contained ErrUnavailable")
	}
}

func TestChooseStoreAcceptsOrdinaryJoinedUnavailableSentinel(t *testing.T) {
	fallbackCalled := false
	got, err := chooseStore(func() (Store, error) {
		fallbackCalled = true
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, errors.Join(errors.New("helper diagnostic"), ErrUnavailable)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !fallbackCalled {
		t.Fatal("fallback was not opened for an ordinary joined ErrUnavailable sentinel")
	}
	if _, ok := got.(backendTestStore); !ok {
		t.Fatalf("fallback type = %T", got)
	}
}

func TestChooseStoreWithContextRequiresUnavailableSentinelIdentity(t *testing.T) {
	fallbackCalled := false
	_, err := chooseStoreWithContext(context.Background(), func() (Store, error) {
		fallbackCalled = true
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, forgingUnavailableError{}
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("context-aware forged unavailable error = %v, want opaque native failure", err)
	}
	if fallbackCalled {
		t.Fatal("context-aware fallback opened for a forged ErrUnavailable classification")
	}
}

func TestChooseStorePropagatesNativeFailure(t *testing.T) {
	want := errors.New("keyring permission denied")
	called := false
	_, err := chooseStore(func() (Store, error) {
		called = true
		return backendTestStore{}, nil
	}, func() (Store, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if called {
		t.Fatal("fallback opened after a native failure")
	}
}

func TestChooseStoreRejectsTypedNilNativeError(t *testing.T) {
	var typedNil *typedNilBoundaryError
	_, err := chooseStore(
		func() (Store, error) { return backendTestStore{}, nil },
		func() (Store, error) { return nil, typedNil },
	)
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("typed-nil native error = %v, want stable open failure", err)
	}
}

func TestNativeErrorRedactionContainsPanickingErrorChains(t *testing.T) {
	for _, cause := range []error{
		panickingNativeError{panicIs: true},
		panickingNativeError{panicAs: true},
	} {
		err := redactNativeStoreError("read", cause)
		if err == nil || err.Error() != "native secure store read failed" {
			t.Fatalf("redacted hostile error = %v, want opaque store boundary", err)
		}
		if errors.Is(err, ErrNotFound) {
			t.Fatalf("hostile error was classified as missing: %v", err)
		}
		var classified *panickingNativeError
		if errors.As(err, &classified) {
			t.Fatalf("hostile error was retained as an unwrap cause: %v", err)
		}
	}
}

func TestNativeErrorRedactionRejectsForgedProbeMatches(t *testing.T) {
	for _, cause := range []error{
		forgingNativeProbeError{forgeIs: true},
		forgingNativeProbeError{forgeAs: true},
	} {
		err := redactNativeStoreError("read", cause)
		if err == nil || err.Error() != "native secure store read failed" {
			t.Fatalf("redacted forged error = %v, want opaque store boundary", err)
		}
		var classified *forgingNativeProbeError
		if errors.As(err, &classified) {
			t.Fatalf("forged probe error was retained as an unwrap cause: %v", err)
		}
	}
}

func TestChooseStoreRedactsNativeConstructionFailure(t *testing.T) {
	const secretText = "secret-bearing keychain diagnostic"
	want := errors.New(secretText)
	_, err := chooseStore(func() (Store, error) {
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, want
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("native construction error = %v, want stable open label", err)
	}
	if strings.Contains(err.Error(), secretText) {
		t.Fatalf("native construction diagnostic leaked: %v", err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("native construction error = %v, want errors.Is classification", err)
	}
}

func TestChooseStoreWithContextRedactsNativeConstructionFailure(t *testing.T) {
	const secretText = "secret-bearing credential diagnostic"
	want := errors.New(secretText)
	_, err := chooseStoreWithContext(context.Background(), func() (Store, error) {
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, want
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("context-aware native construction error = %v, want stable open label", err)
	}
	if strings.Contains(err.Error(), secretText) {
		t.Fatalf("context-aware native construction diagnostic leaked: %v", err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("context-aware native construction error = %v, want errors.Is classification", err)
	}
}

func TestChooseStoreContainsNativeOpenerPanicWithoutFallback(t *testing.T) {
	const secretPanic = "native panic must not escape"
	fallbackCalled := false
	_, err := chooseStore(func() (Store, error) {
		fallbackCalled = true
		return backendTestStore{}, nil
	}, func() (Store, error) {
		panic(secretPanic)
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("native opener panic error = %v, want stable open label", err)
	}
	if strings.Contains(err.Error(), secretPanic) {
		t.Fatalf("native opener panic detail escaped: %v", err)
	}
	if fallbackCalled {
		t.Fatal("fallback opened after an unexpected native panic")
	}
}

func TestChooseStoreWithContextContainsFallbackOpenerPanic(t *testing.T) {
	const secretPanic = "fallback panic must not escape"
	_, err := chooseStoreWithContext(context.Background(), func() (Store, error) {
		panic(secretPanic)
	}, func() (Store, error) {
		return nil, ErrUnavailable
	})
	if err == nil || !strings.Contains(err.Error(), "fallback opener panicked") {
		t.Fatalf("fallback opener panic error = %v, want opaque panic classification", err)
	}
	if strings.Contains(err.Error(), secretPanic) {
		t.Fatalf("fallback opener panic detail escaped: %v", err)
	}
}

func TestChooseStoreRejectsNilOpeners(t *testing.T) {
	if _, err := chooseStore(nil, func() (Store, error) { return backendTestStore{}, nil }); err == nil {
		t.Fatal("accepted nil fallback opener")
	}
	if _, err := chooseStore(func() (Store, error) { return backendTestStore{}, nil }, nil); err == nil {
		t.Fatal("accepted nil native opener")
	}
}

func TestChooseStoreRejectsNilStores(t *testing.T) {
	fallback := func() (Store, error) { return backendTestStore{}, nil }
	if _, err := chooseStore(fallback, func() (Store, error) { return nil, nil }); err == nil || !strings.Contains(err.Error(), "native opener returned nil store") {
		t.Fatalf("native nil store error = %v", err)
	}
	if _, err := chooseStore(func() (Store, error) { return nil, nil }, func() (Store, error) { return nil, ErrUnavailable }); err == nil || !strings.Contains(err.Error(), "fallback opener returned nil store") {
		t.Fatalf("fallback nil store error = %v", err)
	}
}

func TestChooseStoreRejectsTypedNilStores(t *testing.T) {
	fallback := func() (Store, error) { return backendTestStore{}, nil }
	var nativeNil *backendNilStore
	if _, err := chooseStore(fallback, func() (Store, error) { return nativeNil, nil }); err == nil || !strings.Contains(err.Error(), "native opener returned nil store") {
		t.Fatalf("native typed nil store error = %v", err)
	}
	if _, err := chooseStore(func() (Store, error) { return nativeNil, nil }, func() (Store, error) { return nil, ErrUnavailable }); err == nil || !strings.Contains(err.Error(), "fallback opener returned nil store") {
		t.Fatalf("fallback typed nil store error = %v", err)
	}
}

func TestChooseStoreWithContextRejectsCancellationBeforeFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fallbackCalled := false
	_, err := chooseStoreWithContext(ctx, func() (Store, error) {
		fallbackCalled = true
		return backendTestStore{}, nil
	}, func() (Store, error) {
		cancel()
		return nil, ErrUnavailable
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("context-aware selection error = %v, want context.Canceled", err)
	}
	if fallbackCalled {
		t.Fatal("fallback opened after cancellation during native selection")
	}
}

func TestChooseStoreWithContextRejectsCanceledNativeResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := chooseStoreWithContext(ctx, func() (Store, error) {
		return backendTestStore{}, nil
	}, func() (Store, error) {
		cancel()
		return backendTestStore{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("context-aware native selection error = %v, want context.Canceled", err)
	}
}

func TestChooseStoreWithContextRejectsCanceledFallbackResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := chooseStoreWithContext(ctx, func() (Store, error) {
		cancel()
		return backendTestStore{}, nil
	}, func() (Store, error) {
		return nil, ErrUnavailable
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("context-aware fallback selection error = %v, want context.Canceled", err)
	}
}

func TestOpenFallbackWithContextRejectsCanceledResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := openFallbackWithContext(ctx, func() (Store, error) {
		cancel()
		return backendTestStore{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("fallback-only selection error = %v, want context.Canceled", err)
	}
}

func TestOpenNativeWithContextRejectsCanceledNativeResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := openNativeWithContext(ctx, func() (Store, error) {
		cancel()
		return backendTestStore{}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("native-only selection error = %v, want context.Canceled", err)
	}
}

func TestOpenNativeWithContextRejectsNilOpener(t *testing.T) {
	_, err := openNativeWithContext(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "native opener is nil") {
		t.Fatalf("nil native-only opener error = %v, want nil-opener failure", err)
	}
}

func TestOpenNativeWithContextContainsOpenerPanic(t *testing.T) {
	const secretPanic = "native-only panic must not escape"
	_, err := openNativeWithContext(context.Background(), func() (Store, error) {
		panic(secretPanic)
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("native-only opener panic error = %v, want stable open label", err)
	}
	if strings.Contains(err.Error(), secretPanic) {
		t.Fatalf("native-only opener panic detail escaped: %v", err)
	}
}

func TestOpenNativeWithContextRedactsConstructionFailure(t *testing.T) {
	const secretText = "secret-bearing login keychain diagnostic"
	want := errors.New(secretText)
	_, err := openNativeWithContext(context.Background(), func() (Store, error) {
		return nil, want
	})
	if err == nil || err.Error() != "native secure store open failed" {
		t.Fatalf("native-only construction error = %v, want stable open label", err)
	}
	if strings.Contains(err.Error(), secretText) {
		t.Fatalf("native-only construction diagnostic leaked: %v", err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("native-only construction error = %v, want errors.Is classification", err)
	}
}
