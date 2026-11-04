package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const maxNativeVerificationEvidenceSize = 4 << 10

// NativeVerificationResult contains non-secret evidence from one native-store
// lifecycle check. The generated values are intentionally not returned.
type NativeVerificationResult struct {
	Name                string `json:"name"`
	PutVersion          uint64 `json:"put_version"`
	RotateVersion       uint64 `json:"rotate_version"`
	RevokedReadRejected bool   `json:"revoked_read_rejected"`
	RepeatedRevokeOK    bool   `json:"repeated_revoke_ok"`
	CleanupSucceeded    bool   `json:"cleanup_succeeded"`
}

// ValidateNativeVerificationResult checks the success evidence contract
// before a caller treats a native lifecycle run as passed. Failed runs may
// intentionally return partial evidence, but a nil error must never be
// paired with a contradictory or non-supervisor result.
func ValidateNativeVerificationResult(result NativeVerificationResult) error {
	if err := ValidateNativeVerificationName(result.Name); err != nil {
		return fmt.Errorf("native verification result name: %w", err)
	}
	if result.PutVersion != 1 {
		return fmt.Errorf("native verification result put version = %d, want 1", result.PutVersion)
	}
	if result.RotateVersion != 2 {
		return fmt.Errorf("native verification result rotate version = %d, want 2", result.RotateVersion)
	}
	if !result.RevokedReadRejected {
		return errors.New("native verification result did not reject revoked read")
	}
	if !result.RepeatedRevokeOK {
		return errors.New("native verification result did not confirm repeated revoke")
	}
	if !result.CleanupSucceeded {
		return errors.New("native verification result did not confirm cleanup")
	}
	return nil
}

// ParseNativeVerificationEvidence decodes one retained checker result and
// validates the complete success contract before a supervisor treats it as a
// pass. The input is deliberately bounded and uses the same strict JSON
// boundary as persisted/native records, so evidence replay cannot accept a
// parser differential or an unbounded document.
func ParseNativeVerificationEvidence(data []byte) (NativeVerificationResult, error) {
	if len(data) > maxNativeVerificationEvidenceSize {
		return NativeVerificationResult{}, errors.New("native verification evidence exceeds limit")
	}
	var result NativeVerificationResult
	if err := decodeSingleJSON(data, &result); err != nil {
		return NativeVerificationResult{}, fmt.Errorf("parse native verification evidence: %w", err)
	}
	if err := ValidateNativeVerificationResult(result); err != nil {
		return NativeVerificationResult{}, fmt.Errorf("validate native verification evidence: %w", err)
	}
	return result, nil
}

// nativeVerificationError preserves machine-readable classification without
// copying adapter diagnostics into the supervisor CLI's stderr. A native
// seam must not turn a secret-bearing platform error into evidence or a log
// line.
type nativeVerificationError struct {
	operation string
	cause     error
}

func (e *nativeVerificationError) Error() string {
	return "native verification " + e.operation + " failed"
}

func (e *nativeVerificationError) Unwrap() error { return e.cause }

func redactNativeVerificationError(operation string, err error) error {
	return RedactNativeVerificationError(operation, err)
}

// RedactNativeVerificationError wraps an untrusted native error with stable
// operation-level text while retaining errors.Is/errors.As classification.
// Supervisor-facing callers should use this boundary before returning native
// construction or lifecycle failures to a CLI, audit record, or evidence
// channel; platform diagnostics may contain secret-bearing details.
func RedactNativeVerificationError(operation string, err error) error {
	err = sanitizeNativeErrorChain(err)
	if err == nil {
		return nil
	}
	return &nativeVerificationError{operation: safeNativeVerificationOperation(operation), cause: err}
}

// nativeStoreError keeps platform adapter diagnostics out of the shared vault
// error boundary while preserving errors.Is/errors.As classification for
// callers that need to distinguish missing items or OS failures.
type nativeStoreError struct {
	operation string
	cause     error
}

func (e *nativeStoreError) Error() string {
	return "native secure store " + e.operation + " failed"
}

func (e *nativeStoreError) Unwrap() error { return e.cause }

func redactNativeStoreError(operation string, err error) error {
	err = sanitizeNativeErrorChain(err)
	if err == nil {
		return nil
	}
	return &nativeStoreError{operation: safeNativeStoreOperation(operation), cause: err}
}

func safeNativeStoreOperation(operation string) string {
	switch operation {
	case "open", "read", "write", "delete":
		return operation
	default:
		return "operation"
	}
}

// safeNativeVerificationOperation keeps the error label useful for the
// verifier's fixed call sites without trusting arbitrary operation text at a
// supervisor-facing redaction boundary. An operation label is metadata, not
// evidence; unknown labels must not become a secret-bearing diagnostic path.
func safeNativeVerificationOperation(operation string) string {
	switch operation {
	case "open", "cleanup", "create-only", "put", "get", "generate rotation value", "rotate", "revoked read", "repeated revoke":
		return operation
	default:
		return "operation"
	}
}

// MarshalJSON uses an explicit evidence allow-list. Keep the supervisor
// record stable and non-secret even if this in-memory result later gains
// diagnostic fields for internal callers.
func (r NativeVerificationResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name                string `json:"name"`
		PutVersion          uint64 `json:"put_version"`
		RotateVersion       uint64 `json:"rotate_version"`
		RevokedReadRejected bool   `json:"revoked_read_rejected"`
		RepeatedRevokeOK    bool   `json:"repeated_revoke_ok"`
		CleanupSucceeded    bool   `json:"cleanup_succeeded"`
	}{
		Name:                r.Name,
		PutVersion:          r.PutVersion,
		RotateVersion:       r.RotateVersion,
		RevokedReadRejected: r.RevokedReadRejected,
		RepeatedRevokeOK:    r.RepeatedRevokeOK,
		CleanupSucceeded:    r.CleanupSucceeded,
	})
}

// VerifyNativeLifecycle exercises one uniquely named native item without
// overwriting an existing item. It generates test values in memory, verifies
// the shared lifecycle semantics, and removes only the named item through the
// explicit NativeCleanup boundary. Callers must still choose a unique,
// non-secret name and record only the returned evidence.
func VerifyNativeLifecycle(store Store, cleanup NativeCleanup, name string) (result NativeVerificationResult, err error) {
	return VerifyNativeLifecycleContext(context.Background(), store, cleanup, name)
}

// VerifyNativeLifecycleContext is the bounded supervisor-host variant of
// VerifyNativeLifecycle. It checks ctx between native lifecycle calls and
// still cleans an item after a create-only call has passed the absence check.
// Individual native adapters retain their own operation deadlines; this
// context prevents a canceled or expired supervisor run from starting the
// next lifecycle step.
func VerifyNativeLifecycleContext(ctx context.Context, store Store, cleanup NativeCleanup, name string) (result NativeVerificationResult, err error) {
	result = NativeVerificationResult{Name: name}
	if ctx == nil || nilContext(ctx) {
		return result, errors.New("native verification context is nil")
	}
	if err := ValidateNativeVerificationName(name); err != nil {
		return result, err
	}
	if nilStore(store) {
		return result, errors.New("native verification store is nil")
	}
	if nilInterface(cleanup) {
		return result, errors.New("native verification cleanup is nil")
	}
	creator, ok := store.(NativeCreateOnly)
	if !ok || nilInterface(creator) {
		return result, errors.New("native verification store lacks create-only boundary")
	}
	contextErr := func() error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("native verification context: %w", err)
		}
		return nil
	}

	// A native write can commit an item and still return an error or panic at
	// the adapter boundary. PutIfAbsent reports whether this invocation passed
	// the absence check, so an existing item is never deleted during cleanup.
	cleanupNeeded := false
	cleanupAttempted := false
	cleanupSucceeded := false
	cleanupItem := func() (cleanupErr error) {
		if cleanupAttempted {
			if cleanupSucceeded {
				return nil
			}
			return errors.New("native verification cleanup already failed")
		}
		cleanupAttempted = true
		defer func() {
			if recover() != nil {
				cleanupErr = errors.New("native verification cleanup panicked")
			}
		}()
		cleanupErr = redactNativeVerificationError("cleanup", cleanup.Delete(name))
		if cleanupErr == nil {
			cleanupSucceeded = true
			result.CleanupSucceeded = true
		}
		return cleanupErr
	}
	fail := func(cause error) (NativeVerificationResult, error) {
		if !cleanupNeeded {
			return result, cause
		}
		if cleanupErr := cleanupItem(); cleanupErr != nil {
			return result, errors.Join(cause, fmt.Errorf("cleanup native verification item: %w", cleanupErr))
		}
		return result, cause
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			panicErr := errors.New("native verification adapter panicked")
			if cleanupNeeded {
				if cleanupErr := cleanupItem(); cleanupErr != nil {
					panicErr = errors.Join(panicErr, fmt.Errorf("cleanup native verification item: %w", cleanupErr))
				}
			}
			err = panicErr
		}
	}()

	first, err := verificationSecret()
	if err != nil {
		return fail(fmt.Errorf("generate native verification value: %w", err))
	}
	if err := contextErr(); err != nil {
		return result, err
	}
	// Keep cleanup armed across the native call: a panic can occur after the
	// adapter has committed the item but before it returns the created flag.
	// A normal pre-existing result disarms cleanup immediately below.
	cleanupNeeded = true
	put, created, err := creator.PutIfAbsent(name, first)
	err = rejectTypedNilError(err)
	if contextErr := contextErr(); contextErr != nil {
		// Preserve the explicit existing-item rule before arming cleanup for a
		// canceled, contradictory create-only response. A canceled successful
		// creation remains owned and must still be removed.
		if !created || errors.Is(err, ErrAlreadyExists) {
			cleanupNeeded = false
			return result, contextErr
		}
		return fail(contextErr)
	}
	// ErrAlreadyExists is an explicit non-ownership result. Treat it as such
	// even if a malformed adapter also reports created=true; cleanup must never
	// delete an item when the native boundary says the name already existed.
	if errors.Is(err, ErrAlreadyExists) {
		created = false
	}
	if !created {
		cleanupNeeded = false
	}
	// Observe cancellation before interpreting any result from the native
	// boundary. A canceled create-only call that did create the item still
	// needs cleanup; a non-creating result must not be treated as owned.
	if contextErr := contextErr(); contextErr != nil {
		if !created {
			return result, contextErr
		}
		return fail(contextErr)
	}
	if !created {
		if errors.Is(err, ErrAlreadyExists) {
			return result, fmt.Errorf("native verification item %q already exists", name)
		}
		if err == nil {
			return result, errors.New("check native verification item: create-only boundary returned no creation and no error")
		}
		return result, fmt.Errorf("check native verification item: %w", redactNativeVerificationError("create-only", err))
	}
	if err != nil {
		return fail(fmt.Errorf("native verification put: %w", redactNativeVerificationError("put", err)))
	}
	if err := contextErr(); err != nil {
		return fail(err)
	}
	if err := validateRecord(name, put); err != nil {
		return fail(errors.New("native verification put returned an invalid record"))
	}
	if put.Version != 1 {
		return fail(fmt.Errorf("native verification put version = %d, want 1", put.Version))
	}
	result.PutVersion = put.Version
	if err := contextErr(); err != nil {
		return fail(err)
	}
	got, err := store.Get(name)
	err = rejectTypedNilError(err)
	// A native read may return after cancellation even when the adapter does
	// not accept a context. Stop before inspecting the record so a stale or
	// malformed response cannot replace the caller's cancellation result.
	if contextErr := contextErr(); contextErr != nil {
		return fail(contextErr)
	}
	if err != nil || got.Value != first || got.Version != put.Version {
		if err == nil {
			err = errors.New("native verification get did not return the stored record")
		}
		return fail(fmt.Errorf("native verification get: %w", redactNativeVerificationError("get", err)))
	}
	if err := validateRecord(name, got); err != nil {
		return fail(errors.New("native verification get returned an invalid record"))
	}
	if err := contextErr(); err != nil {
		return fail(err)
	}

	second, err := verificationSecret()
	if err != nil {
		return fail(fmt.Errorf("generate native rotation value: %w", redactNativeVerificationError("generate rotation value", err)))
	}
	if err := contextErr(); err != nil {
		return fail(err)
	}
	rotated, err := store.Rotate(name, second)
	err = rejectTypedNilError(err)
	if contextErr := contextErr(); contextErr != nil {
		return fail(contextErr)
	}
	if err != nil {
		return fail(fmt.Errorf("native verification rotate: %w", redactNativeVerificationError("rotate", err)))
	}
	if err := contextErr(); err != nil {
		return fail(err)
	}
	if err := validateRecord(name, rotated); err != nil {
		return fail(errors.New("native verification rotate returned an invalid record"))
	}
	if rotated.Version != 2 {
		return fail(fmt.Errorf("native verification rotate version = %d, want 2", rotated.Version))
	}
	result.RotateVersion = rotated.Version
	if err := contextErr(); err != nil {
		return fail(err)
	}
	got, err = store.Get(name)
	err = rejectTypedNilError(err)
	if contextErr := contextErr(); contextErr != nil {
		return fail(contextErr)
	}
	if err != nil || got.Value != second || got.Version != rotated.Version {
		if err == nil {
			err = errors.New("native verification get after rotate did not return the rotated record")
		}
		return fail(fmt.Errorf("native verification get after rotate: %w", redactNativeVerificationError("get after rotate", err)))
	}
	if err := validateRecord(name, got); err != nil {
		return fail(errors.New("native verification get after rotate returned an invalid record"))
	}
	if err := contextErr(); err != nil {
		return fail(err)
	}

	err = store.Revoke(name)
	err = rejectTypedNilError(err)
	if contextErr := contextErr(); contextErr != nil {
		return fail(contextErr)
	}
	if err != nil {
		return fail(fmt.Errorf("native verification revoke: %w", redactNativeVerificationError("revoke", err)))
	}
	if err := contextErr(); err != nil {
		return fail(err)
	}
	_, err = store.Get(name)
	err = rejectTypedNilError(err)
	if contextErr := contextErr(); contextErr != nil {
		return fail(contextErr)
	}
	if !errors.Is(err, ErrRevoked) {
		if err == nil {
			err = errors.New("native verification revoked read returned a live record")
		}
		return fail(fmt.Errorf("native verification revoked read: %w", redactNativeVerificationError("revoked read", err)))
	}
	if err := contextErr(); err != nil {
		return fail(err)
	}
	result.RevokedReadRejected = true
	err = store.Revoke(name)
	err = rejectTypedNilError(err)
	if contextErr := contextErr(); contextErr != nil {
		return fail(contextErr)
	}
	if err != nil {
		return fail(fmt.Errorf("native verification repeated revoke: %w", redactNativeVerificationError("repeated revoke", err)))
	}
	if err := contextErr(); err != nil {
		return fail(err)
	}
	result.RepeatedRevokeOK = true
	if err := cleanupItem(); err != nil {
		return result, fmt.Errorf("cleanup native verification item: %w", err)
	}
	// Cleanup is the final native boundary. Preserve its success evidence, but
	// do not report the overall verification as successful if the supervisor
	// canceled while cleanup was in progress.
	if err := contextErr(); err != nil {
		return result, err
	}
	if err := ValidateNativeVerificationResult(result); err != nil {
		return result, err
	}
	return result, nil
}

func verificationSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
