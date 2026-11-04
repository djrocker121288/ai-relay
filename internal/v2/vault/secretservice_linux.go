//go:build linux

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	secretServiceMaxOutput     = 64 << 10
	secretServiceOperationTime = 10 * time.Second
	secretServiceApplication   = "ai-relay-v2"
	secretServiceLabel         = "AI Relay 2.0"
)

var errSecretServiceOutputLimit = errors.New("secret service output exceeds limit")

// SecretService stores one authenticated, versioned payload per name through
// the user's Secret Service keyring. It never places secret values in argv or
// logs. The system secret-tool binary is used instead of adding a DBus
// library dependency; absence of the binary or a session is ErrUnavailable.
type SecretService struct {
	mu  sync.Mutex
	run func(context.Context, string, []string, string) ([]byte, error)
}

// Keep the Linux native adapter aligned with the shared lifecycle contract.
var _ Store = (*SecretService)(nil)
var _ NativeCleanup = (*SecretService)(nil)
var _ NativeCreateOnly = (*SecretService)(nil)

type secretServicePayload struct {
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Version   uint64    `json:"version"`
	Revoked   bool      `json:"revoked"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *SecretService) ensureRunner() error {
	if s == nil || s.run == nil {
		return errors.New("secret service runner is nil")
	}
	return nil
}

// OpenSecretService probes the local keyring command without writing a
// secret. Callers must explicitly choose fallback behavior when it is absent.
func OpenSecretService(ctx context.Context) (*SecretService, error) {
	return openSecretService(ctx, runSecretTool)
}

func openSecretService(ctx context.Context, run func(context.Context, string, []string, string) ([]byte, error)) (*SecretService, error) {
	if err := validateOpenContext(ctx); err != nil {
		return nil, err
	}
	if run == nil {
		return nil, errors.New("secret service runner is nil")
	}
	s := &SecretService{run: run}
	probeCtx, cancel := context.WithTimeout(ctx, secretServiceOperationTime)
	defer cancel()
	// A version check only proves that the helper is installed. A read-only
	// lookup of a reserved item also verifies that the current process has a
	// usable Secret Service session without creating or changing a secret.
	probeOutput, err := runSecretService(s.run, probeCtx, "lookup", []string{
		"--attribute=application", secretServiceApplication,
		"--attribute=name", secretServiceProbeName,
	}, "")
	// Do not trust an injected or future runner to enforce the context. A
	// successful-looking or oversized result after the bounded probe expired
	// must not select a native backend after the caller has withdrawn the
	// request. Check cancellation before interpreting the returned bytes.
	if probeErr := probeCtx.Err(); probeErr != nil {
		return nil, probeErr
	}
	if _, err := boundedNativeOutput(probeOutput, nil); err != nil {
		return nil, err
	}
	if err != nil {
		if !isSecretMissingResult(probeOutput, err) {
			if isSecretMissingError(err) {
				return nil, errors.New("secret service missing result included output")
			}
			return nil, classifyProbeError(err)
		}
	}
	return s, nil
}

const secretServiceProbeName = "__ai_relay_v2_capability_probe__"

func classifyProbeError(err error) error {
	err = rejectTypedNilError(err)
	if contextErr := canonicalSecretServiceContextError(err); contextErr != nil {
		return contextErr
	}
	// Only an absent helper permits the encrypted-file fallback. Preserve every
	// other native failure so backend selection cannot hide permission or
	// runtime errors.
	if matched, _ := safeSecretServiceErrorsIs(err, exec.ErrNotFound); matched {
		return fmt.Errorf("%w: secret-tool helper unavailable", ErrUnavailable)
	}
	return redactSecretServiceError(err)
}

// redactedSecretServiceError preserves machine-readable classification through
// errors.Is/errors.As while keeping an injected or future runner's diagnostic
// text out of the vault error boundary. The real subprocess runner already
// avoids exposing captured stderr; this wrapper keeps that invariant true for
// every runner implementation.
type redactedSecretServiceError struct{ cause error }

func (e *redactedSecretServiceError) Error() string {
	return "secret service operation failed"
}

func (e *redactedSecretServiceError) Unwrap() error { return e.cause }

func redactSecretServiceError(err error) error {
	err = rejectTypedNilError(err)
	if err == nil {
		return err
	}
	// A runner can wrap a context sentinel with native or secret-bearing
	// diagnostics. Preserve the authoritative cancellation class without
	// returning that untrusted wrapper's Error text.
	if contextErr := canonicalSecretServiceContextError(err); contextErr != nil {
		return contextErr
	}
	// Preserve the established bounded-output classification when the shared
	// runner rejects an injected response before an operation-specific caller
	// can inspect it. The error contains no runner detail to redact.
	if matched, panicked := safeSecretServiceErrorsIs(err, errSecretServiceOutputLimit); matched {
		return errSecretServiceOutputLimit
	} else if panicked {
		// Do not retain a hostile error whose Is method panicked: returning it
		// through Unwrap would let a later caller reproduce the panic.
		return &redactedSecretServiceError{}
	}
	return &redactedSecretServiceError{cause: err}
}

func canonicalSecretServiceContextError(err error) error {
	if matched, _ := safeSecretServiceErrorsIs(err, context.Canceled); matched {
		return context.Canceled
	}
	if matched, _ := safeSecretServiceErrorsIs(err, context.DeadlineExceeded); matched {
		return context.DeadlineExceeded
	}
	return nil
}

// safeSecretServiceErrorsIs/As keep direct internal classification seams
// fail-closed when an injected or future native error implements a panicking
// Is or As method. The runner boundary already contains panics from the
// callable itself; these helpers cover the separate error-chain boundary and
// never expose the panic value or return the hostile error as a usable cause.
func safeSecretServiceErrorsIs(err, target error) (matched, panicked bool) {
	defer func() {
		if recover() != nil {
			matched = false
			panicked = true
		}
	}()
	return errors.Is(err, target), false
}

func safeSecretServiceErrorsAs(err error, target any) (matched, panicked bool) {
	defer func() {
		if recover() != nil {
			matched = false
			panicked = true
		}
	}()
	return errors.As(err, target), false
}

// runSecretService contains an unexpected runner panic at the native boundary.
// A runner may be the real subprocess adapter or an injected/future platform
// seam; neither may terminate a caller or expose a panic value that could
// contain a secret or native diagnostic. A panic after a native write remains
// an ambiguous operation and is reported as an error for the caller to handle.
func runSecretService(run func(context.Context, string, []string, string) ([]byte, error), ctx context.Context, operation string, args []string, stdin string) (output []byte, err error) {
	// Keep the lowest native boundary fail-closed even if a future caller
	// bypasses one of the operation-specific preflights. In particular, do
	// not let a typed-nil context reach a context method or a nil runner reach
	// the panic boundary.
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if run == nil {
		return nil, errors.New("secret service runner is nil")
	}
	if err := validateSecretServiceOperation(operation); err != nil {
		return nil, err
	}
	if err := validateSecretServiceArguments(operation, args, stdin); err != nil {
		return nil, err
	}
	defer func() {
		if recover() != nil {
			output = nil
			err = errors.New("secret service runner panicked")
		}
	}()
	output, err = run(ctx, operation, args, stdin)
	err = rejectTypedNilError(err)
	// Keep the lowest runner seam opaque as well as the operation-specific
	// callers above it. A direct in-process caller must not be able to bypass
	// diagnostic redaction merely by invoking this shared boundary; preserve
	// errors.Is/errors.As classification through the wrapper.
	err = redactSecretServiceError(err)
	// Keep cancellation authoritative even when an injected or future runner
	// returns a successful-looking result after its context has expired. Apply
	// the output bound at this lowest seam as well, so no operation-specific
	// caller can accidentally inspect or classify an oversized response first.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if _, boundErr := boundedNativeOutput(output, nil); boundErr != nil {
		return nil, boundErr
	}
	return output, err
}

// validateSecretServiceOperation keeps the lowest command boundary closed to
// arbitrary secret-tool subcommands. The adapter only needs these three
// operations; rejecting anything else prevents a future or malformed caller
// from dispatching an unintended helper operation through the native runner.
func validateSecretServiceOperation(operation string) error {
	switch operation {
	case "lookup", "store", "clear":
		return nil
	default:
		return errors.New("secret service operation is unsupported")
	}
}

// validateSecretServiceArguments keeps the lowest command boundary bound to
// the adapter's fixed attribute schema. The runner is intentionally not a
// generic secret-tool escape hatch: arbitrary attributes could select a
// different item namespace, and an unrestricted clear could delete an item
// outside the uniquely named supervisor verification boundary.
func validateSecretServiceArguments(operation string, args []string, stdin string) error {
	validAttributes := func(got []string, name string, allowProbe bool) bool {
		if len(got) != 4 || got[0] != "--attribute=application" || got[1] != secretServiceApplication || got[2] != "--attribute=name" {
			return false
		}
		if allowProbe && name == secretServiceProbeName {
			return true
		}
		return validName(name) == nil
	}

	switch operation {
	case "lookup":
		if !validAttributes(args, argsLast(args), true) || stdin != "" {
			return errors.New("secret service lookup arguments are invalid")
		}
	case "store":
		if len(args) != 5 || args[0] != "--label="+secretServiceLabel || !validAttributes(args[1:], argsLast(args), false) || !validSecretServiceStoreInput(argsLast(args), stdin) {
			return errors.New("secret service store arguments are invalid")
		}
	case "clear":
		if !validAttributes(args, argsLast(args), false) || ValidateNativeVerificationName(argsLast(args)) != nil || stdin != "" {
			return errors.New("secret service clear arguments are invalid")
		}
	default:
		return errors.New("secret service operation is unsupported")
	}
	return nil
}

// validSecretServiceStoreInput keeps the lowest runner seam bound to the
// versioned record format. The higher storeWithContext helper repeats these
// checks against its in-memory record; this lower check prevents a future
// internal caller from turning runSecretService into a generic keyring write.
func validSecretServiceStoreInput(name, stdin string) bool {
	b := []byte(stdin)
	if len(b) == 0 || validPayload(b) != nil {
		return false
	}
	var payload secretServicePayload
	if decodeSingleJSON(b, &payload) != nil || payload.Name != name {
		return false
	}
	return validateRecord(name, Record(payload)) == nil
}

func argsLast(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[len(args)-1]
}

func (s *SecretService) Get(name string) (Record, error) {
	if err := s.ensureRunner(); err != nil {
		return Record{}, err
	}
	if err := validName(name); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(name)
}

func (s *SecretService) get(name string) (Record, error) {
	if err := s.ensureRunner(); err != nil {
		return Record{}, err
	}
	if err := validName(name); err != nil {
		return Record{}, err
	}
	b, err := s.lookup(name)
	if err != nil {
		// lookup converts only a validated, empty-output missing result to
		// this private sentinel. Use identity here so a malformed native
		// wrapper that happens to contain the sentinel cannot be promoted to
		// ErrNotFound by broad errors.Is matching.
		if err == errSecretMissing {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	if err := validPayload(b); err != nil {
		return Record{}, err
	}
	var p secretServicePayload
	if err := decodeSingleJSON(b, &p); err != nil || p.Name != name || p.Version == 0 {
		return Record{}, errors.New("secret service record is invalid")
	}
	if err := validateRecord(name, Record(p)); err != nil {
		return Record{}, fmt.Errorf("secret service record is invalid: %w", err)
	}
	if p.Revoked {
		return Record{}, ErrRevoked
	}
	return Record(p), nil
}

func (s *SecretService) Put(name, value string) (Record, error) {
	if err := s.ensureRunner(); err != nil {
		return Record{}, err
	}
	if err := validName(name); err != nil {
		return Record{}, err
	}
	if err := validValue(value); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	version := uint64(1)
	if old, err := s.get(name); err == nil {
		version, err = nextRecordVersion(old.Version)
		if err != nil {
			return Record{}, err
		}
	} else if !errors.Is(err, ErrNotFound) {
		return Record{}, err
	}
	return s.store(secretServicePayload{Name: name, Value: value, Version: version, UpdatedAt: time.Now().UTC()})
}

// PutIfAbsent creates a native item only when the name is absent. The created
// flag remains true after the absence check so callers can clean up a write
// that may have committed before returning an error.
func (s *SecretService) PutIfAbsent(name, value string) (Record, bool, error) {
	if err := s.ensureRunner(); err != nil {
		return Record{}, false, err
	}
	if err := ValidateNativeVerificationName(name); err != nil {
		return Record{}, false, err
	}
	if err := validValue(value); err != nil {
		return Record{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.get(name); err == nil {
		return Record{}, false, ErrAlreadyExists
	} else if errors.Is(err, ErrRevoked) {
		return Record{}, false, ErrAlreadyExists
	} else if !errors.Is(err, ErrNotFound) {
		return Record{}, false, err
	}
	record, err := s.store(secretServicePayload{Name: name, Value: value, Version: 1, UpdatedAt: time.Now().UTC()})
	return record, true, err
}

func (s *SecretService) Rotate(name, value string) (Record, error) {
	if err := s.ensureRunner(); err != nil {
		return Record{}, err
	}
	if err := validName(name); err != nil {
		return Record{}, err
	}
	if err := validValue(value); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.get(name)
	if err != nil {
		return Record{}, err
	}
	version, err := nextRecordVersion(old.Version)
	if err != nil {
		return Record{}, err
	}
	return s.store(secretServicePayload{Name: name, Value: value, Version: version, UpdatedAt: time.Now().UTC()})
}

func (s *SecretService) Revoke(name string) error {
	if err := s.ensureRunner(); err != nil {
		return err
	}
	if err := validName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.get(name)
	if err != nil {
		if errors.Is(err, ErrRevoked) {
			return nil
		}
		return err
	}
	_, err = s.store(secretServicePayload{Name: name, Version: old.Version, Revoked: true, UpdatedAt: time.Now().UTC()})
	return err
}

// Delete removes one named native item for supervisor cleanup. Missing items
// are an idempotent success so a partially completed cleanup can be retried.
// This is intentionally separate from Revoke and is not available on the file
// fallback.
func (s *SecretService) Delete(name string) error {
	if err := s.ensureRunner(); err != nil {
		return err
	}
	if err := ValidateNativeVerificationName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), secretServiceOperationTime)
	defer cancel()
	return s.deleteWithContext(ctx, name)
}

func (s *SecretService) deleteWithContext(ctx context.Context, name string) error {
	if err := ValidateContext(ctx); err != nil {
		return err
	}
	if err := s.ensureRunner(); err != nil {
		return err
	}
	// Keep the lower cleanup seam safe for direct and future in-process
	// callers as well as the public Delete method. Preserve the established
	// context and unavailable-runner error precedence before validating the
	// name, but never hand malformed input to the native runner.
	if err := validName(name); err != nil {
		return err
	}
	output, runErr := runSecretService(s.run, ctx, "clear", []string{"--attribute=application", secretServiceApplication, "--attribute=name", name}, "")
	if err := validateNativeMutationResult(ctx, output, runErr); err != nil {
		return err
	}
	if isSecretMissingResult(output, runErr) {
		return nil
	}
	if isSecretMissingError(runErr) {
		return errors.New("secret service missing result included output")
	}
	return redactSecretServiceError(runErr)
}

var errSecretMissing = errors.New("secret service item missing")

// validateNativeOperationResult is the common post-run boundary for the
// injected and subprocess-backed operations. A runner may return after its
// context expired without surfacing that deadline itself; do not interpret
// its output or missing-item error after cancellation.
func validateNativeOperationResult(ctx context.Context, output []byte) error {
	if err := ValidateContext(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := boundedNativeOutput(output, nil); err != nil {
		return err
	}
	return nil
}

// validateNativeMutationResult keeps store and clear fail-closed when a
// helper reports success but also emits stdout. Those operations have no
// response payload; accepting unexpected bytes would hide a malformed helper
// boundary and could retain secret material in an injected runner or future
// adapter implementation.
func validateNativeMutationResult(ctx context.Context, output []byte, runErr error) error {
	if err := validateNativeOperationResult(ctx, output); err != nil {
		return err
	}
	if len(output) != 0 {
		if isSecretMissingError(runErr) {
			return errors.New("secret service missing result included output")
		}
		return errors.New("secret service mutation returned unexpected output")
	}
	return nil
}

func (s *SecretService) lookup(name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), secretServiceOperationTime)
	defer cancel()
	return s.lookupWithContext(ctx, name)
}

func (s *SecretService) lookupWithContext(ctx context.Context, name string) ([]byte, error) {
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if err := validName(name); err != nil {
		return nil, err
	}
	if err := s.ensureRunner(); err != nil {
		return nil, err
	}
	b, err := runSecretService(s.run, ctx, "lookup", []string{"--attribute=application", secretServiceApplication, "--attribute=name", name}, "")
	// Re-check injected/future runner output before interpreting the error. The
	// real subprocess runner already captures a bounded buffer, but this
	// boundary must remain fail-closed for every runner implementation.
	if err := validateNativeOperationResult(ctx, b); err != nil {
		return nil, err
	}
	if err != nil {
		if isSecretMissingResult(b, err) {
			return nil, errSecretMissing
		}
		if isSecretMissingError(err) {
			return nil, errors.New("secret service missing result included output")
		}
		return nil, redactSecretServiceError(err)
	}
	return b, nil
}

// isSecretMissingResult accepts a missing-item result only when the helper
// returned no stdout bytes. A malformed runner must not turn a non-empty
// native response into absence, because that could select the wrong backend or
// cause a caller to skip an item that was actually returned.
func isSecretMissingResult(output []byte, err error) bool {
	return len(output) == 0 && isSecretMissingError(err)
}

func isSecretMissingError(err error) bool {
	// This classifier is also an internal lower seam. Reject a typed-nil
	// error before errors.As/errors.Is can inspect it, so a malformed injected
	// runner cannot panic classification or be treated as an absent item.
	err = rejectTypedNilError(err)
	if err == nil {
		return false
	}
	var commandErr *secretToolCommandError
	if matched, panicked := safeSecretServiceErrorsAs(err, &commandErr); panicked {
		return false
	} else if matched {
		if commandErr == nil || nilInterface(commandErr.err) {
			return false
		}
		// A command wrapper carrying stderr is a native/session failure even
		// when an injected or future runner also wraps the missing sentinel.
		// Check the wrapper before the generic sentinel path so diagnostics
		// cannot be turned into an absent-item result.
		if len(commandErr.stderr) != 0 {
			return false
		}
		if matched, panicked := safeSecretServiceErrorsIs(commandErr.err, errSecretMissing); matched && !panicked {
			return true
		}
	} else if matched, panicked := safeSecretServiceErrorsIs(err, errSecretMissing); matched && !panicked {
		return true
	}
	if commandErr == nil || nilInterface(commandErr.err) {
		return false
	}
	var exitErr *exec.ExitError
	// secret-tool uses an empty exit-1 result for a missing item. An exit-1
	// result with stderr is a native/session failure and must remain visible.
	if len(commandErr.stderr) != 0 {
		return false
	}
	matched, panicked := safeSecretServiceErrorsAs(commandErr.err, &exitErr)
	if panicked || !matched || exitErr == nil {
		return false
	}
	return exitErr.ExitCode() == 1
}

func (s *SecretService) store(p secretServicePayload) (Record, error) {
	if err := validateRecord(p.Name, Record(p)); err != nil {
		return Record{}, fmt.Errorf("secret service record is invalid: %w", err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		return Record{}, err
	}
	if err := validPayload(b); err != nil {
		return Record{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), secretServiceOperationTime)
	defer cancel()
	return s.storeWithContext(ctx, p, b)
}

func (s *SecretService) storeWithContext(ctx context.Context, p secretServicePayload, b []byte) (Record, error) {
	if err := ValidateContext(ctx); err != nil {
		return Record{}, err
	}
	if err := validateSecretServiceStorePayload(p, b); err != nil {
		return Record{}, err
	}
	if err := s.ensureRunner(); err != nil {
		return Record{}, err
	}
	output, runErr := runSecretService(s.run, ctx, "store", []string{"--label=" + secretServiceLabel, "--attribute=application", secretServiceApplication, "--attribute=name", p.Name}, string(b))
	if err := validateNativeMutationResult(ctx, output, runErr); err != nil {
		return Record{}, err
	}
	if runErr != nil {
		return Record{}, redactSecretServiceError(runErr)
	}
	return Record(p), nil
}

// validateSecretServiceStorePayload repeats the record and payload checks at
// the lowest write helper. The caller normally supplies bytes produced by
// store, but keeping this seam self-contained prevents a future internal path
// from sending a malformed or metadata-mismatched blob to the native runner.
func validateSecretServiceStorePayload(p secretServicePayload, b []byte) error {
	if err := validateRecord(p.Name, Record(p)); err != nil {
		return errors.New("secret service record is invalid")
	}
	if err := validPayload(b); err != nil {
		return err
	}
	var encoded secretServicePayload
	if err := decodeSingleJSON(b, &encoded); err != nil {
		return errors.New("secret service payload is invalid")
	}
	if encoded.Name != p.Name || encoded.Value != p.Value || encoded.Version != p.Version || encoded.Revoked != p.Revoked || !encoded.UpdatedAt.Equal(p.UpdatedAt) {
		return errors.New("secret service payload does not match record")
	}
	return nil
}

func runSecretTool(ctx context.Context, operation string, args []string, stdin string) ([]byte, error) {
	// Keep the concrete subprocess seam safe for direct and future in-process
	// callers as well as the shared runSecretService wrapper. In particular,
	// exec.CommandContext panics for a nil context, and bypassing the wrapper
	// must not turn this helper into a generic secret-tool command path.
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateSecretServiceOperation(operation); err != nil {
		return nil, err
	}
	if err := validateSecretServiceArguments(operation, args, stdin); err != nil {
		return nil, err
	}
	argv := append([]string{operation}, args...)
	cmd := exec.CommandContext(ctx, "secret-tool", argv...)
	cmd.Stdin = strings.NewReader(stdin)
	var stderr boundedBuffer
	cmd.Stderr = &stderr
	var out boundedBuffer
	cmd.Stdout = &out
	err := cmd.Run()
	// CommandContext may report the child termination signal instead of the
	// caller's cancellation/deadline. Preserve the authoritative context
	// result so backend selection cannot misclassify shutdown as a native
	// keyring failure or an unavailable helper.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if _, err := boundedNativeOutput(stderr.Bytes(), nil); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, &secretToolCommandError{err: err, stderr: append([]byte(nil), stderr.Bytes()...)}
	}
	return boundedNativeOutput(out.Bytes(), nil)
}

type secretToolCommandError struct {
	err    error
	stderr []byte
}

func (e *secretToolCommandError) Error() string {
	// Keep the concrete subprocess seam opaque for direct and future internal
	// callers. Unwrap still preserves machine-readable classification without
	// copying native or secret-bearing diagnostics into Error().
	return "secret service command failed"
}

func (e *secretToolCommandError) Unwrap() error {
	if e == nil || nilInterface(e.err) {
		return nil
	}
	return e.err
}

// boundedBuffer keeps one sentinel byte so callers can distinguish an output
// that exactly fits the limit from one that exceeded it, without allowing a
// native helper to grow the worker's memory usage without bound.
type boundedBuffer struct{ data []byte }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := secretServiceMaxOutput + 1 - len(b.data)
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

func (b *boundedBuffer) Bytes() []byte { return b.data }

func boundedNativeOutput(b []byte, err error) ([]byte, error) {
	if len(b) > secretServiceMaxOutput {
		return nil, errSecretServiceOutputLimit
	}
	return b, err
}

var _ Store = (*SecretService)(nil)
