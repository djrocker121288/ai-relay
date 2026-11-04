//go:build linux

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecretServiceRejectsVersionExhaustionBeforeNativeWrite(t *testing.T) {
	const name = "controller/chatgpt"
	payload, err := json.Marshal(secretServicePayload{Name: name, Value: "secret", Version: ^uint64(0), UpdatedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	items := map[string][]byte{name: payload}
	writes := 0
	s := &SecretService{run: func(_ context.Context, op string, args []string, stdin string) ([]byte, error) {
		if op == "lookup" {
			return items[args[len(args)-1]], nil
		}
		if op == "store" {
			writes++
			items[args[len(args)-1]] = []byte(stdin)
		}
		return nil, nil
	}}
	if _, err := s.Rotate(name, "replacement"); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("Rotate at maximum version = %v, want ErrVersionExhausted", err)
	}
	if writes != 0 || string(items[name]) != string(payload) {
		t.Fatalf("version-exhausted rotation reached native store: writes=%d", writes)
	}
}

func TestSecretServiceLifecycleAndSafeArguments(t *testing.T) {
	items := map[string][]byte{}
	var calls []string
	s := &SecretService{run: func(_ context.Context, op string, args []string, stdin string) ([]byte, error) {
		calls = append(calls, op+" "+strings.Join(args, " "))
		name := args[len(args)-1]
		switch op {
		case "lookup":
			b, ok := items[name]
			if !ok {
				return nil, errSecretMissing
			}
			return b, nil
		case "store":
			items[name] = []byte(stdin)
			return nil, nil
		case "clear":
			if _, ok := items[name]; !ok {
				return nil, errSecretMissing
			}
			delete(items, name)
			return nil, nil
		default:
			return nil, nil
		}
	}}

	const name = "supervisor/secretservice-lifecycle"
	r, err := s.Put(name, "top-secret")
	if err != nil || r.Version != 1 {
		t.Fatalf("put: %#v %v", r, err)
	}
	if _, err = s.Rotate(name, "rotated"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(name); err != nil || got.Value != "rotated" || got.Version != 2 {
		t.Fatalf("get: %#v %v", got, err)
	}
	if err = s.Revoke(name); err != nil {
		t.Fatal(err)
	}
	if err = s.Revoke(name); err != nil {
		t.Fatalf("repeated revoke: %v", err)
	}
	if _, err = s.Get(name); err != ErrRevoked {
		t.Fatalf("revoke: %v", err)
	}
	if err = s.Delete(name); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err = s.Delete(name); err != nil {
		t.Fatalf("repeated delete: %v", err)
	}
	if _, err = s.Get(name); err != ErrNotFound {
		t.Fatalf("delete: %v", err)
	}
	for _, call := range calls {
		if strings.Contains(call, "top-secret") || strings.Contains(call, "rotated") {
			t.Fatalf("secret leaked into argv: %q", call)
		}
	}
}

func TestSecretServiceDeleteRejectsProductionNamespaceBeforeNativeDelete(t *testing.T) {
	calls := 0
	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		calls++
		return nil, nil
	}}
	if err := s.Delete("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "supervisor/") {
		t.Fatalf("production delete error = %v, want dedicated-namespace rejection", err)
	}
	if calls != 0 {
		t.Fatalf("production delete reached native runner %d time(s)", calls)
	}
}

func TestSecretServicePutIfAbsentPreservesExistingItem(t *testing.T) {
	items := map[string][]byte{}
	s := &SecretService{run: func(_ context.Context, op string, args []string, stdin string) ([]byte, error) {
		name := args[len(args)-1]
		switch op {
		case "lookup":
			if value, ok := items[name]; ok {
				return value, nil
			}
			return nil, errSecretMissing
		case "store":
			items[name] = []byte(stdin)
		}
		return nil, nil
	}}
	const name = "supervisor/create-only"
	if _, owned, err := s.PutIfAbsent(name, "first"); err != nil || !owned {
		t.Fatalf("first PutIfAbsent = owned=%t err=%v, want ownership", owned, err)
	}
	before := append([]byte(nil), items[name]...)
	if _, owned, err := s.PutIfAbsent(name, "replacement"); !errors.Is(err, ErrAlreadyExists) || owned {
		t.Fatalf("existing PutIfAbsent = owned=%t err=%v, want no ownership and ErrAlreadyExists", owned, err)
	}
	if string(items[name]) != string(before) {
		t.Fatal("existing Secret Service item changed after rejected PutIfAbsent")
	}
}

func TestSecretServicePutIfAbsentRejectsProductionNamespaceBeforeNativeWrite(t *testing.T) {
	calls := 0
	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		calls++
		return nil, nil
	}}
	if _, owned, err := s.PutIfAbsent("controller/chatgpt", "secret"); err == nil || owned || !strings.Contains(err.Error(), "supervisor/") {
		t.Fatalf("production PutIfAbsent = owned=%t err=%v, want dedicated-namespace rejection", owned, err)
	}
	if calls != 0 {
		t.Fatalf("production PutIfAbsent reached native runner %d time(s)", calls)
	}
}

func TestSecretServicePreservesLookupFailures(t *testing.T) {
	want := errors.New("keyring session unavailable")
	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		return nil, want
	}}
	if _, err := s.Put("controller/chatgpt", "secret"); !errors.Is(err, want) {
		t.Fatalf("lookup failure = %v, want %v", err, want)
	}
}

func TestSecretServiceRedactsRunnerErrors(t *testing.T) {
	const sensitive = "runner diagnostic contains top-secret-value"
	want := errors.New(sensitive)
	payload, err := json.Marshal(secretServicePayload{Name: "controller/chatgpt", Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		call func(*SecretService) error
	}{
		{
			name: "lookup",
			call: func(s *SecretService) error {
				_, err := s.Get("controller/chatgpt")
				return err
			},
		},
		{
			name: "store",
			call: func(s *SecretService) error {
				_, err := s.storeWithContext(context.Background(), secretServicePayload{Name: "controller/chatgpt", Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}, payload)
				return err
			},
		},
		{
			name: "delete",
			call: func(s *SecretService) error {
				return s.deleteWithContext(context.Background(), "supervisor/runner-error")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
				return nil, want
			}}
			err := tc.call(s)
			if err == nil || !errors.Is(err, want) {
				t.Fatalf("runner error = %v, want errors.Is match", err)
			}
			if strings.Contains(err.Error(), sensitive) {
				t.Fatalf("runner diagnostic leaked through error: %v", err)
			}
		})
	}

	_, err = openSecretService(context.Background(), func(context.Context, string, []string, string) ([]byte, error) {
		return nil, want
	})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("probe runner error = %v, want errors.Is match", err)
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatalf("probe runner diagnostic leaked through error: %v", err)
	}
}

func TestSecretServiceContainsRunnerPanics(t *testing.T) {
	const sensitive = "runner panic contains top-secret-value"
	payload, err := json.Marshal(secretServicePayload{Name: "controller/chatgpt", Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		call func(*SecretService) error
	}{
		{
			name: "probe",
			call: func(s *SecretService) error {
				_, err := openSecretService(context.Background(), s.run)
				return err
			},
		},
		{
			name: "lookup",
			call: func(s *SecretService) error {
				_, err := s.Get("controller/chatgpt")
				return err
			},
		},
		{
			name: "store",
			call: func(s *SecretService) error {
				_, err := s.storeWithContext(context.Background(), secretServicePayload{Name: "controller/chatgpt", Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}, payload)
				return err
			},
		},
		{
			name: "delete",
			call: func(s *SecretService) error {
				return s.deleteWithContext(context.Background(), "supervisor/runner-panic")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
				panic(sensitive)
			}}
			err := tc.call(s)
			if err == nil || err.Error() != "secret service operation failed" {
				t.Fatalf("runner panic error = %v, want established opaque error", err)
			}
			if strings.Contains(err.Error(), sensitive) {
				t.Fatalf("runner panic leaked through error: %v", err)
			}
		})
	}
}

func TestRunSecretServiceRejectsMalformedBoundaryBeforeRunner(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{name: "nil context", ctx: nil},
		{name: "typed nil context", ctx: (*typedNilContext)(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			_, err := runSecretService(func(context.Context, string, []string, string) ([]byte, error) {
				called = true
				return nil, nil
			}, tc.ctx, "lookup", nil, "")
			if err == nil || !strings.Contains(err.Error(), "context is nil") {
				t.Fatalf("malformed context error = %v, want explicit rejection", err)
			}
			if called {
				t.Fatal("malformed context reached the native runner")
			}
		})
	}

	if _, err := runSecretService(nil, context.Background(), "lookup", nil, ""); err == nil || !strings.Contains(err.Error(), "runner is nil") {
		t.Fatalf("nil runner error = %v, want explicit rejection", err)
	}
}

func TestRunSecretServiceRedactsRunnerErrorsAtLowestBoundary(t *testing.T) {
	const sensitive = "runner diagnostic contains top-secret-value"
	want := errors.New(sensitive)
	_, err := runSecretService(func(context.Context, string, []string, string) ([]byte, error) {
		return nil, want
	}, context.Background(), "lookup", []string{
		"--attribute=application", secretServiceApplication,
		"--attribute=name", "controller/chatgpt",
	}, "")
	if err == nil || err.Error() != "secret service operation failed" {
		t.Fatalf("lowest runner error = %v, want opaque operation failure", err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("lowest runner error = %v, want errors.Is classification", err)
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatalf("lowest runner diagnostic leaked through error: %v", err)
	}
}

func TestSecretServiceRedactsDiagnosticsWrappedAroundContextErrors(t *testing.T) {
	const sensitive = "secret-bearing cancellation diagnostic"
	for _, tc := range []struct {
		name  string
		cause error
		want  error
	}{
		{name: "canceled", cause: context.Canceled, want: context.Canceled},
		{name: "deadline", cause: context.DeadlineExceeded, want: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := fmt.Errorf("%s: %w", sensitive, tc.cause)
			for _, boundary := range []struct {
				name string
				call func(error) error
			}{
				{name: "operation", call: redactSecretServiceError},
				{name: "probe", call: classifyProbeError},
			} {
				t.Run(boundary.name, func(t *testing.T) {
					got := boundary.call(wrapped)
					if got != tc.want {
						t.Fatalf("redacted context error = %v, want canonical %v", got, tc.want)
					}
					if strings.Contains(got.Error(), sensitive) {
						t.Fatalf("wrapped context diagnostic leaked: %v", got)
					}
				})
			}
		})
	}

	_, err := runSecretService(func(context.Context, string, []string, string) ([]byte, error) {
		return nil, fmt.Errorf("%s: %w", sensitive, context.Canceled)
	}, context.Background(), "lookup", []string{
		"--attribute=application", secretServiceApplication,
		"--attribute=name", "controller/chatgpt",
	}, "")
	if err != context.Canceled {
		t.Fatalf("lowest runner wrapped cancellation = %v, want context.Canceled", err)
	}
}

func TestSecretServiceContainsPanickingErrorClassification(t *testing.T) {
	const sensitive = "secret-bearing error classification panic"
	malicious := panickingSecretServiceError{diagnostic: sensitive}

	for _, tc := range []struct {
		name string
		call func(error) error
	}{
		{name: "operation redaction", call: redactSecretServiceError},
		{name: "probe classification", call: classifyProbeError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.call(malicious)
			if got == nil || got.Error() != "secret service operation failed" {
				t.Fatalf("malicious error result = %v, want stable opaque failure", got)
			}
			if strings.Contains(got.Error(), sensitive) {
				t.Fatalf("malicious diagnostic escaped: %v", got)
			}
		})
	}

	if isSecretMissingError(malicious) {
		t.Fatal("malicious error was classified as a missing item")
	}

	_, err := runSecretService(func(context.Context, string, []string, string) ([]byte, error) {
		return nil, malicious
	}, context.Background(), "lookup", []string{
		"--attribute=application", secretServiceApplication,
		"--attribute=name", "controller/chatgpt",
	}, "")
	if err == nil || err.Error() != "secret service operation failed" {
		t.Fatalf("lowest runner malicious error = %v, want stable opaque failure", err)
	}
}

func TestRunSecretServiceRejectsCanceledContextBeforeRunner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := runSecretService(func(context.Context, string, []string, string) ([]byte, error) {
		called = true
		return nil, nil
	}, ctx, "lookup", nil, "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v, want context.Canceled", err)
	}
	if called {
		t.Fatal("canceled context reached the native runner")
	}
}

func TestRunSecretServiceRejectsOversizedRunnerOutputAtBoundary(t *testing.T) {
	output, err := runSecretService(func(context.Context, string, []string, string) ([]byte, error) {
		return []byte(strings.Repeat("x", secretServiceMaxOutput+1)), nil
	}, context.Background(), "lookup", []string{"--attribute=application", secretServiceApplication, "--attribute=name", "controller/chatgpt"}, "")
	if output != nil {
		t.Fatalf("oversized runner output returned %d bytes, want nil", len(output))
	}
	if err == nil || !strings.Contains(err.Error(), "output exceeds limit") {
		t.Fatalf("oversized runner output error = %v, want bounded-output failure", err)
	}
}

func TestSecretServiceLowerHelpersRejectUnavailableRunner(t *testing.T) {
	const name = "controller/chatgpt"
	p := secretServicePayload{Name: name, Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		store *SecretService
	}{
		{name: "nil receiver", store: nil},
		{name: "uninitialized receiver", store: &SecretService{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.store.get(name); err == nil || !strings.Contains(err.Error(), "runner is nil") {
				t.Fatalf("get error = %v, want unavailable runner", err)
			}
			if _, err := tc.store.lookupWithContext(context.Background(), name); err == nil || !strings.Contains(err.Error(), "runner is nil") {
				t.Fatalf("lookup error = %v, want unavailable runner", err)
			}
			if _, err := tc.store.storeWithContext(context.Background(), p, b); err == nil || !strings.Contains(err.Error(), "runner is nil") {
				t.Fatalf("store error = %v, want unavailable runner", err)
			}
			if err := tc.store.deleteWithContext(context.Background(), "supervisor/cleanup"); err == nil || !strings.Contains(err.Error(), "runner is nil") {
				t.Fatalf("delete error = %v, want unavailable runner", err)
			}
		})
	}
}

func TestRunSecretServiceRejectsUnsupportedOperationBeforeRunner(t *testing.T) {
	called := false
	_, err := runSecretService(func(context.Context, string, []string, string) ([]byte, error) {
		called = true
		return nil, nil
	}, context.Background(), "generate", nil, "")
	if err == nil || !strings.Contains(err.Error(), "operation is unsupported") {
		t.Fatalf("unsupported operation error = %v, want fail-closed validation", err)
	}
	if called {
		t.Fatal("unsupported Secret Service operation reached the runner")
	}
}

func TestRunSecretServiceRejectsUnboundArgumentsBeforeRunner(t *testing.T) {
	cases := []struct {
		name      string
		operation string
		args      []string
		stdin     string
	}{
		{
			name:      "lookup changes application",
			operation: "lookup",
			args:      []string{"--attribute=application", "other-app", "--attribute=name", "controller/chatgpt"},
		},
		{
			name:      "lookup adds attribute",
			operation: "lookup",
			args:      []string{"--attribute=application", secretServiceApplication, "--attribute=name", "controller/chatgpt", "--attribute=extra", "value"},
		},
		{
			name:      "store changes label",
			operation: "store",
			args:      []string{"--label=other", "--attribute=application", secretServiceApplication, "--attribute=name", "controller/chatgpt"},
			stdin:     validSecretServiceTestPayload(t, "controller/chatgpt", "secret"),
		},
		{
			name:      "clear targets production namespace",
			operation: "clear",
			args:      []string{"--attribute=application", secretServiceApplication, "--attribute=name", "controller/chatgpt"},
		},
		{
			name:      "clear sends stdin",
			operation: "clear",
			args:      []string{"--attribute=application", secretServiceApplication, "--attribute=name", "supervisor/cleanup"},
			stdin:     "unexpected",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			_, err := runSecretService(func(context.Context, string, []string, string) ([]byte, error) {
				called = true
				return nil, nil
			}, context.Background(), tc.operation, tc.args, tc.stdin)
			if err == nil || !strings.Contains(err.Error(), "arguments are invalid") {
				t.Fatalf("malformed %s boundary error = %v, want fail-closed argument validation", tc.operation, err)
			}
			if called {
				t.Fatal("malformed Secret Service arguments reached the runner")
			}
		})
	}
}

func TestRunSecretServiceRejectsMalformedStoreInputBeforeRunner(t *testing.T) {
	valid := validSecretServiceTestPayload(t, "controller/chatgpt", "secret")
	cases := []struct {
		name  string
		stdin string
	}{
		{name: "plain text", stdin: "secret"},
		{name: "name mismatch", stdin: validSecretServiceTestPayload(t, "controller/other", "secret")},
		{name: "revoked value", stdin: `{"name":"controller/chatgpt","value":"stale","version":1,"revoked":true,"updated_at":"1970-01-01T00:00:01Z"}`},
		{name: "trailing JSON", stdin: valid + ` {}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			_, err := runSecretService(func(context.Context, string, []string, string) ([]byte, error) {
				called = true
				return nil, nil
			}, context.Background(), "store", []string{"--label=" + secretServiceLabel, "--attribute=application", secretServiceApplication, "--attribute=name", "controller/chatgpt"}, tc.stdin)
			if err == nil || !strings.Contains(err.Error(), "arguments are invalid") {
				t.Fatalf("malformed store input error = %v, want fail-closed argument validation", err)
			}
			if called {
				t.Fatal("malformed Secret Service store input reached the runner")
			}
		})
	}
}

func TestRunSecretServiceAcceptsOnlyBoundCommandShapes(t *testing.T) {
	cases := []struct {
		name      string
		operation string
		args      []string
		stdin     string
	}{
		{
			name:      "probe lookup",
			operation: "lookup",
			args:      []string{"--attribute=application", secretServiceApplication, "--attribute=name", secretServiceProbeName},
		},
		{
			name:      "normal lookup",
			operation: "lookup",
			args:      []string{"--attribute=application", secretServiceApplication, "--attribute=name", "controller/chatgpt"},
		},
		{
			name:      "store",
			operation: "store",
			args:      []string{"--label=" + secretServiceLabel, "--attribute=application", secretServiceApplication, "--attribute=name", "controller/chatgpt"},
			stdin:     validSecretServiceTestPayload(t, "controller/chatgpt", "secret"),
		},
		{
			name:      "supervisor clear",
			operation: "clear",
			args:      []string{"--attribute=application", secretServiceApplication, "--attribute=name", "supervisor/cleanup"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			_, err := runSecretService(func(context.Context, string, []string, string) ([]byte, error) {
				called = true
				return nil, nil
			}, context.Background(), tc.operation, tc.args, tc.stdin)
			if err != nil {
				t.Fatalf("valid %s boundary rejected: %v", tc.operation, err)
			}
			if !called {
				t.Fatal("valid Secret Service arguments did not reach the runner")
			}
		})
	}
}

func validSecretServiceTestPayload(t *testing.T, name, value string) string {
	t.Helper()
	payload, err := json.Marshal(secretServicePayload{Name: name, Value: value, Version: 1, UpdatedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

type panickingSecretServiceError struct{ diagnostic string }

func (e panickingSecretServiceError) Error() string { return e.diagnostic }

func (e panickingSecretServiceError) Is(error) bool { panic(e.diagnostic) }

func (e panickingSecretServiceError) As(any) bool { panic(e.diagnostic) }

func TestSecretServiceCleanupRejectsInvalidNameBeforeRunner(t *testing.T) {
	called := false
	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		called = true
		return nil, nil
	}}
	if err := s.deleteWithContext(context.Background(), "controller/with space"); err == nil || !strings.Contains(err.Error(), "invalid secret name") {
		t.Fatalf("invalid cleanup name error = %v, want validation failure", err)
	}
	if called {
		t.Fatal("invalid cleanup name reached the Secret Service runner")
	}
}

func TestSecretServiceDoesNotHideExitOneWithStderr(t *testing.T) {
	exitOne := exec.Command("false")
	if err := exitOne.Run(); err == nil {
		t.Fatal("false unexpectedly succeeded")
	} else if isSecretMissingError(&secretToolCommandError{err: err, stderr: []byte("permission denied")}) {
		t.Fatal("exit-one permission failure was treated as missing")
	}
}

func TestSecretServiceDoesNotHideMissingSentinelWithStderr(t *testing.T) {
	wrapped := &secretToolCommandError{err: errSecretMissing, stderr: []byte("session unavailable")}
	if isSecretMissingError(wrapped) {
		t.Fatal("missing sentinel with native stderr was treated as missing")
	}

	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		return nil, wrapped
	}}
	if _, err := s.Get("controller/chatgpt"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("wrapped missing sentinel with stderr = %v, want ordinary native failure", err)
	}
}

func TestSecretServiceRecognizesEmptyExitOneAsMissing(t *testing.T) {
	exitOne := exec.Command("false")
	if err := exitOne.Run(); err == nil {
		t.Fatal("false unexpectedly succeeded")
	} else if !isSecretMissingError(&secretToolCommandError{err: err}) {
		t.Fatal("empty exit-one lookup was not treated as missing")
	}
}

func TestSecretServiceRejectsMissingResultWithOutput(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*SecretService) error
	}{
		{
			name: "lookup",
			call: func(s *SecretService) error {
				_, err := s.Get("controller/chatgpt")
				return err
			},
		},
		{
			name: "delete",
			call: func(s *SecretService) error {
				return s.Delete("supervisor/missing-result-check")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
				return []byte("unexpected native response"), errSecretMissing
			}}
			err := tc.call(s)
			if err == nil || !strings.Contains(err.Error(), "missing result included output") {
				t.Fatalf("missing result with output error = %v, want fail-closed error", err)
			}
			if strings.Contains(err.Error(), "unexpected native response") {
				t.Fatalf("malformed native output leaked into error: %v", err)
			}
		})
	}

	if _, err := openSecretService(context.Background(), func(context.Context, string, []string, string) ([]byte, error) {
		return []byte("unexpected native response"), errSecretMissing
	}); err == nil || !strings.Contains(err.Error(), "missing result included output") {
		t.Fatalf("probe missing result with output error = %v, want fail-closed error", err)
	}
}

func TestSecretServiceMutationsRejectUnexpectedOutput(t *testing.T) {
	const name = "controller/chatgpt"
	payload, err := json.Marshal(secretServicePayload{Name: name, Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		call func(*SecretService) error
	}{
		{
			name: "store",
			call: func(s *SecretService) error {
				_, err := s.storeWithContext(context.Background(), secretServicePayload{Name: name, Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}, payload)
				return err
			},
		},
		{
			name: "delete",
			call: func(s *SecretService) error {
				return s.deleteWithContext(context.Background(), "supervisor/mutation-output")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
				return []byte("unexpected mutation response"), nil
			}}
			err := tc.call(s)
			if err == nil || !strings.Contains(err.Error(), "mutation returned unexpected output") {
				t.Fatalf("mutation output error = %v, want fail-closed error", err)
			}
			if strings.Contains(err.Error(), "unexpected mutation response") {
				t.Fatalf("unexpected mutation output leaked into error: %v", err)
			}
		})
	}
}

func TestSecretServiceProbePreservesCancellation(t *testing.T) {
	if err := classifyProbeError(context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was remapped: %v", err)
	}
	if err := classifyProbeError(context.DeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline was remapped: %v", err)
	}
	if err := classifyProbeError(exec.ErrNotFound); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing helper was not classified: %v", err)
	}
	if _, err := exec.Command("false").Output(); err == nil {
		t.Fatal("false unexpectedly succeeded")
	} else if errors.Is(classifyProbeError(err), ErrUnavailable) {
		t.Fatalf("unexpected native failure was hidden: %v", err)
	}
}

func TestRunSecretToolPreservesCallerCancellation(t *testing.T) {
	d := t.TempDir()
	tool := filepath.Join(d, "secret-tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nsleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", d+string(os.PathListSeparator)+os.Getenv("PATH"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runSecretTool(ctx, "lookup", []string{
		"--attribute=application", secretServiceApplication,
		"--attribute=name", secretServiceProbeName,
	}, "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runSecretTool error = %v, want context.Canceled", err)
	}
}

func TestRunSecretToolRejectsMalformedBoundaryBeforeExec(t *testing.T) {
	validArgs := []string{
		"--attribute=application", secretServiceApplication,
		"--attribute=name", secretServiceProbeName,
	}
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{name: "nil context", ctx: nil},
		{name: "typed nil context", ctx: (*typedNilContext)(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runSecretTool(tc.ctx, "lookup", validArgs, "")
			if err == nil || !strings.Contains(err.Error(), "context is nil") {
				t.Fatalf("malformed runSecretTool context error = %v, want explicit rejection", err)
			}
		})
	}

	for _, tc := range []struct {
		name      string
		operation string
		args      []string
		stdin     string
		want      string
	}{
		{name: "unsupported operation", operation: "generate", want: "operation is unsupported"},
		{name: "unbound attributes", operation: "lookup", args: []string{
			"--attribute=application", "other-app", "--attribute=name", secretServiceProbeName,
		}, want: "arguments are invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runSecretTool(context.Background(), tc.operation, tc.args, tc.stdin)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("malformed runSecretTool request error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSecretServiceProbeVerifiesSessionWithReadOnlyLookup(t *testing.T) {
	var operation string
	var args []string
	_, err := openSecretService(context.Background(), func(_ context.Context, op string, gotArgs []string, stdin string) ([]byte, error) {
		operation = op
		args = append([]string(nil), gotArgs...)
		if stdin != "" {
			t.Fatalf("probe stdin = %q, want empty", stdin)
		}
		return nil, &secretToolCommandError{err: exec.Command("false").Run(), stderr: []byte("session unavailable")}
	})
	if err == nil {
		t.Fatal("session failure was accepted")
	}
	if operation != "lookup" {
		t.Fatalf("probe operation = %q, want lookup", operation)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, secretServiceProbeName) {
		t.Fatalf("probe args = %q, missing reserved capability name", joined)
	}
}

func TestSecretServiceProbeAcceptsMissingReservedItem(t *testing.T) {
	_, err := openSecretService(context.Background(), func(_ context.Context, op string, _ []string, _ string) ([]byte, error) {
		if op != "lookup" {
			t.Fatalf("probe operation = %q, want lookup", op)
		}
		return nil, &secretToolCommandError{err: exec.Command("false").Run()}
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecretServiceProbeRejectsOversizedOutput(t *testing.T) {
	_, err := openSecretService(context.Background(), func(context.Context, string, []string, string) ([]byte, error) {
		return []byte(strings.Repeat("x", secretServiceMaxOutput+1)), nil
	})
	if err == nil || !strings.Contains(err.Error(), "output exceeds limit") {
		t.Fatalf("oversized probe result = %v, want bounded-output failure", err)
	}
}

func TestSecretServiceRejectsMalformedNestedCommandError(t *testing.T) {
	var exitErr *exec.ExitError
	malformed := &secretToolCommandError{err: exitErr}

	if got := malformed.Error(); got != "secret service command failed" {
		t.Fatalf("malformed command error text = %q, want opaque fallback", got)
	}
	if got := malformed.Unwrap(); got != nil {
		t.Fatalf("malformed command error unwrap = %v, want nil", got)
	}
	if isSecretMissingError(malformed) {
		t.Fatal("typed-nil nested exit error was classified as missing")
	}

	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		return nil, malformed
	}}
	_, err := s.Get("controller/chatgpt")
	if err == nil || err.Error() != "secret service operation failed" {
		t.Fatalf("malformed command error result = %v, want opaque operation failure", err)
	}
}

func TestSecretToolCommandErrorRedactsUnderlyingDiagnostic(t *testing.T) {
	const sensitive = "secret-bearing native command diagnostic"
	cause := errors.New(sensitive)
	wrapped := &secretToolCommandError{err: cause, stderr: []byte(sensitive)}

	if got := wrapped.Error(); got != "secret service command failed" {
		t.Fatalf("command error text = %q, want stable opaque text", got)
	}
	if !errors.Is(wrapped, cause) {
		t.Fatal("command error did not preserve underlying classification")
	}
	if strings.Contains(wrapped.Error(), sensitive) {
		t.Fatalf("command diagnostic leaked through direct error text: %v", wrapped)
	}
}

func TestSecretServiceMissingClassifierRejectsTypedNilError(t *testing.T) {
	var typedNil *typedNilBoundaryError
	if isSecretMissingError(typedNil) {
		t.Fatal("typed-nil classifier input was treated as a missing item")
	}
}

func TestSecretServiceProbeErrorBoundariesRejectTypedNilError(t *testing.T) {
	var typedNil *typedNilBoundaryError
	for _, tc := range []struct {
		name string
		call func(error) error
	}{
		{name: "classify probe", call: classifyProbeError},
		{name: "redact operation", call: redactSecretServiceError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.call(typedNil)
			if got == nil {
				t.Fatal("typed-nil error boundary returned nil")
			}
			if strings.Contains(got.Error(), "typed nil native error") {
				t.Fatalf("typed-nil diagnostic leaked: %v", got)
			}
			if errors.Is(got, typedNil) {
				t.Fatal("typed-nil error boundary preserved malformed error identity")
			}
		})
	}
}

func TestSecretServiceRejectsNilProbeContext(t *testing.T) {
	if _, err := OpenSecretService(nil); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context result = %v, want explicit rejection", err)
	}
}

func TestSecretServiceRejectsTypedNilProbeContextBeforeRunner(t *testing.T) {
	var called bool
	var typedNil *typedNilContext
	_, err := openSecretService(typedNil, func(context.Context, string, []string, string) ([]byte, error) {
		called = true
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("typed-nil context result = %v, want explicit rejection", err)
	}
	if called {
		t.Fatal("probe runner was called after typed-nil context rejection")
	}
}

func TestSecretServiceRejectsNilRunner(t *testing.T) {
	if _, err := openSecretService(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "runner is nil") {
		t.Fatalf("nil runner result = %v, want explicit rejection", err)
	}
}

func TestSecretServiceRejectsNilRunnerOnLifecycle(t *testing.T) {
	var nilStore *SecretService
	for _, store := range []*SecretService{{}, nilStore} {
		if _, err := store.Get("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "secret service runner is nil") {
			t.Fatalf("Get nil runner error = %v", err)
		}
		if _, err := store.Put("controller/chatgpt", "secret"); err == nil || !strings.Contains(err.Error(), "secret service runner is nil") {
			t.Fatalf("Put nil runner error = %v", err)
		}
		if _, err := store.Rotate("controller/chatgpt", "secret"); err == nil || !strings.Contains(err.Error(), "secret service runner is nil") {
			t.Fatalf("Rotate nil runner error = %v", err)
		}
		if err := store.Revoke("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "secret service runner is nil") {
			t.Fatalf("Revoke nil runner error = %v", err)
		}
		if err := store.Delete("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "secret service runner is nil") {
			t.Fatalf("Delete nil runner error = %v", err)
		}
	}
}

func TestSecretServiceProbeHasBoundedContext(t *testing.T) {
	var got context.Context
	_, err := openSecretService(context.Background(), func(ctx context.Context, _ string, _ []string, _ string) ([]byte, error) {
		got = ctx
		return nil, errors.New("probe failed")
	})
	if err == nil || got == nil {
		t.Fatalf("probe error/context = %v/%v", err, got)
	}
	if _, ok := got.Deadline(); !ok {
		t.Fatal("probe context has no deadline")
	}
}

func TestSecretServiceProbePreservesEarlierCallerDeadline(t *testing.T) {
	caller, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	var got context.Context
	_, err := openSecretService(caller, func(ctx context.Context, _ string, _ []string, _ string) ([]byte, error) {
		got = ctx
		return nil, context.DeadlineExceeded
	})
	if !errors.Is(err, context.DeadlineExceeded) || got == nil {
		t.Fatalf("probe error/context = %v/%v", err, got)
	}
	deadline, ok := got.Deadline()
	if !ok || time.Until(deadline) > 100*time.Millisecond {
		t.Fatalf("caller deadline was not preserved: %v", deadline)
	}
}

func TestSecretServiceProbeRejectsCancellationAfterRunnerReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var called bool
	_, err := openSecretService(ctx, func(_ context.Context, _ string, _ []string, _ string) ([]byte, error) {
		called = true
		cancel()
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("post-run cancellation error = %v, want context.Canceled", err)
	}
	if !called {
		t.Fatal("probe runner was not called")
	}
}

func TestSecretServiceOperationsRejectCancellationAfterRunnerReturns(t *testing.T) {
	const name = "controller/chatgpt"
	payload, err := json.Marshal(secretServicePayload{Name: name, Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		call func(*SecretService, context.Context) error
	}{
		{
			name: "lookup does not become missing",
			call: func(s *SecretService, ctx context.Context) error {
				_, err := s.lookupWithContext(ctx, name)
				return err
			},
		},
		{
			name: "store does not become success",
			call: func(s *SecretService, ctx context.Context) error {
				_, err := s.storeWithContext(ctx, secretServicePayload{Name: name, Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}, payload)
				return err
			},
		},
		{
			name: "delete does not become missing success",
			call: func(s *SecretService, ctx context.Context) error {
				return s.deleteWithContext(ctx, "supervisor/cancellation")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
				cancel()
				return nil, errSecretMissing
			}}
			if err := tc.call(s, ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("post-run operation error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestSecretServiceOperationsRejectNilContextsBeforeRunner(t *testing.T) {
	const name = "controller/chatgpt"
	payload, err := json.Marshal(secretServicePayload{Name: name, Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		call func(*SecretService, context.Context) error
	}{
		{
			name: "lookup",
			call: func(s *SecretService, ctx context.Context) error {
				_, err := s.lookupWithContext(ctx, name)
				return err
			},
		},
		{
			name: "store",
			call: func(s *SecretService, ctx context.Context) error {
				_, err := s.storeWithContext(ctx, secretServicePayload{Name: name, Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}, payload)
				return err
			},
		},
		{
			name: "delete",
			call: func(s *SecretService, ctx context.Context) error {
				return s.deleteWithContext(ctx, "supervisor/cleanup")
			},
		},
	} {
		for _, ctxCase := range []struct {
			name string
			ctx  context.Context
		}{
			{name: "nil", ctx: nil},
			{name: "typed nil", ctx: (*typedNilContext)(nil)},
		} {
			t.Run(tc.name+"/"+ctxCase.name, func(t *testing.T) {
				calls := 0
				s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
					calls++
					return nil, nil
				}}
				err := tc.call(s, ctxCase.ctx)
				if err == nil || !strings.Contains(err.Error(), "context is nil") {
					t.Fatalf("operation error = %v, want context rejection", err)
				}
				if calls != 0 {
					t.Fatalf("runner calls = %d, want zero", calls)
				}
			})
		}
	}
}

func TestSecretServiceCancellationPrecedesOversizedRunnerOutput(t *testing.T) {
	oversized := []byte(strings.Repeat("x", secretServiceMaxOutput+1))

	parent, cancelParent := context.WithCancel(context.Background())
	_, err := openSecretService(parent, func(_ context.Context, _ string, _ []string, _ string) ([]byte, error) {
		cancelParent()
		return oversized, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("probe cancellation with oversized output = %v, want context.Canceled", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		cancel()
		return oversized, errSecretMissing
	}}
	if _, err := s.lookupWithContext(ctx, "controller/chatgpt"); !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup cancellation with oversized output = %v, want context.Canceled", err)
	}
}

func TestSecretServiceOperationsHaveBoundedContexts(t *testing.T) {
	var sawDeadline bool
	s := &SecretService{run: func(ctx context.Context, op string, args []string, stdin string) ([]byte, error) {
		if op != "lookup" {
			t.Fatalf("operation = %q, want lookup", op)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("lookup context has no deadline")
		}
		sawDeadline = true
		return nil, errSecretMissing
	}}
	if _, err := s.Get("controller/chatgpt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get: %v", err)
	}
	if !sawDeadline {
		t.Fatal("lookup did not receive a bounded context")
	}
}

func TestSecretServiceLookupRejectsOversizedRunnerOutput(t *testing.T) {
	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		return []byte(strings.Repeat("x", secretServiceMaxOutput+1)), nil
	}}
	_, err := s.Get("controller/chatgpt")
	if err == nil || !strings.Contains(err.Error(), "output exceeds limit") {
		t.Fatalf("oversized lookup result = %v, want bounded-output failure", err)
	}
}

func TestSecretServiceRejectsOversizedOutput(t *testing.T) {
	if _, err := boundedNativeOutput([]byte(strings.Repeat("x", secretServiceMaxOutput+1)), nil); err == nil {
		t.Fatal("accepted oversized native output")
	}
}

func TestSecretServiceOutputCaptureIsBounded(t *testing.T) {
	var out boundedBuffer
	input := strings.Repeat("x", secretServiceMaxOutput*4)
	n, err := out.Write([]byte(input))
	if err != nil || n != len(input) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	if len(out.Bytes()) != secretServiceMaxOutput+1 {
		t.Fatalf("captured %d bytes, want %d", len(out.Bytes()), secretServiceMaxOutput+1)
	}
	if _, err := boundedNativeOutput(out.Bytes(), nil); err == nil {
		t.Fatal("bounded capture did not retain overflow sentinel")
	}
}

func TestSecretServiceRejectsOversizedSecret(t *testing.T) {
	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		return nil, errSecretMissing
	}}
	if _, err := s.Put("controller/chatgpt", strings.Repeat("x", maxSecretValue+1)); err == nil {
		t.Fatal("accepted oversized secret")
	}
}

func TestSecretServiceRotateRejectsInvalidValueBeforeNativeRead(t *testing.T) {
	calls := 0
	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		calls++
		return nil, errors.New("native read must not run")
	}}
	if _, err := s.Rotate("controller/chatgpt", ""); err == nil || !strings.Contains(err.Error(), "secret value is empty") {
		t.Fatalf("invalid rotation value error = %v, want local validation", err)
	}
	if calls != 0 {
		t.Fatalf("invalid rotation value reached native runner %d time(s)", calls)
	}
}

func TestSecretServiceStoreRejectsInvalidRecordBeforeRunner(t *testing.T) {
	calls := 0
	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		calls++
		return nil, nil
	}}
	if _, err := s.store(secretServicePayload{Name: "controller/chatgpt", Version: 1, Revoked: true, Value: "stale"}); err == nil {
		t.Fatal("accepted revoked secret-service payload with a value")
	}
	if calls != 0 {
		t.Fatal("invalid secret-service payload reached the native runner")
	}
}

func TestSecretServiceStoreWithContextRejectsMalformedOrMismatchedPayloadBeforeRunner(t *testing.T) {
	const name = "controller/chatgpt"
	valid := secretServicePayload{Name: name, Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}
	cases := []struct {
		name    string
		payload secretServicePayload
		encoded secretServicePayload
	}{
		{
			name:    "revoked record retains stale value",
			payload: secretServicePayload{Name: name, Value: "stale", Version: 1, Revoked: true, UpdatedAt: valid.UpdatedAt},
			encoded: secretServicePayload{Name: name, Value: "stale", Version: 1, Revoked: true, UpdatedAt: valid.UpdatedAt},
		},
		{
			name:    "encoded value differs from record",
			payload: valid,
			encoded: secretServicePayload{Name: name, Value: "other-secret", Version: 1, UpdatedAt: valid.UpdatedAt},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
				calls++
				return nil, nil
			}}
			encoded, err := json.Marshal(tc.encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.storeWithContext(context.Background(), tc.payload, encoded); err == nil {
				t.Fatal("accepted malformed or mismatched Secret Service payload")
			}
			if calls != 0 {
				t.Fatalf("runner calls = %d, want zero", calls)
			}
		})
	}
}

func TestSecretServiceStoreRejectsOversizedRunnerOutput(t *testing.T) {
	calls := 0
	s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
		calls++
		return []byte(strings.Repeat("x", secretServiceMaxOutput+1)), nil
	}}
	_, err := s.store(secretServicePayload{Name: "controller/chatgpt", Value: "secret", Version: 1, UpdatedAt: time.Now().UTC()})
	if err == nil || !strings.Contains(err.Error(), "output exceeds limit") {
		t.Fatalf("oversized store output = %v, want bounded-output failure", err)
	}
	if calls != 1 {
		t.Fatalf("runner calls = %d, want 1", calls)
	}
}

func TestSecretServiceRejectsMalformedRecord(t *testing.T) {
	for _, payload := range []string{
		`{"name":"controller/chatgpt","version":1}`,
		`{"name":"controller/chatgpt","version":1,"value":"secret","revoked":true}`,
	} {
		s := &SecretService{run: func(context.Context, string, []string, string) ([]byte, error) {
			return []byte(payload), nil
		}}
		if _, err := s.Get("controller/chatgpt"); err == nil {
			t.Fatalf("accepted malformed Secret Service record: %s", payload)
		}
	}
}
