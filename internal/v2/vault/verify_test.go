package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerifyNativeLifecycleIsRedactedAndCleansOnlyNamedItem(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	store := &Keychain{api: api}
	const name = "supervisor/native-check"

	result, err := VerifyNativeLifecycle(store, store, name)
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != name || result.PutVersion != 1 || result.RotateVersion != 2 || !result.RevokedReadRejected || !result.RepeatedRevokeOK || !result.CleanupSucceeded {
		t.Fatalf("verification result = %#v", result)
	}
	if _, err := store.Get(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("verification item after cleanup = %v, want ErrNotFound", err)
	}
}

func TestNativeVerificationResultUsesStableNonSecretJSON(t *testing.T) {
	result := NativeVerificationResult{
		Name:                "supervisor/json-check",
		PutVersion:          1,
		RotateVersion:       2,
		RevokedReadRejected: true,
		RepeatedRevokeOK:    true,
		CleanupSucceeded:    true,
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"name":"supervisor/json-check","put_version":1,"rotate_version":2,"revoked_read_rejected":true,"repeated_revoke_ok":true,"cleanup_succeeded":true}`
	if string(encoded) != want {
		t.Fatalf("native verification JSON = %s, want %s", encoded, want)
	}
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "value") {
		t.Fatalf("native verification JSON contains a secret-bearing field: %s", encoded)
	}
}

func TestParseNativeVerificationEvidenceAcceptsOnlyValidatedCanonicalResult(t *testing.T) {
	result := NativeVerificationResult{
		Name:                "supervisor/replay-check",
		PutVersion:          1,
		RotateVersion:       2,
		RevokedReadRejected: true,
		RepeatedRevokeOK:    true,
		CleanupSucceeded:    true,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseNativeVerificationEvidence(encoded)
	if err != nil {
		t.Fatalf("ParseNativeVerificationEvidence() = %v", err)
	}
	if got != result {
		t.Fatalf("parsed evidence = %#v, want %#v", got, result)
	}
}

func TestParseNativeVerificationEvidenceRejectsUntrustedDocuments(t *testing.T) {
	valid := `{"name":"supervisor/replay-check","put_version":1,"rotate_version":2,"revoked_read_rejected":true,"repeated_revoke_ok":true,"cleanup_succeeded":true}`
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "duplicate key", data: []byte(`{"name":"supervisor/first","name":"supervisor/second","put_version":1,"rotate_version":2,"revoked_read_rejected":true,"repeated_revoke_ok":true,"cleanup_succeeded":true}`), want: "duplicate JSON object key"},
		{name: "unknown field", data: []byte(`{"name":"supervisor/replay-check","put_version":1,"rotate_version":2,"revoked_read_rejected":true,"repeated_revoke_ok":true,"cleanup_succeeded":true,"secret":"must not be accepted"}`), want: "unknown field"},
		{name: "trailing value", data: append([]byte(valid), []byte(` {"extra":true}`)...), want: "multiple JSON values"},
		{name: "contradictory cleanup", data: []byte(`{"name":"supervisor/replay-check","put_version":1,"rotate_version":2,"revoked_read_rejected":true,"repeated_revoke_ok":true,"cleanup_succeeded":false}`), want: "cleanup"},
		{name: "invalid UTF-8", data: append([]byte(`{"name":"supervisor/replay-check","put_version":1,"rotate_version":2,"revoked_read_rejected":true,"repeated_revoke_ok":true,"cleanup_succeeded":true,"x":"`), 0xff, '"', '}'), want: "valid UTF-8"},
		{name: "oversized", data: bytes.Repeat([]byte{'x'}, maxNativeVerificationEvidenceSize+1), want: "exceeds limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseNativeVerificationEvidence(tt.data); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParseNativeVerificationEvidence() = %v, want %q failure", err, tt.want)
			}
		})
	}
}

func TestValidateNativeVerificationResultRejectsContradictoryEvidence(t *testing.T) {
	valid := NativeVerificationResult{
		Name:                "supervisor/result-check",
		PutVersion:          1,
		RotateVersion:       2,
		RevokedReadRejected: true,
		RepeatedRevokeOK:    true,
		CleanupSucceeded:    true,
	}
	if err := ValidateNativeVerificationResult(valid); err != nil {
		t.Fatalf("valid native verification result rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*NativeVerificationResult)
		want   string
	}{
		{name: "wrong namespace", mutate: func(result *NativeVerificationResult) { result.Name = "controller/chatgpt" }, want: "result name"},
		{name: "wrong put version", mutate: func(result *NativeVerificationResult) { result.PutVersion = 2 }, want: "put version"},
		{name: "wrong rotate version", mutate: func(result *NativeVerificationResult) { result.RotateVersion = 3 }, want: "rotate version"},
		{name: "revoked read accepted", mutate: func(result *NativeVerificationResult) { result.RevokedReadRejected = false }, want: "revoked read"},
		{name: "repeated revoke failed", mutate: func(result *NativeVerificationResult) { result.RepeatedRevokeOK = false }, want: "repeated revoke"},
		{name: "cleanup failed", mutate: func(result *NativeVerificationResult) { result.CleanupSucceeded = false }, want: "cleanup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := valid
			tt.mutate(&result)
			if err := ValidateNativeVerificationResult(result); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateNativeVerificationResult() = %v, want %q failure", err, tt.want)
			}
		})
	}
}

func TestVerifyNativeLifecycleRefusesExistingItem(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	store := &Keychain{api: api}
	const name = "supervisor/existing-check"
	if _, err := store.Put(name, "pre-existing"); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), api.items[name]...)
	if _, err := VerifyNativeLifecycle(store, store, name); err == nil {
		t.Fatal("verification accepted an existing item")
	}
	if string(api.items[name]) != string(before) {
		t.Fatal("existing item changed after rejected verification")
	}
}

func TestVerifyNativeLifecycleRequiresCreateOnlyBoundary(t *testing.T) {
	store := plainVerificationStore{}
	if _, err := VerifyNativeLifecycle(store, plainVerificationCleanup{}, "supervisor/no-create-only"); err == nil || !strings.Contains(err.Error(), "create-only") {
		t.Fatalf("missing create-only boundary error = %v", err)
	}
}

func TestValidateNativeVerificationNameUsesDedicatedNamespace(t *testing.T) {
	for _, name := range []string{"controller/chatgpt", "supervisor/", "supervisor/../chatgpt"} {
		if err := ValidateNativeVerificationName(name); err == nil {
			t.Fatalf("ValidateNativeVerificationName(%q) accepted a non-test namespace", name)
		}
	}
	if err := ValidateNativeVerificationName("supervisor/native-check"); err != nil {
		t.Fatalf("dedicated supervisor name rejected: %v", err)
	}
}

func TestVerifyNativeLifecycleRejectsProductionNamespaceBeforeOpeningStore(t *testing.T) {
	store := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{}}}
	if _, err := VerifyNativeLifecycle(store, store, "controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "supervisor/") {
		t.Fatalf("production namespace accepted: %v", err)
	}
}

func TestVerifyNativeLifecycleCleansAfterFailure(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	store := &Keychain{api: api}
	failing := failingRotateStore{Store: store}
	const name = "supervisor/failure-check"

	result, err := VerifyNativeLifecycle(failing, store, name)
	if err == nil {
		t.Fatal("verification unexpectedly succeeded")
	}
	if !result.CleanupSucceeded {
		t.Fatalf("failed verification did not report cleanup: %#v", result)
	}
	if _, err := store.Get(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed verification item after cleanup = %v, want ErrNotFound", err)
	}
}

func TestVerifyNativeLifecycleRedactsAdapterErrorText(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	base := &Keychain{api: api}
	const secretText = "native-secret-must-not-escape"
	want := errors.New(secretText)
	store := secretBearingRotateStore{Store: base, err: want}

	result, err := VerifyNativeLifecycle(store, base, "supervisor/redacted-error")
	if err == nil || !strings.Contains(err.Error(), "native verification rotate") {
		t.Fatalf("secret-bearing adapter error = %v, want rotate failure", err)
	}
	if strings.Contains(err.Error(), secretText) {
		t.Fatalf("verification error exposed adapter diagnostics: %v", err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("verification error = %v, want errors.Is classification", err)
	}
	if !result.CleanupSucceeded {
		t.Fatalf("secret-bearing adapter failure result = %#v, want cleanup evidence", result)
	}
}

func TestRedactNativeVerificationErrorDoesNotTrustOperationLabel(t *testing.T) {
	const sensitive = "operation-label-secret-must-not-escape"
	want := errors.New("native cause")
	err := RedactNativeVerificationError(sensitive, want)
	if err == nil || err.Error() != "native verification operation failed" {
		t.Fatalf("untrusted operation error = %v, want stable generic label", err)
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatalf("untrusted operation label leaked through error: %v", err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("redacted error = %v, want errors.Is classification", err)
	}

	known := RedactNativeVerificationError("rotate", want)
	if known == nil || known.Error() != "native verification rotate failed" {
		t.Fatalf("known operation error = %v, want stable rotate label", known)
	}
}

func TestRedactNativeStoreErrorHidesDiagnosticsAndPreservesCause(t *testing.T) {
	cause := errors.New("secret-bearing platform diagnostic")
	err := redactNativeStoreError("untrusted-operation", cause)
	if err == nil || err.Error() != "native secure store operation failed" {
		t.Fatalf("redacted native store error = %v", err)
	}
	if strings.Contains(err.Error(), "secret-bearing") {
		t.Fatalf("native store diagnostic leaked: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("redacted native store error does not preserve cause: %v", err)
	}
	for _, operation := range []string{"read", "write", "delete"} {
		if got := redactNativeStoreError(operation, cause).Error(); !strings.Contains(got, operation) {
			t.Fatalf("operation %q omitted from stable error: %q", operation, got)
		}
	}
}

func TestVerifyNativeLifecycleCleansAfterPutErrorWithAmbiguousWrite(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	store := &Keychain{api: api}
	const name = "supervisor/put-error-check"

	result, err := VerifyNativeLifecycle(putErrorAfterWriteStore{Store: store}, store, name)
	if err == nil || !strings.Contains(err.Error(), "native verification put") {
		t.Fatalf("ambiguous put error = %v, want native verification put failure", err)
	}
	if !result.CleanupSucceeded {
		t.Fatalf("ambiguous put failure did not report cleanup: %#v", result)
	}
	if _, err := store.Get(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ambiguous put item after cleanup = %v, want ErrNotFound", err)
	}
}

func TestVerifyNativeLifecycleCleansAfterPutPanicWithAmbiguousWrite(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	store := &Keychain{api: api}
	const name = "supervisor/put-panic-check"

	result, err := VerifyNativeLifecycle(panicAfterWriteStore{Store: store}, store, name)
	if err == nil || !strings.Contains(err.Error(), "adapter panicked") {
		t.Fatalf("ambiguous put panic = %v, want contained panic", err)
	}
	if !result.CleanupSucceeded {
		t.Fatalf("ambiguous put panic did not report cleanup: %#v", result)
	}
	if _, err := store.Get(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ambiguous put panic item after cleanup = %v, want ErrNotFound", err)
	}
}

func TestVerifyNativeLifecycleContainsAdapterPanicAndCleans(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	store := &panicRotateStore{Store: &Keychain{api: api}}
	const name = "supervisor/panic-check"

	result, err := VerifyNativeLifecycle(store, store.Store.(NativeCleanup), name)
	if err == nil || !strings.Contains(err.Error(), "adapter panicked") {
		t.Fatalf("panic verification error = %v, want contained panic", err)
	}
	if !result.CleanupSucceeded {
		t.Fatalf("panic verification cleanup = %#v, want success", result)
	}
	if _, err := store.Store.Get(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("panic verification item after cleanup = %v, want ErrNotFound", err)
	}
}

func TestVerifyNativeLifecycleContainsCleanupPanic(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	store := &Keychain{api: api}
	const name = "supervisor/panic-cleanup-check"

	result, err := VerifyNativeLifecycle(store, panicCleanup{Store: store}, name)
	if err == nil || !strings.Contains(err.Error(), "cleanup native verification item") {
		t.Fatalf("cleanup panic error = %v, want cleanup failure", err)
	}
	if result.CleanupSucceeded {
		t.Fatalf("cleanup panic result = %#v, want hold", result)
	}
}

func TestVerifyNativeLifecycleRejectsMalformedBoundary(t *testing.T) {
	store := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{}}}
	var nilStore *Keychain
	var nilCleanup *Keychain
	for name, got := range map[string]error{
		"nil store": func() error {
			_, err := VerifyNativeLifecycle(nilStore, store, "supervisor/nil-store")
			return err
		}(),
		"nil cleanup": func() error {
			_, err := VerifyNativeLifecycle(store, nilCleanup, "supervisor/nil-cleanup")
			return err
		}(),
		"invalid name": func() error {
			_, err := VerifyNativeLifecycle(store, store, "")
			return err
		}(),
	} {
		if got == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestVerifyNativeLifecycleRejectsInconsistentCreateOnlyResult(t *testing.T) {
	store := &inconsistentCreateOnlyStore{}
	result, err := VerifyNativeLifecycle(store, store, "supervisor/check")
	if err == nil || result.CleanupSucceeded {
		t.Fatalf("inconsistent create-only result = %#v/%v, want fail-closed error", result, err)
	}
	if got, want := err.Error(), "check native verification item: create-only boundary returned no creation and no error"; got != want {
		t.Fatalf("inconsistent create-only error = %q, want %q", got, want)
	}
}

func TestVerifyNativeLifecycleNeverCleansExplicitExistingItemAfterContradictoryCreateResult(t *testing.T) {
	base := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{}}}
	const name = "supervisor/contradictory-existing"
	if _, err := base.Put(name, "pre-existing"); err != nil {
		t.Fatal(err)
	}

	store := contradictoryExistingCreateOnlyStore{Store: base}
	result, err := VerifyNativeLifecycle(store, base, name)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("contradictory create-only result = %#v/%v, want existing-item failure", result, err)
	}
	if result.CleanupSucceeded {
		t.Fatalf("contradictory existing result = %#v, want no cleanup ownership", result)
	}
	got, err := base.Get(name)
	if err != nil {
		t.Fatalf("pre-existing item after rejected verification: %v", err)
	}
	if got.Value != "pre-existing" {
		t.Fatalf("pre-existing item value = %q, want preserved value", got.Value)
	}
}

func TestVerifyNativeLifecycleRejectsMalformedPutRecordAndCleans(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	base := &Keychain{api: api}
	store := &malformedPutRecordStore{Store: base, NativeCreateOnly: base}
	const name = "supervisor/malformed-put-record"

	result, err := VerifyNativeLifecycle(store, base, name)
	if err == nil || !strings.Contains(err.Error(), "invalid record") {
		t.Fatalf("malformed put record error = %v, want invalid-record failure", err)
	}
	if !result.CleanupSucceeded {
		t.Fatalf("malformed put record result = %#v, want cleanup evidence", result)
	}
	if store.rotates != 0 || store.revokes != 0 {
		t.Fatalf("malformed put record reached later lifecycle calls: rotates=%d revokes=%d", store.rotates, store.revokes)
	}
	if _, err := base.Get(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed put record after cleanup = %v, want ErrNotFound", err)
	}
}

type inconsistentCreateOnlyStore struct{}

func (inconsistentCreateOnlyStore) Get(string) (Record, error) { return Record{}, ErrNotFound }
func (inconsistentCreateOnlyStore) Put(string, string) (Record, error) {
	return Record{}, errors.New("unexpected put")
}
func (inconsistentCreateOnlyStore) Rotate(string, string) (Record, error) {
	return Record{}, errors.New("unexpected rotate")
}
func (inconsistentCreateOnlyStore) Revoke(string) error { return errors.New("unexpected revoke") }
func (inconsistentCreateOnlyStore) PutIfAbsent(string, string) (Record, bool, error) {
	return Record{}, false, nil
}
func (inconsistentCreateOnlyStore) Delete(string) error { return nil }

type contradictoryExistingCreateOnlyStore struct{ Store }

func (contradictoryExistingCreateOnlyStore) PutIfAbsent(string, string) (Record, bool, error) {
	return Record{}, true, ErrAlreadyExists
}

type malformedPutRecordStore struct {
	Store
	NativeCreateOnly
	rotates int
	revokes int
}

func (s *malformedPutRecordStore) PutIfAbsent(name, value string) (Record, bool, error) {
	_, created, err := s.NativeCreateOnly.PutIfAbsent(name, value)
	if err != nil || !created {
		return Record{}, created, err
	}
	return Record{Name: name, Value: value, Version: 1}, true, nil
}

func (s *malformedPutRecordStore) Rotate(name, value string) (Record, error) {
	s.rotates++
	return s.Store.Rotate(name, value)
}

func (s *malformedPutRecordStore) Revoke(name string) error {
	s.revokes++
	return s.Store.Revoke(name)
}

func TestVerifyNativeLifecycleContextRejectsCancellationBeforeCreate(t *testing.T) {
	store := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := VerifyNativeLifecycleContext(ctx, store, store, "supervisor/canceled-before-create")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification error = %v, want context.Canceled", err)
	}
	if result.CleanupSucceeded {
		t.Fatalf("canceled verification result = %#v, want no cleanup", result)
	}
	if _, err := store.Get("supervisor/canceled-before-create"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("canceled verification item = %v, want ErrNotFound", err)
	}
}

func TestVerifyNativeLifecycleContextCleansAfterCancellation(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	store := &Keychain{api: api}
	ctx, cancel := context.WithCancel(context.Background())
	wrapped := &cancelOnFirstGetStore{Store: store, NativeCreateOnly: store, cancel: cancel}

	result, err := VerifyNativeLifecycleContext(ctx, wrapped, store, "supervisor/canceled-after-create")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("post-create cancellation error = %v, want context.Canceled", err)
	}
	if !result.CleanupSucceeded {
		t.Fatalf("post-create cancellation result = %#v, want cleanup", result)
	}
	if wrapped.gets != 1 {
		t.Fatalf("post-create cancellation get count = %d, want 1", wrapped.gets)
	}
	if _, err := store.Get("supervisor/canceled-after-create"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-create cancellation item = %v, want ErrNotFound", err)
	}
}

func TestVerifyNativeLifecycleContextRejectsCancellationAfterCleanup(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	store := &Keychain{api: api}
	ctx, cancel := context.WithCancel(context.Background())
	wrapped := &cancelAfterCleanupStore{
		Store:            store,
		NativeCreateOnly: store,
		NativeCleanup:    store,
		cancel:           cancel,
	}

	result, err := VerifyNativeLifecycleContext(ctx, wrapped, wrapped, "supervisor/canceled-after-cleanup")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("post-cleanup cancellation error = %v, want context.Canceled", err)
	}
	if !result.CleanupSucceeded {
		t.Fatalf("post-cleanup cancellation result = %#v, want cleanup evidence", result)
	}
	if _, err := store.Get("supervisor/canceled-after-cleanup"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-cleanup cancellation item = %v, want ErrNotFound", err)
	}
}

func TestVerifyNativeLifecycleContextStopsBeforeReadAfterRecordValidation(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	base := &Keychain{api: api}
	store := &countingGetStore{Store: base, NativeCreateOnly: base}
	ctx := &cancelOnContextCheck{cancelAt: 3}

	result, err := VerifyNativeLifecycleContext(ctx, store, base, "supervisor/canceled-before-read")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation before read error = %v, want context.Canceled", err)
	}
	if result.CleanupSucceeded != true {
		t.Fatalf("cancellation before read result = %#v, want cleanup evidence", result)
	}
	if store.gets != 0 {
		t.Fatalf("cancellation before read get count = %d, want 0", store.gets)
	}
	if _, err := base.Get("supervisor/canceled-before-read"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancellation before read item = %v, want ErrNotFound", err)
	}
}

func TestVerifyNativeLifecycleContextStopsBeforeInterpretingCanceledRead(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	base := &Keychain{api: api}
	ctx, cancel := context.WithCancel(context.Background())
	store := &cancelWithMalformedGetStore{
		Store:            base,
		NativeCreateOnly: base,
		cancel:           cancel,
	}

	result, err := VerifyNativeLifecycleContext(ctx, store, base, "supervisor/canceled-during-read")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during read error = %v, want context.Canceled", err)
	}
	if !result.CleanupSucceeded {
		t.Fatalf("cancellation during read result = %#v, want cleanup evidence", result)
	}
	if store.gets != 1 || store.rotates != 0 {
		t.Fatalf("cancellation during read reached later lifecycle calls: gets=%d rotates=%d", store.gets, store.rotates)
	}
	if _, err := base.Get("supervisor/canceled-during-read"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancellation during read item = %v, want ErrNotFound", err)
	}
}

func TestVerifyNativeLifecycleContextCleansAfterCancellationDuringCreate(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	base := &Keychain{api: api}
	ctx, cancel := context.WithCancel(context.Background())
	store := &cancelDuringCreateStore{
		Store:            base,
		NativeCreateOnly: base,
		cancel:           cancel,
	}

	result, err := VerifyNativeLifecycleContext(ctx, store, base, "supervisor/canceled-during-create")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("create cancellation error = %v, want context.Canceled", err)
	}
	if !result.CleanupSucceeded {
		t.Fatalf("create cancellation result = %#v, want cleanup evidence", result)
	}
	if store.gets != 0 || store.rotates != 0 || store.revokes != 0 {
		t.Fatalf("create cancellation reached later lifecycle calls: gets=%d rotates=%d revokes=%d", store.gets, store.rotates, store.revokes)
	}
	if _, err := base.Get("supervisor/canceled-during-create"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("create cancellation item = %v, want ErrNotFound", err)
	}
}

func TestVerifyNativeLifecycleContextRejectsTypedNilContext(t *testing.T) {
	var ctx *typedNilVerificationContext
	store := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{}}}
	if _, err := VerifyNativeLifecycleContext(ctx, store, store, "supervisor/typed-nil-context"); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("typed-nil context error = %v, want rejection", err)
	}
}

type cancelOnFirstGetStore struct {
	Store
	NativeCreateOnly
	cancel func()
	gets   int
}

type cancelDuringCreateStore struct {
	Store
	NativeCreateOnly
	cancel  func()
	gets    int
	rotates int
	revokes int
}

func (s *cancelDuringCreateStore) PutIfAbsent(name, value string) (Record, bool, error) {
	record, created, err := s.NativeCreateOnly.PutIfAbsent(name, value)
	s.cancel()
	return record, created, err
}

func (s *cancelDuringCreateStore) Get(name string) (Record, error) {
	s.gets++
	return s.Store.Get(name)
}

func (s *cancelDuringCreateStore) Rotate(name, value string) (Record, error) {
	s.rotates++
	return s.Store.Rotate(name, value)
}

func (s *cancelDuringCreateStore) Revoke(name string) error {
	s.revokes++
	return s.Store.Revoke(name)
}

type cancelAfterCleanupStore struct {
	Store
	NativeCreateOnly
	NativeCleanup
	cancel func()
}

type countingGetStore struct {
	Store
	NativeCreateOnly
	gets int
}

type cancelWithMalformedGetStore struct {
	Store
	NativeCreateOnly
	cancel  func()
	gets    int
	rotates int
}

func (s *cancelWithMalformedGetStore) Get(name string) (Record, error) {
	s.gets++
	record, err := s.Store.Get(name)
	if s.gets == 1 {
		s.cancel()
		return Record{Name: name, Value: record.Value, Version: 0, UpdatedAt: record.UpdatedAt}, err
	}
	return record, err
}

func (s *cancelWithMalformedGetStore) Rotate(name, value string) (Record, error) {
	s.rotates++
	return s.Store.Rotate(name, value)
}

func (s *countingGetStore) Get(name string) (Record, error) {
	s.gets++
	return s.Store.Get(name)
}

type cancelOnContextCheck struct {
	checks   int
	cancelAt int
}

func (c *cancelOnContextCheck) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelOnContextCheck) Done() <-chan struct{}       { return nil }
func (c *cancelOnContextCheck) Err() error {
	c.checks++
	if c.checks >= c.cancelAt {
		return context.Canceled
	}
	return nil
}
func (c *cancelOnContextCheck) Value(any) any { return nil }

func (s *cancelAfterCleanupStore) Delete(name string) error {
	err := s.NativeCleanup.Delete(name)
	s.cancel()
	return err
}

func (s *cancelOnFirstGetStore) Get(name string) (Record, error) {
	record, err := s.Store.Get(name)
	s.gets++
	if s.gets == 1 {
		s.cancel()
	}
	return record, err
}

type typedNilVerificationContext struct{}

func (*typedNilVerificationContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*typedNilVerificationContext) Done() <-chan struct{}       { return nil }
func (*typedNilVerificationContext) Err() error                  { return nil }
func (*typedNilVerificationContext) Value(any) any               { return nil }

type failingRotateStore struct{ Store }

func (f failingRotateStore) PutIfAbsent(name, value string) (Record, bool, error) {
	return f.Store.(NativeCreateOnly).PutIfAbsent(name, value)
}

func (failingRotateStore) Rotate(string, string) (Record, error) {
	return Record{}, errors.New("injected rotation failure")
}

type secretBearingRotateStore struct {
	Store
	err error
}

func (s secretBearingRotateStore) PutIfAbsent(name, value string) (Record, bool, error) {
	return s.Store.(NativeCreateOnly).PutIfAbsent(name, value)
}

func (s secretBearingRotateStore) Rotate(string, string) (Record, error) {
	return Record{}, s.err
}

type putErrorAfterWriteStore struct{ Store }

func (s putErrorAfterWriteStore) PutIfAbsent(name, value string) (Record, bool, error) {
	_, created, err := s.Store.(NativeCreateOnly).PutIfAbsent(name, value)
	if err != nil {
		return Record{}, created, err
	}
	return Record{}, created, errors.New("injected ambiguous put failure")
}

func (s putErrorAfterWriteStore) Put(name, value string) (Record, error) {
	_, _ = s.Store.Put(name, value)
	return Record{}, errors.New("injected ambiguous put failure")
}

type panicAfterWriteStore struct{ Store }

func (s panicAfterWriteStore) PutIfAbsent(name, value string) (Record, bool, error) {
	_, _, _ = s.Store.(NativeCreateOnly).PutIfAbsent(name, value)
	panic("injected ambiguous put panic")
}

func (s panicAfterWriteStore) Put(name, value string) (Record, error) {
	_, _ = s.Store.Put(name, value)
	panic("injected ambiguous put panic")
}

type panicRotateStore struct{ Store }

func (s *panicRotateStore) PutIfAbsent(name, value string) (Record, bool, error) {
	return s.Store.(NativeCreateOnly).PutIfAbsent(name, value)
}

func (panicRotateStore) Rotate(string, string) (Record, error) {
	panic("injected native adapter panic")
}

type panicCleanup struct{ Store }

func (panicCleanup) Delete(string) error {
	panic("injected cleanup panic")
}

type plainVerificationStore struct{}

func (plainVerificationStore) Get(string) (Record, error) { return Record{}, ErrNotFound }
func (plainVerificationStore) Put(string, string) (Record, error) {
	return Record{}, nil
}
func (plainVerificationStore) Rotate(string, string) (Record, error) {
	return Record{}, nil
}
func (plainVerificationStore) Revoke(string) error { return nil }

type plainVerificationCleanup struct{}

func (plainVerificationCleanup) Delete(string) error { return nil }
