package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ai-relay/ai-relay/internal/v2/vault"
)

func TestValidateTimeoutBounds(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		valid   bool
	}{
		{name: "zero", timeout: 0},
		{name: "negative", timeout: -time.Second},
		{name: "default", timeout: defaultNativeVerificationTimeout, valid: true},
		{name: "maximum", timeout: maxNativeVerificationTimeout, valid: true},
		{name: "above maximum", timeout: maxNativeVerificationTimeout + time.Nanosecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTimeout(tt.timeout)
			if tt.valid && err != nil {
				t.Fatalf("validateTimeout(%s) = %v, want nil", tt.timeout, err)
			}
			if !tt.valid && err == nil {
				t.Fatalf("validateTimeout(%s) = nil, want error", tt.timeout)
			}
		})
	}
}

func TestVerifyRejectsCanceledContextBeforeOpeningNative(t *testing.T) {
	previous := openNative
	t.Cleanup(func() { openNative = previous })
	openNative = func(context.Context) (vault.Store, error) {
		t.Fatal("openNative called for canceled context")
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := verify(ctx, "supervisor/canceled")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("verify canceled context = %v, want context.Canceled", err)
	}
	if result.Name != "supervisor/canceled" {
		t.Fatalf("result name = %q, want supervisor/canceled", result.Name)
	}
}

func TestVerifyRejectsTypedNilContextBeforeOpeningNative(t *testing.T) {
	previous := openNative
	t.Cleanup(func() { openNative = previous })
	openNative = func(context.Context) (vault.Store, error) {
		t.Fatal("openNative called for typed-nil context")
		return nil, nil
	}

	var ctx *typedNilVerificationContext
	result, err := verify(ctx, "supervisor/typed-nil")
	if err == nil || !strings.Contains(err.Error(), "vault context is nil") {
		t.Fatalf("verify typed-nil context = %v, want typed-nil rejection", err)
	}
	if result.Name != "supervisor/typed-nil" {
		t.Fatalf("result name = %q, want supervisor/typed-nil", result.Name)
	}
}

func TestVerifyRejectsInvalidNameBeforeOpeningNative(t *testing.T) {
	previous := openNative
	t.Cleanup(func() { openNative = previous })
	openNative = func(context.Context) (vault.Store, error) {
		t.Fatal("openNative called for invalid name")
		return nil, nil
	}

	result, err := verify(context.Background(), "not a valid name")
	if err == nil {
		t.Fatal("verify invalid name = nil, want error")
	}
	if result.Name != "not a valid name" {
		t.Fatalf("result name = %q, want original name", result.Name)
	}
}

func TestVerifyRedactsOpenNativeError(t *testing.T) {
	previous := openNative
	t.Cleanup(func() { openNative = previous })
	const secretText = "keychain-secret-must-not-escape"
	want := errors.New(secretText)
	openNative = func(context.Context) (vault.Store, error) {
		return nil, want
	}

	result, err := verify(context.Background(), "supervisor/open-error")
	if err == nil || !strings.Contains(err.Error(), "open native vault") {
		t.Fatalf("open native error = %v, want stable operation classification", err)
	}
	if strings.Contains(err.Error(), secretText) {
		t.Fatalf("open native error exposed native diagnostics: %v", err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("open native error = %v, want errors.Is classification", err)
	}
	if result.Name != "supervisor/open-error" {
		t.Fatalf("result name = %q, want supervisor/open-error", result.Name)
	}
}

func TestVerifyRejectsProductionNamespaceBeforeOpeningNative(t *testing.T) {
	previous := openNative
	t.Cleanup(func() { openNative = previous })
	openNative = func(context.Context) (vault.Store, error) {
		t.Fatal("openNative called for production namespace")
		return nil, nil
	}

	result, err := verify(context.Background(), "controller/chatgpt")
	if err == nil || !strings.Contains(err.Error(), "supervisor/") {
		t.Fatalf("production namespace error = %v, want dedicated-namespace rejection", err)
	}
	if result.Name != "controller/chatgpt" {
		t.Fatalf("result name = %q, want original name", result.Name)
	}
}

func TestVerifyRejectsCancellationAfterOpeningNativeBeforeBoundaryInspection(t *testing.T) {
	previous := openNative
	t.Cleanup(func() { openNative = previous })
	ctx, cancel := context.WithCancel(context.Background())
	openNative = func(context.Context) (vault.Store, error) {
		cancel()
		return verificationStore{}, nil
	}

	result, err := verify(ctx, "supervisor/post-open-cancel")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("post-open cancellation error = %v, want context.Canceled", err)
	}
	if result.Name != "supervisor/post-open-cancel" {
		t.Fatalf("result name = %q, want supervisor/post-open-cancel", result.Name)
	}
	if strings.Contains(err.Error(), "cleanup") {
		t.Fatalf("post-open cancellation inspected the malformed cleanup boundary: %v", err)
	}
}

func TestReadEvidenceValidatesOfflineWithoutOpeningNative(t *testing.T) {
	previous := openNative
	t.Cleanup(func() { openNative = previous })
	openNative = func(context.Context) (vault.Store, error) {
		t.Fatal("offline evidence replay opened native store")
		return nil, nil
	}

	path := filepath.Join(t.TempDir(), "evidence.json")
	data := []byte(`{"name":"supervisor/replay","put_version":1,"rotate_version":2,"revoked_read_rejected":true,"repeated_revoke_ok":true,"cleanup_succeeded":true}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := readEvidence(path)
	if err != nil {
		t.Fatalf("readEvidence() error = %v", err)
	}
	if result.Name != "supervisor/replay" || result.PutVersion != 1 || result.RotateVersion != 2 || !result.RevokedReadRejected || !result.RepeatedRevokeOK || !result.CleanupSucceeded {
		t.Fatalf("readEvidence() = %#v, want complete validated evidence", result)
	}
}

func TestReadEvidenceRejectsOversizedInputBeforeParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized-evidence.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxEvidenceFileBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEvidence(path); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("readEvidence() error = %v, want bounded-size rejection", err)
	}
}

func TestReadEvidenceRejectsBlankPath(t *testing.T) {
	if _, err := readEvidence(" \t"); err == nil {
		t.Fatal("readEvidence accepted a blank path")
	}
}

func TestReadEvidenceRejectsNonRegularPath(t *testing.T) {
	if _, err := readEvidence(t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("readEvidence(directory) error = %v, want regular-file rejection", err)
	}
}

func TestReadEvidenceRejectsSymlinkPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "evidence.json")
	link := filepath.Join(dir, "evidence-link.json")
	data := []byte(`{"name":"supervisor/replay","put_version":1,"rotate_version":2,"revoked_read_rejected":true,"repeated_revoke_ok":true,"cleanup_succeeded":true}`)
	if err := os.WriteFile(target, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if file, err := openEvidenceNoFollow(link); err == nil {
		_ = file.Close()
		t.Fatal("openEvidenceNoFollow accepted a symlink")
	}
	if _, err := readEvidence(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("readEvidence(symlink) error = %v, want regular-file rejection", err)
	}
}

func TestValidateEvidenceFileIdentityRejectsReplacementAfterOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Remove(path); err != nil {
		t.Skipf("cannot replace open evidence path: %v", err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateEvidenceFileIdentity(path, file); err == nil || !strings.Contains(err.Error(), "changed during read") {
		t.Fatalf("validateEvidenceFileIdentity() = %v, want replacement rejection", err)
	}
}

type verificationStore struct{}

func (verificationStore) Get(string) (vault.Record, error) { return vault.Record{}, vault.ErrNotFound }
func (verificationStore) Put(string, string) (vault.Record, error) {
	return vault.Record{}, errors.New("unexpected put")
}
func (verificationStore) Rotate(string, string) (vault.Record, error) {
	return vault.Record{}, errors.New("unexpected rotate")
}
func (verificationStore) Revoke(string) error { return errors.New("unexpected revoke") }

type typedNilVerificationContext struct{}

func (*typedNilVerificationContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*typedNilVerificationContext) Done() <-chan struct{}       { return nil }
func (*typedNilVerificationContext) Err() error                  { return nil }
func (*typedNilVerificationContext) Value(any) any               { return nil }
