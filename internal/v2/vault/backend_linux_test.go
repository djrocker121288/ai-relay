//go:build linux

package vault

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

type typedNilSecretServiceContext struct{}

func (*typedNilSecretServiceContext) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}
func (*typedNilSecretServiceContext) Done() <-chan struct{} { return nil }
func (*typedNilSecretServiceContext) Err() error            { return nil }
func (*typedNilSecretServiceContext) Value(any) any         { return nil }

func TestOpenDefaultRejectsNilContextBeforeFallback(t *testing.T) {
	root := t.TempDir()
	path := root + "/vault.json"
	keyPath := root + "/vault.key"

	_, err := OpenDefault(nil, path, keyPath)
	if err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("OpenDefault(nil) error = %v, want nil-context failure", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("nil context caused fallback vault creation")
	}
	if _, statErr := os.Stat(keyPath); statErr == nil {
		t.Fatal("nil context caused fallback key creation")
	}
}

func TestOpenSecretServiceRejectsTypedNilContextBeforeProbe(t *testing.T) {
	called := false
	var ctx *typedNilSecretServiceContext
	_, err := openSecretService(ctx, func(context.Context, string, []string, string) ([]byte, error) {
		called = true
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("openSecretService(typed nil) error = %v, want nil-context failure", err)
	}
	if called {
		t.Fatal("typed-nil context reached the Secret Service probe")
	}
}
