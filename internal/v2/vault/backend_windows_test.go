//go:build windows

package vault

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenDefaultRejectsNilContextBeforeNativeSelection(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "vault.json")
	keyPath := filepath.Join(d, "vault.key")
	if _, err := OpenDefault(nil, path, keyPath); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("OpenDefault(nil) error = %v, want nil-context failure", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("nil context created the encrypted-file fallback")
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Fatal("nil context created the fallback key")
	}
}

func TestOpenDefaultSelectsCredentialManagerBeforeFallback(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "vault.json")
	keyPath := filepath.Join(d, "vault.key")
	store, err := OpenDefault(context.Background(), path, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(*CredentialManager); !ok {
		t.Fatalf("default store = %T, want *CredentialManager", store)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("native selection created the encrypted-file fallback")
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Fatal("native selection created the fallback key")
	}
}
