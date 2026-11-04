package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAndroidExecutableResolverPrefersInvokedBinary(t *testing.T) {
	dir := t.TempDir()
	invoked := filepath.Join(dir, "ai-relay-arpl")
	if err := os.WriteFile(invoked, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	got := resolveARPLExecutable("android", invoked, "/apex/com.android.runtime/bin/linker64")
	if got != invoked {
		t.Fatalf("resolver=%q, want invoked ARPL binary %q", got, invoked)
	}
}

func TestAndroidExecutableResolverRejectsLinkerAndFallsBackSafely(t *testing.T) {
	got := resolveARPLExecutable("android", "/apex/com.android.runtime/bin/linker64", "/apex/com.android.runtime/bin/linker64")
	if got != "ai-relay-arpl" {
		t.Fatalf("resolver=%q, want safe PATH fallback", got)
	}
	if !androidLinkerPath("/apex/com.android.runtime/bin/linker64") {
		t.Fatal("Android linker path was not rejected")
	}
	if strings.Contains(got, "linker") || strings.Contains(got, "/apex/") {
		t.Fatalf("unsafe linker fallback: %q", got)
	}
}
