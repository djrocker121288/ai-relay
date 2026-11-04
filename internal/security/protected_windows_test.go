//go:build windows

package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCredentialRejectsEveryoneACE(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecretFile(path); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), path, "/grant", "*S-1-1-0:R")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Everyone ACL fixture: %v: %s", err, output)
	}

	if _, err := ReadSecretFile(path); err == nil {
		t.Fatal("Everyone-readable credential accepted")
	}
}
