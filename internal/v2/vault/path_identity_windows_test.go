//go:build windows

package vault

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFileVaultRejectsWindowsCaseOnlyAliasBeforeCreation(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "vault.json")
	caseAlias := filepath.Join(d, "VAULT.JSON")
	if same, err := sameConfiguredPath(path, caseAlias); err != nil || !same {
		t.Fatalf("case-only path identity = %v, %v; want equivalent paths", same, err)
	}
	if _, err := OpenFile(path, caseAlias); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("accepted case-only alias: %v", err)
	}
}
