//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenEvidenceNoFollowRejectsSymlinkedAncestor(t *testing.T) {
	root := t.TempDir()
	targetDir := filepath.Join(root, "target")
	linkDir := filepath.Join(root, "linked")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, linkDir); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	path := filepath.Join(linkDir, "evidence.json")
	if err := os.WriteFile(filepath.Join(targetDir, "evidence.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	if file, err := openEvidenceNoFollow(path); err == nil {
		_ = file.Close()
		t.Fatal("openEvidenceNoFollow accepted a symlinked ancestor")
	}
}
