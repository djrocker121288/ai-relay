//go:build linux || darwin

package distribution

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallRestoresPriorStateAfterDirectorySyncFailure(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "agent")
	if err := os.WriteFile(p, []byte("current"), 0700); err != nil {
		t.Fatal(err)
	}

	originalSync := syncUpdateDirectory
	t.Cleanup(func() { syncUpdateDirectory = originalSync })
	var calls int
	syncUpdateDirectory = func(path string) error {
		calls++
		if calls == 1 {
			return errors.New("injected directory sync failure")
		}
		return originalSync(path)
	}

	if err := Install(p, []byte("replacement"), "1.2.0", "1.1.0"); err == nil {
		t.Fatal("Install unexpectedly succeeded after directory sync failure")
	}
	if calls != 2 {
		t.Fatalf("directory sync calls = %d, want initial failure plus restoration", calls)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "current" {
		t.Fatalf("active executable after failed install = %q, %v", got, err)
	}
	if _, err := os.Stat(p + ".previous"); !os.IsNotExist(err) {
		t.Fatalf("failed install left rollback image: %v", err)
	}
}

func TestRollbackRestoresPriorStateAfterDirectorySyncFailure(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "agent")
	backup := p + ".previous"
	if err := os.WriteFile(p, []byte("current"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("previous"), 0700); err != nil {
		t.Fatal(err)
	}

	originalSync := syncUpdateDirectory
	t.Cleanup(func() { syncUpdateDirectory = originalSync })
	var calls int
	syncUpdateDirectory = func(path string) error {
		calls++
		if calls == 1 {
			return errors.New("injected rollback directory sync failure")
		}
		return originalSync(path)
	}

	if err := Rollback(p); err == nil {
		t.Fatal("Rollback unexpectedly succeeded after directory sync failure")
	}
	if calls != 2 {
		t.Fatalf("directory sync calls = %d, want initial failure plus restoration", calls)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "current" {
		t.Fatalf("active executable after failed rollback = %q, %v", got, err)
	}
	got, err = os.ReadFile(backup)
	if err != nil || string(got) != "previous" {
		t.Fatalf("rollback image after failed rollback = %q, %v", got, err)
	}
	if _, err := os.Lstat(p + ".rollback-tmp"); !os.IsNotExist(err) {
		t.Fatalf("failed rollback left temporary image: %v", err)
	}
}
