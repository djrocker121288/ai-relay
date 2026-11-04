package terminal

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunRequiresApprovalAndBoundsOutput(t *testing.T) {
	dir := t.TempDir()
	executor := Executor{RepositoryRoot: dir}
	if _, err := executor.Run(context.Background(), Request{Command: "printf", Args: []string{"ok"}, WorkingDir: dir, Approval: ApprovalWrite}); err != ErrApprovalRequired {
		t.Fatalf("approval error = %v", err)
	}
	result, err := executor.Run(context.Background(), Request{Command: "printf", Args: []string{"123456789"}, WorkingDir: dir, Approval: ApprovalExecute, Approved: true, MaxOutput: 4})
	if err != nil || result.Stdout != "1234" || !result.OutputTruncated {
		t.Fatalf("bounded result=%+v err=%v", result, err)
	}
}

func TestRunRejectsShellAndOutsideDirectory(t *testing.T) {
	dir := t.TempDir()
	executor := Executor{RepositoryRoot: dir}
	if _, err := executor.Run(context.Background(), Request{Command: "sh", WorkingDir: dir, Approval: ApprovalRead}); err != ErrShellForbidden {
		t.Fatalf("shell error=%v", err)
	}
	if _, err := executor.Run(context.Background(), Request{Command: "rm", Args: []string{"fixture"}, WorkingDir: dir, Approval: ApprovalRead}); err == nil {
		t.Fatal("unapproved mutating command was accepted")
	}
	if _, err := executor.Run(context.Background(), Request{Command: "cat", Args: []string{"/etc/passwd"}, WorkingDir: dir, Approval: ApprovalRead}); err == nil {
		t.Fatal("read escaped repository")
	}
	if _, err := executor.Run(context.Background(), Request{Command: "true", WorkingDir: filepath.Join(dir, "missing"), Approval: ApprovalRead}); err != ErrOutsideRepository {
		t.Fatalf("directory error=%v", err)
	}
}

func TestRunCancellation(t *testing.T) {
	dir := t.TempDir()
	executor := Executor{RepositoryRoot: dir}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := executor.Run(ctx, Request{Command: "sleep", Args: []string{"10"}, WorkingDir: dir, Approval: ApprovalExecute, Approved: true, Timeout: time.Second})
	if err == nil || !result.Canceled {
		t.Fatalf("expected cancellation result=%+v err=%v", result, err)
	}
	if strings.Contains(result.Stdout, "secret") {
		t.Fatal("unexpected output")
	}
	_ = os.WriteFile(filepath.Join(dir, "fixture"), []byte("unchanged"), 0600)
}

func TestReadPolicyRejectsMutatorsAndSymlinkEscapes(t *testing.T) {
	dir := t.TempDir()
	executor := Executor{RepositoryRoot: dir}
	for _, command := range []string{"git", "go", "sed", "printf", "echo"} {
		if _, err := executor.Run(context.Background(), Request{Command: command, Args: []string{"status"}, WorkingDir: dir, Approval: ApprovalRead}); err == nil {
			t.Fatalf("unapproved read accepted potentially mutating command %q", command)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "escape")); err == nil {
		if _, err := executor.Run(context.Background(), Request{Command: "cat", Args: []string{"escape"}, WorkingDir: dir, Approval: ApprovalRead}); err == nil {
			t.Fatal("read followed a symlink outside the repository")
		}
	}
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := executor.Run(context.Background(), Request{Command: "cat", Args: []string{"fixture"}, WorkingDir: dir, Approval: ApprovalRead})
	if err != nil || result.Stdout != "ok" {
		t.Fatalf("bounded read failed: result=%+v err=%v", result, err)
	}
}

func TestRequestCannotChooseRepositoryBoundaryOrInjectLoaderEnvironment(t *testing.T) {
	dir := t.TempDir()
	executor := Executor{RepositoryRoot: dir}
	if _, err := executor.Run(context.Background(), Request{Command: "pwd", WorkingDir: "/", Approval: ApprovalRead}); err != ErrOutsideRepository {
		t.Fatalf("boundary error=%v", err)
	}
	if _, err := executor.Run(context.Background(), Request{Command: "true", WorkingDir: dir, Approval: ApprovalExecute, Approved: true, Environment: map[string]string{"LD_PRELOAD": "/tmp/inject"}}); err == nil {
		t.Fatal("loader environment injection accepted")
	}
}
