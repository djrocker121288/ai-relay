package benchmark

import (
	"context"
	"testing"
)

func TestRunnerRecordsBoundedEvidence(t *testing.T) {
	r := Runner{WorkingDir: t.TempDir(), MaxOutput: 3, ResourceEvidence: "host probe unavailable"}
	got := r.Run(context.Background(), Spec{Name: "fixture", Command: "printf", Capability: "text"}, "abcdef")
	if got.Status != "passed" || got.OutputBytes != 3 || got.Stdout != "abc" || got.PromptSHA256 == "" || !got.OutputTruncated || got.ResourceEvidence != "host probe unavailable" {
		t.Fatalf("result=%+v", got)
	}
}

func TestRunnerRejectsMissingPrompt(t *testing.T) {
	got := (Runner{WorkingDir: t.TempDir()}).Run(context.Background(), Spec{Name: "fixture", Command: "true"}, "")
	if got.Status != "failed" || got.ExitCode != -1 || got.Error == "" {
		t.Fatalf("result=%+v", got)
	}
}

func TestRunnerPreflightAndCancellationAreNotSuccessfulExits(t *testing.T) {
	got := (Runner{WorkingDir: ""}).Run(context.Background(), Spec{Name: "fixture", Command: "true"}, "prompt")
	if got.Status != "failed" || got.ExitCode != -1 || got.Error == "" {
		t.Fatalf("preflight result=%+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got = (Runner{WorkingDir: t.TempDir()}).Run(ctx, Spec{Name: "fixture", Command: "true"}, "prompt")
	if got.Status != "canceled" || got.ExitCode != -1 || got.Error == "" {
		t.Fatalf("canceled result=%+v", got)
	}
	got = (Runner{WorkingDir: t.TempDir()}).Run(nil, Spec{Name: "fixture", Command: "true"}, "prompt")
	if got.Status != "failed" || got.ExitCode != -1 || got.Error == "" {
		t.Fatalf("nil-context result=%+v", got)
	}
}
