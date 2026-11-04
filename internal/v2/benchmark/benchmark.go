// Package benchmark records repeatable local model-command evidence. It never
// downloads, deletes, or modifies a model store.
package benchmark

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ai-relay/ai-relay/internal/v2/terminal"
)

type Spec struct {
	Name       string   `json:"name"`
	Command    string   `json:"command"`
	Args       []string `json:"args,omitempty"`
	Capability string   `json:"capability"`
}

type Result struct {
	Spec             Spec          `json:"spec"`
	Status           string        `json:"status"`
	ExitCode         int           `json:"exit_code"`
	LatencyMillis    int64         `json:"latency_ms"`
	OutputBytes      int           `json:"output_bytes"`
	OutputTruncated  bool          `json:"output_truncated"`
	Stdout           string        `json:"stdout"`
	Stderr           string        `json:"stderr"`
	Thinking         string        `json:"thinking,omitempty"`
	PromptSHA256     string        `json:"prompt_sha256"`
	ResourceEvidence string        `json:"resource_evidence"`
	Metrics          *ModelMetrics `json:"metrics,omitempty"`
	Error            string        `json:"error,omitempty"`
}

type ModelMetrics struct {
	LoadDurationNS       int64   `json:"load_duration_ns"`
	PromptEvalCount      int     `json:"prompt_eval_count"`
	PromptEvalDurationNS int64   `json:"prompt_eval_duration_ns"`
	EvalCount            int     `json:"eval_count"`
	EvalDurationNS       int64   `json:"eval_duration_ns"`
	TokensPerSecond      float64 `json:"tokens_per_second"`
}

type Runner struct {
	WorkingDir       string
	Timeout          time.Duration
	MaxOutput        int
	ResourceEvidence string
}

func (r Runner) Run(ctx context.Context, spec Spec, prompt string) Result {
	result := Result{Spec: spec, Status: "failed", ExitCode: -1, ResourceEvidence: r.ResourceEvidence, PromptSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(prompt)))}
	if ctx == nil {
		result.Error = "context is required"
		return result
	}
	if strings.TrimSpace(spec.Name) == "" || strings.TrimSpace(spec.Command) == "" {
		result.Error = "name and command are required"
		return result
	}
	if strings.TrimSpace(prompt) == "" {
		result.Error = "prompt is required"
		return result
	}
	if result.ResourceEvidence == "" {
		result.ResourceEvidence = "not collected; benchmark never changes model stores"
	}
	start := time.Now()
	request := terminal.Request{Command: spec.Command, Args: spec.Args, WorkingDir: r.WorkingDir, Approval: terminal.ApprovalExecute, Approved: true, Timeout: r.Timeout, MaxOutput: r.MaxOutput}
	// The terminal action contract intentionally has no stdin yet. A model
	// adapter is expected to expose a prompt through an argv/config mechanism.
	request.Args = append(request.Args, prompt)
	action, err := (terminal.Executor{RepositoryRoot: r.WorkingDir}).Run(ctx, request)
	result.LatencyMillis = time.Since(start).Milliseconds()
	result.OutputBytes, result.OutputTruncated = len(action.Stdout)+len(action.Stderr), action.OutputTruncated
	result.Stdout, result.Stderr = action.Stdout, action.Stderr
	if err != nil {
		if action.ExitCode != 0 {
			result.ExitCode = action.ExitCode
		}
		result.Error = err.Error()
		if errors.Is(ctx.Err(), context.Canceled) || action.Canceled {
			result.Status = "canceled"
		}
		return result
	}
	result.ExitCode = action.ExitCode
	result.Status = "passed"
	return result
}

func (r Result) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }
