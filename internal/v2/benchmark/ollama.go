package benchmark

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OllamaRunner struct {
	Endpoint         string
	Timeout          time.Duration
	MaxOutput        int
	NumContext       int
	NumPredict       int
	Seed             int
	ResourceEvidence string
	Client           *http.Client
}

type ollamaTags struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

type ollamaGenerateResponse struct {
	Response           string `json:"response"`
	Thinking           string `json:"thinking"`
	Done               bool   `json:"done"`
	LoadDuration       int64  `json:"load_duration"`
	PromptEvalCount    int    `json:"prompt_eval_count"`
	PromptEvalDuration int64  `json:"prompt_eval_duration"`
	EvalCount          int    `json:"eval_count"`
	EvalDuration       int64  `json:"eval_duration"`
}

func (r OllamaRunner) Run(ctx context.Context, name, model, capability, prompt string) Result {
	result := Result{
		Spec:             Spec{Name: name, Command: "ollama-http", Args: []string{model}, Capability: capability},
		Status:           "failed",
		ExitCode:         -1,
		PromptSHA256:     fmt.Sprintf("%x", sha256.Sum256([]byte(prompt))),
		ResourceEvidence: r.ResourceEvidence,
	}
	if ctx == nil {
		result.Error = "context is required"
		return result
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(model) == "" || strings.TrimSpace(prompt) == "" {
		result.Error = "name, model, and prompt are required"
		return result
	}
	endpoint, err := loopbackEndpoint(r.Endpoint)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if r.Timeout <= 0 {
		r.Timeout = 5 * time.Minute
	}
	if r.Timeout > 10*time.Minute {
		result.Error = "timeout exceeds 10 minutes"
		return result
	}
	if r.MaxOutput <= 0 {
		r.MaxOutput = 256 * 1024
	}
	if r.MaxOutput > 1024*1024 {
		result.Error = "max output exceeds 1048576 bytes"
		return result
	}
	if r.NumContext <= 0 {
		r.NumContext = 4096
	}
	if r.NumPredict <= 0 {
		r.NumPredict = 160
	}
	if r.NumContext > 32768 || r.NumPredict > 4096 {
		result.Error = "requested context or output exceeds benchmark bound"
		return result
	}
	if result.ResourceEvidence == "" {
		result.ResourceEvidence = "not collected; benchmark never changes model stores"
	}
	client := http.Client{}
	if r.Client != nil {
		client = *r.Client
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("Ollama endpoint redirects are not permitted")
	}
	runCtx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	if err := ensureInstalled(runCtx, &client, endpoint, model); err != nil {
		result.Error = err.Error()
		return result
	}
	payload := map[string]any{
		"model": model, "prompt": prompt, "stream": false, "think": false, "keep_alive": "0s",
		"options": map[string]any{"num_ctx": r.NumContext, "num_predict": r.NumPredict, "temperature": 0, "seed": r.Seed},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(runCtx, http.MethodPost, endpoint+"/api/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	started := time.Now()
	response, err := client.Do(req)
	result.LatencyMillis = time.Since(started).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		if runCtx.Err() != nil {
			result.Status = "canceled"
		}
		return result
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, int64(r.MaxOutput+1024*1024+1)))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if response.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("Ollama generate returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(encoded)))
		return result
	}
	var generated ollamaGenerateResponse
	if err := json.Unmarshal(encoded, &generated); err != nil {
		result.Error = "invalid Ollama response: " + err.Error()
		return result
	}
	if !generated.Done {
		result.Error = "Ollama response was not complete"
		return result
	}
	output, thinking := []byte(generated.Response), []byte(generated.Thinking)
	if len(output) > r.MaxOutput {
		output, thinking = output[:r.MaxOutput], nil
		result.OutputTruncated = true
	} else if len(output)+len(thinking) > r.MaxOutput {
		thinking = thinking[:r.MaxOutput-len(output)]
		result.OutputTruncated = true
	}
	result.Stdout = string(output)
	result.Thinking = string(thinking)
	result.OutputBytes = len(output) + len(thinking)
	result.ExitCode = 0
	result.Status = "passed"
	metrics := &ModelMetrics{
		LoadDurationNS: generated.LoadDuration, PromptEvalCount: generated.PromptEvalCount,
		PromptEvalDurationNS: generated.PromptEvalDuration, EvalCount: generated.EvalCount,
		EvalDurationNS: generated.EvalDuration,
	}
	if metrics.EvalDurationNS > 0 {
		metrics.TokensPerSecond = float64(metrics.EvalCount) / (float64(metrics.EvalDurationNS) / float64(time.Second))
	}
	result.Metrics = metrics
	return result
}

func loopbackEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Scheme != "http" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("Ollama endpoint must be a loopback HTTP origin")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", fmt.Errorf("Ollama endpoint must be loopback")
	}
	return strings.TrimRight(raw, "/"), nil
}

func ensureInstalled(ctx context.Context, client *http.Client, endpoint, model string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/api/tags", nil)
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("list installed models: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("list installed models returned HTTP %d", response.StatusCode)
	}
	var tags ollamaTags
	if err := json.NewDecoder(io.LimitReader(response.Body, 4*1024*1024)).Decode(&tags); err != nil {
		return fmt.Errorf("decode installed models: %w", err)
	}
	for _, candidate := range tags.Models {
		if candidate.Name == model || strings.TrimSuffix(candidate.Name, ":latest") == strings.TrimSuffix(model, ":latest") {
			return nil
		}
	}
	return fmt.Errorf("model %q is not already installed; benchmark will not pull it", model)
}
