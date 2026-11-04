package benchmark

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOllamaRunnerUsesInstalledModelAndBoundedOptions(t *testing.T) {
	var generateCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"fixture:latest"}]}`))
		case "/api/generate":
			generateCalled = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			options := body["options"].(map[string]any)
			if options["num_ctx"] != float64(2048) || options["num_predict"] != float64(32) {
				t.Fatalf("options=%v", options)
			}
			if body["think"] != false || body["stream"] != false {
				t.Fatalf("benchmark must request bounded non-streaming final output: %v", body)
			}
			_, _ = w.Write([]byte(`{"response":"package main","thinking":"checked","done":true,"eval_count":10,"eval_duration":2000000000}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	runner := OllamaRunner{Endpoint: server.URL, NumContext: 2048, NumPredict: 32, MaxOutput: 1024}
	got := runner.Run(context.Background(), "fixture", "fixture", "coding", "prompt")
	if !generateCalled || got.Status != "passed" || got.Stdout != "package main" || got.Thinking != "checked" || got.Metrics == nil || got.Metrics.TokensPerSecond != 5 {
		t.Fatalf("result=%+v", got)
	}
}

func TestOllamaRunnerRefusesRedirect(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("redirect target was contacted")
	}))
	defer remote.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, remote.URL, http.StatusFound)
	}))
	defer server.Close()
	got := (OllamaRunner{Endpoint: server.URL}).Run(context.Background(), "redirect", "model", "coding", "prompt")
	if got.Error == "" || !strings.Contains(got.Error, "redirect") {
		t.Fatalf("result=%+v", got)
	}
}

func TestOllamaRunnerRefusesMissingModelAndRemoteEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/generate" {
			t.Fatal("generate called for missing model")
		}
		_, _ = w.Write([]byte(`{"models":[]}`))
	}))
	defer server.Close()
	got := (OllamaRunner{Endpoint: server.URL}).Run(context.Background(), "missing", "missing", "coding", "prompt")
	if got.Error == "" || !strings.Contains(got.Error, "will not pull") {
		t.Fatalf("result=%+v", got)
	}
	got = (OllamaRunner{Endpoint: "https://example.com"}).Run(context.Background(), "remote", "model", "coding", "prompt")
	if got.Error == "" {
		t.Fatal("remote endpoint accepted")
	}
}
