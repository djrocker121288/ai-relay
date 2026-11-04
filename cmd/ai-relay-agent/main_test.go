package main

import (
	"context"
	"encoding/json"
	"github.com/ai-relay/ai-relay/internal/agentcore"
	"github.com/ai-relay/ai-relay/internal/protocol"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestResultOutboxSurvivesRestart(t *testing.T) {
	calls := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var q protocol.Request
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
		}
		if q.Method != "agent.result" {
			t.Errorf("method %s", q.Method)
		}
		status, body := 200, `{"accepted":true}`
		if calls == 1 {
			status, body = 503, "outage"
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	dir := filepath.Join(t.TempDir(), "results")
	c := &client{base: "http://gateway.test", id: "device", secret: "secret", hc: &http.Client{Timeout: time.Second, Transport: transport}, outbox: dir}
	if _, err := c.postResult(protocol.CommandResult{JobID: "job", Result: map[string]any{"stdout": "done"}}); err == nil {
		t.Fatal("expected outage")
	}
	if _, err := os.Stat(filepath.Join(dir, "job.json")); err != nil {
		t.Fatal(err)
	}
	restarted := &client{base: "http://gateway.test", id: "device", secret: "secret", hc: c.hc, outbox: dir}
	restarted.flushResults()
	if _, err := os.Stat(filepath.Join(dir, "job.json")); !os.IsNotExist(err) {
		t.Fatalf("result not removed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPrivilegedAsyncCommandIsRejected(t *testing.T) {
	var result protocol.CommandResult
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var q protocol.Request
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(q.Params)
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"accepted":true}`)), Header: make(http.Header)}, nil
	})
	c := &client{base: "http://gateway.test", id: "d", secret: "s", hc: &http.Client{Transport: transport}}
	core := agentcore.New()
	handle(c, core, &protocol.Command{JobID: "privileged", Method: "agent.exec", Params: map[string]any{"command": "echo", "privileged": true}})
	if result.Error == "" || result.JobID != "privileged" {
		t.Fatalf("missing rejection: %#v", result)
	}
	if len(core.Jobs()) != 0 {
		t.Fatal("privileged command executed")
	}
}

func TestTrailingSlashGatewayPreservesPostForAllClients(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local HTTP listener unavailable: %v", err)
	}
	paths := map[string]int{}
	var pathsMu sync.Mutex
	mux := http.NewServeMux()
	for _, path := range []string{"/v1/enroll", "/v1/agent/poll", "/v1/agent/result"} {
		endpoint := path
		mux.HandleFunc(endpoint, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != endpoint {
				t.Errorf("noncanonical request: %s %s", r.Method, r.URL.Path)
				http.Error(w, "method", 405)
				return
			}
			pathsMu.Lock()
			paths[endpoint]++
			pathsMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if endpoint == "/v1/enroll" {
				w.Write([]byte(`{"device_id":"test-device","secret":"test-secret"}`))
				return
			}
			if endpoint == "/v1/agent/poll" {
				w.Write([]byte(`{"command":null}`))
				return
			}
			w.Write([]byte(`{"accepted":true}`))
		})
	}
	srv := &httptest.Server{Listener: listener, Config: &http.Server{Handler: mux}}
	srv.Start()
	defer srv.Close()
	base := srv.URL + "/"
	if _, _, err := enroll(base, "test-token"); err != nil {
		t.Fatal(err)
	}
	cli := &client{base: base, id: "test-device", secret: "test-secret", hc: srv.Client()}
	var out map[string]any
	if err := cli.request("agent.poll", nil, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.postResult(protocol.CommandResult{JobID: "test-job"}); err != nil {
		t.Fatal(err)
	}
	library := &agentcore.Client{Gateway: base, DeviceID: "test-device", Secret: "test-secret", HTTP: srv.Client()}
	if _, err := library.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	pathsMu.Lock()
	defer pathsMu.Unlock()
	if paths["/v1/enroll"] != 1 || paths["/v1/agent/poll"] != 2 || paths["/v1/agent/result"] != 1 {
		t.Fatalf("missing canonical POST paths: %#v", paths)
	}
}
