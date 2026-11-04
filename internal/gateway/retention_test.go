package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ai-relay/ai-relay/internal/protocol"
	"github.com/ai-relay/ai-relay/internal/security"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNonceRetentionExpiresAndRejectsReplays(t *testing.T) {
	now := time.Unix(2000, 0)
	s := &Server{nonces: map[string]time.Time{}}
	for i := 0; i < 1000; i++ {
		if !s.acceptNonceLocked("d", fmt.Sprint(i), now) {
			t.Fatal("nonce rejected")
		}
	}
	if s.acceptNonceLocked("d", "0", now.Add(time.Minute)) {
		t.Fatal("replay accepted")
	}
	if !s.acceptNonceLocked("d", "fresh", now.Add(11*time.Minute)) {
		t.Fatal("fresh nonce rejected")
	}
	if len(s.nonces) != 1 {
		t.Fatalf("expired nonces retained: %d", len(s.nonces))
	}
}
func TestNonceRetentionFailsClosedAtLimit(t *testing.T) {
	now := time.Unix(2000, 0)
	s := &Server{nonces: map[string]time.Time{}, nonceSweep: now}
	for i := 0; i < maxRememberedNonces; i++ {
		s.nonces[fmt.Sprintf("d:%d", i)] = now.Add(time.Minute)
	}
	if s.acceptNonceLocked("d", "new", now) {
		t.Fatal("saturated replay cache accepted request")
	}
	if len(s.nonces) != maxRememberedNonces {
		t.Fatal("live replay entries were evicted")
	}
	if s.acceptNonceLocked("d", "0", now) {
		t.Fatal("live replay accepted after saturation")
	}
	if !s.acceptNonceLocked("d", "new", now.Add(2*time.Minute)) || len(s.nonces) != 1 {
		t.Fatal("expired cache did not recover")
	}
}

func TestNonceRetentionSteadyIdleRemainsBounded(t *testing.T) {
	now := time.Unix(2000, 0)
	s := &Server{nonces: map[string]time.Time{}}
	for second := 0; second < 7200; second++ {
		when := now.Add(time.Duration(second) * time.Second)
		if !s.acceptNonceLocked("d", fmt.Sprint(second), when) {
			t.Fatal("idle nonce rejected")
		}
		if len(s.nonces) > 660 {
			t.Fatalf("idle retention grew to %d", len(s.nonces))
		}
	}
	if s.acceptNonceLocked("d", "7199", now.Add(7200*time.Second)) {
		t.Fatal("recent idle replay accepted")
	}
}

func TestOversizedSignedIdentifiersDoNotEnterReplayCache(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.devices["d"] = &DeviceRecord{Device: protocol.Device{ID: "d"}, Secret: "secret"}
	for _, field := range []string{"nonce", "id"} {
		q := protocol.Request{Version: protocol.Version, ID: "valid", DeviceID: "d", Timestamp: time.Now().Unix(), Nonce: "valid", Method: "agent.poll", Params: map[string]any{}}
		if field == "nonce" {
			q.Nonce = strings.Repeat("n", 257)
		} else {
			q.ID = strings.Repeat("i", 257)
		}
		q.Signature = security.Sign("secret", q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(q.Params))
		body, _ := json.Marshal(q)
		for _, route := range []string{"/v1/agent/poll", "/v1/request"} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", route, bytes.NewReader(body))
			if route == "/v1/request" {
				s.requestHandler(w, r)
			} else {
				s.agentPoll(w, r)
			}
			if w.Code != 401 || len(s.nonces) != 0 {
				t.Fatalf("oversized %s accepted on %s", field, route)
			}
		}
	}
}
