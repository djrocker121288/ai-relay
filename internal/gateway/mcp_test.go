package gateway

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/ai-relay/ai-relay/internal/protocol"
)

func TestMCPWireCompliance(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, token := issueTestController(t, s, "chatgpt")
	send := func(method, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/mcp", bytes.NewBufferString(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.mcp(w, r)
		return w
	}
	for _, test := range []struct {
		body string
		code int
	}{
		{`{`, -32700},
		{`{"jsonrpc":"1.0","id":1,"method":"ping"}`, -32600},
		{`{"jsonrpc":"2.0","id":2,"method":"unknown"}`, -32601},
		{`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"unknown"}}`, -32602},
		{`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"agent.exec","arguments":{"device_id":"d"}}}`, -32602},
	} {
		w := send("POST", test.body)
		var response map[string]any
		if json.Unmarshal(w.Body.Bytes(), &response) != nil {
			t.Fatalf("invalid response: %s", w.Body.Bytes())
		}
		if _, exists := response["result"]; exists {
			t.Fatal("error response includes result")
		}
		e, ok := response["error"].(map[string]any)
		if !ok || e["code"] != float64(test.code) {
			t.Fatalf("wrong numeric error: %s", w.Body.Bytes())
		}
	}
	w := send("POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if w.Code != 202 || w.Body.Len() != 0 {
		t.Fatal("notification returned JSON-RPC response")
	}
	if w := send("GET", ""); w.Code != 405 {
		t.Fatal("unsupported SSE GET did not return405")
	}
	w = send("POST", `{"jsonrpc":"2.0","id":"health-id","method":"tools/call","params":{"name":"health","arguments":{}}}`)
	var response map[string]any
	json.Unmarshal(w.Body.Bytes(), &response)
	if _, exists := response["error"]; exists {
		t.Fatal("successful response contains error")
	}
	if response["id"] != "health-id" {
		t.Fatal("request ID not preserved")
	}
	result, ok := response["result"].(map[string]any)
	if !ok || result["ok"] != true || result["isError"] != false {
		t.Fatal("legacy result fields lost")
	}
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok || structured["ok"] != true {
		t.Fatal("structuredContent missing")
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatal("MCP content missing")
	}
	block := content[0].(map[string]any)
	if block["type"] != "text" {
		t.Fatal("MCP content type invalid")
	}
	var text map[string]any
	if json.Unmarshal([]byte(block["text"].(string)), &text) != nil || text["ok"] != true {
		t.Fatal("serialized structured text invalid")
	}
	// Application errors must reach the model as tool errors, not protocol errors.
	w = send("POST", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"agent.job","arguments":{"job_id":"absent"}}}`)
	json.Unmarshal(w.Body.Bytes(), &response)
	result, _ = response["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("tool error not represented: %s", w.Body.Bytes())
	}
}

func TestMCPArrayResultsHaveObjectStructuredContent(t *testing.T) {
	result := toolResult([]string{"device"}, nil)
	if _, ok := result["structuredContent"].(map[string]any); !ok {
		t.Fatal("structuredContent must be JSON object in2025-06-18")
	}
}

func TestMCPOriginRejectsDNSRebinding(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ALLOWED_ORIGINS", "")
	request := httptest.NewRequest("POST", "http://evil.example/mcp", nil)
	request.Header.Set("Origin", "http://evil.example")
	if allowedMCPOrigin(request) {
		t.Fatal("matching hostile Origin and Host allowed DNS rebinding")
	}
	request = httptest.NewRequest("POST", "http://127.0.0.1:8743/mcp", nil)
	request.Header.Set("Origin", "http://127.0.0.1:8743")
	if !allowedMCPOrigin(request) {
		t.Fatal("same loopback origin denied")
	}
	request.Header.Set("Origin", "https://portal.example")
	if allowedMCPOrigin(request) {
		t.Fatal("unconfigured browser origin allowed")
	}
	t.Setenv("AI_RELAY_MCP_ALLOWED_ORIGINS", "https://portal.example")
	if !allowedMCPOrigin(request) {
		t.Fatal("explicit configured origin denied")
	}
	request.Header.Del("Origin")
	if !allowedMCPOrigin(request) {
		t.Fatal("SDK without Origin denied")
	}
}

func TestMCPDeviceRevocationPersistsAcrossRestart(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.devices["device-1"] = &DeviceRecord{Device: protocol.Device{ID: "device-1", Name: "persisted"}, Secret: "device-secret"}
	_, controllerToken := issueTestController(t, s, "chatgpt")
	s.adminToken = controllerToken
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "devices.revoke",
			"arguments": map[string]any{"device_id": "device-1"},
		},
	})
	r := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+controllerToken)
	w := httptest.NewRecorder()
	s.mcp(w, r)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"revoked":"device-1"`)) {
		t.Fatalf("MCP revoke failed: %d %s", w.Code, w.Body.String())
	}
	restored, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.devices["device-1"].Revoked {
		t.Fatal("MCP device revocation was not persisted")
	}
}
