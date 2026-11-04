package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ai-relay/ai-relay/internal/protocol"
	"github.com/ai-relay/ai-relay/internal/security"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEnrollAndReplay(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, e := New(dir)
	if e != nil {
		t.Fatal(e)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/v1/enroll", nil)
	req.Header.Set("Authorization", "Bearer test-admin")
	s.enrollHandler(rr, req)
	var tok map[string]string
	json.Unmarshal(rr.Body.Bytes(), &tok)
	b, _ := json.Marshal(map[string]string{"name": "test", "platform": "linux", "arch": "amd64", "token": tok["token"]})
	rr = httptest.NewRecorder()
	s.enrollHandler(rr, httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(b)))
	var got map[string]string
	json.Unmarshal(rr.Body.Bytes(), &got)
	p := map[string]string{"x": "y"}
	pb, _ := json.Marshal(p)
	q := protocol.Request{Version: protocol.Version, ID: "1", DeviceID: got["device_id"], Timestamp: time.Now().Unix(), Nonce: "unique", Method: "health", Params: p}
	q.Signature = security.Sign(got["secret"], q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, pb)
	raw, _ := json.Marshal(q)
	rr = httptest.NewRecorder()
	s.requestHandler(rr, httptest.NewRequest("POST", "/v1/request", bytes.NewReader(raw)))
	if rr.Code != 200 {
		t.Fatalf("request %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.requestHandler(rr, httptest.NewRequest("POST", "/v1/request", bytes.NewReader(raw)))
	if rr.Code != 401 {
		t.Fatalf("replay %d", rr.Code)
	}
	os.RemoveAll(dir)
}

func TestQueuedJobReconnectAndPersistence(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.enroll["t"] = time.Now().Add(time.Minute)
	b, _ := json.Marshal(map[string]string{"name": "agent", "platform": "linux", "arch": "amd64", "token": "t"})
	r := httptest.NewRecorder()
	s.enrollHandler(r, httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(b)))
	var e struct {
		DeviceID string `json:"device_id"`
		Secret   string `json:"secret"`
	}
	if json.Unmarshal(r.Body.Bytes(), &e) != nil || e.DeviceID == "" || e.Secret == "" {
		t.Fatal(r.Body.String())
	}
	s.mu.Lock()
	s.devices[e.DeviceID].Online = true
	s.mu.Unlock()
	j, err := s.enqueue(e.DeviceID, "agent.exec", map[string]any{"command": "echo"})
	if err != nil {
		t.Fatal(err)
	}
	q := protocol.Request{Version: protocol.Version, ID: "poll", DeviceID: e.DeviceID, Timestamp: time.Now().Unix(), Nonce: "pollnonce", Method: "agent.poll", Params: map[string]any{}}
	q.Signature = security.Sign(e.Secret, q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(q.Params))
	raw, _ := json.Marshal(q)
	r = httptest.NewRecorder()
	s.agentPoll(r, httptest.NewRequest("POST", "/v1/agent/poll", bytes.NewReader(raw)))
	if r.Code != 200 || !bytes.Contains(r.Body.Bytes(), []byte(j.ID)) {
		t.Fatalf("poll %d %s", r.Code, r.Body.String())
	}
	stateBytes, err := os.ReadFile(dir + "/state.json")
	if err != nil || bytes.HasPrefix(stateBytes, []byte("{")) {
		t.Fatal("state is not encrypted")
	}
	err = security.CheckProtectedFile(dir + "/state.key")
	if err != nil {
		t.Fatalf("state key permissions: %v", err)
	}
	s2, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.jobs[j.ID] == nil {
		t.Fatal("job not persisted")
	}
	if s2.devices[e.DeviceID] == nil {
		t.Fatal("device not persisted")
	}
}

func controllerMCP(s *Server, token, name string, args map[string]any) (int, []byte) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	r := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.mcp(w, r)
	return w.Code, w.Body.Bytes()
}

func TestAdminAuthorizationRejectsAmbiguousAndOversizedHeaders(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		values []string
		want   int
	}{
		{name: "valid", values: []string{"Bearer test-admin"}, want: http.StatusOK},
		{name: "case-insensitive scheme", values: []string{"bearer test-admin"}, want: http.StatusOK},
		{name: "duplicate", values: []string{"Bearer test-admin", "Bearer test-admin"}, want: http.StatusUnauthorized},
		{name: "oversized", values: []string{"Bearer " + strings.Repeat("a", maxControllerAuthorizationBytes)}, want: http.StatusUnauthorized},
		{name: "wrong scheme", values: []string{"Basic test-admin"}, want: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/v1/enroll", nil)
			for _, value := range tc.values {
				req.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			s.enrollHandler(response, req)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
		})
	}

	req := httptest.NewRequest(http.MethodPut, "/v1/enroll", nil)
	req.Header = http.Header{
		"Authorization": []string{"Bearer test-admin"},
		"authorization": []string{"Bearer test-admin"},
	}
	response := httptest.NewRecorder()
	s.enrollHandler(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("differently cased duplicate admin authorization status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestCaseInsensitiveAuthorizationHeaderExtractionCapsDuplicates(t *testing.T) {
	entries := make([]string, maxAuthorizationHeaderEntries)
	for index := range entries {
		entries[index] = "Bearer duplicate"
	}

	values := headerValuesCaseInsensitive(http.Header{"Authorization": entries}, "authorization")
	if len(values) != maxAuthorizationHeaderValues {
		t.Fatalf("matching values = %d, want cap %d", len(values), maxAuthorizationHeaderValues)
	}
}

func TestCaseInsensitiveAuthorizationHeaderExtractionRejectsOversizedDirectMap(t *testing.T) {
	header := http.Header{"Authorization": []string{"Bearer accepted"}}
	for index := 0; index < maxAuthorizationHeaderFields; index++ {
		header[fmt.Sprintf("X-Direct-%d", index)] = []string{"value"}
	}

	if values := headerValuesCaseInsensitive(header, "authorization"); values != nil {
		t.Fatalf("oversized direct header map returned %v, want fail-closed nil", values)
	}
}

func TestManagerForwardingAndScopes(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	manager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/gateway/submit":
			if r.Method != http.MethodPost {
				t.Errorf("submit method = %s", r.Method)
			}
			_, _ = io.WriteString(w, `{"id":"job-1","state":"QUEUED"}`)
		case "/gateway/jobs/job-1":
			_, _ = io.WriteString(w, `{"id":"job-1","state":"COMPLETED","result":{"content":"done"}}`)
		case "/gateway/jobs":
			_, _ = io.WriteString(w, `{"jobs":[{"id":"job-1","state":"COMPLETED"}]}`)
		case "/gateway/cancel":
			_, _ = io.WriteString(w, `{"job_id":"job-1","cancelled":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer manager.Close()
	old := managerBaseURL
	managerBaseURL = manager.URL
	defer func() { managerBaseURL = old }()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, token := issueTestController(t, s, "chatgpt")
	for _, tc := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"manager.submit", map[string]any{"task": "read only"}, `"id":"job-1"`},
		{"manager.status", map[string]any{"job_id": "job-1"}, `"state":"COMPLETED"`},
		{"manager.result", map[string]any{"job_id": "job-1"}, `"content":"done"`},
		{"manager.jobs", map[string]any{}, `"jobs"`},
		{"manager.cancel", map[string]any{"job_id": "job-1"}, `"cancelled":true`},
	} {
		status, raw := controllerMCP(s, token, tc.name, tc.args)
		if status != http.StatusOK || !bytes.Contains(raw, []byte(tc.want)) || bytes.Contains(raw, []byte(`"isError":true`)) {
			t.Fatalf("%s failed: %d %s", tc.name, status, raw)
		}
	}
	body, _ := json.Marshal(map[string]any{"kind": "chatgpt", "scopes": []string{"job.read"}})
	request := httptest.NewRequest(http.MethodPost, "/v1/controllers", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-admin")
	recorder := httptest.NewRecorder()
	s.controllersHandler(recorder, request)
	var readOnly struct {
		Token string `json:"token"`
	}
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &readOnly) != nil || readOnly.Token == "" {
		t.Fatalf("read-only controller issue failed: %d %s", recorder.Code, recorder.Body.String())
	}
	status, raw := controllerMCP(s, readOnly.Token, "manager.submit", map[string]any{"task": "read only"})
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"code":"FORBIDDEN"`)) {
		t.Fatalf("default controller gained submit scope: %d %s", status, raw)
	}
}

func TestConfidenceMCPDecisionIsBoundedOwnedAndAudited(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"kind": "chatgpt", "scopes": []string{"job.read", "confidence.evaluate"}})
	r := httptest.NewRequest("POST", "/v1/controllers", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer test-admin")
	w := httptest.NewRecorder()
	s.controllersHandler(w, r)
	var issued struct{ ID, Token string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Token == "" {
		t.Fatalf("issue confidence controller: %d %s", w.Code, w.Body.String())
	}
	token := issued.Token
	evidence := []any{
		map[string]any{"name": "deterministic-validation", "score": 0.6, "weight": 0.5, "method": "tests/v1"},
		map[string]any{"name": "runtime-model", "score": 0.7, "weight": 0.3, "method": "benchmark/v1"},
		map[string]any{"name": "task-risk", "score": 0.8, "weight": 0.2, "method": "policy/v1"},
	}
	status, raw := controllerMCP(s, token, "confidence.evaluate", map[string]any{
		"decision_id": "decision-1", "task_id": "task-1", "evidence": evidence,
		"escalation_target": "controller", "requested_scopes": []any{"read-repo"},
	})
	if status != 200 || !bytes.Contains(raw, []byte(`"outcome":"escalate"`)) || !bytes.Contains(raw, []byte(`"digest"`)) {
		t.Fatalf("confidence decision failed: %d %s", status, raw)
	}
	if !bytes.Contains(raw, []byte(`"controller"`)) {
		t.Fatal("decision did not preserve authorized escalation target")
	}
	if !bytes.Contains(raw, []byte(`"owner_id":"`+issued.ID+`"`)) {
		t.Fatalf("decision was not bound to authenticated controller: %s", raw)
	}

	status, raw = controllerMCP(s, token, "confidence.evaluate", map[string]any{
		"decision_id": "decision-2", "task_id": "task-2", "evidence": evidence,
		"escalation_target": "controller", "requested_scopes": []any{"job.control"},
	})
	if status != 200 || !bytes.Contains(raw, []byte("requested scope is not authorized")) {
		t.Fatalf("unauthorized escalation scope was accepted: %d %s", status, raw)
	}

	auditBytes, err := os.ReadFile(s.state + "/audit.jsonl")
	if err != nil || !bytes.Contains(auditBytes, []byte(`"action":"confidence.decision"`)) || !bytes.Contains(auditBytes, []byte(`"controller":"`)) {
		t.Fatalf("confidence decision was not audited: %v %s", err, auditBytes)
	}
}

func TestConfidenceScopeIsOptInAndCannotExpandCallerScope(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, defaultToken := issueTestController(t, s, "chatgpt")
	status, raw := controllerMCP(s, defaultToken, "confidence.evaluate", map[string]any{"decision_id": "d", "task_id": "t", "evidence": []any{}})
	if status != 200 || !bytes.Contains(raw, []byte("confidence.evaluate scope required")) {
		t.Fatalf("default controller silently gained confidence scope: %d %s", status, raw)
	}
	body, _ := json.Marshal(map[string]any{"kind": "gemini", "scopes": []string{"confidence.evaluate"}})
	r := httptest.NewRequest("POST", "/v1/controllers", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer test-admin")
	w := httptest.NewRecorder()
	s.controllersHandler(w, r)
	var issued struct{ Token string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil {
		t.Fatalf("issue restricted controller: %d %s", w.Code, w.Body.String())
	}
	evidence := []any{
		map[string]any{"name": "deterministic-validation", "score": 0.6, "weight": 0.5, "method": "tests/v1"},
		map[string]any{"name": "runtime-model", "score": 0.7, "weight": 0.3, "method": "benchmark/v1"},
		map[string]any{"name": "task-risk", "score": 0.8, "weight": 0.2, "method": "policy/v1"},
	}
	_, raw = controllerMCP(s, issued.Token, "confidence.evaluate", map[string]any{
		"decision_id": "d2", "task_id": "t2", "evidence": evidence,
		"escalation_target": "controller", "requested_scopes": []any{"job.submit"},
	})
	if !bytes.Contains(raw, []byte("requested scope is not authorized")) {
		t.Fatalf("confidence-only controller expanded to job.submit: %s", raw)
	}
	_, raw = controllerMCP(s, issued.Token, "confidence.evaluate", map[string]any{
		"decision_id": "d3", "task_id": "t3", "evidence": evidence, "unknown": true,
		"escalation_target": "controller", "requested_scopes": []any{"read-repo"},
	})
	if !bytes.Contains(raw, []byte("invalid confidence arguments")) {
		t.Fatalf("unknown confidence field was ignored: %s", raw)
	}
}

func TestConfidenceMCPRequiresDedicatedScope(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"kind": "gemini", "scopes": []string{"job.read"}})
	r := httptest.NewRequest("POST", "/v1/controllers", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer test-admin")
	w := httptest.NewRecorder()
	s.controllersHandler(w, r)
	var issued struct{ Token string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil {
		t.Fatalf("issue restricted controller: %d %s", w.Code, w.Body.String())
	}
	status, raw := controllerMCP(s, issued.Token, "confidence.evaluate", map[string]any{
		"decision_id": "decision-3", "task_id": "task-3", "evidence": []any{},
	})
	if status != 200 || !bytes.Contains(raw, []byte("confidence.evaluate scope required")) {
		t.Fatalf("restricted controller was allowed: %d %s", status, raw)
	}
}

func issueTestController(t *testing.T, s *Server, kind string, scopes ...string) (string, string) {
	t.Helper()
	request := map[string]any{"kind": kind}
	if len(scopes) > 0 {
		request["scopes"] = scopes
	}
	body, _ := json.Marshal(request)
	r := httptest.NewRequest("POST", "/v1/controllers", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer test-admin")
	w := httptest.NewRecorder()
	s.controllersHandler(w, r)
	if w.Code != 200 {
		t.Fatalf("issue %s: %d %s", kind, w.Code, w.Body.String())
	}
	var out struct{ ID, Token string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.ID == "" || out.Token == "" {
		t.Fatal(w.Body.String())
	}
	return out.ID, out.Token
}

func TestControllerIdentityOwnershipAndRevocation(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	chatID, chatToken := issueTestController(t, s, "chatgpt")
	_, geminiToken := issueTestController(t, s, "gemini")
	s.devices["d"] = &DeviceRecord{Device: protocol.Device{ID: "d"}, Secret: "secret"}
	status, raw := controllerMCP(s, chatToken, "agent.exec", map[string]any{"device_id": "d", "command": "printf", "controller": "gemini"})
	if status != 200 {
		t.Fatalf("submit: %d %s", status, raw)
	}
	var response struct {
		Result struct {
			Owner string `json:"owner"`
		} `json:"result"`
	}
	json.Unmarshal(raw, &response)
	if response.Result.Owner != chatID {
		t.Fatalf("caller spoof changed owner: %q", response.Result.Owner)
	}
	var job map[string]any
	json.Unmarshal(raw, &job)
	jobID, _ := job["result"].(map[string]any)["id"].(string)
	status, cross := controllerMCP(s, geminiToken, "agent.job", map[string]any{"job_id": jobID})
	if status != 200 || !bytes.Contains(cross, []byte("job belongs to another controller")) {
		t.Fatalf("cross-controller access unexpectedly allowed: %d %s", status, cross)
	}
	_ = chatID
	// Revoke the actual ChatGPT credential; the old token must stop working.
	var id string
	for k, c := range s.controllers {
		if c.Kind == "chatgpt" {
			id = k
		}
	}
	r := httptest.NewRequest("DELETE", "/v1/controllers/"+id, nil)
	r.Header.Set("Authorization", "Bearer test-admin")
	w := httptest.NewRecorder()
	s.controllersHandler(w, r)
	if w.Code != 200 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if status, _ := controllerMCP(s, chatToken, "health", nil); status != 401 {
		t.Fatalf("revoked credential status %d", status)
	}
}

func TestDeviceListingRequiresReadAuthorization(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.devices["d"] = &DeviceRecord{Device: protocol.Device{ID: "d", Name: "private-device"}, Secret: "secret"}

	request := httptest.NewRequest("GET", "/v1/devices", nil)
	response := httptest.NewRecorder()
	s.devicesHandler(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated listing status %d", response.Code)
	}

	_, token := issueTestController(t, s, "chatgpt")
	request = httptest.NewRequest("GET", "/v1/devices", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	s.devicesHandler(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte("private-device")) {
		t.Fatalf("authorized listing failed: %d %s", response.Code, response.Body.String())
	}
}

func TestPerDeviceDispatchContention(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.devices["d"] = &DeviceRecord{Device: protocol.Device{ID: "d"}, Secret: "secret"}
	j1, err := s.enqueue("d", "agent.exec", map[string]any{"command": "one"}, "chatgpt")
	if err != nil {
		t.Fatal(err)
	}
	j2, err := s.enqueue("d", "agent.exec", map[string]any{"command": "two"}, "chatgpt")
	if err != nil {
		t.Fatal(err)
	}
	poll := func(n string) []byte {
		q := protocol.Request{Version: protocol.Version, ID: n, DeviceID: "d", Timestamp: time.Now().Unix(), Nonce: n, Method: "agent.poll", Params: map[string]any{}}
		q.Signature = security.Sign("secret", q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(q.Params))
		b, _ := json.Marshal(q)
		w := httptest.NewRecorder()
		s.agentPoll(w, httptest.NewRequest("POST", "/v1/agent/poll", bytes.NewReader(b)))
		return w.Body.Bytes()
	}
	if !bytes.Contains(poll("p1"), []byte(j1.ID)) {
		t.Fatal("first job was not dispatched")
	}
	if bytes.Contains(poll("p2"), []byte(j2.ID)) {
		t.Fatal("second conflicting job dispatched concurrently")
	}
	result := protocol.CommandResult{JobID: j1.ID, Result: map[string]any{"stdout": "done"}}
	q := protocol.Request{Version: protocol.Version, ID: "result", DeviceID: "d", Timestamp: time.Now().Unix(), Nonce: "result", Method: "agent.result", Params: result}
	q.Signature = security.Sign("secret", q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(q.Params))
	b, _ := json.Marshal(q)
	w := httptest.NewRecorder()
	s.agentResult(w, httptest.NewRequest("POST", "/v1/agent/result", bytes.NewReader(b)))
	if w.Code != 200 || !bytes.Contains(poll("p3"), []byte(j2.ID)) {
		t.Fatal("queued job did not resume after result")
	}
	// A retry after the response was lost must not release the second active job.
	q.ID, q.Nonce = "retry", "retry"
	q.Signature = security.Sign("secret", q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(q.Params))
	b, _ = json.Marshal(q)
	s.agentResult(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/agent/result", bytes.NewReader(b)))
	if !s.active["d"] {
		t.Fatal("duplicate result released another running job")
	}
	s.devices["other"] = &DeviceRecord{Device: protocol.Device{ID: "other"}, Secret: "other-secret"}
	q.DeviceID, q.ID, q.Nonce = "other", "foreign", "foreign"
	q.Params = protocol.CommandResult{JobID: j2.ID}
	q.Signature = security.Sign("other-secret", q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(q.Params))
	b, _ = json.Marshal(q)
	w = httptest.NewRecorder()
	s.agentResult(w, httptest.NewRequest("POST", "/v1/agent/result", bytes.NewReader(b)))
	if w.Code != 404 || j2.State != "running" {
		t.Fatal("foreign device overwrote job")
	}

}

func TestCodexJobAuthorizationLoggingAndPersistence(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	dir := t.TempDir()
	fake := dir + "/fake-codex"
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n[ \"$*\" = '--ask-for-approval never exec --sandbox read-only --skip-git-repo-check -' ] || exit 51\n[ \"$(cat)\" = 'inspect the repository' ] || exit 52\nprintf 'codex-output\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AI_RELAY_CODEX_BIN", fake)
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, ownerToken := issueTestController(t, s, "chatgpt")
	_, otherToken := issueTestController(t, s, "gemini")
	status, raw := controllerMCP(s, ownerToken, "codex.job.submit", map[string]any{"prompt": "inspect the repository", "workdir": dir})
	if status != 200 {
		t.Fatalf("submit: %d %s", status, raw)
	}
	var envelope struct {
		Result CodexJobRecord `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Result.ID == "" {
		t.Fatalf("bad submit: %s", raw)
	}
	id := envelope.Result.ID
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, raw = controllerMCP(s, ownerToken, "codex.job.status", map[string]any{"job_id": id})
		var got struct {
			Result CodexJobRecord `json:"result"`
		}
		_ = json.Unmarshal(raw, &got)
		if got.Result.Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, raw = controllerMCP(s, ownerToken, "codex.job.log", map[string]any{"job_id": id, "tail_bytes": 1024})
	if !bytes.Contains(raw, []byte("codex-output")) {
		t.Fatalf("missing output: %s", raw)
	}
	if _, raw = controllerMCP(s, otherToken, "codex.job.status", map[string]any{"job_id": id}); !bytes.Contains(raw, []byte("another controller")) {
		t.Fatalf("cross-owner read allowed: %s", raw)
	}
	s2, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.codexJobs[id] == nil || s2.codexJobs[id].Status != "completed" {
		t.Fatalf("job was not durable: %#v", s2.codexJobs[id])
	}
	if s2.codexJobs[id].LogPath == "" {
		t.Fatal("durable log path missing internally")
	}
	st, err := os.Stat(s2.codexJobs[id].LogPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("log permissions: %v", err)
	}
}

func TestCodexJobCancellation(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	dir := t.TempDir()
	fake := dir + "/fake-codex"
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nsleep 10\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AI_RELAY_CODEX_BIN", fake)
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, token := issueTestController(t, s, "chatgpt")
	_, raw := controllerMCP(s, token, "codex.job.submit", map[string]any{"prompt": "long task", "workdir": dir})
	var envelope struct {
		Result CodexJobRecord `json:"result"`
	}
	_ = json.Unmarshal(raw, &envelope)
	id := envelope.Result.ID
	if id == "" {
		t.Fatal(raw)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, raw = controllerMCP(s, token, "codex.job.status", map[string]any{"job_id": id})
		if bytes.Contains(raw, []byte(`"status":"running"`)) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	status, raw := controllerMCP(s, token, "codex.job.cancel", map[string]any{"job_id": id})
	if status != 200 {
		t.Fatalf("cancel: %d %s", status, raw)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, raw = controllerMCP(s, token, "codex.job.status", map[string]any{"job_id": id})
		if bytes.Contains(raw, []byte(`"status":"canceled"`)) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job did not cancel: %s", raw)
}

func TestControlsDispatchWhileDeviceBusy(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.devices["d"] = &DeviceRecord{Device: protocol.Device{ID: "d"}, Secret: "secret"}
	s.active["d"] = true
	queued, err := s.enqueue("d", "agent.exec", map[string]any{"command": "later"})
	if err != nil {
		t.Fatal(err)
	}
	control, err := s.enqueue("d", "agent.cancel", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	q := protocol.Request{Version: protocol.Version, ID: "poll", DeviceID: "d", Timestamp: time.Now().Unix(), Nonce: "poll", Method: "agent.poll", Params: map[string]any{}}
	q.Signature = security.Sign("secret", q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(q.Params))
	raw, _ := json.Marshal(q)
	w := httptest.NewRecorder()
	s.agentPoll(w, httptest.NewRequest("POST", "/v1/agent/poll", bytes.NewReader(raw)))
	if !bytes.Contains(w.Body.Bytes(), []byte(control.ID)) {
		t.Fatalf("cancel blocked: %s", w.Body.Bytes())
	}
	if len(s.pending["d"]) != 1 || s.pending["d"][0] != queued.ID || !s.active["d"] {
		t.Fatal("control changed execution queue")
	}
}

func TestCodexSandboxConfiguration(t *testing.T) {
	for _, test := range []struct {
		value, want string
		invalid     bool
	}{
		{"", "read-only", false}, {"read-only", "read-only", false}, {"workspace-write", "workspace-write", false}, {"danger-full-access", "", true}, {"invalid", "", true},
	} {
		t.Run(test.value, func(t *testing.T) {
			t.Setenv("AI_RELAY_CODEX_SANDBOX", test.value)
			got, err := codexSandbox()
			if (err != nil) != test.invalid || got != test.want {
				t.Fatalf("sandbox=%q err=%v", got, err)
			}
		})
	}
}

func TestIdlePollDoesNotRewriteState(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.devices["d"] = &DeviceRecord{Device: protocol.Device{ID: "d"}, Secret: "secret"}
	if err := s.saveStateLocked(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.statePath())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		nonce := fmt.Sprint(i)
		q := protocol.Request{Version: protocol.Version, ID: nonce, DeviceID: "d", Timestamp: time.Now().Unix(), Nonce: nonce, Method: "agent.poll", Params: map[string]any{}}
		q.Signature = security.Sign("secret", q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(q.Params))
		b, _ := json.Marshal(q)
		w := httptest.NewRecorder()
		s.agentPoll(w, httptest.NewRequest("POST", "/v1/agent/poll", bytes.NewReader(b)))
		if w.Code != 200 {
			t.Fatalf("idle poll: %d", w.Code)
		}
	}
	after, err := os.ReadFile(s.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("idle polls rewrote encrypted state")
	}
	if !s.devices["d"].Online || s.devices["d"].LastSeen == 0 {
		t.Fatal("idle poll did not update memory presence")
	}
}

func TestRestartRestoresQueuedAndRunningDispatch(t *testing.T) {
	t.Setenv("AI_RELAY_MCP_ADMIN_TOKEN", "test-admin")
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.devices["d"] = &DeviceRecord{Device: protocol.Device{ID: "d"}, Secret: "secret"}
	s.jobs["running"] = &JobRecord{ID: "running", DeviceID: "d", Method: "agent.exec", State: "running", Created: 1}
	s.jobs["b"] = &JobRecord{ID: "b", DeviceID: "d", Method: "agent.exec", State: "queued", Created: 2}
	s.jobs["a"] = &JobRecord{ID: "a", DeviceID: "d", Method: "agent.exec", State: "queued", Created: 2}
	s.jobs["completed"] = &JobRecord{ID: "completed", DeviceID: "d", State: "completed", Created: 0, Stdout: "historical"}
	if err := s.saveStateLocked(); err != nil {
		t.Fatal(err)
	}
	restored, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.active["d"] || len(restored.pending["d"]) != 2 || restored.pending["d"][0] != "a" || restored.pending["d"][1] != "b" {
		t.Fatal("restart failed to restore ordered queue and active command")
	}
	send := func(method, nonce string, params any) *httptest.ResponseRecorder {
		q := protocol.Request{Version: protocol.Version, ID: nonce, DeviceID: "d", Timestamp: time.Now().Unix(), Nonce: nonce, Method: method, Params: params}
		q.Signature = security.Sign("secret", q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(params))
		raw, _ := json.Marshal(q)
		w := httptest.NewRecorder()
		if method == "agent.poll" {
			restored.agentPoll(w, httptest.NewRequest("POST", "/v1/agent/poll", bytes.NewReader(raw)))
		} else {
			restored.agentResult(w, httptest.NewRequest("POST", "/v1/agent/result", bytes.NewReader(raw)))
		}
		return w
	}
	if w := send("agent.poll", "busy", map[string]any{}); !bytes.Contains(w.Body.Bytes(), []byte(`"command":null`)) {
		t.Fatal("restart duplicated running command")
	}
	if w := send("agent.result", "finish", protocol.CommandResult{JobID: "running", Result: map[string]any{"stdout": "done"}}); w.Code != 200 {
		t.Fatal("existing agent result rejected after restart")
	}
	if w := send("agent.poll", "dispatch", map[string]any{}); !bytes.Contains(w.Body.Bytes(), []byte(`"job_id":"a"`)) {
		t.Fatalf("restored queue did not dispatch: %s", w.Body.Bytes())
	}
	if restored.jobs["completed"].Stdout != "historical" {
		t.Fatal("history changed")
	}
}
