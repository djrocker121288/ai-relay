package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/ai-relay/ai-relay/internal/audit"
	"github.com/ai-relay/ai-relay/internal/protocol"
	"github.com/ai-relay/ai-relay/internal/security"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var managerBaseURL = "http://127.0.0.1:8810"

type DeviceRecord struct {
	protocol.Device
	Secret  string `json:"-"`
	Revoked bool   `json:"revoked"`
}
type Server struct {
	mu          sync.Mutex
	devices     map[string]*DeviceRecord
	enroll      map[string]time.Time
	state       string
	audit       *audit.Log
	mcpToken    string
	adminToken  string
	nonces      map[string]time.Time
	nonceSweep  time.Time
	jobs        map[string]*JobRecord
	pending     map[string][]string
	stateMu     sync.Mutex
	stateKey    []byte
	active      map[string]bool
	controllers map[string]*ControllerRecord
	codexJobs   map[string]*CodexJobRecord
	codex       *codexManager
}

type CodexJobRecord struct {
	ID       string `json:"id"`
	Owner    string `json:"owner"`
	Prompt   string `json:"prompt"`
	Workdir  string `json:"workdir,omitempty"`
	Status   string `json:"status"`
	LogPath  string `json:"log_path"`
	PID      int    `json:"pid,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
	Created  int64  `json:"created"`
	Updated  int64  `json:"updated"`
}
type JobRecord struct {
	ID              string   `json:"id"`
	DeviceID        string   `json:"device_id"`
	Method          string   `json:"method,omitempty"`
	Params          any      `json:"params,omitempty"`
	Status          string   `json:"status,omitempty"`
	Result          any      `json:"result,omitempty"`
	Error           string   `json:"error,omitempty"`
	Command         string   `json:"command"`
	Args            []string `json:"args,omitempty"`
	State           string   `json:"state"`
	Stdout          string   `json:"stdout"`
	Stderr          string   `json:"stderr"`
	StdoutTruncated bool     `json:"stdout_truncated"`
	StderrTruncated bool     `json:"stderr_truncated"`
	Exit            *int     `json:"exit,omitempty"`
	Created         int64    `json:"created"`
	Updated         int64    `json:"updated"`
	Owner           string   `json:"owner"`
	Target          string   `json:"target"`
}

func New(state string) (*Server, error) {
	if e := os.MkdirAll(state, 0700); e != nil {
		return nil, e
	}
	a, e := audit.Open(filepath.Join(state, "audit.jsonl"))
	if e != nil {
		return nil, e
	}
	key, e := ensureStateKey(state)
	if e != nil {
		return nil, e
	}
	s := &Server{devices: map[string]*DeviceRecord{}, enroll: map[string]time.Time{}, state: state, audit: a, mcpToken: tokenFromEnvCompat("AI_RELAY_MCP_TOKEN", "AI_RELAY_MCP_TOKEN_FILE", "RLI_MCP_TOKEN", "RLI_MCP_TOKEN_FILE"), adminToken: tokenFromEnvCompat("AI_RELAY_MCP_ADMIN_TOKEN", "AI_RELAY_MCP_ADMIN_TOKEN_FILE", "RLI_MCP_ADMIN_TOKEN", "RLI_MCP_ADMIN_TOKEN_FILE"), nonces: map[string]time.Time{}, jobs: map[string]*JobRecord{}, pending: map[string][]string{}, active: map[string]bool{}, controllers: map[string]*ControllerRecord{}, codexJobs: map[string]*CodexJobRecord{}, stateKey: key}
	if e := s.loadState(); e != nil {
		return nil, e
	}
	s.codex = newCodexManager(s)
	return s, nil
}
func tokenFromEnvCompat(value, file, legacyValue, legacyFile string) string {
	if v := tokenFromEnv(value, file); v != "" {
		return v
	}
	return tokenFromEnv(legacyValue, legacyFile)
}
func tokenFromEnv(value, file string) string {
	if v := strings.TrimSpace(os.Getenv(value)); v != "" {
		return v
	}
	if path := os.Getenv(file); path != "" {
		v, err := security.ReadSecretFile(path)
		if err != nil {
			panic(err)
		}
		return v
	}
	return ""
}

func (s *Server) Routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthz", s.health)
	m.HandleFunc("/v1/enroll", s.enrollHandler)
	m.HandleFunc("/v1/devices", s.devicesHandler)
	m.HandleFunc("/v1/devices/", s.devicesHandler)
	m.HandleFunc("/v1/controllers", s.controllersHandler)
	m.HandleFunc("/v1/controllers/", s.controllersHandler)
	m.HandleFunc("/v1/request", s.requestHandler)
	m.HandleFunc("/v1/agent/poll", s.agentPoll)
	m.HandleFunc("/v1/agent/result", s.agentResult)
	m.HandleFunc("/v1/jobs/", s.jobHandler)
	m.HandleFunc("/mcp", s.mcp)
	return m
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	devices := len(s.devices)
	s.mu.Unlock()
	write(w, map[string]any{"ok": true, "version": protocol.Version, "devices": devices})
}
func (s *Server) enrollHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var x struct {
			Name     string `json:"name"`
			Platform string `json:"platform"`
			Arch     string `json:"arch"`
			Token    string `json:"token"`
		}
		decodeRequest(r, &x)
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.enroll[x.Token]; !ok || time.Now().After(s.enroll[x.Token]) {
			http.Error(w, "invalid enrollment token", 401)
			return
		}
		id, _ := security.Token(12)
		sec, _ := security.Secret()
		d := &DeviceRecord{Device: protocol.Device{ID: id, Name: x.Name, Platform: x.Platform, Arch: x.Arch, Online: true, LastSeen: time.Now().Unix()}, Secret: sec}
		s.devices[id] = d
		delete(s.enroll, x.Token)
		if err := s.saveStateLocked(); err != nil {
			delete(s.devices, id)
			http.Error(w, "enrollment persistence failed", http.StatusInternalServerError)
			return
		}
		write(w, map[string]any{"version": protocol.Version, "device_id": id, "secret": sec})
		return
	}
	if r.Method == "PUT" {
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", 401)
			return
		}
		t, _ := security.Token(24)
		s.mu.Lock()
		s.pruneEnrollLocked(time.Now())
		s.enroll[t] = time.Now().Add(15 * time.Minute)
		s.mu.Unlock()
		write(w, map[string]any{"token": t, "expires_in": 900})
		return
	}
	http.Error(w, "method", 405)
}
func (s *Server) devicesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		c := s.controllerFromRequest(r)
		if c == nil || !hasScope(c, scopeRead) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		var x []protocol.Device
		for _, d := range s.devices {
			x = append(x, d.Device)
		}
		write(w, x)
		return
	}
	if r.Method == "DELETE" {
		if !s.isAdmin(r) {
			http.Error(w, "unauthorized", 401)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		id := strings.TrimPrefix(r.URL.Path, "/v1/devices/")
		if d := s.devices[id]; d != nil {
			d.Revoked = true
			d.Online = false
			_ = s.saveStateLocked()
			write(w, map[string]any{"revoked": id})
			return
		}
	}
	http.Error(w, "method", 405)
}
func (s *Server) requestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	b, err := readRequestBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	var q protocol.Request
	if json.Unmarshal(b, &q) != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if len(q.Nonce) > 256 || len(q.ID) > 256 {
		http.Error(w, "unauthorized", 401)
		return
	}
	s.mu.Lock()
	d := s.devices[q.DeviceID]
	s.mu.Unlock()
	if d == nil || d.Revoked || !security.Verify(d.Secret, q.Signature, q.Version, q.ID, q.DeviceID, q.Timestamp, q.Nonce, q.Method, paramsBytes(q.Params)) {
		http.Error(w, "unauthorized", 401)
		return
	}
	s.mu.Lock()
	accepted := s.acceptNonceLocked(q.DeviceID, q.Nonce, time.Now())
	s.mu.Unlock()
	if !accepted {
		http.Error(w, "unauthorized", 401)
		return
	}
	write(w, map[string]any{"accepted": true, "method": q.Method})
}
func (s *Server) isAdmin(r *http.Request) bool {
	if s == nil || r == nil || s.adminToken == "" {
		return false
	}
	values := headerValuesCaseInsensitive(r.Header, "Authorization")
	if len(values) != 1 || len(values[0]) > maxControllerAuthorizationBytes {
		return false
	}
	token, ok := parseBearerAuthorization(values[0])
	return ok && security.ConstantTimeEqual(s.adminToken, token)
}
func tools() any {
	str := func() map[string]any { return map[string]any{"type": "string"} }
	obj := func(props map[string]any, required ...string) map[string]any {
		if props == nil {
			props = map[string]any{}
		}
		if required == nil {
			required = []string{}
		}
		return map[string]any{"type": "object", "properties": props, "required": required}
	}
	return map[string]any{"tools": []any{
		map[string]any{"name": "health", "description": "Gateway and device health", "inputSchema": obj(nil)},
		map[string]any{"name": "confidence.evaluate", "description": "Evaluate bounded evidence and return an auditable auto, escalation, or reject decision; never executes work or grants privileges", "inputSchema": obj(map[string]any{
			"decision_id": map[string]any{"type": "string"}, "task_id": map[string]any{"type": "string"},
			"evidence":          map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
			"escalation_target": map[string]any{"type": "string"}, "requested_scopes": map[string]any{"type": "array", "items": str()},
		}, "decision_id", "task_id", "evidence")},
		map[string]any{"name": "devices.list", "description": "List enrolled devices", "inputSchema": obj(nil)},
		map[string]any{"name": "devices.enroll_token", "description": "Create a short-lived enrollment token", "inputSchema": obj(nil)},
		map[string]any{"name": "devices.revoke", "description": "Revoke a device credential", "inputSchema": obj(map[string]any{"device_id": str()}, "device_id")},
		map[string]any{"name": "agent.exec", "description": "Queue a command on a connected agent", "inputSchema": obj(map[string]any{"device_id": str(), "command": str(), "args": map[string]any{"type": "array", "items": str()}, "cwd": str(), "env": map[string]any{"type": "object", "additionalProperties": str()}, "privileged": map[string]any{"type": "boolean", "description": "Unsupported by the portable asynchronous agent; requests are rejected"}}, "device_id", "command")},
		map[string]any{"name": "agent.job", "description": "Read durable job status and stdout/stderr", "inputSchema": obj(map[string]any{"job_id": str()}, "job_id")},
		map[string]any{"name": "agent.cancel", "description": "Cancel a running job", "inputSchema": obj(map[string]any{"job_id": str()}, "job_id")},
		map[string]any{"name": "agent.stdin", "description": "Write stdin to a running job", "inputSchema": obj(map[string]any{"job_id": str(), "data": str()}, "job_id", "data")},
		map[string]any{"name": "manager.submit", "description": "Submit a durable job to the local Server 3 Manager", "inputSchema": obj(map[string]any{
			"task": str(), "agent": str(), "model": str(), "policy": str(), "request_key": str(), "source": str(),
		}, "task")},
		map[string]any{"name": "manager.status", "description": "Read a durable Manager job status", "inputSchema": obj(map[string]any{"job_id": str()}, "job_id")},
		map[string]any{"name": "manager.result", "description": "Read a completed durable Manager job result", "inputSchema": obj(map[string]any{"job_id": str()}, "job_id")},
		map[string]any{"name": "manager.jobs", "description": "List durable Manager jobs", "inputSchema": obj(nil)},
		map[string]any{"name": "manager.cancel", "description": "Cancel a durable Manager job", "inputSchema": obj(map[string]any{"job_id": str()}, "job_id")},
		map[string]any{"name": "codex.job.submit", "description": "Start a durable local Codex job; read-only by default, workspace writes require AI_RELAY_CODEX_SANDBOX=workspace-write on the gateway", "inputSchema": obj(map[string]any{"prompt": str(), "workdir": str()}, "prompt")},
		map[string]any{"name": "codex.job.status", "description": "Read durable Codex job status", "inputSchema": obj(map[string]any{"job_id": str()}, "job_id")},
		map[string]any{"name": "codex.job.log", "description": "Read a bounded Codex job log", "inputSchema": obj(map[string]any{"job_id": str(), "tail_bytes": map[string]any{"type": "integer"}}, "job_id")},
		map[string]any{"name": "codex.job.cancel", "description": "Cancel a locally running Codex job", "inputSchema": obj(map[string]any{"job_id": str()}, "job_id")},
	}}
}

func managerForward(method, path string, body map[string]any) (map[string]any, *protocol.Error) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, &protocol.Error{Code: "INVALID_ARGUMENT", Message: "manager request encoding failed"}
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, strings.TrimRight(managerBaseURL, "/")+path, payload)
	if err != nil {
		return nil, &protocol.Error{Code: "UNAVAILABLE", Message: "manager request failed"}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, &protocol.Error{Code: "UNAVAILABLE", Message: "manager request failed"}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, &protocol.Error{Code: "UNAVAILABLE", Message: "manager response unreadable"}
	}
	var value map[string]any
	if json.Unmarshal(data, &value) != nil || value == nil {
		return nil, &protocol.Error{Code: "UNAVAILABLE", Message: "manager response invalid"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &protocol.Error{Code: "MANAGER_ERROR", Message: "manager request rejected"}
	}
	return value, nil
}

func (s *Server) call(b []byte, r *http.Request, c *ControllerRecord) (any, *protocol.Error) {
	var p map[string]any
	json.Unmarshal(b, &p)
	name, _ := p["name"].(string)
	switch name {
	case "health":
		return map[string]any{"ok": true, "version": protocol.Version}, nil
	case "confidence.evaluate":
		if !hasScope(c, scopeConfidence) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "confidence.evaluate scope required"}
		}
		return s.evaluateConfidence(p, c)
	case "devices.list":
		if !hasScope(c, scopeRead) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.read scope required"}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		var r []protocol.Device
		for _, d := range s.devices {
			r = append(r, d.Device)
		}
		return r, nil
	case "devices.enroll_token":
		if !s.isAdmin(r) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "admin role required"}
		}
		t, _ := security.Token(24)
		s.mu.Lock()
		s.pruneEnrollLocked(time.Now())
		s.enroll[t] = time.Now().Add(15 * time.Minute)
		s.mu.Unlock()
		return map[string]any{"token": t, "expires_in": 900}, nil
	case "devices.revoke":
		if !s.isAdmin(r) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "admin role required"}
		}
		id, _ := p["arguments"].(map[string]any)["device_id"].(string)
		s.mu.Lock()
		if d := s.devices[id]; d != nil {
			d.Revoked = true
			d.Online = false
			if err := s.saveStateLocked(); err != nil {
				s.mu.Unlock()
				return nil, &protocol.Error{Code: "INTERNAL", Message: "device revocation persistence failed"}
			}
		}
		s.mu.Unlock()
		return map[string]any{"revoked": id}, nil
	case "agent.exec":
		if !hasScope(c, scopeSubmit) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.submit scope required"}
		}
		if _, ok := p["arguments"].(map[string]any); !ok {
			return nil, &protocol.Error{Code: "INVALID_ARGUMENT", Message: "arguments"}
		}
		return s.exec(p, c)
	case "manager.submit":
		if !hasScope(c, scopeSubmit) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.submit scope required"}
		}
		a, _ := p["arguments"].(map[string]any)
		return managerForward(http.MethodPost, "/gateway/submit", a)
	case "manager.status", "manager.result":
		if !hasScope(c, scopeRead) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.read scope required"}
		}
		a, _ := p["arguments"].(map[string]any)
		id, _ := a["job_id"].(string)
		if id == "" || strings.ContainsAny(id, "/?#") {
			return nil, &protocol.Error{Code: "INVALID_ARGUMENT", Message: "job_id required"}
		}
		return managerForward(http.MethodGet, "/gateway/jobs/"+id, nil)
	case "manager.jobs":
		if !hasScope(c, scopeRead) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.read scope required"}
		}
		return managerForward(http.MethodGet, "/gateway/jobs", nil)
	case "manager.cancel":
		if !hasScope(c, scopeControl) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.control scope required"}
		}
		a, _ := p["arguments"].(map[string]any)
		id, _ := a["job_id"].(string)
		if id == "" {
			return nil, &protocol.Error{Code: "INVALID_ARGUMENT", Message: "job_id required"}
		}
		return managerForward(http.MethodPost, "/gateway/cancel", map[string]any{"job_id": id})
	case "agent.cancel", "agent.stdin":
		if !hasScope(c, scopeControl) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.control scope required"}
		}
		a, _ := p["arguments"].(map[string]any)
		id, _ := a["job_id"].(string)
		s.mu.Lock()
		j := s.jobs[id]
		if j == nil {
			s.mu.Unlock()
			return nil, &protocol.Error{Code: "NOT_FOUND", Message: "job"}
		}
		if j.Owner != c.ID {
			s.mu.Unlock()
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job belongs to another controller"}
		}
		j.Method = name
		j.Params = a
		j.Status = "control_queued"
		s.pending[j.DeviceID] = append(s.pending[j.DeviceID], id)
		_ = s.saveStateLocked()
		s.mu.Unlock()
		return map[string]any{"job_id": id, "status": "control_queued"}, nil
	case "agent.job":
		if !hasScope(c, scopeRead) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.read scope required"}
		}
		a, _ := p["arguments"].(map[string]any)
		id, _ := a["job_id"].(string)
		s.mu.Lock()
		j := copyJob(s.jobs[id])
		s.mu.Unlock()
		if j == nil {
			return nil, &protocol.Error{Code: "NOT_FOUND", Message: "job"}
		}
		if j.Owner != c.ID {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job belongs to another controller"}
		}
		return j, nil
	case "codex.job.submit":
		if !hasScope(c, scopeSubmit) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.submit scope required"}
		}
		a, _ := p["arguments"].(map[string]any)
		prompt, _ := a["prompt"].(string)
		workdir, _ := a["workdir"].(string)
		j, err := s.codex.submit(c.ID, prompt, workdir)
		if err != nil {
			return nil, &protocol.Error{Code: "INVALID_ARGUMENT", Message: err.Error()}
		}
		_ = s.audit.Write(audit.Event{Action: "codex.submit", Detail: map[string]any{"job_id": j.ID, "owner": c.ID}})
		return j, nil
	case "codex.job.status":
		if !hasScope(c, scopeRead) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.read scope required"}
		}
		a, _ := p["arguments"].(map[string]any)
		id, _ := a["job_id"].(string)
		j, err := s.codex.status(c.ID, id)
		if err != nil {
			return nil, &protocol.Error{Code: "NOT_FOUND", Message: err.Error()}
		}
		return j, nil
	case "codex.job.log":
		if !hasScope(c, scopeRead) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.read scope required"}
		}
		a, _ := p["arguments"].(map[string]any)
		id, _ := a["job_id"].(string)
		tail := 65536
		if n, ok := a["tail_bytes"].(float64); ok && n > 0 && n < 1048576 {
			tail = int(n)
		}
		logText, err := s.codex.log(c.ID, id, tail)
		if err != nil {
			return nil, &protocol.Error{Code: "NOT_FOUND", Message: err.Error()}
		}
		return map[string]any{"job_id": id, "log": logText}, nil
	case "codex.job.cancel":
		if !hasScope(c, scopeControl) {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: "job.control scope required"}
		}
		a, _ := p["arguments"].(map[string]any)
		id, _ := a["job_id"].(string)
		j, err := s.codex.cancel(c.ID, id)
		if err != nil {
			return nil, &protocol.Error{Code: "FORBIDDEN", Message: err.Error()}
		}
		_ = s.audit.Write(audit.Event{Action: "codex.cancel", Detail: map[string]any{"job_id": id, "owner": c.ID}})
		return j, nil
	}
	return nil, &protocol.Error{Code: "UNKNOWN_TOOL", Message: name}
}
func (s *Server) exec(p map[string]any, c *ControllerRecord) (any, *protocol.Error) {
	a, _ := p["arguments"].(map[string]any)
	id, _ := a["device_id"].(string)
	s.mu.Lock()
	d := s.devices[id]
	s.mu.Unlock()
	if d == nil || d.Revoked {
		return nil, &protocol.Error{Code: "NOT_FOUND", Message: "device"}
	}
	j, err := s.enqueue(id, "agent.exec", a, c.ID)
	if err != nil {
		return nil, &protocol.Error{Code: "UNAVAILABLE", Message: err.Error()}
	}
	s.mu.Lock()
	snapshot := copyJob(j)
	s.mu.Unlock()
	_ = s.audit.Write(audit.Event{Device: id, Action: "job.enqueue", Detail: snapshot})
	return snapshot, nil
}
func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func paramsBytes(v any) []byte { b, _ := json.Marshal(v); return b }
func TLSConfig(cert, key string) (*tls.Config, error) {
	c, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	return &tls.Config{Certificates: []tls.Certificate{c}, ClientCAs: pool, MinVersion: tls.VersionTLS13}, nil
}
