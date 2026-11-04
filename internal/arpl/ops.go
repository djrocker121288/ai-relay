package arpl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const DefaultChunkSize = 256 << 10

type OpMessage struct {
	Action     string   `json:"action"`
	Argv       []string `json:"argv,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	TimeoutMS  int64    `json:"timeout_ms,omitempty"`
	Rows       int      `json:"rows,omitempty"`
	Cols       int      `json:"cols,omitempty"`
	Src        string   `json:"src,omitempty"`
	Dest       string   `json:"dest,omitempty"`
	Size       int64    `json:"size,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Offset     int64    `json:"offset,omitempty"`
	Data       string   `json:"data,omitempty"`
	OK         bool     `json:"ok,omitempty"`
	Done       bool     `json:"done,omitempty"`
	Error      string   `json:"error,omitempty"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	ExitCode   int      `json:"exit_code,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
	JobID      string   `json:"job_id,omitempty"`
	JobState   string   `json:"job_state,omitempty"`
	JobLogs    string   `json:"job_logs,omitempty"`
	JobIDs     []string `json:"job_ids,omitempty"`
	Manifest   string   `json:"manifest,omitempty"`
	Delete     bool     `json:"delete,omitempty"`
	Include    []string `json:"include,omitempty"`
	Exclude    []string `json:"exclude,omitempty"`
	BaseSHA256 string   `json:"base_sha256,omitempty"`
	Replace    bool     `json:"replace,omitempty"`
	Mode       uint32   `json:"mode,omitempty"`
	TerminalID string   `json:"terminal_id,omitempty"`
	InputSeq   uint64   `json:"input_seq,omitempty"`
}

type OperationServer struct {
	AllowExec         bool
	FileRoot          string
	MaxFileSize       int64
	MaxOutput         int
	CommandTimeout    time.Duration
	ChunkSize         int
	JobsDir           string
	JobOutputMax      int
	Audit             *AuditLog
	PreserveTerminals bool
	TerminalTTL       time.Duration

	mu         sync.Mutex
	uploads    map[string]*Transfer
	terminals  map[string]*terminalHandle
	jobCancels map[string]context.CancelFunc
}

func (s *OperationServer) defaults() {
	if s.MaxFileSize <= 0 {
		s.MaxFileSize = 8 << 30
	}
	if s.MaxOutput <= 0 {
		s.MaxOutput = 4 << 20
	}
	if s.CommandTimeout <= 0 {
		s.CommandTimeout = 2 * time.Minute
	}
	if s.ChunkSize <= 0 || s.ChunkSize > maxFramePayload/2 {
		s.ChunkSize = DefaultChunkSize
	}
	if s.uploads == nil {
		s.uploads = map[string]*Transfer{}
	}
	if s.terminals == nil {
		s.terminals = map[string]*terminalHandle{}
	}
	if s.jobCancels == nil {
		s.jobCancels = map[string]context.CancelFunc{}
	}
}

func (s *OperationServer) Handle(ctx context.Context, state SessionState, frame Frame, send func(Frame) error) error {
	s.defaults()
	var req OpMessage
	if err := json.Unmarshal(frame.Payload, &req); err != nil || req.Action == "" {
		return s.respond(frame, send, OpMessage{Action: "error", Error: "invalid operation request"})
	}
	if s.Audit != nil {
		_ = s.Audit.Write(AuditEvent{Event: "capability_invoked", PeerID: state.PeerID, Capability: operationCapability(req.Action), Action: req.Action, OK: true})
	}
	switch req.Action {
	case "exec":
		if err := requireOperation(state, CapabilityExec); err != nil {
			return s.respond(frame, send, OpMessage{Action: "exec_result", Error: err.Error(), ExitCode: -1})
		}
		return s.handleExec(ctx, frame, req, send)
	case "terminal_start":
		if err := requireOperation(state, CapabilityTerminal); err != nil {
			return s.respond(frame, send, OpMessage{Action: "terminal_exit", Error: err.Error(), ExitCode: -1})
		}
		return s.handleTerminalStart(ctx, state, frame, req, send)
	case "terminal_attach":
		if err := requireOperation(state, CapabilityTerminal); err != nil {
			return s.respond(frame, send, OpMessage{Action: "terminal_exit", Error: err.Error(), ExitCode: -1})
		}
		return s.handleTerminalAttach(state, frame, req, send)
	case "terminal_input":
		return s.handleTerminalInput(state, frame, req)
	case "terminal_resize":
		return s.handleTerminalResize(state, frame, req)
	case "terminal_close":
		return s.handleTerminalClose(state, frame, req)
	case "upload_begin":
		if err := requireOperation(state, CapabilityFileWrite); err != nil {
			return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: err.Error()})
		}
		return s.handleUploadBegin(state, frame, req, send)
	case "upload_chunk":
		if err := requireOperation(state, CapabilityFileWrite); err != nil {
			return s.respond(frame, send, OpMessage{Action: "upload_ack", Error: err.Error()})
		}
		return s.handleUploadChunk(state, frame, req, send)
	case "upload_finish":
		if err := requireOperation(state, CapabilityFileWrite); err != nil {
			return s.respond(frame, send, OpMessage{Action: "upload_done", Error: err.Error()})
		}
		return s.handleUploadFinish(state, frame, send)
	case "download_begin":
		if err := requireOperation(state, CapabilityFileRead); err != nil {
			return s.respond(frame, send, OpMessage{Action: "download_meta", Error: err.Error()})
		}
		return s.handleDownload(frame, req, send)
	case "job_run", "job_status", "job_logs", "job_cancel", "job_list":
		if err := requireOperation(state, CapabilityJob); err != nil {
			return s.respond(frame, send, OpMessage{Action: "job_result", Error: err.Error()})
		}
		return s.handleJob(ctx, state, frame, req, send)
	case "sync_manifest":
		if err := requireOperation(state, CapabilitySync); err != nil {
			return s.respond(frame, send, OpMessage{Action: "sync_manifest", Error: err.Error()})
		}
		return s.handleSyncManifest(state, frame, req, send)
	case "sync_delete":
		if err := requireOperation(state, CapabilitySync); err != nil {
			return s.respond(frame, send, OpMessage{Action: "sync_delete", Error: err.Error()})
		}
		return s.handleSyncDelete(state, frame, req, send)
	default:
		return s.respond(frame, send, OpMessage{Action: "error", Error: "unknown operation"})
	}
}

func operationCapability(action string) string {
	switch action {
	case "exec", "job_run", "job_status", "job_logs", "job_cancel", "job_list", "terminal_start", "terminal_attach", "terminal_input", "terminal_resize", "terminal_close":
		if strings.HasPrefix(action, "job_") {
			return CapabilityJob
		}
		if strings.HasPrefix(action, "terminal_") {
			return CapabilityTerminal
		}
		return CapabilityExec
	case "upload_begin", "upload_chunk", "upload_finish":
		return CapabilityFileWrite
	case "download_begin":
		return CapabilityFileRead
	case "sync_manifest", "sync_delete":
		return CapabilitySync
	default:
		return ""
	}
}

func requireOperation(state SessionState, capability string) error {
	return authorizeCapabilities(state.Capabilities, capability)
}

func (s *OperationServer) handleSyncManifest(_ SessionState, frame Frame, req OpMessage, send func(Frame) error) error {
	if s.FileRoot == "" {
		return s.respond(frame, send, OpMessage{Action: "sync_manifest", Error: "file operations are disabled"})
	}
	root, err := SecureSyncRoot(s.FileRoot, req.Src)
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "sync_manifest", Error: err.Error()})
	}
	m, err := BuildSyncManifest(root, SyncOptions{Include: req.Include, Exclude: req.Exclude, MaxFileSize: s.MaxFileSize})
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "sync_manifest", Error: err.Error()})
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.respond(frame, send, OpMessage{Action: "sync_manifest", OK: true, Manifest: string(b)})
}

func (s *OperationServer) handleSyncDelete(state SessionState, frame Frame, req OpMessage, send func(Frame) error) error {
	if s.FileRoot == "" {
		return s.respond(frame, send, OpMessage{Action: "sync_delete", Error: "file operations are disabled"})
	}
	if !req.Delete {
		return s.respond(frame, send, OpMessage{Action: "sync_delete", Error: "delete must be explicitly enabled"})
	}
	root, err := SecureSyncRoot(s.FileRoot, req.Src)
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "sync_delete", Error: err.Error()})
	}
	var desired SyncManifest
	if err = json.Unmarshal([]byte(req.Manifest), &desired); err != nil {
		return s.respond(frame, send, OpMessage{Action: "sync_delete", Error: "invalid desired sync manifest"})
	}
	seen := make(map[string]struct{}, len(desired.Entries))
	for _, entry := range desired.Entries {
		if entry.Symlink {
			return s.respond(frame, send, OpMessage{Action: "sync_delete", Error: "symlinks are not accepted by remote sync"})
		}
		if _, err = SecureSyncPath(root, entry.Path); err != nil {
			return s.respond(frame, send, OpMessage{Action: "sync_delete", Error: err.Error()})
		}
		seen[filepath.ToSlash(entry.Path)] = struct{}{}
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil || info.IsDir() || path == root {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to delete through symlink %s", path)
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if !syncMatch(filepath.ToSlash(rel), req.Include, req.Exclude) {
			return nil
		}
		if _, ok := seen[filepath.ToSlash(rel)]; !ok {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "sync_delete", Error: err.Error()})
	}
	if s.Audit != nil {
		_ = s.Audit.Write(AuditEvent{Event: "sync_delete", PeerID: state.PeerID, Action: "sync_delete", OK: true})
	}
	return s.respond(frame, send, OpMessage{Action: "sync_delete", OK: true, Done: true})
}

func (s *OperationServer) respond(in Frame, send func(Frame) error, msg OpMessage) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return send(Frame{Channel: in.Channel, StreamID: in.StreamID, Payload: b})
}

type boundedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.limit <= 0 {
		b.truncated = b.truncated || n > 0
		return n, nil
	}
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return n, nil
}

func validateArgv(argv []string) error {
	if len(argv) == 0 || len(argv) > 256 {
		return errors.New("argv must contain 1..256 arguments")
	}
	total := 0
	for _, a := range argv {
		if strings.ContainsRune(a, 0) {
			return errors.New("argv contains NUL")
		}
		total += len(a)
	}
	if total > 64<<10 {
		return errors.New("argv is too large")
	}
	return nil
}

func (s *OperationServer) handleExec(ctx context.Context, frame Frame, req OpMessage, send func(Frame) error) error {
	if !s.AllowExec {
		return s.respond(frame, send, OpMessage{Action: "exec_result", Error: "remote exec is disabled", ExitCode: -1})
	}
	if err := validateArgv(req.Argv); err != nil {
		return s.respond(frame, send, OpMessage{Action: "exec_result", Error: err.Error(), ExitCode: -1})
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 || timeout > s.CommandTimeout {
		timeout = s.CommandTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, req.Argv[0], req.Argv[1:]...)
	if req.Cwd != "" {
		if strings.ContainsRune(req.Cwd, 0) {
			return s.respond(frame, send, OpMessage{Action: "exec_result", Error: "invalid cwd", ExitCode: -1})
		}
		cmd.Dir = req.Cwd
	}
	var out, er boundedBuffer
	out.limit, er.limit = s.MaxOutput, s.MaxOutput
	cmd.Stdout, cmd.Stderr = &out, &er
	err := cmd.Run()
	code := 0
	errText := ""
	if err != nil {
		code = -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			errText = "command timed out"
		} else {
			errText = err.Error()
		}
	}
	return s.respond(frame, send, OpMessage{
		Action: "exec_result", OK: err == nil, Error: errText, ExitCode: code,
		Stdout: out.buf.String(), Stderr: er.buf.String(), Truncated: out.truncated || er.truncated,
	})
}

func uploadKey(state SessionState, frame Frame) string {
	return state.SessionID + ":" + fmt.Sprint(frame.StreamID)
}

func (s *OperationServer) handleTerminalStart(ctx context.Context, state SessionState, frame Frame, req OpMessage, send func(Frame) error) error {
	if !s.AllowExec {
		return s.respond(frame, send, OpMessage{Action: "terminal_exit", Error: "remote exec is disabled", ExitCode: -1})
	}
	if err := validateArgv(req.Argv); err != nil {
		return s.respond(frame, send, OpMessage{Action: "terminal_exit", Error: err.Error(), ExitCode: -1})
	}
	if req.Cwd != "" && strings.ContainsRune(req.Cwd, 0) {
		return s.respond(frame, send, OpMessage{Action: "terminal_exit", Error: "invalid cwd", ExitCode: -1})
	}
	rows, cols := normalizeTerminalSize(req.Rows, req.Cols)
	terminalID := req.TerminalID
	if terminalID == "" {
		terminalID = fmt.Sprintf("stream-%d", frame.StreamID)
	}
	key := state.SessionID + ":" + terminalID
	legacyKey := uploadKey(state, frame)

	s.mu.Lock()
	if s.terminals[key] != nil {
		s.mu.Unlock()
		return s.respond(frame, send, OpMessage{Action: "terminal_exit", Error: "terminal stream is already active", ExitCode: -1})
	}
	term, err := newTerminalSession(ctx, req.Argv, req.Cwd, rows, cols)
	if err == nil {
		h := &terminalHandle{term: term, terminalID: terminalID, legacyKey: legacyKey, sink: func(m OpMessage) error { return s.respond(frame, send, m) }}
		s.terminals[key] = h
		if legacyKey != key {
			s.terminals[legacyKey] = h
		}
	}
	s.mu.Unlock()
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "terminal_exit", Error: err.Error(), ExitCode: -1})
	}
	if err = s.respond(frame, send, OpMessage{Action: "terminal_ready", OK: true, Rows: int(rows), Cols: int(cols), TerminalID: terminalID}); err != nil {
		s.mu.Lock()
		if s.terminals[key] != nil && s.terminals[key].term == term {
			s.deleteTerminalLocked(s.terminals[key])
		}
		s.mu.Unlock()
		_ = term.Close()
		return err
	}

	go func() {
		code, runErr := term.Run(func(data []byte) error {
			return s.emitTerminal(key, OpMessage{
				Action: "terminal_data",
				Data:   base64.RawStdEncoding.EncodeToString(data),
			})
		})
		errText := ""
		if runErr != nil {
			errText = runErr.Error()
		}
		_ = s.emitTerminal(key, OpMessage{
			Action:   "terminal_exit",
			OK:       runErr == nil,
			Error:    errText,
			ExitCode: code,
			Done:     true,
		})
		s.mu.Lock()
		if s.terminals[key] != nil && s.terminals[key].term == term {
			s.deleteTerminalLocked(s.terminals[key])
		}
		s.mu.Unlock()
	}()
	return nil
}

type terminalHandle struct {
	term       terminalSession
	terminalID string
	legacyKey  string
	mu         sync.Mutex
	sink       func(OpMessage) error
	scrollback []byte
	expires    *time.Timer
	lastInput  uint64
}

func (s *OperationServer) emitTerminal(key string, msg OpMessage) error {
	s.mu.Lock()
	h := s.terminals[key]
	s.mu.Unlock()
	if h == nil {
		return errors.New("terminal session is gone")
	}
	h.mu.Lock()
	sink := h.sink
	if sink == nil && msg.Action == "terminal_data" {
		raw, _ := base64.RawStdEncoding.DecodeString(msg.Data)
		h.scrollback = append(h.scrollback, raw...)
		if len(h.scrollback) > 1<<20 {
			h.scrollback = h.scrollback[len(h.scrollback)-(1<<20):]
		}
		h.mu.Unlock()
		return nil
	}
	h.mu.Unlock()
	if sink == nil {
		return nil
	}
	return sink(msg)
}

func (s *OperationServer) handleTerminalAttach(state SessionState, frame Frame, req OpMessage, send func(Frame) error) error {
	key := uploadKey(state, frame)
	// A reconnect uses the stable logical terminal ID. The stream-key fallback
	// keeps the v0.1 CLI and older clients compatible.
	if req.TerminalID != "" {
		key = state.SessionID + ":" + req.TerminalID
	}
	s.mu.Lock()
	h := s.terminals[key]
	s.mu.Unlock()
	if h == nil {
		return s.respond(frame, send, OpMessage{Action: "terminal_exit", Error: "terminal session not found", ExitCode: -1})
	}
	h.mu.Lock()
	h.sink = func(m OpMessage) error { return s.respond(frame, send, m) }
	replay := append([]byte(nil), h.scrollback...)
	h.scrollback = nil
	if h.expires != nil {
		h.expires.Stop()
		h.expires = nil
	}
	h.mu.Unlock()
	if err := s.respond(frame, send, OpMessage{Action: "terminal_ready", OK: true, TerminalID: h.terminalID}); err != nil {
		return err
	}
	if len(replay) > 0 {
		return s.respond(frame, send, OpMessage{Action: "terminal_data", Data: base64.RawStdEncoding.EncodeToString(replay)})
	}
	return nil
}

func (s *OperationServer) handleTerminalInput(state SessionState, frame Frame, req OpMessage) error {
	key := terminalLookupKey(state, frame, req.TerminalID)
	raw, err := base64.RawStdEncoding.DecodeString(req.Data)
	if err != nil || len(raw) > 64<<10 {
		return errors.New("invalid terminal input")
	}
	s.mu.Lock()
	h := s.terminals[key]
	s.mu.Unlock()
	if h == nil {
		return errors.New("terminal stream is not active")
	}
	h.mu.Lock()
	if req.InputSeq != 0 {
		if req.InputSeq <= h.lastInput {
			h.mu.Unlock()
			return nil
		}
		h.lastInput = req.InputSeq
	}
	h.mu.Unlock()
	_, err = h.term.Write(raw)
	return err
}

func (s *OperationServer) handleTerminalResize(state SessionState, frame Frame, req OpMessage) error {
	rows, cols := normalizeTerminalSize(req.Rows, req.Cols)
	key := terminalLookupKey(state, frame, req.TerminalID)
	s.mu.Lock()
	h := s.terminals[key]
	s.mu.Unlock()
	if h == nil {
		return errors.New("terminal stream is not active")
	}
	return h.term.Resize(rows, cols)
}

func (s *OperationServer) handleTerminalClose(state SessionState, frame Frame, req OpMessage) error {
	key := terminalLookupKey(state, frame, req.TerminalID)
	s.mu.Lock()
	h := s.terminals[key]
	if h != nil {
		s.deleteTerminalLocked(h)
	}
	s.mu.Unlock()
	if h == nil {
		return nil
	}
	return h.term.Close()
}

func terminalLookupKey(state SessionState, frame Frame, terminalID string) string {
	if terminalID != "" {
		return state.SessionID + ":" + terminalID
	}
	return uploadKey(state, frame)
}

func (s *OperationServer) deleteTerminalLocked(h *terminalHandle) {
	if h == nil {
		return
	}
	for key, candidate := range s.terminals {
		if candidate == h {
			delete(s.terminals, key)
		}
	}
}

func (s *OperationServer) AbortStreams(state SessionState, streamIDs []uint64) {
	if s == nil || len(streamIDs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range streamIDs {
		key := state.SessionID + ":" + fmt.Sprint(id)
		if tx := s.uploads[key]; tx != nil {
			_ = tx.Abort()
			delete(s.uploads, key)
		}
		if h := s.terminals[key]; h != nil {
			if s.PreserveTerminals {
				h.mu.Lock()
				h.sink = nil
				ttl := s.TerminalTTL
				if ttl <= 0 {
					ttl = 5 * time.Minute
				}
				h.expires = time.AfterFunc(ttl, func() {
					s.mu.Lock()
					if s.terminals[key] == h {
						s.deleteTerminalLocked(h)
						_ = h.term.Close()
					}
					s.mu.Unlock()
				})
				h.mu.Unlock()
			} else {
				h.mu.Lock()
				sink := h.sink
				h.sink = nil
				h.mu.Unlock()
				_ = h.term.Close()
				s.deleteTerminalLocked(h)
				if sink != nil {
					_ = sink(OpMessage{Action: "terminal_exit", Error: "terminal stream closed", ExitCode: -1, Done: true})
				}
			}
		}
	}
}

func (s *OperationServer) receiver() (*FileReceiver, error) {
	if s.FileRoot == "" {
		return nil, errors.New("file operations are disabled")
	}
	if err := os.MkdirAll(s.FileRoot, 0700); err != nil {
		return nil, err
	}
	return &FileReceiver{Roots: []string{s.FileRoot}, MaxFileSize: s.MaxFileSize}, nil
}

func (s *OperationServer) handleUploadBegin(state SessionState, frame Frame, req OpMessage, send func(Frame) error) error {
	r, err := s.receiver()
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: err.Error()})
	}
	_, finalPath, pathErr := r.safePath(req.Dest)
	if pathErr != nil {
		return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: pathErr.Error()})
	}
	if err = os.MkdirAll(filepath.Dir(finalPath), 0700); err != nil {
		return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: err.Error()})
	}
	if err = rejectSymlink(finalPath); err != nil {
		return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: err.Error()})
	}
	if st, statErr := os.Stat(finalPath); statErr == nil {
		if !st.Mode().IsRegular() {
			return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: "destination already exists and is not a regular file"})
		}
		size, digest, digestErr := fileDigest(finalPath)
		if digestErr != nil {
			return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: digestErr.Error()})
		}
		if size == req.Size && strings.EqualFold(digest, req.SHA256) {
			return s.respond(frame, send, OpMessage{Action: "upload_ready", OK: true, Done: true, Offset: size, Size: size, SHA256: digest})
		}
		if req.BaseSHA256 != "" && !strings.EqualFold(req.BaseSHA256, digest) {
			return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: "sync conflict: destination changed since manifest exchange"})
		}
		if !req.Replace {
			return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: "destination already exists with different content"})
		}
	} else if !os.IsNotExist(statErr) {
		return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: statErr.Error()})
	}
	key := uploadKey(state, frame)
	s.mu.Lock()
	if old := s.uploads[key]; old != nil {
		_ = old.Abort()
		delete(s.uploads, key)
	}
	tx, err := r.BeginWithOptions(req.Dest, req.Size, req.SHA256, 0, req.Replace)
	if err == nil {
		tx.mode = os.FileMode(req.Mode & 0777)
		s.uploads[key] = tx
	}
	s.mu.Unlock()
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "upload_ready", Error: err.Error()})
	}
	if s.Audit != nil {
		_ = s.Audit.Write(AuditEvent{Event: "transfer", PeerID: state.PeerID, Action: "upload_begin", OK: true, Metadata: map[string]string{"size": fmt.Sprint(req.Size)}})
	}
	return s.respond(frame, send, OpMessage{Action: "upload_ready", OK: true, Offset: tx.Offset()})
}

func (s *OperationServer) handleUploadChunk(state SessionState, frame Frame, req OpMessage, send func(Frame) error) error {
	raw, err := base64.RawStdEncoding.DecodeString(req.Data)
	if err != nil || len(raw) > s.ChunkSize {
		return s.respond(frame, send, OpMessage{Action: "upload_ack", Error: "invalid upload chunk"})
	}
	key := uploadKey(state, frame)
	s.mu.Lock()
	tx := s.uploads[key]
	if tx == nil {
		s.mu.Unlock()
		return s.respond(frame, send, OpMessage{Action: "upload_ack", Error: "upload is not initialized"})
	}
	err = tx.WriteChunk(req.Offset, raw)
	offset := tx.Offset()
	s.mu.Unlock()
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "upload_ack", Error: err.Error(), Offset: offset})
	}
	return s.respond(frame, send, OpMessage{Action: "upload_ack", OK: true, Offset: offset})
}

func (s *OperationServer) handleUploadFinish(state SessionState, frame Frame, send func(Frame) error) error {
	key := uploadKey(state, frame)
	s.mu.Lock()
	tx := s.uploads[key]
	if tx == nil {
		s.mu.Unlock()
		return s.respond(frame, send, OpMessage{Action: "upload_done", Error: "upload is not initialized"})
	}
	err := tx.Complete()
	if err == nil {
		delete(s.uploads, key)
	}
	s.mu.Unlock()
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "upload_done", Error: err.Error()})
	}
	return s.respond(frame, send, OpMessage{Action: "upload_done", OK: true, Done: true})
}

func (s *OperationServer) resolveReadPath(name string) (string, error) {
	r, err := s.receiver()
	if err != nil {
		return "", err
	}
	_, path, err := r.safePath(name)
	if err != nil {
		return "", err
	}
	if err := rejectSymlink(path); err != nil {
		return "", err
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("download source is not a regular file")
	}
	if st.Size() > s.MaxFileSize {
		return "", errors.New("download exceeds maximum file size")
	}
	return path, nil
}

func fileDigest(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func (s *OperationServer) handleDownload(frame Frame, req OpMessage, send func(Frame) error) error {
	path, err := s.resolveReadPath(req.Src)
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "download_meta", Error: err.Error()})
	}
	size, digest, err := fileDigest(path)
	if err != nil {
		return s.respond(frame, send, OpMessage{Action: "download_meta", Error: err.Error()})
	}
	if req.Offset < 0 || req.Offset > size {
		return s.respond(frame, send, OpMessage{Action: "download_meta", Error: "invalid download resume offset"})
	}
	if err := s.respond(frame, send, OpMessage{Action: "download_meta", OK: true, Size: size, SHA256: digest, Offset: req.Offset}); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Seek(req.Offset, io.SeekStart); err != nil {
		return err
	}
	buf := make([]byte, s.ChunkSize)
	offset := req.Offset
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if err := s.respond(frame, send, OpMessage{Action: "download_chunk", OK: true, Offset: offset, Data: base64.RawStdEncoding.EncodeToString(buf[:n])}); err != nil {
				return err
			}
			offset += int64(n)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return s.respond(frame, send, OpMessage{Action: "download_done", OK: true, Done: true, Offset: offset, Size: size, SHA256: digest})
}

func SafeLocalPart(dest string) (string, error) {
	if dest == "" || strings.ContainsRune(dest, 0) {
		return "", errors.New("invalid destination")
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	return abs + ".part", nil
}
