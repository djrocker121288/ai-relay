package arpl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func callOp(t *testing.T, s *OperationServer, state SessionState, ch Channel, msg OpMessage) []OpMessage {
	t.Helper()
	b, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	var out []OpMessage
	err = s.Handle(context.Background(), state, Frame{Channel: ch, SessionID: state.SessionID, StreamID: 9, Sequence: 1, Payload: b}, func(f Frame) error {
		var m OpMessage
		if err := json.Unmarshal(f.Payload, &m); err != nil {
			return err
		}
		out = append(out, m)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func portableExecArgv(text string) []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd.exe", "/d", "/c", "echo", text}
	}
	return []string{"printf", "%s", text}
}

func TestOperationExecEnabledAndDisabled(t *testing.T) {
	state := SessionState{SessionID: NewSessionID()}
	disabled := &OperationServer{}
	resp := callOp(t, disabled, state, ChannelExec, OpMessage{Action: "exec", Argv: portableExecArgv("blocked")})
	if len(resp) != 1 || resp[0].OK || !strings.Contains(resp[0].Error, "disabled") {
		t.Fatalf("disabled exec response = %#v", resp)
	}

	enabled := &OperationServer{AllowExec: true, MaxOutput: 1024, CommandTimeout: 5 * time.Second}
	resp = callOp(t, enabled, state, ChannelExec, OpMessage{Action: "exec", Argv: portableExecArgv("arpl-exec-ok")})
	if len(resp) != 1 || !resp[0].OK || strings.TrimSpace(resp[0].Stdout) != "arpl-exec-ok" || resp[0].ExitCode != 0 {
		t.Fatalf("enabled exec response = %#v", resp)
	}
}

func TestOperationUploadResumeAndDownload(t *testing.T) {
	root := t.TempDir()
	state := SessionState{SessionID: NewSessionID()}
	server := &OperationServer{FileRoot: root, MaxFileSize: 1 << 20, ChunkSize: 8}
	data := []byte("persistent encrypted file transfer")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])

	resp := callOp(t, server, state, ChannelFile, OpMessage{Action: "upload_begin", Dest: "remote.bin", Size: int64(len(data)), SHA256: digest})
	if len(resp) != 1 || !resp[0].OK || resp[0].Offset != 0 {
		t.Fatalf("upload begin = %#v", resp)
	}
	first := data[:8]
	resp = callOp(t, server, state, ChannelFile, OpMessage{Action: "upload_chunk", Offset: 0, Data: base64.RawStdEncoding.EncodeToString(first)})
	if len(resp) != 1 || !resp[0].OK || resp[0].Offset != int64(len(first)) {
		t.Fatalf("upload chunk = %#v", resp)
	}

	// Match the production Server.OnDisconnect path: release active stream
	// handles while preserving the .part file before reconnect/resume.
	server.AbortStreams(state, []uint64{9})
	server = &OperationServer{FileRoot: root, MaxFileSize: 1 << 20, ChunkSize: 8}
	resp = callOp(t, server, state, ChannelFile, OpMessage{Action: "upload_begin", Dest: "remote.bin", Size: int64(len(data)), SHA256: digest})
	if len(resp) != 1 || !resp[0].OK || resp[0].Offset != int64(len(first)) {
		t.Fatalf("resume begin = %#v", resp)
	}
	offset := resp[0].Offset
	for offset < int64(len(data)) {
		end := offset + 8
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		resp = callOp(t, server, state, ChannelFile, OpMessage{Action: "upload_chunk", Offset: offset, Data: base64.RawStdEncoding.EncodeToString(data[offset:end])})
		if len(resp) != 1 || !resp[0].OK {
			t.Fatalf("resume chunk = %#v", resp)
		}
		offset = resp[0].Offset
	}
	resp = callOp(t, server, state, ChannelFile, OpMessage{Action: "upload_finish"})
	if len(resp) != 1 || !resp[0].OK || !resp[0].Done {
		t.Fatalf("upload finish = %#v", resp)
	}
	got, err := os.ReadFile(filepath.Join(root, "remote.bin"))
	if err != nil || string(got) != string(data) {
		t.Fatalf("uploaded file mismatch err=%v got=%q", err, got)
	}

	resp = callOp(t, server, state, ChannelFile, OpMessage{Action: "download_begin", Src: "remote.bin", Offset: 0})
	if len(resp) < 2 || resp[0].Action != "download_meta" || !resp[0].OK || resp[0].SHA256 != digest {
		t.Fatalf("download responses = %#v", resp)
	}
	var downloaded []byte
	for _, m := range resp[1:] {
		if m.Action == "download_chunk" {
			chunk, err := base64.RawStdEncoding.DecodeString(m.Data)
			if err != nil {
				t.Fatal(err)
			}
			downloaded = append(downloaded, chunk...)
		}
	}
	if string(downloaded) != string(data) || resp[len(resp)-1].Action != "download_done" || !resp[len(resp)-1].Done {
		t.Fatalf("download mismatch data=%q responses=%#v", downloaded, resp)
	}
}

func TestOperationTraversalAndUnknownAction(t *testing.T) {
	root := t.TempDir()
	state := SessionState{SessionID: NewSessionID()}
	server := &OperationServer{FileRoot: root}
	resp := callOp(t, server, state, ChannelFile, OpMessage{Action: "upload_begin", Dest: "../escape", Size: 1, SHA256: strings.Repeat("0", 64)})
	if len(resp) != 1 || resp[0].Error == "" {
		t.Fatalf("traversal accepted: %#v", resp)
	}
	resp = callOp(t, server, state, ChannelTool, OpMessage{Action: "definitely_unknown"})
	if len(resp) != 1 || resp[0].Action != "error" || resp[0].Error == "" {
		t.Fatalf("unknown action accepted: %#v", resp)
	}
}

func TestOperationUploadBeginIsIdempotentAfterCompletion(t *testing.T) {
	root := t.TempDir()
	state := SessionState{SessionID: NewSessionID()}
	server := &OperationServer{FileRoot: root, MaxFileSize: 1 << 20, ChunkSize: 8}
	data := []byte("idempotent-complete")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])

	resp := callOp(t, server, state, ChannelFile, OpMessage{Action: "upload_begin", Dest: "done.bin", Size: int64(len(data)), SHA256: digest})
	if len(resp) != 1 || !resp[0].OK {
		t.Fatalf("begin = %#v", resp)
	}
	offset := resp[0].Offset
	for offset < int64(len(data)) {
		end := offset + 8
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		resp = callOp(t, server, state, ChannelFile, OpMessage{
			Action: "upload_chunk", Offset: offset,
			Data: base64.RawStdEncoding.EncodeToString(data[offset:end]),
		})
		if len(resp) != 1 || !resp[0].OK {
			t.Fatalf("chunk = %#v", resp)
		}
		offset = resp[0].Offset
	}
	resp = callOp(t, server, state, ChannelFile, OpMessage{Action: "upload_finish"})
	if len(resp) != 1 || !resp[0].OK || !resp[0].Done {
		t.Fatalf("finish = %#v", resp)
	}

	resp = callOp(t, server, state, ChannelFile, OpMessage{Action: "upload_begin", Dest: "done.bin", Size: int64(len(data)), SHA256: digest})
	if len(resp) != 1 || !resp[0].OK || !resp[0].Done || resp[0].Offset != int64(len(data)) {
		t.Fatalf("idempotent begin = %#v", resp)
	}

	other := sha256.Sum256([]byte("different"))
	resp = callOp(t, server, state, ChannelFile, OpMessage{Action: "upload_begin", Dest: "done.bin", Size: int64(len(data)), SHA256: hex.EncodeToString(other[:])})
	if len(resp) != 1 || resp[0].Error == "" {
		t.Fatalf("different-content overwrite accepted = %#v", resp)
	}
}
