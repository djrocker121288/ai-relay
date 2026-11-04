package arpl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCapabilityDenyBoundary(t *testing.T) {
	id, _ := NewIdentity()
	r := NewPeerRegistry()
	peer, _ := NewIdentity()
	device := r.Allow(peer.PublicKey)
	if err := r.SetCapabilities(device, []string{CapabilityControl}); err != nil {
		t.Fatal(err)
	}
	if err := r.Authorize(device, CapabilityExec); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("authorize=%v", err)
	}
	_ = id
}
func TestEnrollmentSingleUseAndReplay(t *testing.T) {
	issuer, _ := NewIdentity()
	peer, _ := NewIdentity()
	m := EnrollmentManager{Identity: issuer, TTL: time.Minute}
	p, err := m.Issue(peer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Consume(p, peer.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err = m.Consume(p, peer.PublicKey); err == nil {
		t.Fatal("replay accepted")
	}
	p.Expires = time.Now().Add(-time.Minute).Unix()
	if err = m.Consume(p, peer.PublicKey); err == nil {
		t.Fatal("expired payload accepted")
	}
}

func TestEnrollmentPublicMaterialAuthorizesConnection(t *testing.T) {
	issuer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(t.TempDir(), "used.json")
	issuerManager := EnrollmentManager{Identity: issuer, TTL: time.Minute}
	payload, err := issuerManager.Issue(peer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if payload.PeerPublicKey == "" || strings.Contains(payload.PeerPublicKey, "PRIVATE") {
		t.Fatalf("payload contains invalid key material: %#v", payload)
	}
	consumer := EnrollmentManager{Identity: issuer, StorePath: store}
	if err := consumer.Consume(payload, nil); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Consume(payload, nil); err == nil {
		t.Fatal("durable enrollment replay accepted")
	}
	serverPeers := NewPeerRegistry()
	serverPeers.Allow(peer.PublicKey)
	clientPeers := NewPeerRegistry()
	clientPeers.Allow(issuer.PublicKey)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	serverResult := make(chan error, 1)
	go func() { _, e := HandshakeServer(context.Background(), b, issuer, serverPeers, ""); serverResult <- e }()
	if _, err = HandshakeClient(context.Background(), a, peer, clientPeers, NewSessionID()); err != nil {
		t.Fatal(err)
	}
	if err = <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestRemoteSyncManifestTransferAndDelete(t *testing.T) {
	local := t.TempDir()
	remote := t.TempDir()
	if err := os.MkdirAll(filepath.Join(local, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "nested", "new.txt"), []byte("new content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remote, "old.txt"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &OperationServer{FileRoot: remote, MaxFileSize: 1 << 20, ChunkSize: 4}
	state := SessionState{SessionID: NewSessionID()}
	response := callOp(t, s, state, ChannelFile, OpMessage{Action: "sync_manifest", Src: "."})
	if len(response) != 1 || !response[0].OK {
		t.Fatalf("manifest=%#v", response)
	}
	var remoteManifest SyncManifest
	if err := json.Unmarshal([]byte(response[0].Manifest), &remoteManifest); err != nil {
		t.Fatal(err)
	}
	localManifest, err := BuildSyncManifest(local, SyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	entry := localManifest.Entries[0]
	response = callOp(t, s, state, ChannelFile, OpMessage{Action: "upload_begin", Dest: entry.Path, Size: entry.Size, SHA256: entry.SHA256, Replace: true, Mode: entry.Mode})
	if len(response) != 1 || !response[0].OK {
		t.Fatalf("upload begin=%#v", response)
	}
	data, _ := os.ReadFile(filepath.Join(local, filepath.FromSlash(entry.Path)))
	for offset := int64(0); offset < int64(len(data)); {
		end := offset + 4
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		response = callOp(t, s, state, ChannelFile, OpMessage{Action: "upload_chunk", Offset: offset, Data: base64.RawStdEncoding.EncodeToString(data[offset:end])})
		if len(response) != 1 || !response[0].OK {
			t.Fatalf("chunk=%#v", response)
		}
		offset = response[0].Offset
	}
	response = callOp(t, s, state, ChannelFile, OpMessage{Action: "upload_finish"})
	if len(response) != 1 || !response[0].OK {
		t.Fatalf("finish=%#v", response)
	}
	manifestBytes, _ := json.Marshal(localManifest)
	response = callOp(t, s, state, ChannelFile, OpMessage{Action: "sync_delete", Src: ".", Manifest: string(manifestBytes), Delete: true})
	if len(response) != 1 || !response[0].OK {
		t.Fatalf("delete=%#v", response)
	}
	if _, err := os.Stat(filepath.Join(remote, "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("old file remains: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(remote, "nested", "new.txt")); err != nil || string(got) != "new content" {
		t.Fatalf("synced file=%q err=%v", got, err)
	}
}
func TestSyncManifestAndTraversal(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := BuildSyncManifest(root, SyncOptions{})
	if err != nil || len(m.Entries) != 1 || m.Entries[0].SHA256 == "" {
		t.Fatalf("manifest=%#v err=%v", m, err)
	}
	if _, err = SecureSyncPath(root, "../escape"); err == nil {
		t.Fatal("traversal accepted")
	}
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(dst, "a.txt"), []byte("receiver-change"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SyncTrees(root, dst, SyncOptions{BaseHashes: map[string]string{"a.txt": "old-base"}}, false); err == nil {
		t.Fatal("sync conflict was not rejected")
	}
}
func TestReleaseSignatureHashAndRollback(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	src := filepath.Join(t.TempDir(), "candidate")
	target := filepath.Join(t.TempDir(), "installed")
	if err := os.WriteFile(src, []byte("new"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0700); err != nil {
		t.Fatal(err)
	}
	a, _ := HashArtifact(src)
	m := ReleaseManifest{Version: "test", BuildID: "b", Artifacts: []ReleaseArtifact{a}}
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	tampered := m
	tampered.BuildID = "tampered"
	if err := tampered.Verify(pub); err == nil {
		t.Fatal("tampered release manifest accepted")
	}
	if err := StageAndActivateUpdate(src, m, pub, UpdateOptions{Target: target, Health: func(string) error { return errors.New("forced") }}); err == nil {
		t.Fatal("failed health accepted")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "old" {
		t.Fatalf("rollback=%q", b)
	}
}

func TestDurableJobDisconnectAndCancel(t *testing.T) {
	s := &OperationServer{JobsDir: t.TempDir(), CommandTimeout: time.Second, JobOutputMax: 1024}
	state := SessionState{SessionID: NewSessionID()}
	msgs := callOp(t, s, state, ChannelTool, OpMessage{Action: "job_run", Argv: portableExecArgv("durable-job")})
	if len(msgs) != 1 || !msgs[0].OK || msgs[0].JobID == "" {
		t.Fatalf("job start=%#v", msgs)
	}
	deadline := time.Now().Add(2 * time.Second)
	finished := false
	for time.Now().Before(deadline) {
		r := callOp(t, s, state, ChannelTool, OpMessage{Action: "job_status", JobID: msgs[0].JobID})
		if len(r) == 1 && r[0].JobState == "succeeded" {
			finished = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !finished {
		t.Fatal("durable job did not finish")
	}
	if runtime.GOOS == "windows" {
		return
	}
	slow := callOp(t, s, state, ChannelTool, OpMessage{Action: "job_run", Argv: []string{"/bin/sh", "-c", "sleep 30"}})
	if len(slow) != 1 || !slow[0].OK {
		t.Fatalf("slow job start=%#v", slow)
	}
	cancelled := callOp(t, s, state, ChannelTool, OpMessage{Action: "job_cancel", JobID: slow[0].JobID})
	if len(cancelled) != 1 || !cancelled[0].OK {
		t.Fatalf("cancel=%#v", cancelled)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r := callOp(t, s, state, ChannelTool, OpMessage{Action: "job_status", JobID: slow[0].JobID})
		if len(r) == 1 && r[0].JobState == "cancelled" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("cancelled job did not persist cancelled state")
}

func TestRouteFallbackPrefersReachableDirect(t *testing.T) {
	selected, statuses, err := SelectRoute(context.Background(), []RouteCandidate{{Kind: RouteLAN, Priority: 0, Probe: func(context.Context) (time.Duration, error) { return 0, errors.New("unreachable") }}, {Kind: RouteDirect, Priority: 1, Probe: func(context.Context) (time.Duration, error) { return time.Millisecond, nil }}, {Kind: RouteRelay, Priority: 2, Probe: func(context.Context) (time.Duration, error) { return time.Millisecond, nil }}})
	if err != nil || selected.Kind != RouteDirect || len(statuses) != 2 {
		t.Fatalf("selected=%#v statuses=%#v err=%v", selected, statuses, err)
	}
}

func TestAuditRedactsAndRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a := &AuditLog{Path: path, MaxBytes: 100, Keep: 2}
	if err := a.Write(AuditEvent{Event: "test", Metadata: map[string]string{"authorization": "token=hidden"}, OK: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.Write(AuditEvent{Event: "test2", Metadata: map[string]string{"v": "safe"}, OK: true}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if string(b) == "" || strings.Contains(string(b), "hidden") {
		t.Fatalf("audit redaction failed: %q", b)
	}
}
