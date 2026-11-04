package arpl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIdentityAllowUnknownAndRevoked(t *testing.T) {
	server, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peers := NewPeerRegistry()
	peers.Allow(client.PublicKey)
	if err := peers.Check(client.DeviceID, client.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := peers.Check(server.DeviceID, server.PublicKey); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("unknown peer accepted: %v", err)
	}
	peers.Revoke(client.DeviceID)
	if err := peers.Check(client.DeviceID, client.PublicKey); !errors.Is(err, ErrRevokedPeer) {
		t.Fatalf("revoked peer accepted: %v", err)
	}
	path := filepath.Join(t.TempDir(), "identity.json")
	store := FileKeyStore{Path: path}
	if err := store.Save(client); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DeviceID != client.DeviceID || !bytes.Equal(loaded.PrivateKey, client.PrivateKey) {
		t.Fatal("identity round trip changed key")
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		t.Fatalf("identity file is not regular: %v", err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		t.Fatalf("identity file is not owner-only: mode=%v", st.Mode().Perm())
	}
}

func TestSignedHandshakeAndEncryptedFrameReplay(t *testing.T) {
	server, _ := NewIdentity()
	client, _ := NewIdentity()
	serverPeers, clientPeers := NewPeerRegistry(), NewPeerRegistry()
	serverPeers.Allow(client.PublicKey)
	clientPeers.Allow(server.PublicKey)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	serverResult := make(chan struct {
		c   SessionCrypto
		err error
	}, 1)
	go func() {
		defer b.Close()
		c, err := HandshakeServer(context.Background(), b, server, serverPeers, "")
		serverResult <- struct {
			c   SessionCrypto
			err error
		}{c, err}
	}()
	clientCrypto, clientErr := HandshakeClient(context.Background(), a, client, clientPeers, "0123456789abcdef0123456789abcdef")
	serverCrypto := <-serverResult
	if clientErr != nil || serverCrypto.err != nil {
		t.Fatalf("client=%v server=%v", clientErr, serverCrypto.err)
	}
	if clientCrypto.SessionID != serverCrypto.c.SessionID {
		t.Fatalf("session mismatch %q %q", clientCrypto.SessionID, serverCrypto.c.SessionID)
	}
	clientCodec, _ := NewFrameCodec(&clientCrypto)
	serverCodec, _ := NewFrameCodec(&serverCrypto.c)
	f := Frame{Channel: ChannelExec, SessionID: clientCrypto.SessionID, StreamID: 4, Sequence: 1, Payload: []byte("argv-json")}
	raw, err := clientCodec.Seal(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := serverCodec.Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != "argv-json" {
		t.Fatalf("payload mismatch")
	}
	if _, err = serverCodec.Open(raw); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay accepted: %v", err)
	}
	raw[len(raw)-1] ^= 1
	if _, err = serverCodec.Open(raw); err == nil {
		t.Fatal("tampered frame accepted")
	}
}

func TestSessionResumeRegistry(t *testing.T) {
	r := NewSessionRegistry()
	state := SessionState{SessionID: "0123456789abcdef0123456789abcdef", LastAck: map[uint64]uint64{3: 7}}
	r.Put(state)
	got, ok := r.Resume(state.SessionID)
	if !ok || got.LastAck[3] != 7 {
		t.Fatalf("session was not retained: %#v %v", got, ok)
	}
	r.Remove(state.SessionID)
	if _, ok := r.Resume(state.SessionID); ok {
		t.Fatal("removed session resumed")
	}
}

func TestInterruptedTransferResumeHashAndTraversal(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("ARPL resumable transfer")
	sum := sha256.Sum256(data)
	receiver := &FileReceiver{Roots: []string{root}, MaxFileSize: 1024}
	tx, err := receiver.Begin("nested/file.txt", int64(len(data)), hex.EncodeToString(sum[:]), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.WriteChunk(0, data[:5]); err != nil {
		t.Fatal(err)
	}
	if err := tx.Abort(); err != nil {
		t.Fatal(err)
	}
	tx, err = receiver.Begin("nested/file.txt", int64(len(data)), hex.EncodeToString(sum[:]), 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.WriteChunk(5, data[5:]); err != nil {
		t.Fatal(err)
	}
	if err := tx.Complete(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "nested", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("resumed file differs")
	}
	if _, err := receiver.Begin("../escape", 1, hex.EncodeToString(sum[:]), 0); !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("traversal accepted: %v", err)
	}
	if _, err := receiver.Begin(filepath.Join(root, "absolute"), 1, hex.EncodeToString(sum[:]), 0); !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("absolute path accepted: %v", err)
	}
}
