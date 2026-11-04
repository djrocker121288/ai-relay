package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ai-relay/ai-relay/internal/arpl"
)

type plainDialTransport struct{ addr string }

func (t plainDialTransport) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", t.addr)
}

func TestResidentDaemonControlExecSendPull(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test command uses printf")
	}

	serverID, err := arpl.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := arpl.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverPeers := arpl.NewPeerRegistry()
	serverPeers.Allow(clientID.PublicKey)
	clientPeers := arpl.NewPeerRegistry()
	clientPeers.Allow(serverID.PublicKey)

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	fileRoot := t.TempDir()
	ops := &arpl.OperationServer{
		AllowExec:      true,
		FileRoot:       fileRoot,
		MaxFileSize:    1 << 20,
		MaxOutput:      1 << 20,
		CommandTimeout: 5 * time.Second,
	}
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	server := &arpl.Server{
		Listener:     upstream,
		Identity:     serverID,
		Peers:        serverPeers,
		Sessions:     arpl.NewSessionRegistry(),
		Handler:      ops.Handle,
		OnDisconnect: ops.AbortStreams,
	}
	go func() { _ = server.Serve(serverCtx) }()

	resident := arpl.NewResidentClient()
	resident.Transport = plainDialTransport{addr: upstream.Addr().String()}
	resident.Identity = clientID
	resident.Peers = clientPeers
	resident.Store = &arpl.MemorySessionStore{}
	resident.Heartbeat = 25 * time.Millisecond
	resident.MinBackoff = 10 * time.Millisecond
	resident.MaxBackoff = 30 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- resident.Run(ctx) }()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err = resident.WaitConnected(waitCtx); err != nil {
		waitCancel()
		t.Fatal(err)
	}
	waitCancel()

	control, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	token, err := newControlToken()
	if err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(t.TempDir(), "link.json")
	if err = writePrivateJSON(stateFile, linkState{Address: control.Addr().String(), Token: token, PID: os.Getpid(), Version: "test"}); err != nil {
		t.Fatal(err)
	}
	controlCtx, cancelControl := context.WithCancel(ctx)
	defer cancelControl()
	go func() {
		for {
			conn, acceptErr := control.Accept()
			if acceptErr != nil {
				return
			}
			go handleLinkControl(controlCtx, cancelControl, resident, token, conn)
		}
	}()

	status, err := callLinkState(stateFile, linkRequest{Op: "status"}, 2*time.Second)
	if err != nil || !status.OK || !status.Connected {
		t.Fatalf("status err=%v response=%#v", err, status)
	}

	execResp, err := callLinkState(stateFile, linkRequest{
		Op: "exec", Argv: []string{"printf", "resident-daemon-ok"}, TimeoutMS: 2000,
	}, 5*time.Second)
	if err != nil || !execResp.OK || execResp.Stdout != "resident-daemon-ok" {
		t.Fatalf("exec err=%v response=%#v", err, execResp)
	}

	source := filepath.Join(t.TempDir(), "source.bin")
	payload := []byte("resident daemon resumable file payload")
	if err = os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	sendResp, err := callLinkState(stateFile, linkRequest{Op: "send", Src: source, Dest: "remote.bin"}, 5*time.Second)
	if err != nil || !sendResp.OK {
		t.Fatalf("send err=%v response=%#v", err, sendResp)
	}
	remote, err := os.ReadFile(filepath.Join(fileRoot, "remote.bin"))
	if err != nil || string(remote) != string(payload) {
		t.Fatalf("remote file err=%v data=%q", err, remote)
	}

	// Re-sending the same completed file exercises the idempotent completion
	// path used after an ambiguous reconnect.
	sendResp, err = callLinkState(stateFile, linkRequest{Op: "send", Src: source, Dest: "remote.bin"}, 5*time.Second)
	if err != nil || !sendResp.OK {
		t.Fatalf("idempotent send err=%v response=%#v", err, sendResp)
	}

	dest := filepath.Join(t.TempDir(), "pulled.bin")
	pullResp, err := callLinkState(stateFile, linkRequest{Op: "pull", Src: "remote.bin", Dest: dest}, 5*time.Second)
	if err != nil || !pullResp.OK {
		t.Fatalf("pull err=%v response=%#v", err, pullResp)
	}
	pulled, err := os.ReadFile(dest)
	if err != nil || string(pulled) != string(payload) {
		t.Fatalf("pulled file err=%v data=%q", err, pulled)
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("resident client did not stop")
	}
}

type trackingDialTransport struct {
	addr string
	mu   sync.Mutex
	conn net.Conn
}

func (t *trackingDialTransport) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
	return conn, nil
}

func (t *trackingDialTransport) dropCurrent() {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func TestResidentTerminalReattachesAfterTransportDrop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test requires a Unix PTY")
	}

	serverID, err := arpl.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := arpl.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverPeers := arpl.NewPeerRegistry()
	serverPeers.Allow(clientID.PublicKey)
	clientPeers := arpl.NewPeerRegistry()
	clientPeers.Allow(serverID.PublicKey)

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	ops := &arpl.OperationServer{
		AllowExec:         true,
		CommandTimeout:    5 * time.Second,
		PreserveTerminals: true,
		TerminalTTL:       time.Minute,
	}
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	server := &arpl.Server{
		Listener:     upstream,
		Identity:     serverID,
		Peers:        serverPeers,
		Sessions:     arpl.NewSessionRegistry(),
		Handler:      ops.Handle,
		OnDisconnect: ops.AbortStreams,
	}
	go func() { _ = server.Serve(serverCtx) }()

	transport := &trackingDialTransport{addr: upstream.Addr().String()}
	resident := arpl.NewResidentClient()
	resident.Transport = transport
	resident.Identity = clientID
	resident.Peers = clientPeers
	resident.Store = &arpl.MemorySessionStore{}
	resident.Heartbeat = 25 * time.Millisecond
	resident.MinBackoff = 10 * time.Millisecond
	resident.MaxBackoff = 30 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- resident.Run(ctx) }()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err = resident.WaitConnected(waitCtx); err != nil {
		waitCancel()
		t.Fatal(err)
	}
	waitCancel()

	control, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	token, err := newControlToken()
	if err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(t.TempDir(), "link.json")
	if err = writePrivateJSON(stateFile, linkState{Address: control.Addr().String(), Token: token, PID: os.Getpid(), Version: "test"}); err != nil {
		t.Fatal(err)
	}
	controlCtx, cancelControl := context.WithCancel(ctx)
	defer cancelControl()
	go func() {
		for {
			conn, acceptErr := control.Accept()
			if acceptErr != nil {
				return
			}
			go handleLinkControl(controlCtx, cancelControl, resident, token, conn)
		}
	}()

	termConn, reader, err := dialLinkControl(stateFile, linkRequest{
		Op:   "terminal",
		Argv: []string{"/bin/sh", "-c", "IFS= read -r x; printf 'BEFORE:%s\\n' \"$x\"; IFS= read -r y; printf 'AFTER:%s\\n' \"$y\""},
		Rows: 24, Cols: 80,
	}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer termConn.Close()

	readUntil := func(want string) string {
		t.Helper()
		_ = termConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var out strings.Builder
		for {
			var header [5]byte
			if _, err := io.ReadFull(reader, header[:]); err != nil {
				t.Fatalf("terminal read while waiting for %q: %v; output=%q", want, err, out.String())
			}
			n := int(binary.BigEndian.Uint32(header[1:]))
			if n < 0 || n > localTerminalMaxFrame {
				t.Fatalf("invalid local terminal frame size %d", n)
			}
			payload := make([]byte, n)
			if _, err := io.ReadFull(reader, payload); err != nil {
				t.Fatal(err)
			}
			switch header[0] {
			case localTerminalData:
				out.Write(payload)
				if strings.Contains(out.String(), want) {
					return out.String()
				}
			case localTerminalError:
				t.Fatalf("terminal returned error while waiting for %q: %s", want, payload)
			case localTerminalExit:
				t.Fatalf("terminal exited before %q; output=%q", want, out.String())
			}
		}
	}

	if _, err = termConn.Write([]byte("one\n")); err != nil {
		t.Fatal(err)
	}
	if got := readUntil("BEFORE:one"); !strings.Contains(got, "BEFORE:one") {
		t.Fatalf("first stage output=%q", got)
	}

	transport.dropCurrent()

	if _, err = termConn.Write([]byte("two\n")); err != nil {
		t.Fatal(err)
	}
	if got := readUntil("AFTER:two"); !strings.Contains(got, "AFTER:two") {
		t.Fatalf("reattached stage output=%q", got)
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("resident client did not stop")
	}
}

func TestAndroidDirectArgsMapsPeerControlState(t *testing.T) {
	base := t.TempDir()
	settingsPath := filepath.Join(base, "settings.json")
	macControl := filepath.Join(base, "control-mac.json")
	phoneControl := filepath.Join(base, "control-phone.json")
	settings := ARPLSettings{
		Version: 1,
		Peers: []PeerSettings{
			{Name: "Mac Mini", Enabled: true, PublicKey: "mac-peer-key", ControlState: macControl},
			{Name: "Server 3", Enabled: true, PublicKey: "server3-peer-key", ControlState: phoneControl},
		},
	}
	if err := writePrivateJSON(settingsPath, settings); err != nil {
		t.Fatal(err)
	}

	got, err := androidDirectArgs([]string{"--control-state", phoneControl, "/bin/sh"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "control-state") || strings.Contains(joined, "127.0.0.1") {
		t.Fatalf("Android direct args retained local control dependency: %#v", got)
	}
	if !strings.Contains(joined, settingsPath) || !strings.Contains(joined, "server3-peer-key") {
		t.Fatalf("Android direct args did not select matching remote peer: %#v", got)
	}
	if strings.Contains(joined, "mac-peer-key") {
		t.Fatalf("Android direct args selected the wrong peer: %#v", got)
	}
}

func TestAndroidDirectArgsControlStateEqualsForm(t *testing.T) {
	base := t.TempDir()
	settingsPath := filepath.Join(base, "settings.json")
	control := filepath.Join(base, "control-server3.json")
	settings := ARPLSettings{
		Version: 1,
		Peers: []PeerSettings{
			{Name: "Server 3", Enabled: true, PublicKey: "server3-peer-key", ControlState: control},
		},
	}
	if err := writePrivateJSON(settingsPath, settings); err != nil {
		t.Fatal(err)
	}

	got, err := androidDirectArgs([]string{"--control-state=" + control, "uname", "-a"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "control-state") {
		t.Fatalf("Android direct args retained control-state: %#v", got)
	}
	if !strings.Contains(joined, settingsPath) || !strings.Contains(joined, "server3-peer-key") {
		t.Fatalf("Android direct args did not derive settings/peer: %#v", got)
	}
}
