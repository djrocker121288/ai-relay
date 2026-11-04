package arpl

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testDialTransport struct{ addr string }

func (t testDialTransport) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", t.addr)
}

type trackingListener struct {
	net.Listener
	mu      sync.Mutex
	current net.Conn
	accepts atomic.Int64
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.current = c
	l.mu.Unlock()
	l.accepts.Add(1)
	return c, nil
}

func (l *trackingListener) dropCurrent() {
	l.mu.Lock()
	c := l.current
	l.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func residentExec(t *testing.T, client *ResidentClient, text string) OpMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.OpenStream(ctx, ChannelExec)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	payload, err := json.Marshal(OpMessage{Action: "exec", Argv: portableExecArgv(text)})
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.Send(ctx, payload, time.Now().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := stream.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var response OpMessage
	if err = json.Unmarshal(frame.Payload, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func residentJob(t *testing.T, client *ResidentClient, msg OpMessage) OpMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.OpenStream(ctx, ChannelTool)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	b, _ := json.Marshal(msg)
	if err = stream.Send(ctx, b, time.Now().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := stream.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var response OpMessage
	if err = json.Unmarshal(frame.Payload, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestHeartbeatTimeoutsAllowShortIntervalSchedulingJitter(t *testing.T) {
	if got := staleConnectionTimeout(20 * time.Millisecond); got < time.Second {
		t.Fatalf("short-heartbeat stale timeout = %v, want at least 1s", got)
	}
	if got := heartbeatWriteTimeout(20 * time.Millisecond); got < 500*time.Millisecond {
		t.Fatalf("short-heartbeat write timeout = %v, want at least 500ms", got)
	}
	if got := staleConnectionTimeout(5 * time.Second); got != 15*time.Second {
		t.Fatalf("normal stale timeout = %v, want 15s", got)
	}
	if got := heartbeatWriteTimeout(5 * time.Second); got != 10*time.Second {
		t.Fatalf("normal write timeout = %v, want 10s", got)
	}
}

func TestResidentClientMultiplexAndReconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("resident link integration")
	}
	serverID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverPeers := NewPeerRegistry()
	serverPeers.Allow(clientID.PublicKey)
	clientPeers := NewPeerRegistry()
	clientPeers.Allow(serverID.PublicKey)

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &trackingListener{Listener: base}
	defer listener.Close()

	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	ops := &OperationServer{AllowExec: true, MaxOutput: 4096, CommandTimeout: 2 * time.Second, JobsDir: t.TempDir()}
	server := &Server{
		Listener: listener,
		Identity: serverID,
		Peers:    serverPeers,
		Sessions: NewSessionRegistry(),
		Handler:  ops.Handle,
	}
	go func() { _ = server.Serve(serverCtx) }()

	store := &MemorySessionStore{}
	client := NewResidentClient()
	client.Transport = testDialTransport{addr: listener.Addr().String()}
	client.Identity = clientID
	client.Peers = clientPeers
	client.Store = store
	client.Heartbeat = 20 * time.Millisecond
	client.MinBackoff = 10 * time.Millisecond
	client.MaxBackoff = 30 * time.Millisecond

	clientCtx, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	done := make(chan error, 1)
	go func() { done <- client.Run(clientCtx) }()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err = client.WaitConnected(waitCtx); err != nil {
		waitCancel()
		t.Fatal(err)
	}
	waitCancel()

	first := residentExec(t, client, "first")
	if !first.OK || strings.TrimSpace(first.Stdout) != "first" {
		t.Fatalf("first resident exec failed: %#v", first)
	}
	before, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	listener.dropCurrent()
	deadline := time.Now().Add(2 * time.Second)
	for listener.accepts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if listener.accepts.Load() < 2 {
		t.Fatal("resident client did not reconnect after forced drop")
	}
	waitCtx, waitCancel = context.WithTimeout(context.Background(), 2*time.Second)
	if err = client.WaitConnected(waitCtx); err != nil {
		waitCancel()
		t.Fatal(err)
	}
	waitCancel()

	second := residentExec(t, client, "second")
	if !second.OK || strings.TrimSpace(second.Stdout) != "second" {
		t.Fatalf("second resident exec failed: %#v", second)
	}
	after, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before.SessionID == "" || after.SessionID != before.SessionID {
		t.Fatalf("logical session changed across reconnect: before=%q after=%q", before.SessionID, after.SessionID)
	}
	if runtime.GOOS != "windows" {
		job := residentJob(t, client, OpMessage{Action: "job_run", Argv: []string{"/bin/sh", "-c", "sleep 0.2; printf durable"}})
		if !job.OK || job.JobID == "" {
			t.Fatalf("job start=%#v", job)
		}
		listener.dropCurrent()
		deadline = time.Now().Add(2 * time.Second)
		for listener.accepts.Load() < 3 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if listener.accepts.Load() < 3 {
			t.Fatal("resident client did not reconnect for job status")
		}
		waitCtx, waitCancel = context.WithTimeout(context.Background(), 2*time.Second)
		if err = client.WaitConnected(waitCtx); err != nil {
			waitCancel()
			t.Fatal(err)
		}
		waitCancel()
		deadline = time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			status := residentJob(t, client, OpMessage{Action: "job_status", JobID: job.JobID})
			if status.JobState == "succeeded" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		status := residentJob(t, client, OpMessage{Action: "job_status", JobID: job.JobID})
		if status.JobState != "succeeded" || status.ExitCode != 0 {
			t.Fatalf("job after reconnect=%#v", status)
		}
	}

	cancelClient()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("resident client did not stop")
	}
}

func TestResidentClientReconnectsWhenHeartbeatsGoSilent(t *testing.T) {
	if testing.Short() {
		t.Skip("resident stale-link integration")
	}

	serverID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverPeers := NewPeerRegistry()
	serverPeers.Allow(clientID.PublicKey)
	clientPeers := NewPeerRegistry()
	clientPeers.Allow(serverID.PublicKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	var accepts atomic.Int64

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			attempt := accepts.Add(1)
			go func(conn net.Conn, attempt int64) {
				defer conn.Close()
				cs, hsErr := HandshakeServer(serverCtx, conn, serverID, serverPeers, "")
				if hsErr != nil {
					return
				}
				codec, codecErr := NewFrameCodec(&cs)
				if codecErr != nil {
					return
				}
				var responseSeq uint64
				for {
					frame, readErr := ReadFrame(conn, codec)
					if readErr != nil {
						return
					}
					if attempt == 1 {
						// Simulate a half-open mobile path: writes are still
						// consumed, but the peer never sends anything back.
						continue
					}
					if frame.Channel == ChannelControl && frame.StreamID == 0 && string(frame.Payload) == "heartbeat" {
						responseSeq++
						_ = WriteFrame(conn, codec, Frame{
							Channel:   ChannelControl,
							SessionID: cs.SessionID,
							StreamID:  0,
							Sequence:  responseSeq,
							Ack:       frame.Sequence,
							Payload:   []byte("heartbeat-ack"),
						})
					}
				}
			}(conn, attempt)
		}
	}()

	store := &MemorySessionStore{}
	client := NewResidentClient()
	client.Transport = testDialTransport{addr: listener.Addr().String()}
	client.Identity = clientID
	client.Peers = clientPeers
	client.Store = store
	client.Heartbeat = 20 * time.Millisecond
	client.MinBackoff = 10 * time.Millisecond
	client.MaxBackoff = 30 * time.Millisecond

	clientCtx, cancelClient := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(clientCtx) }()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	if err = client.WaitConnected(waitCtx); err != nil {
		waitCancel()
		cancelClient()
		t.Fatal(err)
	}
	waitCancel()

	deadline := time.Now().Add(2 * time.Second)
	for accepts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if accepts.Load() < 2 {
		cancelClient()
		t.Fatal("resident client did not replace a half-open heartbeat-silent connection")
	}

	waitCtx, waitCancel = context.WithTimeout(context.Background(), time.Second)
	if err = client.WaitConnected(waitCtx); err != nil {
		waitCancel()
		cancelClient()
		t.Fatal(err)
	}
	waitCancel()

	// The second peer acknowledges heartbeats, so it should remain stable.
	time.Sleep(4 * client.Heartbeat)
	if got := accepts.Load(); got != 2 {
		cancelClient()
		t.Fatalf("healthy replacement connection was not stable; accepts=%d", got)
	}

	cancelClient()
	select {
	case err = <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("resident client did not stop")
	}
}
