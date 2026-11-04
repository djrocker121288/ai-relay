//go:build !windows

package arpl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOperationTerminalPTYInputOutput(t *testing.T) {
	s := &OperationServer{AllowExec: true}
	state := SessionState{SessionID: "0123456789abcdef0123456789abcdef"}
	streamID := uint64(77)
	responses := make(chan OpMessage, 32)
	send := func(f Frame) error {
		var m OpMessage
		if err := json.Unmarshal(f.Payload, &m); err != nil {
			return err
		}
		responses <- m
		return nil
	}

	start := OpMessage{
		Action: "terminal_start",
		Argv:   []string{"/bin/sh", "-c", "IFS= read -r x; printf 'PTY:%s\\n' \"$x\""},
		Rows:   30,
		Cols:   100,
	}
	b, _ := json.Marshal(start)
	frame := Frame{Channel: ChannelTerminal, StreamID: streamID, Payload: b}
	if err := s.Handle(context.Background(), state, frame, send); err != nil {
		t.Fatal(err)
	}

	select {
	case ready := <-responses:
		if ready.Action != "terminal_ready" || !ready.OK {
			t.Fatalf("ready = %#v", ready)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("terminal ready timeout")
	}

	input := OpMessage{
		Action: "terminal_input",
		Data:   base64.RawStdEncoding.EncodeToString([]byte("hello-arpl\n")),
	}
	b, _ = json.Marshal(input)
	frame.Payload = b
	if err := s.Handle(context.Background(), state, frame, send); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	var output strings.Builder
	exited := false
	for !exited {
		select {
		case msg := <-responses:
			switch msg.Action {
			case "terminal_data":
				raw, err := base64.RawStdEncoding.DecodeString(msg.Data)
				if err != nil {
					t.Fatal(err)
				}
				output.Write(raw)
			case "terminal_exit":
				if msg.ExitCode != 0 {
					t.Fatalf("exit = %#v", msg)
				}
				exited = true
			}
		case <-deadline:
			t.Fatalf("terminal exit timeout; output=%q", output.String())
		}
	}
	if !strings.Contains(output.String(), "PTY:hello-arpl") {
		t.Fatalf("output = %q", output.String())
	}
}

func TestOperationTerminalAbortStream(t *testing.T) {
	s := &OperationServer{AllowExec: true}
	state := SessionState{SessionID: "fedcba9876543210fedcba9876543210"}
	streamID := uint64(88)
	responses := make(chan OpMessage, 16)
	send := func(f Frame) error {
		var m OpMessage
		if err := json.Unmarshal(f.Payload, &m); err != nil {
			return err
		}
		responses <- m
		return nil
	}
	start := OpMessage{Action: "terminal_start", Argv: []string{"/bin/sh", "-c", "sleep 30"}}
	b, _ := json.Marshal(start)
	frame := Frame{Channel: ChannelTerminal, StreamID: streamID, Payload: b}
	if err := s.Handle(context.Background(), state, frame, send); err != nil {
		t.Fatal(err)
	}
	select {
	case <-responses:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal ready timeout")
	}
	s.AbortStreams(state, []uint64{streamID})
	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg := <-responses:
			if msg.Action == "terminal_exit" {
				return
			}
		case <-deadline:
			t.Fatal("aborted terminal did not exit")
		}
	}
}

func TestOperationTerminalReattachAfterDisconnect(t *testing.T) {
	s := &OperationServer{AllowExec: true, PreserveTerminals: true, TerminalTTL: time.Minute}
	state := SessionState{SessionID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	frame := Frame{Channel: ChannelTerminal, StreamID: 91}
	responses := make(chan OpMessage, 32)
	send := func(f Frame) error {
		var m OpMessage
		if err := json.Unmarshal(f.Payload, &m); err != nil {
			return err
		}
		responses <- m
		return nil
	}
	b, _ := json.Marshal(OpMessage{Action: "terminal_start", Argv: []string{"/bin/sh", "-c", "IFS= read -r x; printf 'REATTACHED:%s\\n' \"$x\""}})
	frame.Payload = b
	if err := s.Handle(context.Background(), state, frame, send); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-responses:
		if m.Action != "terminal_ready" {
			t.Fatalf("ready=%#v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ready timeout")
	}
	s.AbortStreams(state, []uint64{frame.StreamID})
	attach := frame
	ab, _ := json.Marshal(OpMessage{Action: "terminal_attach"})
	attach.Payload = ab
	if err := s.Handle(context.Background(), state, attach, send); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-responses:
		if m.Action != "terminal_ready" {
			t.Fatalf("attach=%#v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("attach timeout")
	}
	in, _ := json.Marshal(OpMessage{Action: "terminal_input", Data: base64.RawStdEncoding.EncodeToString([]byte("yes\n"))})
	inFrame := frame
	inFrame.Payload = in
	if err := s.Handle(context.Background(), state, inFrame, send); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case m := <-responses:
			if m.Action == "terminal_data" {
				raw, _ := base64.RawStdEncoding.DecodeString(m.Data)
				if strings.Contains(string(raw), "REATTACHED:yes") {
					return
				}
			}
		case <-deadline:
			t.Fatal("reattached output timeout")
		}
	}
}

func TestTerminalReattachUsesStableIDAcrossTransportStream(t *testing.T) {
	s := &OperationServer{AllowExec: true, PreserveTerminals: true, TerminalTTL: time.Second}
	state := SessionState{SessionID: NewSessionID()}
	ready := callOp(t, s, state, ChannelTerminal, OpMessage{Action: "terminal_start", TerminalID: "stable-terminal", Argv: []string{"/bin/sh", "-c", "sleep 30"}})
	if len(ready) != 1 || !ready[0].OK || ready[0].TerminalID != "stable-terminal" {
		t.Fatalf("ready=%#v", ready)
	}
	s.AbortStreams(state, []uint64{9})
	attached := callOp(t, s, state, ChannelTerminal, OpMessage{Action: "terminal_attach", TerminalID: "stable-terminal"})
	if len(attached) != 1 || !attached[0].OK || attached[0].TerminalID != "stable-terminal" {
		t.Fatalf("attach=%#v", attached)
	}
	input := OpMessage{Action: "terminal_input", TerminalID: "stable-terminal", InputSeq: 1, Data: base64.RawStdEncoding.EncodeToString([]byte("\004"))}
	if err := s.Handle(context.Background(), state, Frame{Channel: ChannelTerminal, SessionID: state.SessionID, StreamID: 11, Sequence: 1, Payload: mustJSON(input)}, func(Frame) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.Handle(context.Background(), state, Frame{Channel: ChannelTerminal, SessionID: state.SessionID, StreamID: 11, Sequence: 2, Payload: mustJSON(input)}, func(Frame) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_ = callOp(t, s, state, ChannelTerminal, OpMessage{Action: "terminal_close", TerminalID: "stable-terminal"})
}

func TestTerminalContinuityReconnectsThroughHTTPRelay(t *testing.T) {
	token := "terminal-relay-token"
	hub := NewHTTPRelayHub(token)
	ts := httptest.NewServer(hub.Handler())
	defer ts.Close()
	pair, err := NewRelayPairID()
	if err != nil {
		t.Fatal(err)
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
	listener, err := NewHTTPRelayListener(ts.URL, pair, token, ts.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ops := &OperationServer{AllowExec: true, PreserveTerminals: true, TerminalTTL: time.Minute}
	server := &Server{
		Listener: listener, Identity: serverID, Peers: serverPeers,
		Sessions: NewSessionRegistry(), Handler: func(ctx context.Context, state SessionState, frame Frame, send func(Frame) error) error {
			handlerErr := ops.Handle(ctx, state, frame, send)
			if handlerErr != nil {
				t.Logf("relay terminal handler error: %v", handlerErr)
			}
			return handlerErr
		}, OnDisconnect: ops.AbortStreams,
	}
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(serverCtx) }()

	transport := HTTPRelayTransport{URL: ts.URL, PairID: pair, Token: token, Client: ts.Client(), AllowInsecureHTTP: true}
	sessionID := NewSessionID()
	connect := func() (net.Conn, *FrameCodec) {
		ctx := context.Background()
		conn, dialErr := transport.Dial(ctx)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		crypto, handshakeErr := HandshakeClient(ctx, conn, clientID, clientPeers, sessionID)
		if handshakeErr != nil {
			conn.Close()
			t.Fatal(handshakeErr)
		}
		codec, codecErr := NewFrameCodec(&crypto)
		if codecErr != nil {
			conn.Close()
			t.Fatal(codecErr)
		}
		return conn, codec
	}
	send := func(conn net.Conn, codec *FrameCodec, stream uint64, seq uint64, msg OpMessage) {
		b, marshalErr := json.Marshal(msg)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if writeErr := WriteFrame(conn, codec, Frame{Channel: ChannelTerminal, SessionID: sessionID, StreamID: stream, Sequence: seq, Deadline: time.Now().Add(3 * time.Second), Payload: b}); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	read := func(conn net.Conn, codec *FrameCodec) OpMessage {
		frame, readErr := ReadFrame(conn, codec)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var msg OpMessage
		if unmarshalErr := json.Unmarshal(frame.Payload, &msg); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		return msg
	}

	first, firstCodec := connect()
	send(first, firstCodec, 1, 1, OpMessage{Action: "terminal_start", TerminalID: "relay-terminal", Argv: []string{"/bin/sh", "-c", "IFS= read -r x; printf 'RELAY:%s\\n' \"$x\""}})
	ready := read(first, firstCodec)
	if !ready.OK || ready.TerminalID != "relay-terminal" {
		t.Fatalf("terminal start=%#v", ready)
	}
	_ = first.Close()

	second, secondCodec := connect()
	defer second.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		send(second, secondCodec, 2, 1, OpMessage{Action: "terminal_attach", TerminalID: "relay-terminal"})
		attached := read(second, secondCodec)
		if attached.OK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("terminal attach failed after relay reconnect: %#v", attached)
		}
		time.Sleep(20 * time.Millisecond)
	}
	send(second, secondCodec, 2, 2, OpMessage{Action: "terminal_input", TerminalID: "relay-terminal", InputSeq: 1, Data: base64.RawStdEncoding.EncodeToString([]byte("through-relay\n"))})
	for {
		msg := read(second, secondCodec)
		if msg.Action != "terminal_data" {
			if msg.Action == "terminal_exit" {
				t.Fatalf("terminal exited before replay: %#v", msg)
			}
			continue
		}
		raw, decodeErr := base64.RawStdEncoding.DecodeString(msg.Data)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if strings.Contains(string(raw), "RELAY:through-relay") {
			return
		}
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestUnixTerminalNormalizesDumbTERM(t *testing.T) {
	t.Setenv("TERM", "dumb")
	session, err := newTerminalSession(context.Background(), []string{"/bin/sh", "-c", `printf 'TERM=%s\n' "$TERM"`}, "", 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var output strings.Builder
	code, runErr := session.Run(func(data []byte) error {
		output.Write(data)
		return nil
	})
	if runErr != nil || code != 0 {
		t.Fatalf("terminal run code=%d err=%v output=%q", code, runErr, output.String())
	}
	if !strings.Contains(output.String(), "TERM=xterm-256color") {
		t.Fatalf("terminal did not normalize TERM: %q", output.String())
	}
}
