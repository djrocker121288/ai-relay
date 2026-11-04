package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ai-relay/ai-relay/internal/arpl"
	"golang.org/x/term"
)

const (
	linkControlMaxRequest  = 1 << 20
	linkControlMaxResponse = 16 << 20
)

type linkState struct {
	Address string `json:"address"`
	Token   string `json:"token"`
	PID     int    `json:"pid"`
	Version string `json:"version"`
}

type linkRequest struct {
	Token     string   `json:"token"`
	Op        string   `json:"op"`
	Argv      []string `json:"argv,omitempty"`
	Cwd       string   `json:"cwd,omitempty"`
	TimeoutMS int64    `json:"timeout_ms,omitempty"`
	Rows      int      `json:"rows,omitempty"`
	Cols      int      `json:"cols,omitempty"`
	Src       string   `json:"src,omitempty"`
	Dest      string   `json:"dest,omitempty"`
	Overwrite bool     `json:"overwrite,omitempty"`
}

type linkResponse struct {
	OK        bool   `json:"ok"`
	Connected bool   `json:"connected,omitempty"`
	Path      string `json:"path,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
	Stdout    string `json:"stdout,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
	ExitCode  int    `json:"exit_code,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Summary   string `json:"summary,omitempty"`
}

func linkStateFile() string {
	key, _ := defaults()
	return filepath.Join(filepath.Dir(key), "link.json")
}

func forceStopFile(stateFile string) string { return stateFile + ".force-stop" }

func writePrivateJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0600)
	if err = os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(path, 0600)
	return nil
}

func readLinkState(path string) (linkState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return linkState{}, err
	}
	var state linkState
	if err = json.Unmarshal(b, &state); err != nil {
		return linkState{}, err
	}
	if state.Address == "" || len(state.Token) != 64 {
		return linkState{}, errors.New("invalid ARPL link state")
	}
	host, _, err := net.SplitHostPort(state.Address)
	if err != nil {
		return linkState{}, err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return linkState{}, errors.New("ARPL local control address is not loopback")
	}
	return state, nil
}

func newControlToken() (string, error) {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func buildResident(o clientOptions, heartbeat time.Duration) (*arpl.ResidentClient, error) {
	var lanAddresses, directAddresses []string
	if o.settingsFile != "" {
		s, err := loadSettings(o.settingsFile)
		if err != nil {
			return nil, err
		}
		if err = validateSettings(s); err != nil {
			return nil, err
		}
		if !s.Client.Enabled {
			return nil, errors.New("ARPL client is disabled in settings")
		}
		o.key = s.Security.KeyFile
		if o.relayTokenFile == "" {
			o.relayTokenFile = s.Security.RelayTokenFile
		}
		if !o.relayURLExplicit && o.relayURL == "" {
			o.relayURL = s.Relay.URL
		}
		var selected *PeerSettings
		for i := range s.Peers {
			p := &s.Peers[i]
			if !p.Enabled {
				continue
			}
			if o.peerExplicit && !peerKeyEqual(p.PublicKey, o.peer) {
				continue
			}
			selected = p
			break
		}
		if selected != nil {
			if !o.peerExplicit && o.peer == "" {
				o.peer = selected.PublicKey
			}
			if !o.relayPairExplicit && o.relayPair == "" {
				o.relayPair = selected.OutboundPair
			}
			if !o.relayURLExplicit && selected.RelayURL != "" {
				o.relayURL = selected.RelayURL
			}
			lanAddresses = append(lanAddresses, selected.LANAddresses...)
			directAddresses = append(directAddresses, selected.DirectAddresses...)
			if !o.sessionExplicit && selected.SessionFile != "" {
				o.session = selected.SessionFile
			}
			if selected.Heartbeat != "" {
				if d, e := time.ParseDuration(selected.Heartbeat); e == nil {
					heartbeat = d
				}
			}
		}
		if !o.sessionExplicit && o.session == "" {
			o.session = filepath.Join(filepath.Dir(o.settingsFile), "session.json")
		}
	}
	if o.peer == "" {
		return nil, errors.New("-peer-key is required")
	}
	if o.relayURL == "" && o.addr == "" {
		return nil, errors.New("-addr or -relay-url is required")
	}
	id, err := load(o.key)
	if err != nil {
		return nil, err
	}
	pub, err := decodePublic(o.peer)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if o.ca != "" {
		b, e := os.ReadFile(o.ca)
		if e != nil || !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid -ca-file")
		}
	} else if system, e := x509.SystemCertPool(); e == nil {
		roots = system
	}
	client := arpl.NewResidentClient()
	var relayTransport arpl.Transport
	if o.relayURL != "" {
		token := ""
		if o.relayTokenFile != "" {
			var e error
			token, e = readSecretFile(o.relayTokenFile)
			if e != nil {
				return nil, e
			}
		}
		if o.relayPair == "" {
			return nil, errors.New("-relay-pair is required with -relay-url")
		}
		if strings.HasPrefix(strings.ToLower(o.relayURL), "ws://") || strings.HasPrefix(strings.ToLower(o.relayURL), "wss://") {
			relayTransport = arpl.WSRelayTransport{
				URL: o.relayURL, PairID: o.relayPair, Token: token, Identity: id,
				AllowInsecureWS: o.relayInsecureHTTP,
			}
		} else {
			relayTransport = arpl.HTTPRelayTransport{
				URL: o.relayURL, PairID: o.relayPair, Token: token, Identity: id,
				AllowInsecureHTTP: o.relayInsecureHTTP,
			}
		}
	} else {
	}
	client.Identity = id
	client.Peers = arpl.NewPeerRegistry()
	client.Peers.Allow(pub)
	client.Store = arpl.FileSessionStore{Path: o.session}
	client.Heartbeat = heartbeat
	routes := make([]arpl.AuthenticatedRoute, 0, len(lanAddresses)+len(directAddresses)+2)
	seen := map[string]bool{}
	addTCP := func(kind arpl.RouteKind, address string) {
		address = strings.TrimSpace(address)
		if address == "" || seen[address] {
			return
		}
		seen[address] = true
		routes = append(routes, arpl.AuthenticatedRoute{Kind: kind, Address: address, Transport: arpl.TLSTCPTransport{Address: address, Config: arpl.PinnedTLSConfig("", roots, nil)}})
	}
	for _, address := range lanAddresses {
		addTCP(arpl.RouteLAN, address)
	}
	for _, address := range directAddresses {
		addTCP(arpl.RouteDirect, address)
	}
	if o.addr != "" {
		addTCP(arpl.RouteDirect, o.addr)
	}
	if relayTransport != nil {
		routes = append(routes, arpl.AuthenticatedRoute{Kind: arpl.RouteRelay, Address: o.relayURL, Transport: relayTransport})
	}
	if len(routes) == 0 {
		return nil, errors.New("no ARPL route configured")
	}
	client.Connect = func(ctx context.Context, sessionID string) (net.Conn, arpl.SessionCrypto, arpl.RouteStatus, error) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		return arpl.ConnectRoutes(dialCtx, id, client.Peers, sessionID, routes)
	}
	client.OnRoute = func(status arpl.RouteStatus) {
		if status.Selected {
			fmt.Fprintf(os.Stderr, "ARPL route=%s latency_ms=%d\n", status.Kind, status.Latency.Milliseconds())
		}
	}
	return client, nil
}

func linkCommand(args []string) {
	if len(args) == 0 {
		fatal(errors.New("link requires run, status, stop, exec, send, pull, or terminal"))
	}
	switch args[0] {
	case "run":
		linkRun(args[1:])
	case "status":
		linkStatus(args[1:])
	case "stop":
		linkStop(args[1:])
	case "exec":
		if runtime.GOOS == "android" {
			smartExec(args[1:])
			return
		}
		linkExec(args[1:])
	case "send":
		if runtime.GOOS == "android" {
			smartSend(args[1:])
			return
		}
		linkSend(args[1:])
	case "pull":
		if runtime.GOOS == "android" {
			smartPull(args[1:])
			return
		}
		linkPull(args[1:])
	case "terminal":
		if runtime.GOOS == "android" {
			smartTerminal(args[1:])
			return
		}
		linkTerminal(args[1:])
	default:
		fatal(fmt.Errorf("unknown link operation %q", args[0]))
	}
}

func linkRun(args []string) {
	f := flag.NewFlagSet("link run", flag.ExitOnError)
	var o clientOptions
	o.addFlags(f)
	heartbeat := 20 * time.Second
	stateFile := linkStateFile()
	clearForceStop := false
	stopMarker := ""
	f.DurationVar(&heartbeat, "heartbeat", heartbeat, "encrypted link heartbeat interval")
	f.StringVar(&stateFile, "control-state", stateFile, "owner-only local daemon state file")
	f.StringVar(&stopMarker, "intentional-stop-marker", "", "owner-only durable intentional-disconnect marker")
	f.BoolVar(&clearForceStop, "clear-force-stop", false, "explicitly clear the intentional-disconnect marker")
	_ = f.Parse(args)
	if stopMarker == "" {
		stopMarker = forceStopFile(stateFile)
	}
	if _, err := os.Stat(stopMarker); err == nil && !clearForceStop {
		fatal(errors.New("ARPL link intentionally stopped; use --clear-force-stop to resume"))
	}
	if clearForceStop {
		_ = clearPeerStopMarker(stopMarker)
	}
	f.Visit(func(v *flag.Flag) {
		switch v.Name {
		case "peer-key":
			o.peerExplicit = true
		case "session-file":
			o.sessionExplicit = true
		case "relay-url":
			o.relayURLExplicit = true
		case "relay-pair":
			o.relayPairExplicit = true
		}
	})

	resident, err := buildResident(o, heartbeat)
	if err != nil {
		fatal(err)
	}

	if _, err = os.Stat(stateFile); err == nil {
		if resp, probeErr := callLinkState(stateFile, linkRequest{Op: "status"}, 500*time.Millisecond); probeErr == nil && resp.OK {
			fatal(errors.New("ARPL resident link is already running"))
		}
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal(err)
	}
	token, err := newControlToken()
	if err != nil {
		listener.Close()
		fatal(err)
	}
	state := linkState{Address: listener.Addr().String(), Token: token, PID: os.Getpid(), Version: "0.2.0"}
	if err = writePrivateJSON(stateFile, state); err != nil {
		listener.Close()
		fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer listener.Close()
	defer func() {
		current, e := readLinkState(stateFile)
		if e == nil && subtle.ConstantTimeCompare([]byte(current.Token), []byte(token)) == 1 {
			_ = os.Remove(stateFile)
		}
	}()

	runErr := make(chan error, 1)
	go func() { runErr <- resident.Run(ctx) }()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	fmt.Printf("ARPL resident link active; local control=%s pid=%d\n", state.Address, state.PID)
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			select {
			case <-ctx.Done():
				return
			default:
				select {
				case err = <-runErr:
					if err != nil && !errors.Is(err, context.Canceled) {
						fatal(err)
					}
					return
				default:
					fatal(acceptErr)
				}
			}
		}
		go handleLinkControl(ctx, cancel, resident, token, conn)
	}
}

func handleLinkControl(ctx context.Context, cancel context.CancelFunc, resident *arpl.ResidentClient, token string, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(24 * time.Hour))
	var req linkRequest
	dec := json.NewDecoder(io.LimitReader(conn, linkControlMaxRequest))
	if err := dec.Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(linkResponse{Error: "invalid local ARPL request"})
		return
	}
	if len(req.Token) != len(token) || subtle.ConstantTimeCompare([]byte(req.Token), []byte(token)) != 1 {
		_ = json.NewEncoder(conn).Encode(linkResponse{Error: "local ARPL authentication failed"})
		return
	}
	if req.Op == "terminal" {
		_ = conn.SetDeadline(time.Time{})
		handleLinkTerminalControl(ctx, resident, conn, req)
		return
	}

	opCtx := ctx
	var opCancel context.CancelFunc
	if req.Op == "exec" {
		d := time.Duration(req.TimeoutMS) * time.Millisecond
		if d <= 0 {
			d = 30 * time.Second
		}
		opCtx, opCancel = context.WithTimeout(ctx, d+30*time.Second)
	} else {
		opCtx, opCancel = context.WithTimeout(ctx, 24*time.Hour)
	}
	defer opCancel()

	var resp linkResponse
	switch req.Op {
	case "status":
		probeCtx, probeCancel := context.WithTimeout(ctx, 50*time.Millisecond)
		err := resident.WaitConnected(probeCtx)
		probeCancel()
		resp.OK = true
		resp.Connected = err == nil
		route := resident.LastRoute()
		resp.Path = string(route.Kind)
		resp.LatencyMS = route.Latency.Milliseconds()
		if err != nil {
			resp.Summary = fmt.Sprintf("resident daemon running; upstream reconnect pending path=%s latency_ms=%d", route.Kind, resp.LatencyMS)
		} else {
			resp.Summary = fmt.Sprintf("resident daemon running; upstream connected path=%s latency_ms=%d", route.Kind, resp.LatencyMS)
		}
	case "stop":
		resp = linkResponse{OK: true, Summary: "resident link stopping"}
		_ = json.NewEncoder(conn).Encode(resp)
		cancel()
		return
	case "exec":
		resp = residentExecOperation(opCtx, resident, req)
	case "send":
		resp = residentSendOperation(opCtx, resident, req.Src, req.Dest)
	case "pull":
		resp = residentPullOperation(opCtx, resident, req.Src, req.Dest, req.Overwrite)
	default:
		resp.Error = "unknown local ARPL operation"
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

const (
	localTerminalData     byte = 1
	localTerminalExit     byte = 2
	localTerminalError    byte = 3
	localTerminalMaxFrame      = 2 << 20
)

func writeLocalTerminalFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > localTerminalMaxFrame {
		return errors.New("local terminal frame too large")
	}
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

func handleLinkTerminalControl(ctx context.Context, resident *arpl.ResidentClient, conn net.Conn, req linkRequest) {
	if len(req.Argv) == 0 {
		_ = json.NewEncoder(conn).Encode(linkResponse{Error: "terminal requires argv"})
		return
	}

	// Use a stable logical terminal ID from the first frame onward. The remote
	// OperationServer preserves PTYs across transport loss and can attach a new
	// stream to this ID after the resident link reconnects.
	terminalID := "terminal-" + arpl.NewSessionID()
	errTerminalNotFound := errors.New("terminal session not found")

	requestStream := func(action string) (*arpl.ResidentStream, error) {
		if err := resident.WaitConnected(ctx); err != nil {
			return nil, err
		}
		stream, err := resident.OpenStream(ctx, arpl.ChannelTerminal)
		if err != nil {
			return nil, err
		}
		msg := arpl.OpMessage{Action: action, TerminalID: terminalID}
		if action == "terminal_start" {
			msg.Argv = req.Argv
			msg.Cwd = req.Cwd
			msg.Rows = req.Rows
			msg.Cols = req.Cols
		}
		if err = streamSendMessage(ctx, stream, msg, time.Time{}); err != nil {
			stream.Close()
			return nil, err
		}
		ready, err := streamRecvMessage(ctx, stream)
		if err != nil {
			stream.Close()
			return nil, err
		}
		if ready.Action != "terminal_ready" || !ready.OK {
			stream.Close()
			msg := ready.Error
			if msg == "" {
				msg = "remote PTY did not become ready"
			}
			if msg == errTerminalNotFound.Error() {
				return nil, errTerminalNotFound
			}
			return nil, errors.New(msg)
		}
		if ready.TerminalID != "" {
			terminalID = ready.TerminalID
		}
		return stream, nil
	}

	// terminal_start is ambiguous if the transport dies before terminal_ready
	// reaches us. In that case attach first; only start again when the server
	// proves that the stable terminal ID does not exist.
	openInitial := func() (*arpl.ResidentStream, error) {
		mayExist := false
		for {
			action := "terminal_start"
			if mayExist {
				action = "terminal_attach"
			}
			stream, err := requestStream(action)
			if err == nil {
				return stream, nil
			}
			if errors.Is(err, arpl.ErrLinkDisconnected) {
				if action == "terminal_start" {
					mayExist = true
				}
				continue
			}
			if action == "terminal_attach" && errors.Is(err, errTerminalNotFound) {
				mayExist = false
				continue
			}
			if action == "terminal_start" && strings.Contains(err.Error(), "already active") {
				mayExist = true
				continue
			}
			return nil, err
		}
	}

	reattach := func() (*arpl.ResidentStream, error) {
		for {
			stream, err := requestStream("terminal_attach")
			if err == nil {
				return stream, nil
			}
			if errors.Is(err, arpl.ErrLinkDisconnected) {
				continue
			}
			return nil, err
		}
	}

	current, err := openInitial()
	if err != nil {
		_ = json.NewEncoder(conn).Encode(linkResponse{Error: err.Error()})
		return
	}
	defer func() {
		if current != nil {
			current.Close()
		}
	}()

	if err = json.NewEncoder(conn).Encode(linkResponse{OK: true, Summary: "remote PTY ready"}); err != nil {
		_ = streamSendMessage(context.Background(), current, arpl.OpMessage{Action: "terminal_close", TerminalID: terminalID}, time.Time{})
		return
	}

	type inputResult struct {
		data []byte
		err  error
	}
	inputEvents := make(chan inputResult, 16)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, readErr := conn.Read(buf)
			if n > 0 {
				data := append([]byte(nil), buf[:n]...)
				inputEvents <- inputResult{data: data}
			}
			if readErr != nil {
				inputEvents <- inputResult{err: readErr}
				return
			}
		}
	}()

	type recvResult struct {
		stream *arpl.ResidentStream
		frame  arpl.Frame
		err    error
	}
	recvEvents := make(chan recvResult, 4)
	startRecv := func(stream *arpl.ResidentStream) {
		go func() {
			frame, recvErr := stream.Recv(ctx)
			recvEvents <- recvResult{stream: stream, frame: frame, err: recvErr}
		}()
	}
	startRecv(current)

	reconnectCurrent := func() error {
		if current != nil {
			current.Close()
		}
		stream, reconnectErr := reattach()
		if reconnectErr != nil {
			return reconnectErr
		}
		current = stream
		startRecv(current)
		return nil
	}

	var inputSeq uint64
	sendInput := func(data []byte) error {
		inputSeq++
		msg := arpl.OpMessage{
			Action:     "terminal_input",
			TerminalID: terminalID,
			InputSeq:   inputSeq,
			Data:       base64.RawStdEncoding.EncodeToString(data),
		}
		for {
			sendErr := streamSendMessage(ctx, current, msg, time.Time{})
			if sendErr == nil {
				return nil
			}
			if !errors.Is(sendErr, arpl.ErrLinkDisconnected) {
				return sendErr
			}
			if reconnectErr := reconnectCurrent(); reconnectErr != nil {
				return reconnectErr
			}
			// Reuse the same InputSeq. The server de-duplicates a frame that
			// reached the PTY just before the old transport disappeared.
		}
	}

	closeRemote := func() {
		if current != nil {
			_ = streamSendMessage(context.Background(), current, arpl.OpMessage{Action: "terminal_close", TerminalID: terminalID}, time.Time{})
		}
	}

	for {
		select {
		case <-ctx.Done():
			closeRemote()
			return
		case in := <-inputEvents:
			if in.err != nil {
				if errors.Is(in.err, io.EOF) {
					inputEvents = nil
					if err = sendInput([]byte{0x04}); err != nil {
						_ = writeLocalTerminalFrame(conn, localTerminalError, []byte(err.Error()))
						return
					}
					continue
				}
				closeRemote()
				return
			}
			if len(in.data) > 0 {
				if err = sendInput(in.data); err != nil {
					_ = writeLocalTerminalFrame(conn, localTerminalError, []byte(err.Error()))
					return
				}
			}
		case result := <-recvEvents:
			if result.stream != current {
				// A receiver from the pre-reconnect stream finished after a
				// new stream was already attached.
				continue
			}
			if result.err != nil {
				if errors.Is(result.err, arpl.ErrLinkDisconnected) {
					if err = reconnectCurrent(); err != nil {
						_ = writeLocalTerminalFrame(conn, localTerminalError, []byte(err.Error()))
						return
					}
					continue
				}
				_ = writeLocalTerminalFrame(conn, localTerminalError, []byte(result.err.Error()))
				return
			}
			var msg arpl.OpMessage
			if err = json.Unmarshal(result.frame.Payload, &msg); err != nil {
				_ = writeLocalTerminalFrame(conn, localTerminalError, []byte(err.Error()))
				return
			}
			switch msg.Action {
			case "terminal_data":
				raw, decodeErr := base64.RawStdEncoding.DecodeString(msg.Data)
				if decodeErr != nil {
					_ = writeLocalTerminalFrame(conn, localTerminalError, []byte("invalid terminal output"))
					return
				}
				if err = writeLocalTerminalFrame(conn, localTerminalData, raw); err != nil {
					closeRemote()
					return
				}
			case "terminal_exit":
				out := linkResponse{OK: msg.OK, Error: msg.Error, ExitCode: msg.ExitCode}
				b, _ := json.Marshal(out)
				_ = writeLocalTerminalFrame(conn, localTerminalExit, b)
				return
			}
			startRecv(current)
		}
	}
}

func dialLinkControl(stateFile string, req linkRequest, timeout time.Duration) (net.Conn, *bufio.Reader, error) {
	state, err := readLinkState(stateFile)
	if err != nil {
		return nil, nil, err
	}
	req.Token = state.Token
	dialer := net.Dialer{Timeout: minDuration(timeout, 2*time.Second)}
	conn, err := dialer.Dial("tcp", state.Address)
	if err != nil {
		return nil, nil, err
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if err = json.NewEncoder(conn).Encode(req); err != nil {
		conn.Close()
		return nil, nil, err
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	var resp linkResponse
	if err = json.Unmarshal(line, &resp); err != nil {
		conn.Close()
		return nil, nil, err
	}
	if !resp.OK {
		conn.Close()
		if resp.Error == "" {
			resp.Error = "remote PTY setup failed"
		}
		return nil, nil, errors.New(resp.Error)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, reader, nil
}

func linkTerminal(args []string) {
	f := flag.NewFlagSet("link terminal", flag.ExitOnError)
	stateFile := linkStateFile()
	cwd := ""
	f.StringVar(&stateFile, "control-state", stateFile, "owner-only local daemon state file")
	f.StringVar(&cwd, "cwd", "", "remote working directory")
	_ = f.Parse(args)
	argv := f.Args()
	if len(argv) == 0 {
		argv = []string{"/bin/sh"}
	}

	rows, cols := 24, 80
	stdoutFD := int(os.Stdout.Fd())
	if term.IsTerminal(stdoutFD) {
		if w, h, e := term.GetSize(stdoutFD); e == nil && w > 0 && h > 0 {
			cols, rows = w, h
		}
	}

	conn, reader, err := dialLinkControl(stateFile, linkRequest{
		Op: "terminal", Argv: argv, Cwd: cwd, Rows: rows, Cols: cols,
	}, 10*time.Second)
	if err != nil {
		fatal(err)
	}
	defer conn.Close()

	stdinFD := int(os.Stdin.Fd())
	var oldState *term.State
	if term.IsTerminal(stdinFD) {
		oldState, err = term.MakeRaw(stdinFD)
		if err != nil {
			fatal(err)
		}
		defer term.Restore(stdinFD, oldState)
	}

	inputDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(inputDone)
	}()

	for {
		var header [5]byte
		if _, err = io.ReadFull(reader, header[:]); err != nil {
			if !errors.Is(err, io.EOF) {
				fmt.Fprintln(os.Stderr, "ARPL terminal:", err)
			}
			return
		}
		n := int(binary.BigEndian.Uint32(header[1:]))
		if n < 0 || n > localTerminalMaxFrame {
			fmt.Fprintln(os.Stderr, "ARPL terminal: invalid local frame")
			return
		}
		payload := make([]byte, n)
		if _, err = io.ReadFull(reader, payload); err != nil {
			fmt.Fprintln(os.Stderr, "ARPL terminal:", err)
			return
		}
		switch header[0] {
		case localTerminalData:
			_, _ = os.Stdout.Write(payload)
		case localTerminalExit:
			var resp linkResponse
			if json.Unmarshal(payload, &resp) == nil && resp.Error != "" && resp.ExitCode != 0 {
				fmt.Fprintln(os.Stderr, "\r\nARPL remote terminal:", resp.Error)
			}
			return
		case localTerminalError:
			fmt.Fprintln(os.Stderr, "\r\nARPL terminal:", string(payload))
			return
		default:
			fmt.Fprintln(os.Stderr, "\r\nARPL terminal: unknown local frame")
			return
		}
		select {
		case <-inputDone:
		default:
		}
	}
}

func streamSendMessage(ctx context.Context, stream *arpl.ResidentStream, msg arpl.OpMessage, deadline time.Time) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return stream.Send(ctx, b, deadline)
}

func streamRecvMessage(ctx context.Context, stream *arpl.ResidentStream) (arpl.OpMessage, error) {
	frame, err := stream.Recv(ctx)
	if err != nil {
		return arpl.OpMessage{}, err
	}
	var msg arpl.OpMessage
	if err = json.Unmarshal(frame.Payload, &msg); err != nil {
		return arpl.OpMessage{}, err
	}
	return msg, nil
}

func residentExecOperation(ctx context.Context, resident *arpl.ResidentClient, req linkRequest) linkResponse {
	if len(req.Argv) == 0 {
		return linkResponse{Error: "exec requires argv", ExitCode: -1}
	}
	if err := resident.WaitConnected(ctx); err != nil {
		return linkResponse{Error: err.Error(), ExitCode: -1}
	}
	stream, err := resident.OpenStream(ctx, arpl.ChannelExec)
	if err != nil {
		return linkResponse{Error: err.Error(), ExitCode: -1}
	}
	defer stream.Close()
	msg := arpl.OpMessage{Action: "exec", Argv: req.Argv, Cwd: req.Cwd, TimeoutMS: req.TimeoutMS}
	deadline := time.Now().Add(60 * time.Second)
	if req.TimeoutMS > 0 {
		deadline = time.Now().Add(time.Duration(req.TimeoutMS)*time.Millisecond + 30*time.Second)
	}
	if err = streamSendMessage(ctx, stream, msg, deadline); err != nil {
		return linkResponse{Error: "encrypted link lost before exec request was confirmed: " + err.Error(), ExitCode: -1}
	}
	result, err := streamRecvMessage(ctx, stream)
	if err != nil {
		if errors.Is(err, arpl.ErrLinkDisconnected) {
			return linkResponse{Error: "encrypted link dropped while exec result was pending; command was not replayed to avoid duplicate execution", ExitCode: -1}
		}
		return linkResponse{Error: err.Error(), ExitCode: -1}
	}
	return linkResponse{
		OK: result.OK, Error: result.Error, Stdout: result.Stdout, Stderr: result.Stderr,
		ExitCode: result.ExitCode, Truncated: result.Truncated,
	}
}

func residentSendOperation(ctx context.Context, resident *arpl.ResidentClient, src, dest string) linkResponse {
	if src == "" || dest == "" {
		return linkResponse{Error: "send requires source and destination"}
	}
	size, digest, err := localDigest(src)
	if err != nil {
		return linkResponse{Error: err.Error()}
	}
	file, err := os.Open(src)
	if err != nil {
		return linkResponse{Error: err.Error()}
	}
	defer file.Close()

	for {
		if err = resident.WaitConnected(ctx); err != nil {
			return linkResponse{Error: err.Error()}
		}
		stream, openErr := resident.OpenStream(ctx, arpl.ChannelFile)
		if openErr != nil {
			if errors.Is(openErr, arpl.ErrLinkDisconnected) {
				continue
			}
			return linkResponse{Error: openErr.Error()}
		}

		retry := false
		if err = streamSendMessage(ctx, stream, arpl.OpMessage{Action: "upload_begin", Dest: dest, Size: size, SHA256: digest}, time.Now().Add(5*time.Minute)); err != nil {
			retry = errors.Is(err, arpl.ErrLinkDisconnected)
			stream.Close()
			if retry {
				continue
			}
			return linkResponse{Error: err.Error()}
		}
		ready, recvErr := streamRecvMessage(ctx, stream)
		if recvErr != nil {
			retry = errors.Is(recvErr, arpl.ErrLinkDisconnected)
			stream.Close()
			if retry {
				continue
			}
			return linkResponse{Error: recvErr.Error()}
		}
		if ready.Error != "" {
			stream.Close()
			return linkResponse{Error: ready.Error}
		}
		if ready.Done && ready.OK && ready.Offset == size {
			stream.Close()
			return linkResponse{OK: true, Summary: fmt.Sprintf("already present %s (%d bytes, sha256=%s)", dest, size, digest)}
		}
		if ready.Offset < 0 || ready.Offset > size {
			stream.Close()
			return linkResponse{Error: "server returned invalid upload resume offset"}
		}
		if _, err = file.Seek(ready.Offset, io.SeekStart); err != nil {
			stream.Close()
			return linkResponse{Error: err.Error()}
		}
		offset := ready.Offset
		buf := make([]byte, arpl.DefaultChunkSize)
		for offset < size {
			n, readErr := file.Read(buf)
			if n > 0 {
				chunk := arpl.OpMessage{Action: "upload_chunk", Offset: offset, Data: base64.RawStdEncoding.EncodeToString(buf[:n])}
				if err = streamSendMessage(ctx, stream, chunk, time.Now().Add(5*time.Minute)); err != nil {
					retry = errors.Is(err, arpl.ErrLinkDisconnected)
					break
				}
				ack, e := streamRecvMessage(ctx, stream)
				if e != nil {
					err = e
					retry = errors.Is(e, arpl.ErrLinkDisconnected)
					break
				}
				if ack.Error != "" {
					err = errors.New(ack.Error)
					break
				}
				if ack.Offset <= offset || ack.Offset > size {
					err = errors.New("invalid upload acknowledgement offset")
					break
				}
				offset = ack.Offset
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				err = readErr
				break
			}
		}
		if retry {
			stream.Close()
			continue
		}
		if err != nil {
			stream.Close()
			return linkResponse{Error: err.Error()}
		}
		if offset != size {
			stream.Close()
			return linkResponse{Error: "local upload source ended at unexpected size"}
		}
		if err = streamSendMessage(ctx, stream, arpl.OpMessage{Action: "upload_finish"}, time.Now().Add(5*time.Minute)); err != nil {
			retry = errors.Is(err, arpl.ErrLinkDisconnected)
			stream.Close()
			if retry {
				continue
			}
			return linkResponse{Error: err.Error()}
		}
		done, e := streamRecvMessage(ctx, stream)
		stream.Close()
		if e != nil {
			if errors.Is(e, arpl.ErrLinkDisconnected) {
				continue
			}
			return linkResponse{Error: e.Error()}
		}
		if done.Error != "" || !done.OK {
			if done.Error == "" {
				done.Error = "remote upload did not complete"
			}
			return linkResponse{Error: done.Error}
		}
		return linkResponse{OK: true, Summary: fmt.Sprintf("sent %s -> %s (%d bytes, sha256=%s)", src, dest, size, digest)}
	}
}

func residentPullOperation(ctx context.Context, resident *arpl.ResidentClient, src, dest string, overwrite bool) linkResponse {
	if src == "" || dest == "" {
		return linkResponse{Error: "pull requires source and destination"}
	}
	if _, err := os.Stat(dest); err == nil && !overwrite {
		return linkResponse{Error: "destination exists; use overwrite"}
	}
	part, err := arpl.SafeLocalPart(dest)
	if err != nil {
		return linkResponse{Error: err.Error()}
	}
	if err = os.MkdirAll(filepath.Dir(part), 0700); err != nil {
		return linkResponse{Error: err.Error()}
	}
	current := int64(0)
	if st, e := os.Stat(part); e == nil {
		if !st.Mode().IsRegular() {
			return linkResponse{Error: "local .part path is not a regular file"}
		}
		current = st.Size()
	}

	var expectedSize int64 = -1
	var expectedHash string
	for {
		if err = resident.WaitConnected(ctx); err != nil {
			return linkResponse{Error: err.Error()}
		}
		out, e := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if e != nil {
			return linkResponse{Error: e.Error()}
		}
		stream, openErr := resident.OpenStream(ctx, arpl.ChannelFile)
		if openErr != nil {
			out.Close()
			if errors.Is(openErr, arpl.ErrLinkDisconnected) {
				continue
			}
			return linkResponse{Error: openErr.Error()}
		}
		if err = streamSendMessage(ctx, stream, arpl.OpMessage{Action: "download_begin", Src: src, Offset: current}, time.Now().Add(5*time.Minute)); err != nil {
			stream.Close()
			out.Close()
			if errors.Is(err, arpl.ErrLinkDisconnected) {
				continue
			}
			return linkResponse{Error: err.Error()}
		}
		meta, e := streamRecvMessage(ctx, stream)
		if e != nil {
			stream.Close()
			out.Close()
			if errors.Is(e, arpl.ErrLinkDisconnected) {
				continue
			}
			return linkResponse{Error: e.Error()}
		}
		if meta.Error != "" {
			stream.Close()
			out.Close()
			return linkResponse{Error: meta.Error}
		}
		if meta.Offset != current || meta.Size < current || len(meta.SHA256) != 64 {
			stream.Close()
			out.Close()
			return linkResponse{Error: "invalid download resume metadata"}
		}
		if expectedSize >= 0 && (expectedSize != meta.Size || expectedHash != meta.SHA256) {
			stream.Close()
			out.Close()
			return linkResponse{Error: "remote file changed during resumed download"}
		}
		expectedSize, expectedHash = meta.Size, meta.SHA256
		retry := false
		for {
			msg, recvErr := streamRecvMessage(ctx, stream)
			if recvErr != nil {
				retry = errors.Is(recvErr, arpl.ErrLinkDisconnected)
				err = recvErr
				break
			}
			if msg.Error != "" {
				err = errors.New(msg.Error)
				break
			}
			switch msg.Action {
			case "download_chunk":
				raw, decodeErr := base64.RawStdEncoding.DecodeString(msg.Data)
				if decodeErr != nil || msg.Offset != current {
					err = errors.New("invalid download chunk")
					break
				}
				if _, e = out.Write(raw); e != nil {
					err = e
					break
				}
				current += int64(len(raw))
			case "download_done":
				if !msg.OK || current != expectedSize {
					err = errors.New("download ended at unexpected size")
					break
				}
				if e = out.Sync(); e != nil {
					err = e
					break
				}
				stream.Close()
				out.Close()
				size, digest, digestErr := localDigest(part)
				if digestErr != nil || size != expectedSize || digest != expectedHash {
					if digestErr == nil {
						digestErr = errors.New("download SHA-256 mismatch")
					}
					return linkResponse{Error: digestErr.Error()}
				}
				if overwrite {
					_ = os.Remove(dest)
				}
				if e = os.Rename(part, dest); e != nil {
					return linkResponse{Error: e.Error()}
				}
				return linkResponse{OK: true, Summary: fmt.Sprintf("pulled %s -> %s (%d bytes, sha256=%s)", src, dest, size, digest)}
			default:
				err = fmt.Errorf("unexpected response %q", msg.Action)
			}
			if err != nil {
				break
			}
		}
		stream.Close()
		_ = out.Sync()
		_ = out.Close()
		if retry {
			continue
		}
		if err != nil {
			return linkResponse{Error: err.Error()}
		}
	}
}

func callLinkState(stateFile string, req linkRequest, timeout time.Duration) (linkResponse, error) {
	state, err := readLinkState(stateFile)
	if err != nil {
		return linkResponse{}, err
	}
	req.Token = state.Token
	dialer := net.Dialer{Timeout: minDuration(timeout, 2*time.Second)}
	conn, err := dialer.Dial("tcp", state.Address)
	if err != nil {
		return linkResponse{}, err
	}
	defer conn.Close()
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err = json.NewEncoder(conn).Encode(req); err != nil {
		return linkResponse{}, err
	}
	var resp linkResponse
	if err = json.NewDecoder(io.LimitReader(conn, linkControlMaxResponse)).Decode(&resp); err != nil {
		return linkResponse{}, err
	}
	return resp, nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 || a > b {
		return b
	}
	return a
}

func linkStatus(args []string) {
	f := flag.NewFlagSet("link status", flag.ExitOnError)
	stateFile := linkStateFile()
	f.StringVar(&stateFile, "control-state", stateFile, "owner-only local daemon state file")
	_ = f.Parse(args)
	resp, err := callLinkState(stateFile, linkRequest{Op: "status"}, time.Second)
	if err != nil {
		fmt.Printf("resident=stopped_or_unreachable error=%q\n", err.Error())
		return
	}
	fmt.Printf("resident=running connected=%t path=%s latency_ms=%d summary=%q\n", resp.Connected, resp.Path, resp.LatencyMS, resp.Summary)
}

func linkStop(args []string) {
	f := flag.NewFlagSet("link stop", flag.ExitOnError)
	stateFile := linkStateFile()
	settingsFile, peerKey, stopMarker := "", "", ""
	f.StringVar(&stateFile, "control-state", stateFile, "owner-only local daemon state file")
	f.StringVar(&settingsFile, "settings-file", "", "ARPL settings file")
	f.StringVar(&peerKey, "peer-key", "", "peer public key for settings-derived control state")
	f.StringVar(&stopMarker, "intentional-stop-marker", "", "owner-only durable intentional-disconnect marker")
	_ = f.Parse(args)
	if settingsFile != "" && peerKey != "" {
		if marker, ok := peerStopMarkerForKey(settingsFile, peerKey); ok {
			stopMarker = marker
			for _, p := range mustLoadSettingsPeers(settingsFile) {
				if peerKeyEqual(p.PublicKey, peerKey) {
					stateFile = peerSupervisorPaths(settingsFile, p).Control
					break
				}
			}
		}
	}
	if stopMarker == "" {
		stopMarker = forceStopFile(stateFile)
	}
	if err := writePeerStopMarker(stopMarker); err != nil {
		fatal(err)
	}
	resp, err := callLinkState(stateFile, linkRequest{Op: "stop"}, 2*time.Second)
	if err != nil {
		fmt.Println("ARPL resident link stopped; durable intentional-disconnect marker written")
		return
	}
	fmt.Println(resp.Summary)
}

func mustLoadSettingsPeers(path string) []PeerSettings {
	s, err := loadSettings(path)
	if err != nil {
		return nil
	}
	return s.Peers
}

func linkExec(args []string) {
	f := flag.NewFlagSet("link exec", flag.ExitOnError)
	stateFile := linkStateFile()
	cwd := ""
	timeout := 30 * time.Second
	f.StringVar(&stateFile, "control-state", stateFile, "owner-only local daemon state file")
	f.StringVar(&cwd, "cwd", "", "remote working directory")
	f.DurationVar(&timeout, "timeout", timeout, "remote command timeout")
	_ = f.Parse(args)
	argv := f.Args()
	if len(argv) == 0 {
		fatal(errors.New("exec requires argv after flags"))
	}
	resp, err := callLinkState(stateFile, linkRequest{Op: "exec", Argv: argv, Cwd: cwd, TimeoutMS: timeout.Milliseconds()}, timeout+45*time.Second)
	if err != nil {
		fatal(err)
	}
	renderExecResponse(resp)
}

func renderExecResponse(resp linkResponse) {
	if resp.Stdout != "" {
		fmt.Fprint(os.Stdout, resp.Stdout)
	}
	if resp.Stderr != "" {
		fmt.Fprint(os.Stderr, resp.Stderr)
	}
	if resp.Error != "" {
		fmt.Fprintln(os.Stderr, "ARPL:", resp.Error)
	}
	if resp.Truncated {
		fmt.Fprintln(os.Stderr, "ARPL: output truncated by server limit")
	}
	if !resp.OK {
		if resp.ExitCode > 0 && resp.ExitCode < 256 {
			os.Exit(resp.ExitCode)
		}
		os.Exit(1)
	}
}

func linkSend(args []string) {
	f := flag.NewFlagSet("link send", flag.ExitOnError)
	stateFile := linkStateFile()
	src, dest := "", ""
	f.StringVar(&stateFile, "control-state", stateFile, "owner-only local daemon state file")
	f.StringVar(&src, "src", "", "local source file")
	f.StringVar(&dest, "dest", "", "remote destination relative to server file root")
	_ = f.Parse(args)
	resp, err := callLinkState(stateFile, linkRequest{Op: "send", Src: src, Dest: dest}, 24*time.Hour)
	if err != nil {
		fatal(err)
	}
	if !resp.OK {
		fatal(errors.New(resp.Error))
	}
	fmt.Println(resp.Summary)
}

func linkPull(args []string) {
	f := flag.NewFlagSet("link pull", flag.ExitOnError)
	stateFile := linkStateFile()
	src, dest := "", ""
	overwrite := false
	f.StringVar(&stateFile, "control-state", stateFile, "owner-only local daemon state file")
	f.StringVar(&src, "src", "", "remote source relative to server file root")
	f.StringVar(&dest, "dest", "", "local destination file")
	f.BoolVar(&overwrite, "overwrite", false, "replace an existing completed destination")
	_ = f.Parse(args)
	resp, err := callLinkState(stateFile, linkRequest{Op: "pull", Src: src, Dest: dest, Overwrite: overwrite}, 24*time.Hour)
	if err != nil {
		fatal(err)
	}
	if !resp.OK {
		fatal(errors.New(resp.Error))
	}
	fmt.Println(resp.Summary)
}

func hasCLIFlag(args []string, names ...string) bool {
	for _, arg := range args {
		for _, name := range names {
			if arg == name || strings.HasPrefix(arg, name+"=") {
				return true
			}
		}
	}
	return false
}

func removeControlStateArg(args []string) ([]string, string, bool, error) {
	out := make([]string, 0, len(args))
	stateFile := ""
	found := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-control-state" || arg == "--control-state":
			if i+1 >= len(args) {
				return nil, "", true, errors.New("control-state requires a path")
			}
			stateFile = args[i+1]
			found = true
			i++
		case strings.HasPrefix(arg, "-control-state="):
			stateFile = strings.TrimPrefix(arg, "-control-state=")
			found = true
		case strings.HasPrefix(arg, "--control-state="):
			stateFile = strings.TrimPrefix(arg, "--control-state=")
			found = true
		default:
			out = append(out, arg)
		}
	}
	return out, stateFile, found, nil
}

func sameControlPath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA == nil {
		a = aa
	}
	if errB == nil {
		b = bb
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func androidDirectArgs(args []string) ([]string, error) {
	out, stateFile, found, err := removeControlStateArg(args)
	if err != nil {
		return nil, err
	}
	if !found {
		return out, nil
	}

	settingsFile := filepath.Join(filepath.Dir(stateFile), "settings.json")
	s, err := loadSettings(settingsFile)
	if err != nil {
		return nil, fmt.Errorf("Android direct mode cannot load %s: %w", settingsFile, err)
	}
	for _, p := range s.Peers {
		if !p.Enabled || !sameControlPath(p.ControlState, stateFile) {
			continue
		}
		if !hasCLIFlag(out, "-settings-file", "--settings-file") {
			out = append([]string{"--settings-file", settingsFile}, out...)
		}
		if !hasCLIFlag(out, "-peer-key", "--peer-key") {
			out = append([]string{"--peer-key", p.PublicKey}, out...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("Android direct mode cannot map control state %s to an enabled peer", stateFile)
}

func shouldUseResident(args []string) bool {
	directFlags := []string{
		"-addr", "--addr", "-peer-key", "--peer-key", "-ca-file", "--ca-file",
		"-key-file", "--key-file", "-session-file", "--session-file",
		"-relay-url", "--relay-url", "-relay-pair", "--relay-pair",
		"-relay-token-file", "--relay-token-file", "-relay-insecure-http", "--relay-insecure-http",
	}
	explicitControl := false
	for _, arg := range args {
		if arg == "-control-state" || arg == "--control-state" ||
			strings.HasPrefix(arg, "-control-state=") || strings.HasPrefix(arg, "--control-state=") {
			explicitControl = true
		}
		for _, prefix := range directFlags {
			if arg == prefix || strings.HasPrefix(arg, prefix+"=") {
				return false
			}
		}
	}
	if explicitControl {
		return true
	}
	_, err := os.Stat(linkStateFile())
	return err == nil
}

func smartExec(args []string) {
	if runtime.GOOS == "android" {
		directArgs, err := androidDirectArgs(args)
		if err != nil {
			fatal(err)
		}
		execRemote(directArgs)
		return
	}
	if shouldUseResident(args) {
		linkExec(args)
		return
	}
	execRemote(args)
}

func smartSend(args []string) {
	if runtime.GOOS == "android" {
		directArgs, err := androidDirectArgs(args)
		if err != nil {
			fatal(err)
		}
		sendFile(directArgs)
		return
	}
	if shouldUseResident(args) {
		linkSend(args)
		return
	}
	sendFile(args)
}

func smartPull(args []string) {
	if runtime.GOOS == "android" {
		directArgs, err := androidDirectArgs(args)
		if err != nil {
			fatal(err)
		}
		pullFile(directArgs)
		return
	}
	if shouldUseResident(args) {
		linkPull(args)
		return
	}
	pullFile(args)
}

func smartTerminal(args []string) {
	if runtime.GOOS == "android" {
		directArgs, err := androidDirectArgs(args)
		if err != nil {
			fatal(err)
		}
		terminalRemote(directArgs)
		return
	}
	if shouldUseResident(args) {
		linkTerminal(args)
		return
	}
	terminalRemote(args)
}
