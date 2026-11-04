package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ai-relay/ai-relay/internal/arpl"
	"golang.org/x/term"
)

type clientOptions struct {
	addr, key, session, peer, ca        string
	settingsFile                        string
	relayURL, relayPair, relayTokenFile string
	relayInsecureHTTP                   bool
	peerExplicit, sessionExplicit       bool
	relayURLExplicit, relayPairExplicit bool
}

func (o *clientOptions) addFlags(f *flag.FlagSet) {
	o.key, o.session = defaults()
	f.StringVar(&o.settingsFile, "settings-file", "", "ARPL settings file")
	f.StringVar(&o.addr, "addr", "", "ARPL server host:port")
	f.StringVar(&o.key, "key-file", o.key, "owner-only ARPL identity file")
	f.StringVar(&o.session, "session-file", o.session, "owner-only logical session state")
	f.StringVar(&o.peer, "peer-key", "", "allowlisted server Ed25519 public key")
	f.StringVar(&o.ca, "ca-file", "", "CA certificate for TLS server")
	f.StringVar(&o.relayURL, "relay-url", "", "HTTPS ARPL relay URL")
	f.StringVar(&o.relayPair, "relay-pair", "", "ARPL relay pair ID")
	f.StringVar(&o.relayTokenFile, "relay-token-file", "", "file containing ARPL relay bearer token")
	f.BoolVar(&o.relayInsecureHTTP, "relay-insecure-http", false, "allow plain HTTP relay (local testing only)")
}

type rpcClient struct {
	conn   io.ReadWriteCloser
	codec  *arpl.FrameCodec
	state  arpl.SessionState
	store  arpl.FileSessionStore
	seq    uint64
	sendMu sync.Mutex
	route  arpl.RouteStatus
}

func openRPC(o clientOptions) (*rpcClient, error) {
	var lanAddresses, directAddresses []string
	if o.settingsFile != "" {
		s, err := loadSettings(o.settingsFile)
		if err != nil {
			return nil, err
		}
		if err = validateSettings(s); err != nil {
			return nil, err
		}
		o.key = s.Security.KeyFile
		o.session = filepath.Join(filepath.Dir(o.settingsFile), "session.json")
		selectedPeer := false
		for _, p := range s.Peers {
			if !p.Enabled {
				continue
			}
			if o.peer != "" && !peerKeyEqual(p.PublicKey, o.peer) {
				continue
			}
			selectedPeer = true
			if o.peer == "" {
				o.peer = p.PublicKey
			}
			if o.relayPair == "" {
				o.relayPair = p.OutboundPair
			}
			if o.relayURL == "" {
				o.relayURL = p.RelayURL
			}
			lanAddresses = append(lanAddresses, p.LANAddresses...)
			directAddresses = append(directAddresses, p.DirectAddresses...)
			if o.session == filepath.Join(filepath.Dir(o.settingsFile), "session.json") && p.SessionFile != "" {
				o.session = p.SessionFile
			}
			break
		}
		if o.peer != "" && !selectedPeer {
			return nil, errors.New("configured peer is not enabled or present in settings")
		}
		if o.relayURL == "" {
			o.relayURL = s.Relay.URL
		}
	}
	if o.peer == "" {
		return nil, errors.New("-peer-key is required")
	}
	if o.relayURL == "" && o.addr == "" && len(lanAddresses) == 0 && len(directAddresses) == 0 {
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
	}
	store := arpl.FileSessionStore{Path: o.session}
	state, err := store.Load(context.Background())
	if err != nil {
		return nil, err
	}
	if state.SessionID == "" {
		state.SessionID = arpl.NewSessionID()
	}
	peers := arpl.NewPeerRegistry()
	peers.Allow(pub)
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
	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	conn, crypto, selected, err := arpl.ConnectRoutes(dialCtx, id, peers, state.SessionID, routes)
	cancel()
	if err != nil {
		return nil, err
	}
	codec, err := arpl.NewFrameCodec(&crypto)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := store.Save(context.Background(), state); err != nil {
		conn.Close()
		return nil, err
	}
	return &rpcClient{conn: conn, codec: codec, state: state, store: store, seq: 1, route: selected}, nil
}

func (c *rpcClient) Close() error { return c.conn.Close() }

func (c *rpcClient) send(channel arpl.Channel, msg arpl.OpMessage) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	f := arpl.Frame{
		Channel: channel, SessionID: c.state.SessionID, StreamID: 1,
		Sequence: c.seq, Deadline: time.Now().Add(5 * time.Minute), Payload: b,
	}
	c.seq++
	return arpl.WriteFrame(c.conn, c.codec, f)
}

func (c *rpcClient) recv() (arpl.OpMessage, error) {
	f, err := arpl.ReadFrame(c.conn, c.codec)
	if err != nil {
		return arpl.OpMessage{}, err
	}
	var msg arpl.OpMessage
	if err := json.Unmarshal(f.Payload, &msg); err != nil {
		return arpl.OpMessage{}, err
	}
	return msg, nil
}

func execRemote(args []string) {
	f := flag.NewFlagSet("exec", flag.ExitOnError)
	var o clientOptions
	o.addFlags(f)
	cwd := ""
	timeout := 30 * time.Second
	f.StringVar(&cwd, "cwd", "", "remote working directory")
	f.DurationVar(&timeout, "timeout", timeout, "remote command timeout")
	_ = f.Parse(args)
	argv := f.Args()
	if len(argv) == 0 {
		fatal(errors.New("exec requires argv after flags"))
	}
	c, err := openRPC(o)
	if err != nil {
		fatal(err)
	}
	defer c.Close()
	if err = c.send(arpl.ChannelExec, arpl.OpMessage{Action: "exec", Argv: argv, Cwd: cwd, TimeoutMS: timeout.Milliseconds()}); err != nil {
		fatal(err)
	}
	resp, err := c.recv()
	if err != nil {
		fatal(err)
	}
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

func terminalRemote(args []string) {
	f := flag.NewFlagSet("terminal", flag.ExitOnError)
	var o clientOptions
	o.addFlags(f)
	cwd := ""
	rows, cols := 24, 80
	f.StringVar(&cwd, "cwd", "", "remote working directory")
	f.IntVar(&rows, "rows", rows, "terminal rows")
	f.IntVar(&cols, "cols", cols, "terminal columns")
	_ = f.Parse(args)
	argv := f.Args()
	if len(argv) == 0 {
		if runtime.GOOS == "windows" {
			argv = []string{"cmd.exe"}
		} else {
			argv = []string{"/bin/sh"}
		}
	}
	c, err := openRPC(o)
	if err != nil {
		fatal(err)
	}
	defer c.Close()
	if err = c.send(arpl.ChannelTerminal, arpl.OpMessage{Action: "terminal_start", Argv: argv, Cwd: cwd, Rows: rows, Cols: cols}); err != nil {
		fatal(err)
	}
	ready, err := c.recv()
	if err != nil || !ready.OK {
		if err == nil {
			err = errors.New(ready.Error)
		}
		fatal(err)
	}
	terminalID := ready.TerminalID
	var inputSeq uint64
	fd := int(os.Stdin.Fd())
	var old *term.State
	if term.IsTerminal(fd) {
		old, err = term.MakeRaw(fd)
		if err != nil {
			fatal(err)
		}
		defer term.Restore(fd, old)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, e := os.Stdin.Read(buf)
			if n > 0 {
				inputSeq++
				if se := c.send(arpl.ChannelTerminal, arpl.OpMessage{Action: "terminal_input", TerminalID: terminalID, InputSeq: inputSeq, Data: base64.RawStdEncoding.EncodeToString(buf[:n])}); se != nil {
					break
				}
			}
			if e != nil {
				break
			}
		}
		close(done)
	}()
	for {
		m, e := c.recv()
		if e != nil {
			break
		}
		switch m.Action {
		case "terminal_data":
			b, e := base64.RawStdEncoding.DecodeString(m.Data)
			if e == nil {
				_, _ = os.Stdout.Write(b)
			}
		case "terminal_exit":
			return
		}
	}
	_ = c.send(arpl.ChannelTerminal, arpl.OpMessage{Action: "terminal_close", TerminalID: terminalID})
}

func localDigest(path string) (int64, string, error) {
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

func sendFile(args []string) {
	f := flag.NewFlagSet("send", flag.ExitOnError)
	var o clientOptions
	o.addFlags(f)
	src, dest := "", ""
	f.StringVar(&src, "src", "", "local source file")
	f.StringVar(&dest, "dest", "", "remote destination relative to server file root")
	_ = f.Parse(args)
	if src == "" || dest == "" {
		fatal(errors.New("send requires -src and -dest"))
	}
	size, digest, err := localDigest(src)
	if err != nil {
		fatal(err)
	}
	in, err := os.Open(src)
	if err != nil {
		fatal(err)
	}
	defer in.Close()
	c, err := openRPC(o)
	if err != nil {
		fatal(err)
	}
	defer c.Close()
	if err = c.send(arpl.ChannelFile, arpl.OpMessage{Action: "upload_begin", Dest: dest, Size: size, SHA256: digest}); err != nil {
		fatal(err)
	}
	ready, err := c.recv()
	if err != nil || ready.Error != "" {
		if err == nil {
			err = errors.New(ready.Error)
		}
		fatal(err)
	}
	if ready.Done && ready.OK && ready.Offset == size {
		fmt.Printf("already present %s (%d bytes, sha256=%s)\n", dest, size, digest)
		return
	}
	if ready.Offset < 0 || ready.Offset > size {
		fatal(errors.New("server returned invalid resume offset"))
	}
	if _, err = in.Seek(ready.Offset, io.SeekStart); err != nil {
		fatal(err)
	}
	offset := ready.Offset
	buf := make([]byte, arpl.DefaultChunkSize)
	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			msg := arpl.OpMessage{Action: "upload_chunk", Offset: offset, Data: base64.RawStdEncoding.EncodeToString(buf[:n])}
			if err = c.send(arpl.ChannelFile, msg); err != nil {
				fatal(err)
			}
			ack, e := c.recv()
			if e != nil {
				fatal(e)
			}
			if ack.Error != "" {
				fatal(errors.New(ack.Error))
			}
			offset = ack.Offset
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			fatal(readErr)
		}
	}
	if err = c.send(arpl.ChannelFile, arpl.OpMessage{Action: "upload_finish"}); err != nil {
		fatal(err)
	}
	done, err := c.recv()
	if err != nil || done.Error != "" || !done.OK {
		if err == nil {
			err = errors.New(done.Error)
		}
		fatal(err)
	}
	fmt.Printf("sent %s -> %s (%d bytes, sha256=%s)\n", src, dest, size, digest)
}

func pullFile(args []string) {
	f := flag.NewFlagSet("pull", flag.ExitOnError)
	var o clientOptions
	o.addFlags(f)
	src, dest := "", ""
	overwrite := false
	f.StringVar(&src, "src", "", "remote source relative to server file root")
	f.StringVar(&dest, "dest", "", "local destination file")
	f.BoolVar(&overwrite, "overwrite", false, "replace an existing completed destination")
	_ = f.Parse(args)
	if src == "" || dest == "" {
		fatal(errors.New("pull requires -src and -dest"))
	}
	if _, err := os.Stat(dest); err == nil && !overwrite {
		fatal(errors.New("destination exists; use -overwrite"))
	}
	part, err := arpl.SafeLocalPart(dest)
	if err != nil {
		fatal(err)
	}
	offset := int64(0)
	if st, e := os.Stat(part); e == nil {
		if !st.Mode().IsRegular() {
			fatal(errors.New("local .part path is not a regular file"))
		}
		offset = st.Size()
	}
	if err := os.MkdirAll(filepath.Dir(part), 0700); err != nil {
		fatal(err)
	}
	out, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fatal(err)
	}
	defer out.Close()
	c, err := openRPC(o)
	if err != nil {
		fatal(err)
	}
	defer c.Close()
	if err = c.send(arpl.ChannelFile, arpl.OpMessage{Action: "download_begin", Src: src, Offset: offset}); err != nil {
		fatal(err)
	}
	meta, err := c.recv()
	if err != nil || meta.Error != "" {
		if err == nil {
			err = errors.New(meta.Error)
		}
		fatal(err)
	}
	if meta.Offset != offset {
		fatal(errors.New("server resume offset mismatch"))
	}
	current := offset
	for {
		msg, e := c.recv()
		if e != nil {
			fatal(e)
		}
		if msg.Error != "" {
			fatal(errors.New(msg.Error))
		}
		switch msg.Action {
		case "download_chunk":
			raw, e := base64.RawStdEncoding.DecodeString(msg.Data)
			if e != nil || msg.Offset != current {
				fatal(errors.New("invalid download chunk"))
			}
			if _, e = out.Write(raw); e != nil {
				fatal(e)
			}
			current += int64(len(raw))
		case "download_done":
			if !msg.OK || current != meta.Size {
				fatal(errors.New("download ended at unexpected size"))
			}
			if err := out.Sync(); err != nil {
				fatal(err)
			}
			if err := out.Close(); err != nil {
				fatal(err)
			}
			size, digest, err := localDigest(part)
			if err != nil || size != meta.Size || digest != meta.SHA256 {
				if err == nil {
					err = errors.New("download SHA-256 mismatch")
				}
				fatal(err)
			}
			if overwrite {
				_ = os.Remove(dest)
			}
			if err = os.Rename(part, dest); err != nil {
				fatal(err)
			}
			fmt.Printf("pulled %s -> %s (%d bytes, sha256=%s)\n", src, dest, size, digest)
			return
		default:
			fatal(fmt.Errorf("unexpected response %q", msg.Action))
		}
	}
}

var _ ed25519.PublicKey
