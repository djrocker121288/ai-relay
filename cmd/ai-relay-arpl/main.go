// Command ai-relay-arpl exposes the additive ARPL v0.2 control surface.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ai-relay/ai-relay/internal/arpl"
)

var buildID = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "status":
		status(os.Args[2:])
	case "key":
		key(os.Args[2:])
	case "connect":
		linkRun(os.Args[2:])
	case "link":
		linkCommand(os.Args[2:])
	case "serve":
		serve(os.Args[2:])
	case "host":
		hostCommand(os.Args[2:])
	case "client":
		clientCommand(os.Args[2:])
	case "supervisor":
		supervisorCommand(os.Args[2:])
	case "relay":
		relay(os.Args[2:])
	case "disconnect":
		disconnect(os.Args[2:])
	case "exec":
		smartExec(os.Args[2:])
	case "send":
		smartSend(os.Args[2:])
	case "pull":
		smartPull(os.Args[2:])
	case "terminal":
		smartTerminal(os.Args[2:])
	case "settings":
		settingsCommand(os.Args[2:])
	case "peer":
		peerCommand(os.Args[2:])
	case "enroll":
		enrollmentCommand(os.Args[2:])
	case "doctor":
		doctorCommand(os.Args[2:])
	case "fleet":
		fleetCommand(os.Args[2:])
	case "audit":
		auditCommand(os.Args[2:])
	case "sync":
		syncCommand(os.Args[2:])
	case "job":
		jobCommand(os.Args[2:])
	case "update":
		updateCommand(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("ai-relay-arpl host|client|supervisor|status|serve|relay|connect|link|key|exec|send|pull|terminal|settings|peer|enroll|doctor|fleet|sync|job|update|audit")
}

func supervisorCommand(args []string) {
	if len(args) == 0 || args[0] == "run" {
		if len(args) > 0 {
			args = args[1:]
		}
		supervisorRun(args)
		return
	}
	fatal(errors.New("supervisor requires run"))
}
func defaults() (string, string) {
	d, _ := os.UserConfigDir()
	if d == "" {
		d = "."
	}
	d = filepath.Join(d, "ai-relay", "arpl")
	return filepath.Join(d, "identity.json"), filepath.Join(d, "session.json")
}
func load(path string) (arpl.Identity, error) { return (arpl.FileKeyStore{Path: path}).Load() }

func readSecretFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("secret file path is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", errors.New("secret file is empty")
	}
	return v, nil
}

func status(args []string) {
	f := flag.NewFlagSet("status", flag.ExitOnError)
	key, _ := defaults()
	f.StringVar(&key, "key-file", key, "owner-only ARPL identity file")
	_ = f.Parse(args)
	id, err := load(key)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("ARPL identity: not created")
			return
		}
		fatal(err)
	}
	fmt.Printf("device_id=%s\nfingerprint=%s\npublic_key=%s\n", id.DeviceID, arpl.Fingerprint(id.PublicKey), base64.RawStdEncoding.EncodeToString(id.PublicKey))
}
func key(args []string) {
	if len(args) == 0 {
		fatal(errors.New("key requires fingerprint or rotate"))
	}
	keyPath, _ := defaults()
	switch args[0] {
	case "fingerprint":
		f := flag.NewFlagSet("key fingerprint", flag.ExitOnError)
		f.StringVar(&keyPath, "key-file", keyPath, "owner-only ARPL identity file")
		_ = f.Parse(args[1:])
		id, err := load(keyPath)
		if err != nil {
			fatal(err)
		}
		fmt.Println(arpl.Fingerprint(id.PublicKey))
	case "rotate":
		f := flag.NewFlagSet("key rotate", flag.ExitOnError)
		f.StringVar(&keyPath, "key-file", keyPath, "owner-only ARPL identity file")
		_ = f.Parse(args[1:])
		id, err := arpl.NewIdentity()
		if err != nil {
			fatal(err)
		}
		if err = (arpl.FileKeyStore{Path: keyPath}).Save(id); err != nil {
			fatal(err)
		}
		fmt.Printf("rotated device_id=%s; re-enroll this public key before connecting\n", id.DeviceID)
	default:
		fatal(errors.New("unknown key operation"))
	}
}

func hostCommand(args []string) {
	if len(args) > 0 && args[0] == "run" {
		args = args[1:]
	}
	serve(args)
}

func clientCommand(args []string) {
	if len(args) == 0 {
		fatal(errors.New("client requires connect|status|disconnect|exec|send|pull|terminal"))
	}
	switch args[0] {
	case "connect", "run":
		linkRun(args[1:])
	case "status":
		linkStatus(args[1:])
	case "disconnect", "stop":
		linkStop(args[1:])
	case "exec":
		smartExec(args[1:])
	case "send":
		smartSend(args[1:])
	case "pull":
		smartPull(args[1:])
	case "terminal":
		smartTerminal(args[1:])
	default:
		fatal(errors.New("unknown client operation"))
	}
}

func loadAuthorizedKeys(path string) ([]ed25519.PublicKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []ed25519.PublicKey
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Permit an optional trailing label/comment, similar to authorized_keys.
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pub, err := decodePublic(fields[0])
		if err != nil {
			return nil, fmt.Errorf("authorized key %q: %w", fields[0], err)
		}
		out = append(out, pub)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func serve(args []string) {
	f := flag.NewFlagSet("serve", flag.ExitOnError)
	key, _ := defaults()
	addr, peer, authorizedKeys, certFile, certKey, fileRoot := ":9443", "", "", "", "", ""
	relayURL, relayPair, relayTokenFile := "", "", ""
	settingsFile := ""
	var loadedSettings ARPLSettings
	relayInsecureHTTP := false
	allowExec := false
	maxFile := int64(8 << 30)
	maxOutput := 4 << 20
	commandTimeout := 2 * time.Minute
	f.StringVar(&addr, "addr", addr, "TLS listen address")
	f.StringVar(&key, "key-file", key, "owner-only ARPL identity file")
	f.StringVar(&peer, "peer-key", peer, "allowlisted peer Ed25519 public key (hex/base64)")
	f.StringVar(&authorizedKeys, "authorized-keys", authorizedKeys, "file of trusted ARPL public keys, one per line")
	f.StringVar(&certFile, "cert-file", certFile, "TLS certificate PEM")
	f.StringVar(&certKey, "tls-key-file", certKey, "TLS private key PEM")
	f.StringVar(&relayURL, "relay-url", relayURL, "ARPL relay URL (https:// legacy or wss:// preferred)")
	f.StringVar(&settingsFile, "settings-file", settingsFile, "ARPL settings file")
	f.StringVar(&relayPair, "relay-pair", relayPair, "ARPL relay pair ID")
	f.StringVar(&relayTokenFile, "relay-token-file", relayTokenFile, "file containing ARPL relay bearer token")
	f.BoolVar(&relayInsecureHTTP, "relay-insecure-http", false, "allow plain HTTP relay (local testing only)")
	f.StringVar(&fileRoot, "file-root", fileRoot, "allowed root for send/pull; empty disables files")
	f.BoolVar(&allowExec, "allow-exec", allowExec, "allow remote argv execution")
	f.Int64Var(&maxFile, "max-file", maxFile, "maximum transferred file size in bytes")
	f.IntVar(&maxOutput, "max-output", maxOutput, "maximum stdout/stderr bytes each")
	f.DurationVar(&commandTimeout, "command-timeout", commandTimeout, "maximum remote command time")
	_ = f.Parse(args)
	if settingsFile != "" {
		s, e := loadSettings(settingsFile)
		if e != nil {
			fatal(e)
		}
		if e = validateSettings(s); e != nil {
			fatal(e)
		}
		loadedSettings = s
		key = s.Security.KeyFile
		if relayTokenFile == "" {
			relayTokenFile = s.Security.RelayTokenFile
		}
		if authorizedKeys == "" {
			authorizedKeys = s.Host.AuthorizedKeys
		}
		if relayURL == "" {
			relayURL = s.Relay.URL
		}
		fileRoot = s.Host.FileRoot
		allowExec = s.Host.AllowExec
		maxFile = s.Host.MaxFileBytes
		maxOutput = s.Host.MaxOutputBytes
		if d, e := time.ParseDuration(s.Host.CommandTimeout); e == nil {
			commandTimeout = d
		}
		if peer == "" && len(s.Peers) > 0 {
			for _, p := range s.Peers {
				if p.Enabled && p.PublicKey != "" {
					peer = p.PublicKey
					if relayPair == "" {
						relayPair = p.InboundPair
					}
					break
				}
			}
		}
	}
	if peer == "" && authorizedKeys == "" {
		fatal(errors.New("-peer-key or -authorized-keys is required"))
	}
	id, err := load(key)
	if err != nil {
		fatal(err)
	}
	var pubs []ed25519.PublicKey
	if peer != "" {
		pub, e := decodePublic(peer)
		if e != nil {
			fatal(e)
		}
		pubs = append(pubs, pub)
	}
	filePubs, e := loadAuthorizedKeys(authorizedKeys)
	if e != nil {
		fatal(e)
	}
	pubs = append(pubs, filePubs...)
	if len(pubs) == 0 {
		fatal(errors.New("no valid authorized peer keys"))
	}

	var listener net.Listener
	if relayURL != "" {
		if relayPair == "" {
			fatal(errors.New("-relay-pair is required with -relay-url"))
		}
		token := ""
		if relayTokenFile != "" {
			var e error
			token, e = readSecretFile(relayTokenFile)
			if e != nil {
				fatal(e)
			}
		}
		if strings.HasPrefix(strings.ToLower(relayURL), "ws://") || strings.HasPrefix(strings.ToLower(relayURL), "wss://") {
			var rl *arpl.WSRelayListener
			rl, err = arpl.NewWSRelayListener(relayURL, relayPair, token, nil, relayInsecureHTTP)
			if err == nil {
				rl.Identity = id
				listener = rl
			}
		} else {
			var rl *arpl.HTTPRelayListener
			rl, err = arpl.NewHTTPRelayListener(relayURL, relayPair, token, nil, relayInsecureHTTP)
			if err == nil {
				rl.Identity = id
				listener = rl
			}
		}
	} else {
		if certFile == "" || certKey == "" {
			fatal(errors.New("-cert-file and -tls-key-file are required without -relay-url"))
		}
		cert, e := tls.LoadX509KeyPair(certFile, certKey)
		if e != nil {
			fatal(e)
		}
		listener, err = arpl.TLSListener(addr, cert)
	}
	if err != nil {
		fatal(err)
	}
	defer listener.Close()

	ops := &arpl.OperationServer{AllowExec: allowExec, FileRoot: fileRoot, MaxFileSize: maxFile, MaxOutput: maxOutput, CommandTimeout: commandTimeout, JobsDir: filepath.Join(filepath.Dir(key), "jobs"), Audit: &arpl.AuditLog{Path: filepath.Join(filepath.Dir(key), "audit.jsonl")}, PreserveTerminals: true, TerminalTTL: 10 * time.Minute}
	pathKind := "direct"
	if relayURL != "" {
		pathKind = "relay"
	}
	srv := &arpl.Server{Listener: listener, Identity: id, Peers: arpl.NewPeerRegistry(), Sessions: arpl.NewSessionRegistry(), Handler: ops.Handle, OnDisconnect: ops.AbortStreams, Fleet: &arpl.FleetStore{Path: filepath.Join(filepath.Dir(key), "fleet.json")}, Audit: ops.Audit, Path: pathKind}
	for _, pub := range pubs {
		deviceID := srv.Peers.Allow(pub)
		for _, p := range loadedSettings.Peers {
			if p.PublicKey != "" {
				if configured, e := decodePublic(p.PublicKey); e == nil && configured.Equal(pub) && len(p.Capabilities) > 0 {
					_ = srv.Peers.SetCapabilities(deviceID, p.Capabilities)
				}
			}
		}
	}
	if err = srv.Serve(context.Background()); err != nil {
		fatal(err)
	}
}

func relay(args []string) {
	f := flag.NewFlagSet("relay", flag.ExitOnError)
	listen := "127.0.0.1:18790"
	tokenFile := ""
	authorizedKeys := ""
	f.StringVar(&listen, "listen", listen, "loopback HTTP listen address")
	f.StringVar(&tokenFile, "token-file", tokenFile, "optional file containing legacy ARPL relay bearer token")
	f.StringVar(&authorizedKeys, "authorized-keys", authorizedKeys, "trusted ARPL public keys for signed relay requests")
	_ = f.Parse(args)

	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		fatal(err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		fatal(errors.New("ARPL relay must listen on loopback; publish it through HTTPS reverse proxy/tunnel"))
	}
	token := ""
	if tokenFile != "" {
		var err error
		token, err = readSecretFile(tokenFile)
		if err != nil {
			fatal(err)
		}
	}
	httpHub := arpl.NewHTTPRelayHub(token)
	wsHub := arpl.NewWSRelayHub(token)
	if token == "" {
		pubs, err := loadAuthorizedKeys(authorizedKeys)
		if err != nil {
			fatal(err)
		}
		if len(pubs) == 0 {
			fatal(errors.New("-authorized-keys is required when -token-file is not used"))
		}
		peers := arpl.NewPeerRegistry()
		for _, pub := range pubs {
			peers.Allow(pub)
		}
		httpHub.Peers = peers
		wsHub.Peers = peers
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
			wsHub.Handler().ServeHTTP(w, r)
			return
		}
		httpHub.Handler().ServeHTTP(w, r)
	})
	server := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       0,
	}
	if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
}

func connect(args []string) {
	linkRun(args)
}

func disconnect(args []string) {
	if _, err := os.Stat(linkStateFile()); err == nil {
		linkStop(nil)
		return
	}
	f := flag.NewFlagSet("disconnect", flag.ExitOnError)
	dir, _ := defaults()
	f.StringVar(&dir, "state-dir", filepath.Dir(dir), "ARPL state directory")
	_ = f.Parse(args)
	if err := os.MkdirAll(dir, 0700); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stop"), []byte("stopped\n"), 0600); err != nil {
		fatal(err)
	}
	fmt.Println("ARPL stop marker written")
}

func decodePublic(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("peer key must be 32-byte hex or base64")
	}
	return ed25519.PublicKey(b), nil
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
