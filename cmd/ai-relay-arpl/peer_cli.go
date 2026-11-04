package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ai-relay/ai-relay/internal/arpl"
)

func peerCommand(args []string) {
	if len(args) == 0 {
		fatal(errors.New("peer requires add|remove|list|show|test|rename|enable|disable"))
	}
	path := defaultSettingsPath()
	if len(args) >= 2 && args[0] == "--file" {
		path = args[1]
		args = args[2:]
	}
	if len(args) == 0 {
		fatal(errors.New("peer operation is required"))
	}
	s, err := loadSettings(path)
	if err != nil {
		fatal(err)
	}
	name := func() string {
		if len(args) > 1 {
			return args[1]
		}
		return ""
	}()
	switch args[0] {
	case "list":
		for _, p := range s.Peers {
			fmt.Printf("%s enabled=%t auto=%t key=%t\n", p.Name, p.Enabled, p.AutoConnect, p.PublicKey != "")
		}
	case "show":
		p, ok := findPeer(s, name)
		if !ok {
			fatal(errors.New("peer not found"))
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(b))
	case "add":
		f := flag.NewFlagSet("peer add", flag.ExitOnError)
		p := PeerSettings{Enabled: true, AutoConnect: true, Heartbeat: s.Client.Heartbeat}
		f.StringVar(&p.Name, "name", "", "peer name")
		f.StringVar(&p.PublicKey, "public-key", "", "peer public key")
		f.StringVar(&p.OutboundPair, "outbound-pair", "", "outbound relay pair")
		f.StringVar(&p.InboundPair, "inbound-pair", "", "inbound relay pair")
		caps := ""
		f.StringVar(&caps, "capabilities", "", "comma-separated capabilities")
		_ = f.Parse(args[1:])
		p.Capabilities = splitCaps(caps)
		if p.Name == "" {
			fatal(errors.New("-name is required"))
		}
		if _, ok := findPeer(s, p.Name); ok {
			fatal(errors.New("peer already exists"))
		}
		s.Peers = append(s.Peers, p)
		if err = saveSettings(path, s); err != nil {
			fatal(err)
		}
		fmt.Println("peer added")
	case "remove":
		mutatePeer(path, &s, name)
	case "rename":
		if len(args) < 3 {
			fatal(errors.New("peer rename OLD NEW"))
		}
		p, ok := findPeer(s, args[1])
		if !ok {
			fatal(errors.New("peer not found"))
		}
		p.Name = args[2]
		if err = saveSettings(path, s); err != nil {
			fatal(err)
		}
		fmt.Println("peer renamed")
	case "enable", "disable":
		p, ok := findPeer(s, name)
		if !ok {
			fatal(errors.New("peer not found"))
		}
		p.Enabled = args[0] == "enable"
		if err = saveSettings(path, s); err != nil {
			fatal(err)
		}
		marker := peerStopMarker(path, *p)
		if p.Enabled {
			if err = clearPeerStopMarker(marker); err != nil {
				fatal(err)
			}
		} else if err = writePeerStopMarker(marker); err != nil {
			fatal(err)
		}
		fmt.Println("peer updated")
	case "test":
		p, ok := findPeer(s, name)
		if !ok {
			fatal(errors.New("peer not found"))
		}
		if p.PublicKey == "" {
			fatal(errors.New("peer has no public key"))
		}
		if _, err = decodePublic(p.PublicKey); err != nil {
			fatal(err)
		}
		addr := ""
		if len(p.LANAddresses) > 0 {
			addr = p.LANAddresses[0]
		} else if len(p.DirectAddresses) > 0 {
			addr = p.DirectAddresses[0]
		}
		if addr == "" && p.RelayURL == "" && s.Relay.URL == "" {
			fatal(errors.New("peer identity is valid but no direct or relay route is configured"))
		}
		_, session := defaults()
		if p.SessionFile != "" {
			session = p.SessionFile
		}
		o := clientOptions{addr: addr, key: s.Security.KeyFile, session: session, peer: p.PublicKey, relayURL: p.RelayURL, relayPair: p.OutboundPair, relayTokenFile: s.Security.RelayTokenFile}
		if o.relayURL == "" {
			o.relayURL = s.Relay.URL
		}
		c, connectErr := openRPC(o)
		if connectErr != nil {
			fatal(connectErr)
		}
		defer c.Close()
		fmt.Printf("peer reachable path=%s latency_ms=%d\n", c.route.Kind, c.route.Latency.Milliseconds())
	default:
		fatal(errors.New("unknown peer operation"))
	}
}
func splitCaps(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, x := range strings.Split(v, ",") {
		if strings.TrimSpace(x) != "" {
			out = append(out, strings.TrimSpace(x))
		}
	}
	return arpl.NormalizeCapabilities(out)
}
func findPeer(s ARPLSettings, name string) (*PeerSettings, bool) {
	for i := range s.Peers {
		if strings.EqualFold(s.Peers[i].Name, name) {
			return &s.Peers[i], true
		}
	}
	return nil, false
}
func mutatePeer(path string, s *ARPLSettings, name string) {
	for i := range s.Peers {
		if strings.EqualFold(s.Peers[i].Name, name) {
			s.Peers = append(s.Peers[:i], s.Peers[i+1:]...)
			if err := saveSettings(path, *s); err != nil {
				fatal(err)
			}
			fmt.Println("peer removed")
			return
		}
	}
	fatal(errors.New("peer not found"))
}

func enrollmentCommand(args []string) {
	if len(args) > 0 && args[0] == "consume" {
		enrollmentConsume(args[1:])
		return
	}
	f := flag.NewFlagSet("enrollment", flag.ExitOnError)
	key, _ := defaults()
	peerKey := ""
	ttl := 5 * time.Minute
	f.StringVar(&key, "key-file", key, "local identity file")
	f.StringVar(&peerKey, "peer-key", "", "peer public key")
	f.DurationVar(&ttl, "ttl", ttl, "payload lifetime (max 15m)")
	_ = f.Parse(args)
	if peerKey == "" {
		fatal(errors.New("-peer-key is required"))
	}
	pub, err := decodePublic(peerKey)
	if err != nil {
		fatal(err)
	}
	id, err := load(key)
	if err != nil {
		fatal(err)
	}
	m := arpl.EnrollmentManager{Identity: id, TTL: ttl, StorePath: key + ".enrollment-used"}
	p, err := m.Issue(pub)
	if err != nil {
		fatal(err)
	}
	payload, err := arpl.EncodeEnrollment(p)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("code=%s\nexpires=%s\npayload=%s\n", p.Code, time.Unix(p.Expires, 0).UTC().Format(time.RFC3339), payload)
}

func enrollmentConsume(args []string) {
	f := flag.NewFlagSet("enrollment consume", flag.ExitOnError)
	defaultKey, _ := defaults()
	key := defaultKey
	peerKey, payload, payloadFile, path, name := "", "", "", "", "enrolled-peer"
	f.StringVar(&key, "key-file", key, "local identity file")
	f.StringVar(&peerKey, "peer-key", "", "enrolling peer public key (optional when payload carries it)")
	f.StringVar(&payload, "payload", "", "one-time enrollment payload")
	f.StringVar(&payloadFile, "payload-file", "", "file containing an enrollment payload")
	f.StringVar(&path, "settings-file", defaultSettingsPath(), "settings file")
	f.StringVar(&name, "name", name, "peer name")
	_ = f.Parse(args)
	if payload != "" && payloadFile != "" {
		fatal(errors.New("enroll consume accepts either -payload or -payload-file, not both"))
	}
	if payload == "" && payloadFile != "" {
		b, err := os.ReadFile(payloadFile)
		if err != nil {
			fatal(err)
		}
		payload = strings.TrimSpace(string(b))
	}
	if payload == "" {
		fatal(errors.New("enroll consume requires -payload"))
	}
	// Android/Termux and other isolated installs pass the settings file but
	// cannot rely on the process HOME. Resolve the configured identity unless
	// the caller explicitly selected another key path.
	if key == defaultKey {
		if configured, settingsErr := loadSettings(path); settingsErr == nil && configured.Security.KeyFile != "" {
			key = configured.Security.KeyFile
		}
	}
	p, err := arpl.DecodeEnrollment(payload)
	if err != nil {
		fatal(err)
	}
	if peerKey == "" {
		peerKey = p.PeerPublicKey
	}
	pub, err := decodePublic(peerKey)
	if err != nil {
		fatal(err)
	}
	id, err := load(key)
	if err != nil {
		fatal(err)
	}
	m := arpl.EnrollmentManager{Identity: id, StorePath: key + ".enrollment-used"}
	if err = m.Consume(p, pub); err != nil {
		fatal(err)
	}
	s, err := loadSettings(path)
	if err != nil {
		fatal(err)
	}
	if _, ok := findPeer(s, name); ok {
		fatal(errors.New("peer name already exists"))
	}
	s.Peers = append(s.Peers, PeerSettings{Name: name, Enabled: true, AutoConnect: true, PublicKey: peerKey, Capabilities: arpl.AllCapabilities()})
	if err = saveSettings(path, s); err != nil {
		fatal(err)
	}
	fmt.Println("peer enrolled")
}
