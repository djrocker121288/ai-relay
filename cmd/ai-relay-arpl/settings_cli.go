package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ARPLSettings struct {
	Version  int               `json:"version"`
	Device   DeviceSettings    `json:"device"`
	Relay    RelaySettings     `json:"relay"`
	Host     HostSettings      `json:"host"`
	Client   ClientSettings    `json:"client"`
	Security SecuritySettings  `json:"security"`
	Service  ServiceSettings   `json:"service"`
	Peers    []PeerSettings    `json:"peers"`
	Advanced map[string]string `json:"advanced,omitempty"`
}

type DeviceSettings struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

type RelaySettings struct {
	URL            string `json:"url"`
	Listen         string `json:"listen"`
	TunnelEnabled  bool   `json:"tunnel_enabled"`
	TunnelProvider string `json:"tunnel_provider"`
	TunnelHostname string `json:"tunnel_hostname"`
	TunnelPath     string `json:"tunnel_path"`
}

type HostSettings struct {
	Enabled        bool   `json:"enabled"`
	AllowExec      bool   `json:"allow_exec"`
	FileRoot       string `json:"file_root"`
	AuthorizedKeys string `json:"authorized_keys"`
	CommandTimeout string `json:"command_timeout"`
	MaxFileBytes   int64  `json:"max_file_bytes"`
	MaxOutputBytes int    `json:"max_output_bytes"`
}

type ClientSettings struct {
	Enabled      bool   `json:"enabled"`
	Heartbeat    string `json:"heartbeat"`
	ReconnectMin string `json:"reconnect_min"`
	ReconnectMax string `json:"reconnect_max"`
}

type SecuritySettings struct {
	KeyFile        string `json:"key_file"`
	RelayTokenFile string `json:"relay_token_file,omitempty"`
	SecureStore    string `json:"secure_store"`
}

type ServiceSettings struct {
	AutoStart     bool   `json:"auto_start"`
	RestartPolicy string `json:"restart_policy"`
	StartHost     bool   `json:"start_host"`
	StartClient   bool   `json:"start_client"`
}

type PeerSettings struct {
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	PublicKey       string   `json:"public_key"`
	OutboundPair    string   `json:"outbound_pair"`
	InboundPair     string   `json:"inbound_pair"`
	SessionFile     string   `json:"session_file"`
	ControlState    string   `json:"control_state"`
	RelayURL        string   `json:"relay_url,omitempty"`
	Heartbeat       string   `json:"heartbeat,omitempty"`
	AutoConnect     bool     `json:"auto_connect"`
	Capabilities    []string `json:"capabilities,omitempty"`
	LANAddresses    []string `json:"lan_addresses,omitempty"`
	DirectAddresses []string `json:"direct_addresses,omitempty"`
}

func defaultSettingsPath() string {
	d, _ := os.UserConfigDir()
	if d == "" {
		d = "."
	}
	return filepath.Join(d, "ai-relay", "arpl", "settings.json")
}

func defaultSettings() ARPLSettings {
	home, _ := os.UserHomeDir()
	cfg, _ := os.UserConfigDir()
	if cfg == "" {
		cfg = filepath.Join(home, ".config")
	}
	base := filepath.Join(cfg, "ai-relay", "arpl")
	host, _ := os.Hostname()
	if host == "" {
		host = "arpl-device"
	}
	return ARPLSettings{
		Version: 1,
		Device:  DeviceSettings{Name: host, Role: "both"},
		Relay: RelaySettings{
			URL:            "",
			Listen:         "127.0.0.1:18790",
			TunnelEnabled:  false,
			TunnelProvider: "",
			TunnelHostname: "",
			TunnelPath:     "/arpl/relay",
		},
		Host: HostSettings{
			Enabled: true, AllowExec: true, FileRoot: home,
			AuthorizedKeys: filepath.Join(base, "host_authorized_keys"),
			CommandTimeout: "2m", MaxFileBytes: 8 << 30, MaxOutputBytes: 4 << 20,
		},
		Client: ClientSettings{
			Enabled: true, Heartbeat: "5s", ReconnectMin: "1s", ReconnectMax: "60s",
		},
		Security: SecuritySettings{
			KeyFile:     filepath.Join(base, "identity.json"),
			SecureStore: "auto",
		},
		Service: ServiceSettings{
			AutoStart: true, RestartPolicy: "always", StartHost: true, StartClient: true,
		},
		Peers:    []PeerSettings{},
		Advanced: map[string]string{},
	}
}

func loadSettings(path string) (ARPLSettings, error) {
	s := defaultSettings()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	if s.Advanced == nil {
		s.Advanced = map[string]string{}
	}
	return s, nil
}

func saveSettings(path string, s ARPLSettings) error {
	if err := validateSettings(s); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".arpl-settings-*")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	defer os.Remove(tmp)
	if err = tmpFile.Chmod(0600); err == nil {
		_, err = tmpFile.Write(b)
	}
	if err == nil {
		err = tmpFile.Sync()
	}
	if closeErr := tmpFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func validatePairSetting(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	if len(v) != 64 {
		return errors.New("pair ID must be 64 hex characters")
	}
	_, err := hex.DecodeString(v)
	if err != nil {
		return errors.New("pair ID must be hex")
	}
	return nil
}

func validateSettings(s ARPLSettings) error {
	if s.Version <= 0 {
		return errors.New("settings version must be positive")
	}
	switch s.Device.Role {
	case "both", "host", "client", "relay":
	default:
		return errors.New("device role must be both, host, client, or relay")
	}
	if strings.TrimSpace(s.Device.Name) == "" {
		return errors.New("device name is required")
	}
	if s.Relay.URL != "" {
		u, err := url.Parse(s.Relay.URL)
		if err != nil || u.Host == "" {
			return errors.New("relay URL is invalid")
		}
		switch u.Scheme {
		case "wss", "https":
		default:
			return errors.New("relay URL must use wss or https")
		}
	}
	if s.Relay.TunnelEnabled {
		if strings.TrimSpace(s.Relay.TunnelHostname) == "" {
			return errors.New("tunnel hostname is required when tunnel is enabled")
		}
		if !strings.HasPrefix(s.Relay.TunnelPath, "/") {
			return errors.New("tunnel path must start with /")
		}
	}
	for name, value := range map[string]string{
		"heartbeat":       s.Client.Heartbeat,
		"reconnect min":   s.Client.ReconnectMin,
		"reconnect max":   s.Client.ReconnectMax,
		"command timeout": s.Host.CommandTimeout,
	} {
		if _, err := time.ParseDuration(value); err != nil {
			return fmt.Errorf("%s is invalid: %w", name, err)
		}
	}
	min, _ := time.ParseDuration(s.Client.ReconnectMin)
	max, _ := time.ParseDuration(s.Client.ReconnectMax)
	if min <= 0 || max <= 0 || min > max {
		return errors.New("reconnect min/max must be positive and min <= max")
	}
	if s.Host.MaxFileBytes < 0 || s.Host.MaxOutputBytes < 0 {
		return errors.New("size limits cannot be negative")
	}
	switch s.Service.RestartPolicy {
	case "on-failure", "always", "never":
	default:
		return errors.New("restart policy must be on-failure, always, or never")
	}
	switch s.Security.SecureStore {
	case "auto", "file", "keychain", "dpapi", "keystore", "secret-service", "tpm":
	default:
		return errors.New("secure store value is invalid")
	}
	seen := map[string]bool{}
	for i, p := range s.Peers {
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("peer %d has no name", i+1)
		}
		key := strings.ToLower(strings.TrimSpace(p.Name))
		if seen[key] {
			return fmt.Errorf("duplicate peer name %q", p.Name)
		}
		seen[key] = true
		if p.PublicKey != "" {
			if _, err := decodePublic(p.PublicKey); err != nil {
				return fmt.Errorf("peer %q public key: %w", p.Name, err)
			}
		}
		if err := validatePairSetting(p.OutboundPair); err != nil {
			return fmt.Errorf("peer %q outbound pair: %w", p.Name, err)
		}
		if err := validatePairSetting(p.InboundPair); err != nil {
			return fmt.Errorf("peer %q inbound pair: %w", p.Name, err)
		}
		if p.Heartbeat != "" {
			if _, err := time.ParseDuration(p.Heartbeat); err != nil {
				return fmt.Errorf("peer %q heartbeat: %w", p.Name, err)
			}
		}
		for _, address := range append(append([]string{}, p.LANAddresses...), p.DirectAddresses...) {
			if _, _, err := net.SplitHostPort(strings.TrimSpace(address)); err != nil {
				return fmt.Errorf("peer %q route %q is invalid: %w", p.Name, address, err)
			}
		}
	}
	return nil
}

func settingsCommand(args []string) {
	path := defaultSettingsPath()
	if len(args) >= 2 && args[0] == "--file" {
		path = args[1]
		args = args[2:]
	} else if len(args) >= 3 && args[1] == "--file" {
		path = args[2]
		args = append([]string{args[0]}, args[3:]...)
	}
	if len(args) == 0 || args[0] == "edit" || args[0] == "tui" {
		if err := runSettingsTUI(path); err != nil {
			fatal(err)
		}
		return
	}
	switch args[0] {
	case "apply":
		f := flag.NewFlagSet("settings apply", flag.ExitOnError)
		dry := false
		platform := runtime.GOOS
		output := ""
		f.BoolVar(&dry, "dry-run", false, "render without writing")
		f.StringVar(&platform, "platform", platform, "linux|darwin|windows|android")
		f.StringVar(&output, "output-dir", output, "generated service output directory")
		_ = f.Parse(args[1:])
		if err := applySettings(path, platform, output, dry); err != nil {
			fatal(err)
		}
		if !dry {
			fmt.Println("ARPL service configuration applied")
		}
	case "path":
		fmt.Println(path)
	case "show":
		s, err := loadSettings(path)
		if err != nil {
			fatal(err)
		}
		b, _ := json.MarshalIndent(s, "", "  ")
		fmt.Println(string(b))
	case "validate":
		s, err := loadSettings(path)
		if err != nil {
			fatal(err)
		}
		if err = validateSettings(s); err != nil {
			fatal(err)
		}
		fmt.Println("settings valid")
	case "init":
		if _, err := os.Stat(path); err == nil {
			fatal(errors.New("settings file already exists"))
		}
		s := defaultSettings()
		if err := saveSettings(path, s); err != nil {
			fatal(err)
		}
		fmt.Println(path)
	default:
		fatal(errors.New("settings requires edit|show|validate|apply|path|init"))
	}
}

type tuiReader struct{ r *bufio.Reader }

func (t tuiReader) line(prompt, current string) string {
	if current != "" {
		fmt.Printf("%s [%s]: ", prompt, current)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	v, _ := t.r.ReadString('\n')
	v = strings.TrimSpace(v)
	if v == "" {
		return current
	}
	return v
}

func (t tuiReader) boolean(prompt string, current bool) bool {
	def := "n"
	if current {
		def = "y"
	}
	for {
		fmt.Printf("%s [y/n, %s]: ", prompt, def)
		v, _ := t.r.ReadString('\n')
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return current
		}
		switch v {
		case "y", "yes", "true", "1", "on":
			return true
		case "n", "no", "false", "0", "off":
			return false
		}
		fmt.Println("Enter y or n.")
	}
}

func (t tuiReader) int64(prompt string, current int64) int64 {
	for {
		v := t.line(prompt, strconv.FormatInt(current, 10))
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return n
		}
		fmt.Println("Enter a whole number.")
	}
}

func (t tuiReader) integer(prompt string, current int) int {
	for {
		v := t.line(prompt, strconv.Itoa(current))
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
		fmt.Println("Enter a whole number.")
	}
}

func clearSettingsScreen() {
	fmt.Print("\033[2J\033[H")
}

func settingsHeader(s ARPLSettings, path string) {
	fmt.Println("┌──────────────────────────────────────────────────────────────┐")
	fmt.Println("│                    AI Relay · ARPL Settings                  │")
	fmt.Println("└──────────────────────────────────────────────────────────────┘")
	fmt.Printf(" Device: %s   Role: %s   Transport: %s\n", s.Device.Name, s.Device.Role, s.Relay.URL)
	fmt.Printf(" Settings: %s\n", path)
	fmt.Println(" Private keys and secret contents are never displayed here.")
	fmt.Println()
}

func runSettingsTUI(path string) error {
	s, err := loadSettings(path)
	if err != nil {
		return err
	}
	in := tuiReader{r: bufio.NewReader(os.Stdin)}
	dirty := false
	for {
		clearSettingsScreen()
		settingsHeader(s, path)
		fmt.Println("  1  Device")
		fmt.Println("  2  Relay / Tunnel")
		fmt.Println("  3  Host permissions")
		fmt.Println("  4  Client / reconnect")
		fmt.Println("  5  Security")
		fmt.Println("  6  Services / autostart")
		fmt.Printf("  7  Peer profiles (%d)\n", len(s.Peers))
		fmt.Printf("  8  Advanced (%d)\n", len(s.Advanced))
		fmt.Println("  v  Validate")
		fmt.Println("  s  Save")
		fmt.Println("  q  Save & exit")
		fmt.Println("  x  Exit without saving")
		if dirty {
			fmt.Println("\n  * unsaved changes")
		}
		fmt.Print("\nSelect: ")
		choice, _ := in.r.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "1":
			editDeviceSettings(in, &s)
			dirty = true
		case "2":
			editRelaySettings(in, &s)
			dirty = true
		case "3":
			editHostSettings(in, &s)
			dirty = true
		case "4":
			editClientSettings(in, &s)
			dirty = true
		case "5":
			editSecuritySettings(in, &s)
			dirty = true
		case "6":
			editServiceSettings(in, &s)
			dirty = true
		case "7":
			editPeerSettings(in, &s)
			dirty = true
		case "8":
			editAdvancedSettings(in, &s)
			dirty = true
		case "v":
			if err := validateSettings(s); err != nil {
				pauseTUI(in, "INVALID: "+err.Error())
			} else {
				pauseTUI(in, "Settings are valid.")
			}
		case "s":
			if err := saveSettings(path, s); err != nil {
				pauseTUI(in, "SAVE FAILED: "+err.Error())
			} else {
				dirty = false
				pauseTUI(in, "Saved.")
			}
		case "q":
			if err := saveSettings(path, s); err != nil {
				pauseTUI(in, "SAVE FAILED: "+err.Error())
				continue
			}
			fmt.Println("Saved", path)
			return nil
		case "x":
			if dirty && !in.boolean("Discard unsaved changes", false) {
				continue
			}
			return nil
		}
	}
}

func pauseTUI(in tuiReader, msg string) {
	fmt.Println("\n" + msg)
	fmt.Print("Press Enter...")
	_, _ = in.r.ReadString('\n')
}

func editDeviceSettings(in tuiReader, s *ARPLSettings) {
	clearSettingsScreen()
	fmt.Println("DEVICE")
	s.Device.Name = in.line("Device name", s.Device.Name)
	s.Device.Role = in.line("Role (both|host|client|relay)", s.Device.Role)
}

func editRelaySettings(in tuiReader, s *ARPLSettings) {
	clearSettingsScreen()
	fmt.Println("RELAY / TUNNEL")
	s.Relay.URL = in.line("Relay URL", s.Relay.URL)
	s.Relay.Listen = in.line("Local relay listen", s.Relay.Listen)
	s.Relay.TunnelEnabled = in.boolean("Tunnel enabled", s.Relay.TunnelEnabled)
	s.Relay.TunnelProvider = in.line("Tunnel provider", s.Relay.TunnelProvider)
	s.Relay.TunnelHostname = in.line("Tunnel hostname", s.Relay.TunnelHostname)
	s.Relay.TunnelPath = in.line("Tunnel path", s.Relay.TunnelPath)
}

func editHostSettings(in tuiReader, s *ARPLSettings) {
	clearSettingsScreen()
	fmt.Println("HOST")
	s.Host.Enabled = in.boolean("Host enabled", s.Host.Enabled)
	s.Host.AllowExec = in.boolean("Allow remote command execution", s.Host.AllowExec)
	s.Host.FileRoot = in.line("File transfer root", s.Host.FileRoot)
	s.Host.AuthorizedKeys = in.line("Authorized keys file", s.Host.AuthorizedKeys)
	s.Host.CommandTimeout = in.line("Command timeout", s.Host.CommandTimeout)
	s.Host.MaxFileBytes = in.int64("Maximum file bytes", s.Host.MaxFileBytes)
	s.Host.MaxOutputBytes = in.integer("Maximum stdout/stderr bytes", s.Host.MaxOutputBytes)
}

func editClientSettings(in tuiReader, s *ARPLSettings) {
	clearSettingsScreen()
	fmt.Println("CLIENT / RECONNECT")
	s.Client.Enabled = in.boolean("Client enabled", s.Client.Enabled)
	s.Client.Heartbeat = in.line("Heartbeat", s.Client.Heartbeat)
	s.Client.ReconnectMin = in.line("Minimum reconnect delay", s.Client.ReconnectMin)
	s.Client.ReconnectMax = in.line("Maximum reconnect delay", s.Client.ReconnectMax)
}

func editSecuritySettings(in tuiReader, s *ARPLSettings) {
	clearSettingsScreen()
	fmt.Println("SECURITY")
	s.Security.KeyFile = in.line("Identity key file", s.Security.KeyFile)
	s.Security.RelayTokenFile = in.line("Relay token file path (blank for signed identity auth)", s.Security.RelayTokenFile)
	s.Security.SecureStore = in.line("Secure store (auto|file|keychain|dpapi|keystore|secret-service|tpm)", s.Security.SecureStore)
	fmt.Println("\nSecret token values and private keys are intentionally not editable here.")
	pauseTUI(in, "")
}

func editServiceSettings(in tuiReader, s *ARPLSettings) {
	clearSettingsScreen()
	fmt.Println("SERVICES / AUTOSTART")
	s.Service.AutoStart = in.boolean("Autostart ARPL", s.Service.AutoStart)
	s.Service.StartHost = in.boolean("Start host service", s.Service.StartHost)
	s.Service.StartClient = in.boolean("Start resident client", s.Service.StartClient)
	s.Service.RestartPolicy = in.line("Restart policy (on-failure|always|never)", s.Service.RestartPolicy)
	fmt.Println("\nUse on-failure to preserve deliberate force-disconnect behavior.")
	pauseTUI(in, "")
}

func editPeerSettings(in tuiReader, s *ARPLSettings) {
	for {
		clearSettingsScreen()
		fmt.Println("PEER PROFILES")
		for i, p := range s.Peers {
			fmt.Printf("  %d  %-18s enabled=%t auto=%t\n", i+1, p.Name, p.Enabled, p.AutoConnect)
		}
		fmt.Println("\n  a  Add peer")
		fmt.Println("  b  Back")
		fmt.Print("\nSelect peer number: ")
		v, _ := in.r.ReadString('\n')
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "b" || v == "" {
			return
		}
		if v == "a" {
			p := PeerSettings{Enabled: true, AutoConnect: true, Heartbeat: s.Client.Heartbeat}
			p.Name = in.line("Peer name", "")
			if p.Name != "" {
				s.Peers = append(s.Peers, p)
			}
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > len(s.Peers) {
			continue
		}
		editOnePeer(in, s, n-1)
	}
}

func editOnePeer(in tuiReader, s *ARPLSettings, idx int) {
	p := &s.Peers[idx]
	clearSettingsScreen()
	fmt.Printf("PEER: %s\n", p.Name)
	p.Name = in.line("Name", p.Name)
	p.Enabled = in.boolean("Enabled", p.Enabled)
	p.AutoConnect = in.boolean("Auto-connect", p.AutoConnect)
	p.PublicKey = in.line("Peer public key", p.PublicKey)
	p.OutboundPair = in.line("Outbound relay pair ID", p.OutboundPair)
	p.InboundPair = in.line("Inbound relay pair ID", p.InboundPair)
	p.SessionFile = in.line("Session state file", p.SessionFile)
	p.ControlState = in.line("Local control state file", p.ControlState)
	p.RelayURL = in.line("Relay URL override (blank=global)", p.RelayURL)
	p.Heartbeat = in.line("Heartbeat override (blank=global)", p.Heartbeat)
	if in.boolean("Delete this peer", false) {
		s.Peers = append(s.Peers[:idx], s.Peers[idx+1:]...)
	}
}

func editAdvancedSettings(in tuiReader, s *ARPLSettings) {
	for {
		clearSettingsScreen()
		fmt.Println("ADVANCED / FUTURE SETTINGS")
		fmt.Println("Unknown future-safe key/value settings are preserved here.")
		keys := make([]string, 0, len(s.Advanced))
		for k := range s.Advanced {
			keys = append(keys, k)
		}
		for _, k := range keys {
			fmt.Printf("  %s = %s\n", k, s.Advanced[k])
		}
		fmt.Println("\n  a  Add/update")
		fmt.Println("  d  Delete")
		fmt.Println("  b  Back")
		fmt.Print("\nSelect: ")
		v, _ := in.r.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "b", "":
			return
		case "a":
			k := in.line("Key", "")
			if k != "" {
				s.Advanced[k] = in.line("Value", s.Advanced[k])
			}
		case "d":
			k := in.line("Key to delete", "")
			delete(s.Advanced, k)
		}
	}
}
