package distribution

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// TunnelConfig describes the operator-owned edge in front of AI Relay. The
// distribution service never reads or logs provider credentials.
type TunnelConfig struct {
	Provider string `json:"provider,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Target   string `json:"target,omitempty"`
	Config   string `json:"config,omitempty"`
}

var hostnameRE = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

func (c TunnelConfig) Enabled() bool { return c.Provider != "" || c.Hostname != "" }

func (c TunnelConfig) Validate() error {
	if !c.Enabled() {
		return nil
	}
	if c.Provider == "" || c.Hostname == "" {
		return errors.New("tunnel provider and hostname must both be set")
	}
	if !hostnameRE.MatchString(c.Hostname) || strings.Contains(c.Hostname, "..") {
		return errors.New("tunnel hostname must be a DNS hostname without a scheme or path")
	}
	if net.ParseIP(c.Hostname) != nil {
		return errors.New("tunnel hostname must not be an IP address")
	}
	u, err := url.Parse(c.Target)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil {
		return errors.New("tunnel target must be an http URL without userinfo")
	}
	host := u.Hostname()
	if !net.ParseIP(host).IsLoopback() && host != "localhost" {
		return errors.New("tunnel target must be loopback")
	}
	return nil
}

func LoadTunnelConfig(env func(string) string) (TunnelConfig, error) {
	c := TunnelConfig{
		Provider: strings.TrimSpace(env("AI_RELAY_TUNNEL_PROVIDER")),
		Hostname: strings.TrimSpace(env("AI_RELAY_TUNNEL_HOSTNAME")),
		Target:   strings.TrimSpace(env("AI_RELAY_TUNNEL_TARGET")),
		Config:   strings.TrimSpace(env("AI_RELAY_TUNNEL_CONFIG")),
	}
	if c.Target == "" {
		c.Target = "http://127.0.0.1:8787"
	}
	if err := c.Validate(); err != nil {
		return TunnelConfig{}, fmt.Errorf("invalid AI Relay tunnel configuration: %w", err)
	}
	return c, nil
}

func EnvironmentTunnelConfig() (TunnelConfig, error) { return LoadTunnelConfig(os.Getenv) }
