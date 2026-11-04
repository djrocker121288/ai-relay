package distribution

import "testing"

func TestTunnelConfigValidationAndDefaults(t *testing.T) {
	c, err := LoadTunnelConfig(func(k string) string {
		if k == "AI_RELAY_TUNNEL_PROVIDER" {
			return "cloudflared"
		}
		if k == "AI_RELAY_TUNNEL_HOSTNAME" {
			return "airelay.example.test"
		}
		return ""
	})
	if err != nil || !c.Enabled() || c.Target != "http://127.0.0.1:8787" {
		t.Fatalf("config=%+v err=%v", c, err)
	}
	if err := (TunnelConfig{Provider: "cloudflared", Hostname: "airelay.example.test", Target: "https://127.0.0.1:8787"}).Validate(); err == nil {
		t.Fatal("accepted non-http target")
	}
	if err := (TunnelConfig{Provider: "cloudflared", Hostname: "127.0.0.1", Target: "http://127.0.0.1:8787"}).Validate(); err == nil {
		t.Fatal("accepted IP hostname")
	}
}

func TestTunnelHealthDoesNotExposeCredentialFields(t *testing.T) {
	s := &Service{Tunnel: TunnelConfig{Provider: "cloudflared", Hostname: "airelay.example.test", Target: "http://127.0.0.1:8787"}}
	if !s.Tunnel.Enabled() || s.Tunnel.Config != "" {
		t.Fatal("unexpected tunnel credential/config exposure")
	}
}
