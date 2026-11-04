package arpl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"
)

// Transport is deliberately independent of SSH. TLS 1.3/TCP is the v0.1
// adapter; a QUIC implementation can satisfy this interface later.
type Transport interface {
	Dial(context.Context) (net.Conn, error)
}

type TLSTCPTransport struct {
	Address    string
	ServerName string
	Config     *tls.Config
}

func (t TLSTCPTransport) Dial(ctx context.Context) (net.Conn, error) {
	if t.Address == "" {
		return nil, errors.New("ARPL address is required")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: t.ServerName, NextProtos: []string{"arpl/0.1"}}
	if t.Config != nil {
		cfg = t.Config.Clone()
		if cfg.MinVersion < tls.VersionTLS13 {
			cfg.MinVersion = tls.VersionTLS13
		}
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{"arpl/0.1"}
		}
	}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(t.Address)
		if err == nil {
			cfg.ServerName = host
		}
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", t.Address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func TLSListener(addr string, cert tls.Certificate) (net.Listener, error) {
	if len(cert.Certificate) == 0 {
		return nil, errors.New("ARPL TLS certificate is required")
	}
	return tls.Listen("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{"arpl/0.1"}})
}

// PinnedTLSConfig makes certificate pinning optional at the TLS layer. ARPL's
// signed identity allowlist remains authoritative and should be used even when
// deployments use a private CA.
func PinnedTLSConfig(serverName string, roots *x509.CertPool, cert *tls.Certificate) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots, NextProtos: []string{"arpl/0.1"}}
	if cert != nil {
		c.Certificates = []tls.Certificate{*cert}
	}
	return c
}
