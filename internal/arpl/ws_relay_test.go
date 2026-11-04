package arpl

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWSRelayFullDuplexBearer(t *testing.T) {
	hub := NewWSRelayHub("relay-secret")
	ts := httptest.NewServer(hub.Handler())
	defer ts.Close()

	pair, err := NewRelayPairID()
	if err != nil {
		t.Fatal(err)
	}
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	listener, err := NewWSRelayListener(wsURL, pair, "relay-secret", ts.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			serverDone <- e
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, e = io.ReadFull(conn, buf); e != nil {
			serverDone <- e
			return
		}
		if string(buf) != "ping" {
			serverDone <- errUnexpectedData(string(buf))
			return
		}
		_, e = conn.Write([]byte("pong"))
		serverDone <- e
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := (WSRelayTransport{
		URL: wsURL, PairID: pair, Token: "relay-secret",
		Client: ts.Client(), AllowInsecureWS: true,
	}).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err = io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q", reply)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestWSRelaySignedAuth(t *testing.T) {
	hostID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hub := NewWSRelayHub("")
	hub.Peers = NewPeerRegistry()
	hub.Peers.Allow(hostID.PublicKey)
	hub.Peers.Allow(clientID.PublicKey)

	ts := httptest.NewServer(hub.Handler())
	defer ts.Close()
	pair, err := NewRelayPairID()
	if err != nil {
		t.Fatal(err)
	}
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	listener, err := NewWSRelayListener(wsURL, pair, "", ts.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	listener.Identity = hostID
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			_ = c.Close()
		}
		accepted <- e
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := (WSRelayTransport{
		URL: wsURL, PairID: pair, Identity: clientID,
		Client: ts.Client(), AllowInsecureWS: true,
	}).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if err = <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestWSRelayRejectsBadToken(t *testing.T) {
	hub := NewWSRelayHub("correct")
	ts := httptest.NewServer(hub.Handler())
	defer ts.Close()
	pair, err := NewRelayPairID()
	if err != nil {
		t.Fatal(err)
	}
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = (WSRelayTransport{
		URL: wsURL, PairID: pair, Token: "wrong",
		Client: ts.Client(), AllowInsecureWS: true,
	}).Dial(ctx)
	if err == nil {
		t.Fatal("expected bad relay token to be rejected")
	}
}

type unexpectedDataError string

func (e unexpectedDataError) Error() string { return "unexpected relay data: " + string(e) }
func errUnexpectedData(s string) error      { return unexpectedDataError(s) }
