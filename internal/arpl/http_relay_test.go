package arpl

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPRelayFullDuplexAndReconnect(t *testing.T) {
	token := "relay-test-token"
	hub := NewHTTPRelayHub(token)
	ts := httptest.NewServer(hub.Handler())
	defer ts.Close()
	pair, err := NewRelayPairID()
	if err != nil {
		t.Fatal(err)
	}
	clientTransport := HTTPRelayTransport{
		URL: ts.URL, PairID: pair, Token: token, Client: ts.Client(), AllowInsecureHTTP: true,
	}
	serverListener, err := NewHTTPRelayListener(ts.URL, pair, token, ts.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer serverListener.Close()

	runOnce := func(left, right string) {
		t.Helper()
		accepted := make(chan net.Conn, 1)
		acceptErr := make(chan error, 1)
		go func() {
			conn, e := serverListener.Accept()
			if e != nil {
				acceptErr <- e
				return
			}
			accepted <- conn
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		clientConn, e := clientTransport.Dial(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer clientConn.Close()

		var serverConn net.Conn
		select {
		case serverConn = <-accepted:
		case e = <-acceptErr:
			t.Fatal(e)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		defer serverConn.Close()

		clientWrite := make(chan error, 1)
		go func() {
			_, e := clientConn.Write([]byte(left))
			clientWrite <- e
		}()
		got := make([]byte, len(left))
		if _, e = io.ReadFull(serverConn, got); e != nil {
			t.Fatal(e)
		}
		if string(got) != left {
			t.Fatalf("server got %q", got)
		}
		if e = <-clientWrite; e != nil {
			t.Fatal(e)
		}

		serverWrite := make(chan error, 1)
		go func() {
			_, e := serverConn.Write([]byte(right))
			serverWrite <- e
		}()
		got = make([]byte, len(right))
		if _, e = io.ReadFull(clientConn, got); e != nil {
			t.Fatal(e)
		}
		if string(got) != right {
			t.Fatalf("client got %q", got)
		}
		if e = <-serverWrite; e != nil {
			t.Fatal(e)
		}
	}

	runOnce("dial-to-accept", "accept-to-dial")
	runOnce("reconnected-one", "reconnected-two")
}

func TestHTTPRelayRejectsBadToken(t *testing.T) {
	hub := NewHTTPRelayHub("correct")
	ts := httptest.NewServer(hub.Handler())
	defer ts.Close()
	pair, err := NewRelayPairID()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = (HTTPRelayTransport{
		URL: ts.URL, PairID: pair, Token: "wrong", Client: ts.Client(), AllowInsecureHTTP: true,
	}).Dial(ctx)
	if err == nil {
		t.Fatal("relay accepted wrong token")
	}
}

func TestRelayPairIDValidation(t *testing.T) {
	if err := validatePairID("not-a-pair"); err == nil {
		t.Fatal("accepted invalid pair")
	}
	pair, err := NewRelayPairID()
	if err != nil || validatePairID(pair) != nil {
		t.Fatalf("valid pair failed: %q %v", pair, err)
	}
}

func TestHTTPRelaySignedARPLHandshake(t *testing.T) {
	token := "relay-handshake-token"
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
	clientPeers := NewPeerRegistry()
	serverPeers.Allow(clientID.PublicKey)
	clientPeers.Allow(serverID.PublicKey)

	listener, err := NewHTTPRelayListener(ts.URL+"/arpl/relay", pair, token, ts.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type serverResult struct {
		crypto SessionCrypto
		err    error
	}
	result := make(chan serverResult, 1)
	clientHandshakeDone := make(chan struct{})
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			result <- serverResult{err: e}
			return
		}
		defer conn.Close()
		c, e := HandshakeServer(ctx, conn, serverID, serverPeers, "")
		result <- serverResult{crypto: c, err: e}
		if e == nil {
			select {
			case <-clientHandshakeDone:
			case <-ctx.Done():
			}
		}
	}()

	transport := HTTPRelayTransport{
		URL: ts.URL + "/arpl/relay", PairID: pair, Token: token,
		Client: ts.Client(), AllowInsecureHTTP: true,
	}
	conn, err := transport.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	clientCrypto, err := HandshakeClient(ctx, conn, clientID, clientPeers, NewSessionID())
	if err != nil {
		t.Fatal(err)
	}
	close(clientHandshakeDone)
	sr := <-result
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	if clientCrypto.SessionID == "" || clientCrypto.SessionID != sr.crypto.SessionID {
		t.Fatalf("relay handshake session mismatch client=%q server=%q", clientCrypto.SessionID, sr.crypto.SessionID)
	}
}

func TestHTTPRelaySignedIdentityModeHandshake(t *testing.T) {
	hub := NewHTTPRelayHub("")
	serverID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hub.Peers = NewPeerRegistry()
	hub.Peers.Allow(serverID.PublicKey)
	hub.Peers.Allow(clientID.PublicKey)
	ts := httptest.NewServer(hub.Handler())
	defer ts.Close()

	pair, err := DeterministicRelayPairID(clientID.DeviceID, serverID.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := NewHTTPRelayListener(ts.URL, pair, "", ts.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	listener.Identity = serverID
	defer listener.Close()

	serverPeers := NewPeerRegistry()
	serverPeers.Allow(clientID.PublicKey)
	clientPeers := NewPeerRegistry()
	clientPeers.Allow(serverID.PublicKey)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		c   SessionCrypto
		err error
	}
	serverResult := make(chan result, 1)
	clientDone := make(chan struct{})
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			serverResult <- result{err: e}
			return
		}
		defer conn.Close()
		c, e := HandshakeServer(ctx, conn, serverID, serverPeers, "")
		serverResult <- result{c: c, err: e}
		if e == nil {
			select {
			case <-clientDone:
			case <-ctx.Done():
			}
		}
	}()

	transport := HTTPRelayTransport{
		URL: ts.URL, PairID: pair, Identity: clientID,
		Client: ts.Client(), AllowInsecureHTTP: true,
	}
	conn, err := transport.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cc, err := HandshakeClient(ctx, conn, clientID, clientPeers, NewSessionID())
	if err != nil {
		t.Fatal(err)
	}
	close(clientDone)
	sr := <-serverResult
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	if cc.SessionID == "" || cc.SessionID != sr.c.SessionID {
		t.Fatalf("session mismatch client=%q server=%q", cc.SessionID, sr.c.SessionID)
	}
}

func TestHTTPRelaySignedIdentityRejectsUnknown(t *testing.T) {
	hub := NewHTTPRelayHub("")
	allowed, _ := NewIdentity()
	unknown, _ := NewIdentity()
	hub.Peers = NewPeerRegistry()
	hub.Peers.Allow(allowed.PublicKey)
	ts := httptest.NewServer(hub.Handler())
	defer ts.Close()
	pair, _ := NewRelayPairID()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := (HTTPRelayTransport{
		URL: ts.URL, PairID: pair, Identity: unknown,
		Client: ts.Client(), AllowInsecureHTTP: true,
	}).Dial(ctx)
	if err == nil {
		t.Fatal("signed relay accepted unknown identity")
	}
}

func TestHTTPRelaySignedIdentityRejectsReplay(t *testing.T) {
	hub := NewHTTPRelayHub("")
	id, _ := NewIdentity()
	hub.Peers = NewPeerRegistry()
	hub.Peers.Allow(id.PublicKey)
	pair, _ := NewRelayPairID()
	req := httptest.NewRequest(http.MethodPut, "http://relay.test/arpl/relay", nil)
	if err := setRelayHeaders(req, pair, "dial", strings.Repeat("a", 32), "recv", "", id); err != nil {
		t.Fatal(err)
	}
	rr1 := httptest.NewRecorder()
	hub.Handler().ServeHTTP(rr1, req)
	if rr1.Code != http.StatusMethodNotAllowed {
		t.Fatalf("first signed request status=%d want=%d", rr1.Code, http.StatusMethodNotAllowed)
	}
	req2 := httptest.NewRequest(http.MethodPut, "http://relay.test/arpl/relay", nil)
	for k, vv := range req.Header {
		for _, v := range vv {
			req2.Header.Add(k, v)
		}
	}
	rr2 := httptest.NewRecorder()
	hub.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("replayed signed request status=%d want=%d", rr2.Code, http.StatusUnauthorized)
	}
}
