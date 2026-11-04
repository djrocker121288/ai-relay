package arpl

import (
	"context"
	"net"
	"testing"
)

type routeTestTransport struct {
	server Identity
	client Identity
	peers  *PeerRegistry
	valid  bool
}

func (t routeTestTransport) Dial(ctx context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	if !t.valid {
		_ = server.Close()
		return client, nil
	}
	go func() {
		defer server.Close()
		_, _ = HandshakeServer(ctx, server, t.server, t.peers, "")
	}()
	return client, nil
}

func TestConnectRoutesFallsThroughHandshakeFailure(t *testing.T) {
	server, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverPeers := NewPeerRegistry()
	serverPeers.Allow(client.PublicKey)
	clientPeers := NewPeerRegistry()
	clientPeers.Allow(server.PublicKey)
	conn, crypto, selected, err := ConnectRoutes(context.Background(), client, clientPeers, NewSessionID(), []AuthenticatedRoute{
		{Kind: RouteLAN, Address: "bad", Transport: routeTestTransport{valid: false}},
		{Kind: RouteRelay, Address: "relay", Transport: routeTestTransport{server: server, peers: serverPeers, valid: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if selected.Kind != RouteRelay || !selected.Selected || crypto.PeerID != server.DeviceID {
		t.Fatalf("selected=%#v crypto=%#v", selected, crypto)
	}
}
