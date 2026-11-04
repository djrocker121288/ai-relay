package arpl

import (
	"context"
	"errors"
	"net"
	"sort"
	"time"
)

type RouteKind string

const (
	RouteLAN    RouteKind = "lan"
	RouteDirect RouteKind = "direct"
	RouteRelay  RouteKind = "relay"
)

type RouteCandidate struct {
	Kind     RouteKind
	Address  string
	Priority int
	Probe    func(context.Context) (time.Duration, error)
}
type RouteStatus struct {
	Kind     RouteKind     `json:"kind"`
	Address  string        `json:"address,omitempty"`
	Latency  time.Duration `json:"latency"`
	Selected bool          `json:"selected"`
	Error    string        `json:"error,omitempty"`
}

type NamedTransport struct {
	Name      string
	Transport Transport
}
type FallbackTransport struct{ Routes []NamedTransport }

type AuthenticatedRoute struct {
	Kind      RouteKind
	Address   string
	Transport Transport
}

// ConnectRoutes performs dial and ARPL identity handshake as one route
// attempt. A reachable but unauthorized route is therefore not allowed to
// prevent the configured relay fallback.
func ConnectRoutes(ctx context.Context, local Identity, peers *PeerRegistry, sessionID string, routes []AuthenticatedRoute) (net.Conn, SessionCrypto, RouteStatus, error) {
	var last error
	for _, route := range routes {
		if route.Transport == nil {
			continue
		}
		started := time.Now()
		conn, err := route.Transport.Dial(ctx)
		if err == nil {
			crypto, handshakeErr := HandshakeClient(ctx, conn, local, peers, sessionID)
			if handshakeErr == nil {
				return conn, crypto, RouteStatus{Kind: route.Kind, Address: route.Address, Latency: time.Since(started), Selected: true}, nil
			}
			_ = conn.Close()
			err = handshakeErr
		}
		last = err
	}
	if last == nil {
		last = errors.New("no reachable ARPL route")
	}
	return nil, SessionCrypto{}, RouteStatus{}, last
}

func (t FallbackTransport) Dial(ctx context.Context) (net.Conn, error) {
	var last error
	for _, r := range t.Routes {
		if r.Transport == nil {
			continue
		}
		c, err := r.Transport.Dial(ctx)
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no ARPL route configured")
	}
	return nil, last
}

func SelectRoute(ctx context.Context, candidates []RouteCandidate) (RouteCandidate, []RouteStatus, error) {
	ordered := append([]RouteCandidate(nil), candidates...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Priority < ordered[j].Priority })
	statuses := make([]RouteStatus, 0, len(ordered))
	for _, c := range ordered {
		if c.Probe == nil {
			statuses = append(statuses, RouteStatus{Kind: c.Kind, Address: c.Address, Error: "route probe is not configured"})
			continue
		}
		started := time.Now()
		latency, err := c.Probe(ctx)
		if latency <= 0 {
			latency = time.Since(started)
		}
		st := RouteStatus{Kind: c.Kind, Address: c.Address, Latency: latency}
		if err != nil {
			st.Error = err.Error()
			statuses = append(statuses, st)
			continue
		}
		st.Selected = true
		statuses = append(statuses, st)
		return c, statuses, nil
	}
	return RouteCandidate{}, statuses, errors.New("no reachable ARPL route")
}

func TCPProbe(address string, timeout time.Duration) func(context.Context) (time.Duration, error) {
	return func(ctx context.Context) (time.Duration, error) {
		started := time.Now()
		d := net.Dialer{Timeout: timeout}
		c, err := d.DialContext(ctx, "tcp", address)
		if err != nil {
			return time.Since(started), err
		}
		_ = c.Close()
		return time.Since(started), nil
	}
}
