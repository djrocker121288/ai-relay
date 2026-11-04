package arpl

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// WSRelayTransport carries the ARPL byte stream over a single bidirectional
// WebSocket. WSS is the preferred public tunnel/proxy transport.
type WSRelayTransport struct {
	URL             string
	PairID          string
	Token           string
	Identity        Identity
	Client          *http.Client
	AllowInsecureWS bool
}

func (t WSRelayTransport) Dial(ctx context.Context) (net.Conn, error) {
	return openWSRelayConn(ctx, t.Client, t.URL, t.PairID, "dial", t.Token, t.Identity, t.AllowInsecureWS)
}

type WSRelayListener struct {
	URL             string
	PairID          string
	Token           string
	Identity        Identity
	Client          *http.Client
	AllowInsecureWS bool

	once   sync.Once
	closed chan struct{}
}

func NewWSRelayListener(rawURL, pairID, token string, client *http.Client, allowInsecureWS bool) (*WSRelayListener, error) {
	if err := validateWSRelayURL(rawURL, allowInsecureWS); err != nil {
		return nil, err
	}
	if err := validatePairID(pairID); err != nil {
		return nil, err
	}
	return &WSRelayListener{
		URL: rawURL, PairID: pairID, Token: token, Client: client,
		AllowInsecureWS: allowInsecureWS, closed: make(chan struct{}),
	}, nil
}

func (l *WSRelayListener) Accept() (net.Conn, error) {
	if l == nil || l.closed == nil {
		return nil, net.ErrClosed
	}

	// A relay-backed listener is a long-lived logical listener. Public mobile
	// and tunnel paths can reset WebSockets, time out TLS handshakes, or
	// temporarily fail DNS. Treat those as transient accept failures and retry
	// in this same process so the OperationServer (including preserved PTYs)
	// survives the transport outage.
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		select {
		case <-l.closed:
			return nil, net.ErrClosed
		default:
		}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-l.closed:
				cancel()
			case <-ctx.Done():
			}
		}()

		conn, err := openWSRelayConn(ctx, l.Client, l.URL, l.PairID, "accept", l.Token, l.Identity, l.AllowInsecureWS)
		cancel()
		if err == nil {
			return conn, nil
		}
		select {
		case <-l.closed:
			return nil, net.ErrClosed
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (l *WSRelayListener) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.closed != nil {
			close(l.closed)
		}
	})
	return nil
}

func (l *WSRelayListener) Addr() net.Addr {
	if l == nil {
		return relayAddr("wss-relay")
	}
	return relayAddr(l.URL)
}

func validateWSRelayURL(rawURL string, allowInsecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return errors.New("invalid ARPL WebSocket relay URL")
	}
	if u.Scheme != "wss" && !(allowInsecure && u.Scheme == "ws") {
		return errors.New("ARPL WebSocket relay URL must use wss")
	}
	return nil
}

func openWSRelayConn(parent context.Context, client *http.Client, rawURL, pairID, role, token string, identity Identity, allowInsecure bool) (net.Conn, error) {
	if err := validateWSRelayURL(rawURL, allowInsecure); err != nil {
		return nil, err
	}
	if err := validatePairID(pairID); err != nil {
		return nil, err
	}
	if role != "dial" && role != "accept" {
		return nil, errors.New("invalid ARPL relay role")
	}

	endpointBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, endpointBytes); err != nil {
		return nil, err
	}
	endpoint := hex.EncodeToString(endpointBytes)

	req, err := http.NewRequestWithContext(parent, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if err = setRelayHeaders(req, pairID, role, endpoint, "ws", token, identity); err != nil {
		return nil, err
	}

	c, resp, err := websocket.Dial(parent, rawURL, &websocket.DialOptions{
		HTTPClient: client,
		HTTPHeader: req.Header,
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

type wsRelayEndpoint struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func newWSRelayEndpoint(conn net.Conn) *wsRelayEndpoint {
	return &wsRelayEndpoint{conn: conn, done: make(chan struct{})}
}

func (e *wsRelayEndpoint) finish() {
	e.once.Do(func() { close(e.done) })
}

type wsRelayPair struct {
	dial, accept *wsRelayEndpoint
	created      time.Time
}

type WSRelayHub struct {
	Token       string
	Peers       *PeerRegistry
	MaxPairs    int
	IdleTimeout time.Duration
	AuthSkew    time.Duration

	mu       sync.Mutex
	pairs    map[string]*wsRelayPair
	authOnce sync.Once
	authHub  *HTTPRelayHub
}

func NewWSRelayHub(token string) *WSRelayHub {
	return &WSRelayHub{
		Token: token, MaxPairs: 1024, IdleTimeout: 2 * time.Minute,
		AuthSkew: 90 * time.Second, pairs: map[string]*wsRelayPair{},
		authHub: NewHTTPRelayHub(""),
	}
}

func (h *WSRelayHub) Handler() http.Handler {
	return http.HandlerFunc(h.serveHTTP)
}

func (h *WSRelayHub) authorize(r *http.Request, pairID, role, endpointID string) error {
	if h.Token != "" {
		want := "Bearer " + h.Token
		got := r.Header.Get("Authorization")
		if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return errors.New("unauthorized")
		}
		return nil
	}
	h.authOnce.Do(func() {
		h.authHub.Peers = h.Peers
		h.authHub.AuthSkew = h.AuthSkew
	})
	return h.authHub.verifySignedRequest(r, pairID, role, endpointID, "ws")
}

func (h *WSRelayHub) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil {
		http.Error(w, "relay unavailable", http.StatusServiceUnavailable)
		return
	}
	pairID := strings.ToLower(strings.TrimSpace(r.Header.Get(relayHeaderPair)))
	role := strings.ToLower(strings.TrimSpace(r.Header.Get(relayHeaderRole)))
	endpointID := strings.ToLower(strings.TrimSpace(r.Header.Get(relayHeaderEndpoint)))
	direction := strings.ToLower(strings.TrimSpace(r.Header.Get(relayHeaderDirection)))
	if validatePairID(pairID) != nil || (role != "dial" && role != "accept") || !validateEndpointID(endpointID) || direction != "ws" {
		http.Error(w, "invalid relay headers", http.StatusBadRequest)
		return
	}
	if err := h.authorize(r, pairID, role, endpointID); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	ep := newWSRelayEndpoint(conn)

	var a, b *wsRelayEndpoint
	h.mu.Lock()
	if h.pairs == nil {
		h.pairs = map[string]*wsRelayPair{}
	}
	maxPairs := h.MaxPairs
	if maxPairs <= 0 {
		maxPairs = 1024
	}
	p := h.pairs[pairID]
	if p == nil {
		if len(h.pairs) >= maxPairs {
			h.mu.Unlock()
			_ = conn.Close()
			ep.finish()
			return
		}
		p = &wsRelayPair{created: time.Now()}
		h.pairs[pairID] = p
	}

	occupied := false
	if role == "dial" {
		occupied = p.dial != nil
		if !occupied {
			p.dial = ep
		}
	} else {
		occupied = p.accept != nil
		if !occupied {
			p.accept = ep
		}
	}
	if occupied {
		h.mu.Unlock()
		_ = conn.Close()
		ep.finish()
		return
	}
	if p.dial != nil && p.accept != nil {
		a, b = p.dial, p.accept
		delete(h.pairs, pairID)
	}
	h.mu.Unlock()

	if a != nil && b != nil {
		go bridgeWSRelay(a, b)
	} else {
		timeout := h.IdleTimeout
		if timeout <= 0 {
			timeout = 2 * time.Minute
		}
		go h.expireWSRelay(pairID, role, ep, timeout)
	}

	select {
	case <-ep.done:
	case <-r.Context().Done():
		h.removeWSRelayEndpoint(pairID, role, ep)
		_ = ep.conn.Close()
		ep.finish()
	}
}

func bridgeWSRelay(a, b *wsRelayEndpoint) {
	var once sync.Once
	closeBoth := func() {
		_ = a.conn.Close()
		_ = b.conn.Close()
		a.finish()
		b.finish()
	}
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		once.Do(closeBoth)
	}
	go copyOne(a.conn, b.conn)
	go copyOne(b.conn, a.conn)
}

func (h *WSRelayHub) expireWSRelay(pairID, role string, ep *wsRelayEndpoint, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-timer.C:
		h.removeWSRelayEndpoint(pairID, role, ep)
		_ = ep.conn.Close()
		ep.finish()
	case <-ep.done:
	}
}

func (h *WSRelayHub) removeWSRelayEndpoint(pairID, role string, ep *wsRelayEndpoint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.pairs[pairID]
	if p == nil {
		return
	}
	if role == "dial" && p.dial == ep {
		p.dial = nil
	}
	if role == "accept" && p.accept == ep {
		p.accept = nil
	}
	if p.dial == nil && p.accept == nil {
		delete(h.pairs, pairID)
	}
}
