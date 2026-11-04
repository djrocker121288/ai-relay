package arpl

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var ErrLinkDisconnected = errors.New("ARPL resident link disconnected")

type frameResult struct {
	frame Frame
	err   error
}

type residentConn struct {
	conn  net.Conn
	codec *FrameCodec

	writeMu sync.Mutex

	pendingMu sync.Mutex
	pending   map[uint64]chan frameResult
}

func (c *residentConn) send(f Frame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !f.Deadline.IsZero() {
		if err := c.conn.SetWriteDeadline(f.Deadline); err != nil {
			return err
		}
		defer c.conn.SetWriteDeadline(time.Time{})
	}
	return WriteFrame(c.conn, c.codec, f)
}

func (c *residentConn) register(streamID uint64) chan frameResult {
	ch := make(chan frameResult, 16)
	c.pendingMu.Lock()
	c.pending[streamID] = ch
	c.pendingMu.Unlock()
	return ch
}

func (c *residentConn) unregister(streamID uint64) {
	c.pendingMu.Lock()
	if ch := c.pending[streamID]; ch != nil {
		delete(c.pending, streamID)
		close(ch)
	}
	c.pendingMu.Unlock()
}

func (c *residentConn) dispatch(f Frame) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	ch := c.pending[f.StreamID]
	if ch == nil {
		return
	}
	select {
	case ch <- frameResult{frame: f}:
	default:
		// A peer must not be able to grow memory without bound when a local
		// consumer stalls. Drop the connection instead; resumable operations
		// can reconnect from their last verified checkpoint.
		_ = c.conn.Close()
	}
}

func (c *residentConn) failAll(err error) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	for id, ch := range c.pending {
		select {
		case ch <- frameResult{err: err}:
		default:
		}
		close(ch)
		delete(c.pending, id)
	}
}

// ResidentClient owns one authenticated ARPL connection at a time and
// reconnects indefinitely. Streams are multiplexed over the active
// connection. A stream receives ErrLinkDisconnected if its underlying
// transport disappears; callers can then safely reopen resumable operations.
type ResidentClient struct {
	Transport Transport
	Identity  Identity
	Peers     *PeerRegistry
	Store     SessionStore

	Heartbeat              time.Duration
	MinBackoff, MaxBackoff time.Duration
	Rand                   *rand.Rand
	// Connect is an optional route-aware connector. It performs the complete
	// dial and authenticated handshake so an authentication failure on a
	// reachable route can still fall through to the next allowed route.
	Connect func(context.Context, string) (net.Conn, SessionCrypto, RouteStatus, error)
	OnRoute func(RouteStatus)

	mu      sync.RWMutex
	active  *residentConn
	changed chan struct{}

	nextStream atomic.Uint64
	routeMu    sync.RWMutex
	lastRoute  RouteStatus
}

func NewResidentClient() *ResidentClient {
	c := &ResidentClient{changed: make(chan struct{})}
	c.nextStream.Store(0)
	return c
}

func (c *ResidentClient) signalLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *ResidentClient) setActive(a *residentConn) {
	c.mu.Lock()
	if c.active != a {
		c.active = a
		c.signalLocked()
	}
	c.mu.Unlock()
}

func (c *ResidentClient) current() (*residentConn, <-chan struct{}) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.active, c.changed
}

func (c *ResidentClient) WaitConnected(ctx context.Context) error {
	for {
		a, changed := c.current()
		if a != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (c *ResidentClient) Run(ctx context.Context) error {
	if (c.Transport == nil && c.Connect == nil) || c.Store == nil {
		return errors.New("ARPL transport and session store are required")
	}
	if err := c.Identity.Validate(); err != nil {
		return err
	}
	if c.Peers == nil {
		return errors.New("ARPL peer registry is required")
	}

	state, err := c.Store.Load(ctx)
	if err != nil {
		return err
	}
	if state.SessionID == "" {
		state.SessionID = NewSessionID()
	}
	if state.LastAck == nil {
		state.LastAck = map[uint64]uint64{}
	}
	if state.NextSeq == nil {
		state.NextSeq = map[uint64]uint64{}
	}
	if err = c.Store.Save(ctx, state); err != nil {
		return err
	}

	heartbeat := c.Heartbeat
	if heartbeat <= 0 {
		heartbeat = 20 * time.Second
	}
	minBackoff := c.MinBackoff
	if minBackoff <= 0 {
		minBackoff = time.Second
	}
	maxBackoff := c.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 60 * time.Second
	}
	rng := c.Rand
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	backoff := minBackoff

	for {
		if err := ctx.Err(); err != nil {
			c.setActive(nil)
			return err
		}
		var conn net.Conn
		var crypto SessionCrypto
		var connectErr error
		var route RouteStatus
		if c.Connect != nil {
			conn, crypto, route, connectErr = c.Connect(ctx, state.SessionID)
		} else {
			conn, connectErr = c.Transport.Dial(ctx)
		}
		if connectErr != nil {
			if err := waitBackoff(ctx, nil, jitter(backoff, rng)); err != nil {
				c.setActive(nil)
				return err
			}
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}

		if c.Connect == nil {
			var hsErr error
			crypto, hsErr = HandshakeClient(ctx, conn, c.Identity, c.Peers, state.SessionID)
			if hsErr != nil {
				_ = conn.Close()
				if err := waitBackoff(ctx, nil, jitter(backoff, rng)); err != nil {
					c.setActive(nil)
					return err
				}
				backoff = nextBackoff(backoff, maxBackoff)
				continue
			}
		}
		if c.OnRoute != nil {
			c.OnRoute(route)
		}
		c.routeMu.Lock()
		c.lastRoute = route
		c.routeMu.Unlock()
		codec, codecErr := NewFrameCodec(&crypto)
		if codecErr != nil {
			_ = conn.Close()
			c.setActive(nil)
			return codecErr
		}

		active := &residentConn{conn: conn, codec: codec, pending: map[uint64]chan frameResult{}}
		c.setActive(active)
		backoff = minBackoff

		err = c.serveConnection(ctx, active, &state, heartbeat)
		c.setActive(nil)
		active.failAll(ErrLinkDisconnected)
		_ = conn.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := waitBackoff(ctx, nil, jitter(backoff, rng)); err != nil {
			return err
		}
		backoff = nextBackoff(backoff, maxBackoff)
	}
}

func (c *ResidentClient) LastRoute() RouteStatus {
	if c == nil {
		return RouteStatus{}
	}
	c.routeMu.RLock()
	defer c.routeMu.RUnlock()
	return c.lastRoute
}

func cloneSessionState(in SessionState) SessionState {
	out := SessionState{
		SessionID:    in.SessionID,
		PeerID:       in.PeerID,
		Capabilities: append([]string(nil), in.Capabilities...),
	}
	if in.LastAck != nil {
		out.LastAck = make(map[uint64]uint64, len(in.LastAck))
		for k, v := range in.LastAck {
			out.LastAck[k] = v
		}
	}
	if in.NextSeq != nil {
		out.NextSeq = make(map[uint64]uint64, len(in.NextSeq))
		for k, v := range in.NextSeq {
			out.NextSeq[k] = v
		}
	}
	return out
}

func nextBackoff(current, max time.Duration) time.Duration {
	if current >= max {
		return max
	}
	current *= 2
	if current > max {
		return max
	}
	return current
}

// staleConnectionTimeout allows three missed heartbeats before redialing, but
// keeps a scheduling floor for short configured heartbeats. Without that floor,
// a busy host with a 20ms heartbeat can mistake routine scheduling latency for
// a broken socket and tear down an otherwise healthy resident session.
func staleConnectionTimeout(heartbeat time.Duration) time.Duration {
	if heartbeat <= 0 {
		heartbeat = 20 * time.Second
	}
	timeout := heartbeat * 3
	if timeout < time.Second {
		return time.Second
	}
	return timeout
}

// heartbeatWriteTimeout protects against genuinely wedged writes without
// timing out healthy links during brief scheduler or network jitter.
func heartbeatWriteTimeout(heartbeat time.Duration) time.Duration {
	if heartbeat <= 0 {
		heartbeat = 20 * time.Second
	}
	timeout := heartbeat * 2
	if timeout < 500*time.Millisecond {
		return 500 * time.Millisecond
	}
	return timeout
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

func (c *ResidentClient) serveConnection(ctx context.Context, active *residentConn, state *SessionState, heartbeat time.Duration) error {
	readErr := make(chan error, 1)
	activity := make(chan struct{}, 1)
	var stateMu sync.Mutex
	go func() {
		for {
			f, err := ReadFrame(active.conn, active.codec)
			if err != nil {
				readErr <- err
				return
			}
			stateMu.Lock()
			if state.LastAck == nil {
				state.LastAck = map[uint64]uint64{}
			}
			state.LastAck[f.StreamID] = f.Sequence
			snapshot := cloneSessionState(*state)
			stateMu.Unlock()
			_ = c.Store.Save(context.Background(), snapshot)
			select {
			case activity <- struct{}{}:
			default:
			}
			if f.Channel == ChannelControl && f.StreamID == 0 {
				continue
			}
			active.dispatch(f)
		}
	}()

	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	staleTimer := time.NewTimer(staleConnectionTimeout(heartbeat))
	defer staleTimer.Stop()

	var heartbeatSeq uint64
	for {
		select {
		case err := <-readErr:
			if err == nil {
				return ErrLinkDisconnected
			}
			return err
		case <-activity:
			resetTimer(staleTimer, staleConnectionTimeout(heartbeat))
		case <-staleTimer.C:
			_ = active.conn.Close()
			return ErrLinkDisconnected
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			heartbeatSeq++
			stateMu.Lock()
			sessionID := state.SessionID
			ack := state.LastAck[0]
			stateMu.Unlock()
			f := Frame{
				Channel:   ChannelControl,
				SessionID: sessionID,
				StreamID:  0,
				Sequence:  heartbeatSeq,
				Ack:       ack,
				Deadline:  time.Now().Add(heartbeatWriteTimeout(heartbeat)),
				Payload:   []byte("heartbeat"),
			}
			if err := active.send(f); err != nil {
				return err
			}
		}
	}
}

// ResidentStream is bound to one live encrypted connection. If the transport
// drops, Recv returns ErrLinkDisconnected. Open a new stream after reconnect;
// resumable file operations can then continue from the remote/local .part
// checkpoint without replaying already verified bytes.
type ResidentStream struct {
	client   *ResidentClient
	active   *residentConn
	id       uint64
	channel  Channel
	recv     chan frameResult
	sequence uint64
	closed   atomic.Bool
}

func (c *ResidentClient) OpenStream(ctx context.Context, channel Channel) (*ResidentStream, error) {
	if channel == ChannelControl || channel > ChannelTool {
		return nil, errors.New("invalid ARPL resident stream channel")
	}
	for {
		active, changed := c.current()
		if active == nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		id := c.nextStream.Add(1)
		if id == 0 {
			id = c.nextStream.Add(1)
		}
		recv := active.register(id)
		// Recheck that the same connection is still published after
		// registration. Otherwise unregister and wait for the reconnect.
		now, _ := c.current()
		if now != active {
			active.unregister(id)
			continue
		}
		return &ResidentStream{client: c, active: active, id: id, channel: channel, recv: recv}, nil
	}
}

func (s *ResidentStream) Send(ctx context.Context, payload []byte, deadline time.Time) error {
	if s == nil || s.active == nil || s.closed.Load() {
		return io.ErrClosedPipe
	}
	if len(payload) > maxFramePayload {
		return errors.New("ARPL resident stream payload too large")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.sequence++
	f := Frame{
		Channel:   s.channel,
		SessionID: s.active.codec.crypto.SessionID,
		StreamID:  s.id,
		Sequence:  s.sequence,
		Deadline:  deadline,
		Payload:   append([]byte(nil), payload...),
	}
	if err := s.active.send(f); err != nil {
		return ErrLinkDisconnected
	}
	return nil
}

func (s *ResidentStream) Recv(ctx context.Context) (Frame, error) {
	if s == nil || s.recv == nil || s.closed.Load() {
		return Frame{}, io.ErrClosedPipe
	}
	select {
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	case result, ok := <-s.recv:
		if !ok {
			return Frame{}, ErrLinkDisconnected
		}
		if result.err != nil {
			return Frame{}, result.err
		}
		return result.frame, nil
	}
}

func (s *ResidentStream) Close() error {
	if s == nil || s.closed.Swap(true) {
		return nil
	}
	s.active.unregister(s.id)
	return nil
}
