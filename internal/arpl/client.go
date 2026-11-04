package arpl

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"
)

type SessionState struct {
	SessionID    string            `json:"session_id"`
	PeerID       string            `json:"peer_id,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
	LastAck      map[uint64]uint64 `json:"last_ack,omitempty"`
	NextSeq      map[uint64]uint64 `json:"next_seq,omitempty"`
}
type SessionStore interface {
	Load(context.Context) (SessionState, error)
	Save(context.Context, SessionState) error
}

type MemorySessionStore struct {
	mu    sync.Mutex
	State SessionState
}

func (s *MemorySessionStore) Load(context.Context) (SessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.State, nil
}
func (s *MemorySessionStore) Save(_ context.Context, v SessionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = v
	return nil
}

type Client struct {
	Transport              Transport
	Identity               Identity
	Peers                  *PeerRegistry
	Store                  SessionStore
	Heartbeat              time.Duration
	MinBackoff, MaxBackoff time.Duration
	Rand                   *rand.Rand
	OnConnect              func(SessionState)
	OnFrame                func(Frame) error
	Stop                   <-chan struct{}
}

func (c *Client) Run(ctx context.Context) error {
	if c.Transport == nil || c.Store == nil {
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
		if err = c.Store.Save(ctx, state); err != nil {
			return err
		}
	}
	heartbeat := c.Heartbeat
	if heartbeat <= 0 {
		heartbeat = 20 * time.Second
	}
	min := c.MinBackoff
	if min <= 0 {
		min = time.Second
	}
	max := c.MaxBackoff
	if max <= 0 {
		max = 60 * time.Second
	}
	rng := c.Rand
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	backoff := min
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-c.Stop:
			return nil
		default:
		}
		conn, e := c.Transport.Dial(ctx)
		if e != nil {
			d := jitter(backoff, rng)
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return ctx.Err()
			case <-c.Stop:
				return nil
			}
			if backoff < max {
				backoff *= 2
				if backoff > max {
					backoff = max
				}
			}
			continue
		}
		cs, e := HandshakeClient(ctx, conn, c.Identity, c.Peers, state.SessionID)
		if e != nil {
			_ = conn.Close()
			if e = waitBackoff(ctx, c.Stop, jitter(backoff, rng)); e != nil {
				return e
			}
			if backoff < max {
				backoff *= 2
				if backoff > max {
					backoff = max
				}
			}
			continue
		}
		codec, e := NewFrameCodec(&cs)
		if e != nil {
			_ = conn.Close()
			return e
		}
		backoff = min
		if c.OnConnect != nil {
			c.OnConnect(state)
		}
		err = c.connected(ctx, conn, codec, &state, heartbeat)
		_ = conn.Close()
		if err == nil {
			return nil
		}
	}
}

func (c *Client) connected(ctx context.Context, conn net.Conn, codec *FrameCodec, state *SessionState, heartbeat time.Duration) error {
	readErr := make(chan error, 1)
	activity := make(chan struct{}, 1)
	var stateMu sync.Mutex
	go func() {
		for {
			f, e := ReadFrame(conn, codec)
			if e != nil {
				readErr <- e
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
			if c.OnFrame != nil {
				if e = c.OnFrame(f); e != nil {
					readErr <- e
					return
				}
			}
		}
	}()

	t := time.NewTicker(heartbeat)
	defer t.Stop()
	staleTimer := time.NewTimer(staleConnectionTimeout(heartbeat))
	defer staleTimer.Stop()

	stateMu.Lock()
	if state.NextSeq == nil {
		state.NextSeq = map[uint64]uint64{}
	}
	seq := state.NextSeq[0] + 1
	stateMu.Unlock()

	for {
		select {
		case e := <-readErr:
			return e
		case <-activity:
			resetTimer(staleTimer, staleConnectionTimeout(heartbeat))
		case <-staleTimer.C:
			_ = conn.Close()
			return ErrLinkDisconnected
		case <-ctx.Done():
			return ctx.Err()
		case <-c.Stop:
			return nil
		case <-t.C:
			stateMu.Lock()
			sessionID := state.SessionID
			ack := state.LastAck[0]
			stateMu.Unlock()

			sentSeq := seq
			deadline := time.Now().Add(heartbeatWriteTimeout(heartbeat))
			f := Frame{
				Channel:   ChannelControl,
				SessionID: sessionID,
				StreamID:  0,
				Sequence:  sentSeq,
				Ack:       ack,
				Deadline:  deadline,
				Payload:   []byte("heartbeat"),
			}
			if e := conn.SetWriteDeadline(deadline); e != nil {
				return e
			}
			e := WriteFrame(conn, codec, f)
			_ = conn.SetWriteDeadline(time.Time{})
			if e != nil {
				return e
			}
			stateMu.Lock()
			state.NextSeq[0] = sentSeq
			snapshot := cloneSessionState(*state)
			stateMu.Unlock()
			seq++
			_ = c.Store.Save(context.Background(), snapshot)
		}
	}
}

func waitBackoff(ctx context.Context, stop <-chan struct{}, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-stop:
		return nil
	}
}

func jitter(d time.Duration, r *rand.Rand) time.Duration {
	if d <= 0 {
		return 0
	}
	n := d / 5
	if n <= 0 {
		return d
	}
	return d - n + time.Duration(r.Int63n(int64(2*n)+1))
}
