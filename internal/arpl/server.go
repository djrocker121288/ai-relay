package arpl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// SessionRegistry retains logical sessions independently of accepted sockets.
// A reconnect with the same session ID can continue work until the operator
// explicitly revokes the peer or removes the session.
type SessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]SessionState
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{sessions: map[string]SessionState{}}
}
func (r *SessionRegistry) Resume(id string) (SessionState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	return s, ok
}
func (r *SessionRegistry) Put(s SessionState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = map[string]SessionState{}
	}
	r.sessions[s.SessionID] = s
}
func (r *SessionRegistry) Remove(id string) { r.mu.Lock(); defer r.mu.Unlock(); delete(r.sessions, id) }

type Server struct {
	Listener     net.Listener
	Identity     Identity
	Peers        *PeerRegistry
	Sessions     *SessionRegistry
	OnFrame      func(SessionState, Frame) error
	Handler      func(context.Context, SessionState, Frame, func(Frame) error) error
	OnDisconnect func(SessionState, []uint64)
	Fleet        *FleetStore
	Audit        *AuditLog
	Path         string
}

func (s *Server) Serve(ctx context.Context) error {
	if s.Listener == nil || s.Sessions == nil || s.Peers == nil {
		return errors.New("ARPL server is incomplete")
	}
	if err := s.Identity.Validate(); err != nil {
		return err
	}
	for {
		conn, e := s.Listener.Accept()
		if e != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return e
			}
		}
		go s.handle(ctx, conn)
	}
}
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	started := time.Now()
	cs, e := HandshakeServer(ctx, conn, s.Identity, s.Peers, "")
	if e != nil {
		if s.Audit != nil {
			_ = s.Audit.Write(AuditEvent{Event: "auth_failed", OK: false, Metadata: map[string]string{"reason": e.Error()}})
		}
		return
	}
	state, ok := s.Sessions.Resume(cs.SessionID)
	if !ok {
		state = SessionState{SessionID: cs.SessionID}
	}
	state.PeerID = cs.PeerID
	state.Capabilities = s.Peers.Capabilities(cs.PeerID)
	connectedAt := time.Now().UTC()
	if s.Audit != nil {
		_ = s.Audit.Write(AuditEvent{Event: "connect", PeerID: cs.PeerID, OK: true})
	}
	if s.Fleet != nil {
		path := s.Path
		if path == "" {
			path = "accepted"
		}
		_ = s.Fleet.Update(FleetRecord{DeviceID: cs.PeerID, OS: cs.PeerOS, Arch: cs.PeerArch, Version: cs.PeerVersion, BuildHash: cs.PeerBuildHash, Capabilities: state.Capabilities, Connected: true, Path: path, LatencyMS: time.Since(started).Milliseconds(), LastConnect: connectedAt})
	}
	s.Sessions.Put(state)
	seenStreams := map[uint64]struct{}{}
	defer func() {
		if s.Audit != nil {
			_ = s.Audit.Write(AuditEvent{Event: "disconnect", PeerID: cs.PeerID, OK: true, Metadata: map[string]string{"uptime_seconds": fmt.Sprintf("%d", int64(time.Since(connectedAt).Seconds()))}})
		}
		if s.Fleet != nil {
			path := s.Path
			if path == "" {
				path = "accepted"
			}
			_ = s.Fleet.Update(FleetRecord{DeviceID: cs.PeerID, OS: cs.PeerOS, Arch: cs.PeerArch, Version: cs.PeerVersion, BuildHash: cs.PeerBuildHash, Capabilities: state.Capabilities, Connected: false, Path: path, LastDisconnect: time.Now().UTC(), UptimeSeconds: int64(time.Since(connectedAt).Seconds())})
		}
		if s.OnDisconnect != nil {
			ids := make([]uint64, 0, len(seenStreams))
			for id := range seenStreams {
				ids = append(ids, id)
			}
			s.OnDisconnect(state, ids)
		}
	}()
	codec, e := NewFrameCodec(&cs)
	if e != nil {
		return
	}
	var writeMu sync.Mutex
	responseSeq := map[uint64]uint64{}
	for {
		f, e := ReadFrame(conn, codec)
		if e != nil {
			return
		}
		if state.LastAck == nil {
			state.LastAck = map[uint64]uint64{}
		}
		state.LastAck[f.StreamID] = f.Sequence
		if f.StreamID != 0 {
			seenStreams[f.StreamID] = struct{}{}
		}
		s.Sessions.Put(state)
		requestStreamID := f.StreamID
		requestSequence := f.Sequence
		send := func(out Frame) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			if out.SessionID == "" {
				out.SessionID = state.SessionID
			}
			if out.StreamID == 0 {
				out.StreamID = requestStreamID
			}
			if out.Sequence == 0 {
				responseSeq[out.StreamID]++
				out.Sequence = responseSeq[out.StreamID]
			}
			if out.Ack == 0 {
				out.Ack = requestSequence
			}
			return WriteFrame(conn, codec, out)
		}
		if f.Channel == ChannelControl && f.StreamID == 0 && string(f.Payload) == "heartbeat" {
			if e = send(Frame{Channel: ChannelControl, StreamID: 0, Payload: []byte("heartbeat-ack")}); e != nil {
				return
			}
			continue
		}
		if s.Handler != nil {
			if e = s.Handler(ctx, state, f, send); e != nil {
				return
			}
			continue
		}
		if s.OnFrame != nil {
			if e = s.OnFrame(state, f); e != nil {
				return
			}
		}
	}
}
