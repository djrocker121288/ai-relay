package arpl

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	maxFramePayload = 1 << 20
	frameHeaderSize = 72
	frameMagic      = "ARPL"
)

type Channel uint8

const (
	ChannelControl Channel = iota
	ChannelTerminal
	ChannelExec
	ChannelFile
	ChannelTelemetry
	ChannelTool
)

type Frame struct {
	Channel   Channel
	Flags     uint16
	SessionID string
	StreamID  uint64
	Sequence  uint64
	Ack       uint64
	Deadline  time.Time
	Payload   []byte
}

func (f Frame) validate() error {
	if len(f.SessionID) != 32 {
		return errors.New("ARPL session ID must be 32 hex characters")
	}
	for _, c := range f.SessionID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return errors.New("invalid ARPL session ID")
		}
	}
	if len(f.Payload) > maxFramePayload {
		return fmt.Errorf("ARPL payload exceeds %d bytes", maxFramePayload)
	}
	if f.Channel > ChannelTool {
		return errors.New("invalid ARPL channel")
	}
	return nil
}

func NewSessionID() string {
	var b [16]byte
	_, _ = io.ReadFull(randReader{}, b[:])
	return hexEncode(b[:])
}

// randReader keeps this file's helper testable without exposing key material.
type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return cryptoRandRead(p) }

var cryptoRandRead = func(p []byte) (int, error) { return io.ReadFull(randSource{}, p) }

type randSource struct{}

func (randSource) Read(p []byte) (int, error) { return cryptoRand(p) }

// These indirections are replaced by crypto/rand through rand.go; keeping the
// generator isolated avoids accidental use for identity or handshake keys.
func hexEncode(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2], out[i*2+1] = h[v>>4], h[v&15]
	}
	return string(out)
}

type FrameCodec struct {
	crypto                   *SessionCrypto
	sendAEAD                 cipher.AEAD
	recvAEAD                 cipher.AEAD
	lastSendSeq, lastRecvSeq map[uint64]uint64
}

func NewFrameCodec(c *SessionCrypto) (*FrameCodec, error) {
	if c == nil || len(c.SessionID) != 32 {
		return nil, errors.New("ARPL crypto session is required")
	}
	a, err := aes.NewCipher(c.sendKey[:])
	if err != nil {
		return nil, err
	}
	send, err := cipher.NewGCM(a)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(c.recvKey[:])
	if err != nil {
		return nil, err
	}
	recv, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &FrameCodec{crypto: c, sendAEAD: send, recvAEAD: recv, lastSendSeq: map[uint64]uint64{}, lastRecvSeq: map[uint64]uint64{}}, nil
}

func nonce(prefix [4]byte, counter uint64) []byte {
	n := make([]byte, 12)
	copy(n, prefix[:])
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}
func sessionBytes(s string) []byte {
	out := make([]byte, 16)
	for i := range out {
		out[i] = fromHex(s[i*2])<<4 | fromHex(s[i*2+1])
	}
	return out
}
func fromHex(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	return c - 'a' + 10
}

func (s *FrameCodec) Seal(f Frame) ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	if f.SessionID != s.crypto.SessionID {
		return nil, errors.New("ARPL frame session mismatch")
	}
	if prior := s.lastSendSeq[f.StreamID]; f.Sequence <= prior {
		return nil, ErrReplay
	}
	counter := s.crypto.NextSendCounter()
	plain := f.Payload
	// Associated data authenticates all routing, ordering, deadline and session metadata.
	head := makeHeader(f, counter, uint32(len(plain)+s.sendAEAD.Overhead()))
	ciphertext := s.sendAEAD.Seal(nil, nonce(s.crypto.sendPrefix, counter), plain, head)
	s.lastSendSeq[f.StreamID] = f.Sequence
	return marshalFrame(head, ciphertext)
}

func (s *FrameCodec) Open(raw []byte) (Frame, error) {
	head, payload, err := splitFrame(raw)
	if err != nil {
		return Frame{}, err
	}
	f, counter, err := parseHeader(head)
	if err != nil {
		return Frame{}, err
	}
	if f.SessionID != s.crypto.SessionID {
		return Frame{}, errors.New("ARPL frame session mismatch")
	}
	if !f.Deadline.IsZero() && time.Now().After(f.Deadline) {
		return Frame{}, errors.New("ARPL frame deadline exceeded")
	}
	if counter != s.crypto.LastRecvCounter()+1 {
		return Frame{}, ErrReplay
	}
	if prior := s.lastRecvSeq[f.StreamID]; f.Sequence <= prior {
		return Frame{}, ErrReplay
	}
	plain, err := s.recvAEAD.Open(nil, nonce(s.crypto.recvPrefix, counter), payload, head)
	if err != nil {
		return Frame{}, errors.New("ARPL frame authentication failed")
	}
	s.crypto.recv = counter
	s.lastRecvSeq[f.StreamID] = f.Sequence
	f.Payload = plain
	return f, nil
}

func makeHeader(f Frame, counter uint64, payloadLen uint32) []byte {
	h := make([]byte, frameHeaderSize)
	copy(h[:4], frameMagic)
	h[4] = 1
	h[5] = byte(f.Channel)
	binary.BigEndian.PutUint16(h[6:8], f.Flags)
	copy(h[8:24], sessionBytes(f.SessionID))
	binary.BigEndian.PutUint64(h[24:32], f.StreamID)
	binary.BigEndian.PutUint64(h[32:40], f.Sequence)
	binary.BigEndian.PutUint64(h[40:48], f.Ack)
	if !f.Deadline.IsZero() {
		binary.BigEndian.PutUint64(h[48:56], uint64(f.Deadline.UnixNano()))
	}
	binary.BigEndian.PutUint32(h[56:60], payloadLen)
	binary.BigEndian.PutUint64(h[60:68], counter)
	return h
}
func marshalFrame(header, payload []byte) ([]byte, error) {
	if len(header) != frameHeaderSize || len(payload) > maxFramePayload+16 {
		return nil, errors.New("invalid ARPL frame")
	}
	out := make([]byte, len(header)+len(payload))
	copy(out, header)
	copy(out[len(header):], payload)
	return out, nil
}
func splitFrame(raw []byte) ([]byte, []byte, error) {
	if len(raw) < frameHeaderSize || len(raw) > frameHeaderSize+maxFramePayload+16 {
		return nil, nil, errors.New("invalid ARPL frame size")
	}
	if string(raw[:4]) != frameMagic || raw[4] != 1 {
		return nil, nil, errors.New("invalid ARPL frame header")
	}
	n := binary.BigEndian.Uint32(raw[56:60])
	if int(n) != len(raw)-frameHeaderSize || n > maxFramePayload+16 {
		return nil, nil, errors.New("invalid ARPL payload length")
	}
	return raw[:frameHeaderSize], raw[frameHeaderSize:], nil
}
func parseHeader(h []byte) (Frame, uint64, error) {
	if len(h) != frameHeaderSize || string(h[:4]) != frameMagic || h[4] != 1 {
		return Frame{}, 0, errors.New("invalid ARPL frame header")
	}
	sid := hexEncode(h[8:24])
	f := Frame{Channel: Channel(h[5]), Flags: binary.BigEndian.Uint16(h[6:8]), SessionID: sid, StreamID: binary.BigEndian.Uint64(h[24:32]), Sequence: binary.BigEndian.Uint64(h[32:40]), Ack: binary.BigEndian.Uint64(h[40:48])}
	nanos := int64(binary.BigEndian.Uint64(h[48:56]))
	if nanos != 0 {
		f.Deadline = time.Unix(0, nanos)
	}
	if f.Channel > ChannelTool {
		return Frame{}, 0, errors.New("invalid ARPL channel")
	}
	return f, binary.BigEndian.Uint64(h[60:68]), nil
}

// WriteFrame and ReadFrame are length-delimited transport operations. The
// outer length is bounded before allocation and is independent of TCP reads.
func WriteFrame(w io.Writer, state *FrameCodec, f Frame) error {
	raw, err := state.Seal(f)
	if err != nil {
		return err
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(raw)))
	if _, err = w.Write(n[:]); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}
func ReadFrame(r io.Reader, state *FrameCodec) (Frame, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return Frame{}, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size < frameHeaderSize || size > frameHeaderSize+maxFramePayload+16 {
		return Frame{}, errors.New("ARPL frame length out of bounds")
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(r, raw); err != nil {
		return Frame{}, err
	}
	return state.Open(raw)
}
