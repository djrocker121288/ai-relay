package arpl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

const maxHandshakeMessage = 16 << 10

type hello struct {
	Version   string `json:"version"`
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
	Challenge string `json:"challenge"`
	Ephemeral string `json:"ephemeral"`
	Resume    string `json:"resume,omitempty"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
	BuildHash string `json:"build_hash,omitempty"`
}

type auth struct {
	DeviceID  string `json:"device_id"`
	Signature string `json:"signature"`
}

// SessionCrypto is the end-to-end payload protection layer. TLS protects the
// socket; this layer allows an untrusted future relay to forward opaque frames.
type SessionCrypto struct {
	SessionID                  string
	PeerOS, PeerArch           string
	PeerVersion, PeerBuildHash string
	PeerID                     string
	PeerPublicKey              ed25519.PublicKey
	sendKey, recvKey           [32]byte
	sendPrefix, recvPrefix     [4]byte
	send, recv                 uint64
}

func (s *SessionCrypto) NextSendCounter() uint64 { s.send++; return s.send }
func (s *SessionCrypto) LastRecvCounter() uint64 { return s.recv }

func doHandshake(ctx context.Context, rw io.ReadWriter, local Identity, peers *PeerRegistry, initiator bool, resume string) (SessionCrypto, error) {
	if err := local.Validate(); err != nil {
		return SessionCrypto{}, err
	}
	if peers == nil {
		return SessionCrypto{}, errors.New("peer registry is required")
	}
	if err := ctx.Err(); err != nil {
		return SessionCrypto{}, err
	}
	if initiator {
		if resume == "" {
			resume = NewSessionID()
		}
		if len(resume) != 32 {
			return SessionCrypto{}, errors.New("invalid ARPL session ID")
		}
	} else {
		// The initiator is authoritative for the logical session identifier.
		// A responder never invents a competing ID during a reconnect.
		resume = ""
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return SessionCrypto{}, err
	}
	challenge := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, challenge); err != nil {
		return SessionCrypto{}, err
	}
	h := hello{
		Version:   ProtocolVersion,
		DeviceID:  local.DeviceID,
		PublicKey: base64.RawStdEncoding.EncodeToString(local.PublicKey),
		Challenge: base64.RawStdEncoding.EncodeToString(challenge),
		Ephemeral: base64.RawStdEncoding.EncodeToString(eph.PublicKey().Bytes()),
		Resume:    resume,
		OS:        runtime.GOOS, Arch: runtime.GOARCH, BuildHash: os.Getenv("ARPL_BUILD_HASH"),
	}
	localHello, err := json.Marshal(h)
	if err != nil {
		return SessionCrypto{}, err
	}

	var remoteHello []byte
	if initiator {
		if err = writeHandshake(rw, localHello); err != nil {
			return SessionCrypto{}, err
		}
		remoteHello, err = readHandshake(rw)
		if err != nil {
			return SessionCrypto{}, err
		}
	} else {
		remoteHello, err = readHandshake(rw)
		if err != nil {
			return SessionCrypto{}, err
		}
		if err = writeHandshake(rw, localHello); err != nil {
			return SessionCrypto{}, err
		}
	}

	var remote hello
	if err = json.Unmarshal(remoteHello, &remote); err != nil || remote.Version != ProtocolVersion {
		return SessionCrypto{}, errors.New("invalid ARPL hello")
	}
	remotePub, err := base64.RawStdEncoding.DecodeString(remote.PublicKey)
	if err != nil || len(remotePub) != ed25519.PublicKeySize {
		return SessionCrypto{}, errors.New("invalid peer public key")
	}
	if remote.DeviceID != DeviceID(remotePub) {
		return SessionCrypto{}, errors.New("peer device ID mismatch")
	}
	if err = peers.Check(remote.DeviceID, ed25519.PublicKey(remotePub)); err != nil {
		return SessionCrypto{}, err
	}
	remoteChallenge, err := base64.RawStdEncoding.DecodeString(remote.Challenge)
	if err != nil || len(remoteChallenge) != 32 {
		return SessionCrypto{}, errors.New("invalid peer challenge")
	}
	_ = remoteChallenge
	remoteEph, err := base64.RawStdEncoding.DecodeString(remote.Ephemeral)
	if err != nil || len(remoteEph) != 32 {
		return SessionCrypto{}, errors.New("invalid peer ephemeral key")
	}

	// Canonical transcript order is always initiator hello, responder hello.
	transcript := handshakeTranscript(localHello, remoteHello, initiator)
	localSig := ed25519.Sign(local.PrivateKey, transcript)
	if initiator {
		if err = writeHandshake(rw, jsonMust(auth{DeviceID: local.DeviceID, Signature: base64.RawStdEncoding.EncodeToString(localSig)})); err != nil {
			return SessionCrypto{}, err
		}
		ab, e := readHandshake(rw)
		if e != nil {
			return SessionCrypto{}, e
		}
		var a auth
		if json.Unmarshal(ab, &a) != nil {
			return SessionCrypto{}, errors.New("invalid ARPL authentication")
		}
		if err = verifyAuth(a, peers, transcript, remote.DeviceID, remotePub); err != nil {
			return SessionCrypto{}, err
		}
	} else {
		ab, e := readHandshake(rw)
		if e != nil {
			return SessionCrypto{}, e
		}
		var a auth
		if json.Unmarshal(ab, &a) != nil {
			return SessionCrypto{}, errors.New("invalid ARPL authentication")
		}
		if err = verifyAuth(a, peers, transcript, remote.DeviceID, remotePub); err != nil {
			return SessionCrypto{}, err
		}
		if err = writeHandshake(rw, jsonMust(auth{DeviceID: local.DeviceID, Signature: base64.RawStdEncoding.EncodeToString(localSig)})); err != nil {
			return SessionCrypto{}, err
		}
	}

	remoteEphKey, err := ecdh.X25519().NewPublicKey(remoteEph)
	if err != nil {
		return SessionCrypto{}, err
	}
	shared, err := eph.ECDH(remoteEphKey)
	if err != nil {
		return SessionCrypto{}, err
	}

	sessionID := h.Resume
	if !initiator {
		sessionID = remote.Resume
	}
	if len(sessionID) != 32 {
		return SessionCrypto{}, errors.New("invalid ARPL negotiated session ID")
	}

	material := make([]byte, 0, len("ARPL v0.1 key schedule\x00")+len(shared)+len(transcript))
	material = append(material, []byte("ARPL v0.1 key schedule\x00")...)
	material = append(material, shared...)
	material = append(material, transcript...)
	seed := sha256.Sum256(material)
	a, b := deriveKey(seed[:], "initiator"), deriveKey(seed[:], "responder")
	var crypto SessionCrypto
	crypto.SessionID = sessionID
	crypto.PeerID = remote.DeviceID
	crypto.PeerPublicKey = append(ed25519.PublicKey(nil), remotePub...)
	crypto.PeerOS, crypto.PeerArch, crypto.PeerVersion, crypto.PeerBuildHash = remote.OS, remote.Arch, remote.Version, remote.BuildHash
	if initiator {
		crypto.sendKey, crypto.recvKey, crypto.sendPrefix, crypto.recvPrefix = a.key, b.key, a.prefix, b.prefix
	} else {
		crypto.sendKey, crypto.recvKey, crypto.sendPrefix, crypto.recvPrefix = b.key, a.key, b.prefix, a.prefix
	}
	return crypto, nil
}

func HandshakeClient(ctx context.Context, rw io.ReadWriter, local Identity, peers *PeerRegistry, resume string) (SessionCrypto, error) {
	return doHandshake(ctx, rw, local, peers, true, resume)
}
func HandshakeServer(ctx context.Context, rw io.ReadWriter, local Identity, peers *PeerRegistry, resume string) (SessionCrypto, error) {
	return doHandshake(ctx, rw, local, peers, false, resume)
}

func verifyAuth(a auth, peers *PeerRegistry, transcript []byte, expectedDeviceID string, expectedPub []byte) error {
	sig, err := base64.RawStdEncoding.DecodeString(a.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || a.DeviceID == "" {
		return errors.New("invalid ARPL signature")
	}
	if a.DeviceID != expectedDeviceID {
		return errors.New("ARPL authenticated device ID mismatch")
	}
	pub := ed25519.PublicKey(expectedPub)
	if !ed25519.Verify(pub, transcript, sig) {
		return errors.New("ARPL signature verification failed")
	}
	return peers.Check(a.DeviceID, pub)
}

func handshakeTranscript(local, remote []byte, initiator bool) []byte {
	first, second := local, remote
	if !initiator {
		first, second = remote, local
	}
	b := bytes.NewBufferString("ARPL v0.1 signed challenge\x00")
	_ = binary.Write(b, binary.BigEndian, uint32(len(first)))
	b.Write(first)
	_ = binary.Write(b, binary.BigEndian, uint32(len(second)))
	b.Write(second)
	return b.Bytes()
}

type derivedKey struct {
	key    [32]byte
	prefix [4]byte
}

func deriveKey(seed []byte, label string) derivedKey {
	var d derivedKey
	h := sha256.Sum256(append(append([]byte("ARPL key/"), []byte(label)...), seed...))
	copy(d.key[:], h[:])
	p := sha256.Sum256(append([]byte("ARPL nonce/"), h[:]...))
	copy(d.prefix[:], p[:4])
	return d
}

func writeHandshake(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > maxHandshakeMessage {
		return errors.New("invalid ARPL handshake size")
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}
func readHandshake(r io.Reader) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > maxHandshakeMessage {
		return nil, fmt.Errorf("ARPL handshake exceeds %d bytes", maxHandshakeMessage)
	}
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	return b, err
}
func jsonMust(v any) []byte { b, _ := json.Marshal(v); return b }
