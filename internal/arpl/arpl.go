// Package arpl implements ARPL v0.1, the additive persistent device relay
// protocol used by AI Relay. It intentionally does not modify the legacy HTTP
// or SSH paths.
package arpl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const ProtocolVersion = "arpl/0.1"

var (
	ErrUnknownPeer = errors.New("arpl peer is not allowlisted")
	ErrRevokedPeer = errors.New("arpl peer is revoked")
	ErrReplay      = errors.New("arpl replay or counter violation")
)

// Identity is a long-term local device identity. PrivateKey is only used by
// the local signer and is never placed in a handshake message.
type Identity struct {
	DeviceID   string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func NewIdentity() (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	return Identity{DeviceID: DeviceID(pub), PrivateKey: priv, PublicKey: pub}, nil
}

func DeviceID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	parts := make([]string, 0, len(sum)/2)
	for i := 0; i < len(sum); i += 2 {
		parts = append(parts, hex.EncodeToString(sum[i:i+2]))
	}
	return strings.Join(parts, ":")
}

// KeyStore is the OS secure-store boundary. Native keychains/Keystores can
// implement it without changing the protocol. FileKeyStore is the portable
// owner-only fallback.
type KeyStore interface {
	Load() (Identity, error)
	Save(Identity) error
	Delete() error
}

type keyFile struct {
	Version    int    `json:"version"`
	DeviceID   string `json:"device_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type FileKeyStore struct{ Path string }

func (s FileKeyStore) Load() (Identity, error) {
	if s.Path == "" {
		return Identity{}, errors.New("identity key path is required")
	}
	st, err := os.Lstat(s.Path)
	if err != nil {
		return Identity{}, err
	}
	if !st.Mode().IsRegular() || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return Identity{}, errors.New("identity key must be a regular owner-only file")
	}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		return Identity{}, err
	}
	var f keyFile
	if len(b) > 16<<10 || json.Unmarshal(b, &f) != nil || f.Version != 1 {
		return Identity{}, errors.New("invalid ARPL identity file")
	}
	pub, err := base64.StdEncoding.DecodeString(f.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return Identity{}, errors.New("invalid ARPL identity public key")
	}
	priv, err := base64.StdEncoding.DecodeString(f.PrivateKey)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return Identity{}, errors.New("invalid ARPL identity private key")
	}
	if f.DeviceID != DeviceID(pub) || !ed25519.PublicKey(priv[32:]).Equal(ed25519.PublicKey(pub)) {
		return Identity{}, errors.New("ARPL identity key mismatch")
	}
	return Identity{DeviceID: f.DeviceID, PublicKey: ed25519.PublicKey(pub), PrivateKey: ed25519.PrivateKey(priv)}, nil
}

func (s FileKeyStore) Save(id Identity) error {
	if len(id.PrivateKey) != ed25519.PrivateKeySize || len(id.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid ARPL identity")
	}
	if id.DeviceID == "" {
		id.DeviceID = DeviceID(id.PublicKey)
	}
	if id.DeviceID != DeviceID(id.PublicKey) || !ed25519.PublicKey(id.PrivateKey[32:]).Equal(id.PublicKey) {
		return errors.New("ARPL identity key mismatch")
	}
	if s.Path == "" {
		return errors.New("identity key path is required")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(keyFile{Version: 1, DeviceID: id.DeviceID, PublicKey: base64.StdEncoding.EncodeToString(id.PublicKey), PrivateKey: base64.StdEncoding.EncodeToString(id.PrivateKey)})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".arpl-key-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(data, '\n'))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, s.Path)
}

func (s FileKeyStore) Delete() error { return os.Remove(s.Path) }

func LoadOrCreate(store KeyStore) (Identity, error) {
	if store == nil {
		return Identity{}, errors.New("ARPL key store is required")
	}
	id, err := store.Load()
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Identity{}, err
	}
	id, err = NewIdentity()
	if err != nil {
		return Identity{}, err
	}
	if err = store.Save(id); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// PeerRegistry is an explicit allowlist and revocation list. Revocation wins
// over an allow entry and is checked on every new connection/resume.
type PeerRegistry struct {
	mu      sync.RWMutex
	allowed map[string]ed25519.PublicKey
	revoked map[string]time.Time
	caps    map[string][]string
}

func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{allowed: map[string]ed25519.PublicKey{}, revoked: map[string]time.Time{}, caps: map[string][]string{}}
}

func (r *PeerRegistry) Allow(pub ed25519.PublicKey) string {
	id := DeviceID(pub)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.allowed == nil {
		r.allowed = map[string]ed25519.PublicKey{}
	}
	if r.caps == nil {
		r.caps = map[string][]string{}
	}
	r.allowed[id] = append(ed25519.PublicKey(nil), pub...)
	return id
}

// SetCapabilities restricts a trusted peer. Empty policy preserves
// backward-compatible behavior for peers enrolled before capability policy.
func (r *PeerRegistry) SetCapabilities(deviceID string, caps []string) error {
	if r == nil || strings.TrimSpace(deviceID) == "" {
		return errors.New("peer device ID is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.allowed[deviceID]; !ok {
		return ErrUnknownPeer
	}
	if r.caps == nil {
		r.caps = map[string][]string{}
	}
	r.caps[deviceID] = NormalizeCapabilities(caps)
	return nil
}

func (r *PeerRegistry) Capabilities(deviceID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.caps[deviceID]...)
}

func (r *PeerRegistry) Authorize(deviceID, capability string) error {
	if r == nil {
		return ErrUnknownPeer
	}
	return authorizeCapabilities(r.Capabilities(deviceID), capability)
}

func (r *PeerRegistry) Revoke(deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked == nil {
		r.revoked = map[string]time.Time{}
	}
	r.revoked[deviceID] = time.Now().UTC()
}

func (r *PeerRegistry) Check(deviceID string, pub ed25519.PublicKey) error {
	if r == nil {
		return ErrUnknownPeer
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.revoked[deviceID]; ok {
		return ErrRevokedPeer
	}
	known, ok := r.allowed[deviceID]
	if !ok || !known.Equal(pub) {
		return ErrUnknownPeer
	}
	return nil
}

func (r *PeerRegistry) IsRevoked(deviceID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.revoked[deviceID]
	return ok
}

func (id Identity) Validate() error {
	if len(id.PrivateKey) != ed25519.PrivateKeySize || len(id.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid ARPL identity")
	}
	if id.DeviceID != DeviceID(id.PublicKey) || !ed25519.PublicKey(id.PrivateKey[32:]).Equal(id.PublicKey) {
		return errors.New("ARPL identity key mismatch")
	}
	return nil
}

func (id Identity) String() string { return fmt.Sprintf("ARPL identity %s", id.DeviceID) }

// SecureStoreUnavailable documents the portability boundary for callers that
// require a native store rather than the file fallback.
func SecureStoreUnavailable() error {
	return fmt.Errorf("native secure store adapter is not wired on %s; use owner-only FileKeyStore or provide a KeyStore", runtime.GOOS)
}
