package arpl

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type EnrollmentPayload struct {
	Version       int    `json:"version"`
	Issuer        string `json:"issuer"`
	Peer          string `json:"peer"`
	PeerPublicKey string `json:"peer_public_key"`
	Code          string `json:"code"`
	Expires       int64  `json:"expires"`
	Nonce         string `json:"nonce"`
	Sig           string `json:"signature"`
}

type EnrollmentManager struct {
	Identity  Identity
	TTL       time.Duration
	StorePath string
	mu        sync.Mutex
	used      map[string]time.Time
}

func (m *EnrollmentManager) Issue(peerPublicKey ed25519.PublicKey) (EnrollmentPayload, error) {
	if err := m.Identity.Validate(); err != nil {
		return EnrollmentPayload{}, err
	}
	if len(peerPublicKey) != ed25519.PublicKeySize {
		return EnrollmentPayload{}, errors.New("peer public key is required")
	}
	ttl := m.TTL
	if ttl <= 0 || ttl > 15*time.Minute {
		ttl = 5 * time.Minute
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return EnrollmentPayload{}, err
	}
	p := EnrollmentPayload{Version: 1, Issuer: m.Identity.DeviceID, Peer: DeviceID(peerPublicKey), PeerPublicKey: base64.RawStdEncoding.EncodeToString(peerPublicKey), Code: randomCode(), Expires: time.Now().Add(ttl).Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonce[:])}
	p.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(m.Identity.PrivateKey, enrollmentBytes(p)))
	m.mu.Lock()
	if m.used == nil {
		m.used = map[string]time.Time{}
	}
	m.mu.Unlock()
	return p, nil
}

func (m *EnrollmentManager) Consume(p EnrollmentPayload, peerPublicKey ed25519.PublicKey) error {
	if err := m.Identity.Validate(); err != nil {
		return err
	}
	if len(peerPublicKey) == 0 && p.PeerPublicKey != "" {
		decoded, decodeErr := base64.RawStdEncoding.DecodeString(p.PeerPublicKey)
		if decodeErr == nil && len(decoded) == ed25519.PublicKeySize {
			peerPublicKey = ed25519.PublicKey(decoded)
		}
	}
	if p.Version != 1 || p.Issuer != m.Identity.DeviceID || len(peerPublicKey) != ed25519.PublicKeySize || p.Peer != DeviceID(peerPublicKey) || p.Code == "" || p.Nonce == "" || p.PeerPublicKey == "" {
		return errors.New("invalid enrollment payload")
	}
	if time.Now().Unix() >= p.Expires {
		return errors.New("enrollment payload expired")
	}
	sig, err := base64.RawURLEncoding.DecodeString(p.Sig)
	if err != nil || !ed25519.Verify(m.Identity.PublicKey, enrollmentBytes(p), sig) {
		return errors.New("enrollment signature verification failed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.used == nil {
		m.used = map[string]time.Time{}
	}
	if m.StorePath != "" {
		if err := m.loadUsedLocked(); err != nil {
			return err
		}
	}
	if _, ok := m.used[p.Nonce]; ok {
		return errors.New("enrollment payload already used")
	}
	m.used[p.Nonce] = time.Now().UTC()
	if m.StorePath != "" {
		if err := m.saveUsedLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (m *EnrollmentManager) loadUsedLocked() error {
	b, err := os.ReadFile(m.StorePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var v map[string]time.Time
	if err = json.Unmarshal(b, &v); err != nil {
		return err
	}
	for k, t := range v {
		m.used[k] = t
	}
	return nil
}
func (m *EnrollmentManager) saveUsedLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.StorePath), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(m.used)
	if err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(m.StorePath), ".arpl-enrollment-*")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	defer os.Remove(tmp)
	if err = tmpFile.Chmod(0600); err == nil {
		_, err = tmpFile.Write(append(b, '\n'))
	}
	if closeErr := tmpFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, m.StorePath)
}

func EncodeEnrollment(p EnrollmentPayload) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func DecodeEnrollment(v string) (EnrollmentPayload, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return EnrollmentPayload{}, err
	}
	var p EnrollmentPayload
	if err = json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	return p, nil
}
func enrollmentBytes(p EnrollmentPayload) []byte { p.Sig = ""; b, _ := json.Marshal(p); return b }
func randomCode() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%06d", int(b[0])<<8|int(b[1]))
}
