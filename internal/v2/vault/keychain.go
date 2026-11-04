package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	errSecSuccess        = 0
	errSecNoSuchKeychain = -25294
)

// keychainStatusError preserves a Security.framework status for classification
// through the opaque native-store error boundary. Its Error text deliberately
// excludes the numeric status so platform diagnostics cannot become caller or
// supervisor output. Callers that need machine-readable status may use
// errors.As with the local Status() interface.
type keychainStatusError struct {
	operation string
	status    int
}

func (e *keychainStatusError) Error() string {
	return "macOS Keychain " + e.operation + " failed"
}

func (e *keychainStatusError) Status() int { return e.status }

func classifyKeychainAPIStatus(operation string, status int) error {
	if status == errSecSuccess {
		return nil
	}
	switch operation {
	case "read", "write", "delete":
	default:
		operation = "operation"
	}
	return &keychainStatusError{operation: operation, status: status}
}

// keychainProbeStatusError preserves a non-missing Security.framework probe
// status without exposing its numeric native diagnostic. OpenKeychain is an
// exported constructor and therefore needs the same opaque boundary as the
// lifecycle API, while callers may still classify the status with errors.As.
type keychainProbeStatusError struct{ status int }

func (e *keychainProbeStatusError) Error() string { return "macOS Keychain probe failed" }

func (e *keychainProbeStatusError) Status() int { return e.status }

// classifyKeychainProbeStatus keeps backend selection fail-closed: only the
// platform's explicit "no keychain" result permits the encrypted-file
// fallback. Permission and other Security.framework failures remain visible.
// The cgo probe maps success without a default-keychain reference to the same
// unavailable boundary instead of returning an unusable native adapter.
func classifyKeychainProbeStatus(status int) error {
	switch status {
	case errSecSuccess:
		return nil
	case errSecNoSuchKeychain:
		return ErrUnavailable
	default:
		return &keychainProbeStatusError{status: status}
	}
}

// keychainAPI is deliberately narrow so lifecycle tests do not need a macOS
// login session or write real Keychain items.
type keychainAPI interface {
	read(account string) ([]byte, error)
	write(account string, payload []byte) error
	delete(account string) error
}

// The platform API is an injected seam in tests and a native boundary in
// production. Contain an unexpected implementation panic here so ordinary
// Store callers receive a stable opaque error. PutIfAbsent still observes the
// returned error after its absence check and reports ownership for cleanup.
func safeKeychainRead(api keychainAPI, account string) (data []byte, err error) {
	defer func() {
		if recover() != nil {
			data = nil
			err = errors.New("keychain API read panicked")
		}
	}()
	return api.read(account)
}

func safeKeychainWrite(api keychainAPI, account string, payload []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("keychain API write panicked")
		}
	}()
	return api.write(account, payload)
}

func safeKeychainDelete(api keychainAPI, account string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("keychain API delete panicked")
		}
	}()
	return api.delete(account)
}

// Keychain stores a versioned payload in the macOS user's login Keychain.
// Platform code owns the native encryption and access-control boundary.
type Keychain struct {
	mu  sync.Mutex
	api keychainAPI
}

// Keep the macOS native adapter aligned with the shared lifecycle contract.
var _ Store = (*Keychain)(nil)
var _ NativeCleanup = (*Keychain)(nil)
var _ NativeCreateOnly = (*Keychain)(nil)

func (s *Keychain) ensureAPI() error {
	if s == nil || nilInterface(s.api) {
		return errors.New("keychain API is nil")
	}
	return nil
}

type keychainPayload struct {
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Version   uint64    `json:"version"`
	Revoked   bool      `json:"revoked"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Keychain) Get(name string) (Record, error) {
	if err := s.ensureAPI(); err != nil {
		return Record{}, err
	}
	if err := validName(name); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(name)
}

func (s *Keychain) get(name string) (Record, error) {
	if err := validName(name); err != nil {
		return Record{}, err
	}
	if err := s.ensureAPI(); err != nil {
		return Record{}, err
	}
	b, err := safeKeychainRead(s.api, name)
	err = rejectTypedNilError(err)
	if err != nil {
		// Keep the explicit missing-item classification stable across native
		// backends. The injected and Security.framework adapters use ErrNotFound
		// for an absent account; do not turn that expected result into an opaque
		// read failure while preserving opaque diagnostics for other failures.
		if matched, _ := safeNativeErrorIs(err, ErrNotFound); matched {
			return Record{}, ErrNotFound
		}
		return Record{}, redactNativeStoreError("read", err)
	}
	if err := validPayload(b); err != nil {
		return Record{}, err
	}
	var p keychainPayload
	if err := decodeSingleJSON(b, &p); err != nil || p.Name != name || p.Version == 0 {
		return Record{}, errors.New("keychain record is invalid")
	}
	if err := validateRecord(name, Record(p)); err != nil {
		return Record{}, errors.New("keychain record is invalid")
	}
	if p.Revoked {
		return Record{}, ErrRevoked
	}
	return Record(p), nil
}

func (s *Keychain) Put(name, value string) (Record, error) {
	if err := s.ensureAPI(); err != nil {
		return Record{}, err
	}
	if err := validName(name); err != nil {
		return Record{}, err
	}
	if err := validValue(value); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	version := uint64(1)
	if old, err := s.get(name); err == nil {
		version, err = nextRecordVersion(old.Version)
		if err != nil {
			return Record{}, err
		}
	} else if matched, _ := safeNativeErrorIs(err, ErrNotFound); !matched {
		return Record{}, err
	}
	return s.store(keychainPayload{Name: name, Value: value, Version: version, UpdatedAt: time.Now().UTC()})
}

// PutIfAbsent creates a native item only when the name is absent. The created
// flag remains true after the absence check so callers can clean up a write
// that may have committed before returning an error.
func (s *Keychain) PutIfAbsent(name, value string) (Record, bool, error) {
	if err := s.ensureAPI(); err != nil {
		return Record{}, false, err
	}
	if err := ValidateNativeVerificationName(name); err != nil {
		return Record{}, false, err
	}
	if err := validValue(value); err != nil {
		return Record{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.get(name); err == nil {
		return Record{}, false, ErrAlreadyExists
	} else if matched, _ := safeNativeErrorIs(err, ErrRevoked); matched {
		return Record{}, false, ErrAlreadyExists
	} else if matched, _ := safeNativeErrorIs(err, ErrNotFound); !matched {
		return Record{}, false, err
	}
	record, err := s.store(keychainPayload{Name: name, Value: value, Version: 1, UpdatedAt: time.Now().UTC()})
	return record, true, err
}

func (s *Keychain) Rotate(name, value string) (Record, error) {
	if err := s.ensureAPI(); err != nil {
		return Record{}, err
	}
	if err := validName(name); err != nil {
		return Record{}, err
	}
	if err := validValue(value); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.get(name)
	if err != nil {
		return Record{}, err
	}
	version, err := nextRecordVersion(old.Version)
	if err != nil {
		return Record{}, err
	}
	return s.store(keychainPayload{Name: name, Value: value, Version: version, UpdatedAt: time.Now().UTC()})
}

func (s *Keychain) Revoke(name string) error {
	if err := s.ensureAPI(); err != nil {
		return err
	}
	if err := validName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.get(name)
	if err != nil {
		if matched, _ := safeNativeErrorIs(err, ErrRevoked); matched {
			return nil
		}
		return err
	}
	_, err = s.store(keychainPayload{Name: name, Version: old.Version, Revoked: true, UpdatedAt: time.Now().UTC()})
	return err
}

// Delete removes one named native item for supervisor cleanup. Missing items
// are an idempotent success so a partially completed cleanup can be retried.
// This is intentionally separate from Revoke and is not available on the file
// fallback.
func (s *Keychain) Delete(name string) error {
	if err := s.ensureAPI(); err != nil {
		return err
	}
	if err := ValidateNativeVerificationName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := rejectTypedNilError(safeKeychainDelete(s.api, name))
	if matched, _ := safeNativeErrorIs(err, ErrNotFound); matched {
		return nil
	}
	return redactNativeStoreError("delete", err)
}

func (s *Keychain) store(p keychainPayload) (Record, error) {
	if err := validateRecord(p.Name, Record(p)); err != nil {
		return Record{}, fmt.Errorf("keychain record is invalid: %w", err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		return Record{}, err
	}
	return s.storeWithPayload(p, b)
}

// storeWithPayload repeats the record and serialized-payload checks at the
// lowest write helper. Keeping this boundary self-contained prevents a future
// caller from sending a malformed or metadata-mismatched blob to the native
// Keychain API after an otherwise valid in-memory record check.
func (s *Keychain) storeWithPayload(p keychainPayload, b []byte) (Record, error) {
	if err := validateRecord(p.Name, Record(p)); err != nil {
		return Record{}, errors.New("keychain record is invalid")
	}
	if err := validPayload(b); err != nil {
		return Record{}, err
	}
	var encoded keychainPayload
	if err := decodeSingleJSON(b, &encoded); err != nil {
		return Record{}, errors.New("keychain payload is invalid")
	}
	if encoded.Name != p.Name || encoded.Value != p.Value || encoded.Version != p.Version || encoded.Revoked != p.Revoked || !encoded.UpdatedAt.Equal(p.UpdatedAt) {
		return Record{}, errors.New("keychain payload does not match record")
	}
	if err := s.ensureAPI(); err != nil {
		return Record{}, err
	}
	if err := rejectTypedNilError(safeKeychainWrite(s.api, p.Name, b)); err != nil {
		return Record{}, redactNativeStoreError("write", err)
	}
	return Record(p), nil
}
