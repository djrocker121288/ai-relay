//go:build windows

package vault

import (
	"encoding/json"
	"errors"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	credTypeGeneric                       = 1
	credPersistLocalMachine               = 2
	errorNotFound           syscall.Errno = 1168
)

// credentialAPI is deliberately narrow so lifecycle tests do not need a
// Windows profile or write real credentials.
type credentialAPI interface {
	read(target *uint16) (*nativeCredential, error)
	write(c *nativeCredential) error
	delete(target *uint16) error
}

// CredentialManager stores an authenticated, versioned payload in the
// current Windows user's Credential Manager. The OS owns encryption and
// access control; secret bytes never enter argv, logs, or environment.
type CredentialManager struct {
	mu  sync.Mutex
	api credentialAPI
}

// Keep the Windows native adapter aligned with the shared lifecycle contract.
var _ Store = (*CredentialManager)(nil)
var _ NativeCleanup = (*CredentialManager)(nil)
var _ NativeCreateOnly = (*CredentialManager)(nil)

func (s *CredentialManager) ensureAPI() error {
	if s == nil || nilInterface(s.api) {
		return errors.New("credential manager API is nil")
	}
	return nil
}

// The platform API is an injected seam in tests and a native boundary in
// production. Contain an unexpected implementation panic here so ordinary
// Store callers receive a stable opaque error. PutIfAbsent still observes the
// returned error after its absence check and reports ownership for cleanup.
func safeCredentialRead(api credentialAPI, target *uint16) (credential *nativeCredential, err error) {
	defer func() {
		if recover() != nil {
			credential = nil
			err = errors.New("credential manager API read panicked")
		}
	}()
	return api.read(target)
}

func safeCredentialWrite(api credentialAPI, credential *nativeCredential) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("credential manager API write panicked")
		}
	}()
	return api.write(credential)
}

func safeCredentialDelete(api credentialAPI, target *uint16) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("credential manager API delete panicked")
		}
	}()
	return api.delete(target)
}

type nativeCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

type credentialPayload struct {
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Version   uint64    `json:"version"`
	Revoked   bool      `json:"revoked"`
	UpdatedAt time.Time `json:"updated_at"`
}

func OpenCredentialManager() *CredentialManager {
	return &CredentialManager{api: windowsCredentialAPI{}}
}

func (s *CredentialManager) Get(name string) (Record, error) {
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

func (s *CredentialManager) get(name string) (Record, error) {
	if err := validName(name); err != nil {
		return Record{}, err
	}
	if err := s.ensureAPI(); err != nil {
		return Record{}, err
	}
	p, err := s.read(name)
	if err != nil {
		return Record{}, err
	}
	if p.Revoked {
		return Record{}, ErrRevoked
	}
	return Record(p), nil
}

func (s *CredentialManager) Put(name, value string) (Record, error) {
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
	return s.store(credentialPayload{Name: name, Value: value, Version: version, UpdatedAt: time.Now().UTC()})
}

// PutIfAbsent creates a native credential only when the target is absent. The
// created flag remains true after the absence check so callers can clean up a
// write that may have committed before returning an error.
func (s *CredentialManager) PutIfAbsent(name, value string) (Record, bool, error) {
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
	record, err := s.store(credentialPayload{Name: name, Value: value, Version: 1, UpdatedAt: time.Now().UTC()})
	return record, true, err
}

func (s *CredentialManager) Rotate(name, value string) (Record, error) {
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
	return s.store(credentialPayload{Name: name, Value: value, Version: version, UpdatedAt: time.Now().UTC()})
}

func (s *CredentialManager) Revoke(name string) error {
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
	_, err = s.store(credentialPayload{Name: name, Version: old.Version, Revoked: true, UpdatedAt: time.Now().UTC()})
	return err
}

// Delete removes one named native credential for supervisor cleanup. Missing
// credentials are an idempotent success so cleanup can be retried safely.
// This is intentionally separate from Revoke and is not available on the file
// fallback.
func (s *CredentialManager) Delete(name string) error {
	if err := s.ensureAPI(); err != nil {
		return err
	}
	if err := ValidateNativeVerificationName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target, err := syscall.UTF16PtrFromString(credentialTarget(name))
	if err != nil {
		return err
	}
	err = rejectTypedNilError(safeCredentialDelete(s.api, target))
	if matched, _ := safeNativeErrorIs(err, errorNotFound); matched {
		return nil
	}
	return redactNativeStoreError("delete", err)
}

func (s *CredentialManager) read(name string) (credentialPayload, error) {
	if err := validName(name); err != nil {
		return credentialPayload{}, err
	}
	if err := s.ensureAPI(); err != nil {
		return credentialPayload{}, err
	}
	target, err := syscall.UTF16PtrFromString(credentialTarget(name))
	if err != nil {
		return credentialPayload{}, redactNativeStoreError("read", err)
	}
	c, err := safeCredentialRead(s.api, target)
	err = rejectTypedNilError(err)
	if matched, _ := safeNativeErrorIs(err, errorNotFound); matched {
		return credentialPayload{}, ErrNotFound
	}
	if err != nil {
		// Keep native API diagnostics out of the shared vault boundary while
		// preserving errors.Is/errors.As classification for callers that need
		// to distinguish an OS failure from an absent credential.
		return credentialPayload{}, redactNativeStoreError("read", err)
	}
	if c == nil {
		return credentialPayload{}, errors.New("credential payload is empty")
	}
	b, err := boundedCredentialBlob(c.CredentialBlob, c.CredentialBlobSize)
	if err != nil {
		return credentialPayload{}, err
	}
	var p credentialPayload
	if err := decodeSingleJSON(b, &p); err != nil || p.Name != name || p.Version == 0 {
		return credentialPayload{}, errors.New("credential payload is invalid")
	}
	if err := validateRecord(name, Record(p)); err != nil {
		return credentialPayload{}, errors.New("credential payload is invalid")
	}
	return p, nil
}

func (s *CredentialManager) store(p credentialPayload) (Record, error) {
	if err := validateRecord(p.Name, Record(p)); err != nil {
		return Record{}, errors.New("credential payload is invalid")
	}
	b, err := json.Marshal(p)
	if err != nil {
		return Record{}, err
	}
	return s.storeWithPayload(p, b)
}

// storeWithPayload repeats the record and serialized-payload checks at the
// lowest write helper. Keeping this boundary self-contained prevents a future
// caller from sending a malformed or metadata-mismatched blob to Credential
// Manager after an otherwise valid in-memory record check.
func (s *CredentialManager) storeWithPayload(p credentialPayload, b []byte) (Record, error) {
	if err := validateRecord(p.Name, Record(p)); err != nil {
		return Record{}, errors.New("credential payload is invalid")
	}
	if err := validPayload(b); err != nil {
		return Record{}, err
	}
	var encoded credentialPayload
	if err := decodeSingleJSON(b, &encoded); err != nil {
		return Record{}, errors.New("credential payload is invalid")
	}
	if encoded.Name != p.Name || encoded.Value != p.Value || encoded.Version != p.Version || encoded.Revoked != p.Revoked || !encoded.UpdatedAt.Equal(p.UpdatedAt) {
		return Record{}, errors.New("credential payload does not match record")
	}
	if err := s.ensureAPI(); err != nil {
		return Record{}, err
	}
	target, err := syscall.UTF16PtrFromString(credentialTarget(p.Name))
	if err != nil {
		return Record{}, err
	}
	user, err := syscall.UTF16PtrFromString("AI Relay 2.0")
	if err != nil {
		return Record{}, err
	}
	c := nativeCredential{Type: credTypeGeneric, TargetName: target, CredentialBlobSize: uint32(len(b)), Persist: credPersistLocalMachine, UserName: user, CredentialBlob: &b[0]}
	if err := rejectTypedNilError(safeCredentialWrite(s.api, &c)); err != nil {
		return Record{}, redactNativeStoreError("write", err)
	}
	return Record(p), nil
}

func credentialTarget(name string) string { return "AI Relay 2.0/" + name }

type windowsCredentialAPI struct{}

var (
	advapi32   = syscall.NewLazyDLL("advapi32.dll")
	credRead   = advapi32.NewProc("CredReadW")
	credWrite  = advapi32.NewProc("CredWriteW")
	credDelete = advapi32.NewProc("CredDeleteW")
	credFree   = advapi32.NewProc("CredFree")
)

func (windowsCredentialAPI) read(target *uint16) (*nativeCredential, error) {
	var c *nativeCredential
	r, _, e := credRead.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&c)))
	if r == 0 {
		return nil, e
	}
	if c == nil {
		return nil, errors.New("credential manager returned no payload")
	}
	defer credFree.Call(uintptr(unsafe.Pointer(c)))
	copy, err := ownedCredentialBlob(c)
	if err != nil {
		return nil, err
	}
	return copy, nil
}

func (windowsCredentialAPI) write(c *nativeCredential) error {
	r, _, e := credWrite.Call(uintptr(unsafe.Pointer(c)), 0)
	if r == 0 {
		return e
	}
	return nil
}

func (windowsCredentialAPI) delete(target *uint16) error {
	r, _, e := credDelete.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0)
	if r == 0 {
		return e
	}
	return nil
}

func copyBytes(dst []byte, src *byte) {
	for i := range dst {
		dst[i] = *(*byte)(unsafe.Add(unsafe.Pointer(src), i))
	}
}

func boundedCredentialBlob(src *byte, size uint32) ([]byte, error) {
	if size > maxPayloadSize {
		return nil, errors.New("credential payload exceeds limit")
	}
	if size == 0 {
		return nil, nil
	}
	if src == nil {
		return nil, errors.New("credential payload is empty")
	}
	b := make([]byte, size)
	copyBytes(b, src)
	return b, nil
}

// ownedCredentialBlob copies only the blob needed after CredFree releases the
// native CREDENTIALW allocation. Returning a blob-only shape avoids retaining
// dangling TargetName, Comment, Attribute, or UserName pointers in a Go value
// that outlives the native allocation.
func ownedCredentialBlob(src *nativeCredential) (*nativeCredential, error) {
	if src == nil {
		return nil, errors.New("credential manager returned no payload")
	}
	b, err := boundedCredentialBlob(src.CredentialBlob, src.CredentialBlobSize)
	if err != nil {
		return nil, err
	}
	owned := &nativeCredential{CredentialBlobSize: uint32(len(b))}
	if len(b) > 0 {
		owned.CredentialBlob = &b[0]
	}
	return owned, nil
}

var _ Store = (*CredentialManager)(nil)
