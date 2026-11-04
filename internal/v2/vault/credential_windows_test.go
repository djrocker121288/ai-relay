//go:build windows

package vault

import (
	"encoding/json"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestCredentialManagerRejectsNilAPI(t *testing.T) {
	var nilStore *CredentialManager
	var typedNilAPI *fakeCredentialAPI
	for _, store := range []*CredentialManager{{}, nilStore, {api: typedNilAPI}} {
		if _, err := store.Get("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "credential manager API is nil") {
			t.Fatalf("Get nil API error = %v", err)
		}
		if _, err := store.Put("controller/chatgpt", "secret"); err == nil || !strings.Contains(err.Error(), "credential manager API is nil") {
			t.Fatalf("Put nil API error = %v", err)
		}
		if _, err := store.Rotate("controller/chatgpt", "secret"); err == nil || !strings.Contains(err.Error(), "credential manager API is nil") {
			t.Fatalf("Rotate nil API error = %v", err)
		}
		if err := store.Revoke("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "credential manager API is nil") {
			t.Fatalf("Revoke nil API error = %v", err)
		}
		if err := store.Delete("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "credential manager API is nil") {
			t.Fatalf("Delete nil API error = %v", err)
		}
	}
}

func TestCredentialManagerLowerReadBoundaryRejectsUnavailableAPI(t *testing.T) {
	var nilStore *CredentialManager
	var typedNilAPI *fakeCredentialAPI
	for _, store := range []*CredentialManager{nilStore, {}, {api: typedNilAPI}} {
		if _, err := store.get("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "credential manager API is nil") {
			t.Fatalf("get unavailable API error = %v, want fail-closed API error", err)
		}
	}
}

func TestCredentialManagerLowerWriteBoundaryRejectsUnavailableAPI(t *testing.T) {
	valid := credentialPayload{Name: "controller/chatgpt", Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var nilStore *CredentialManager
	var typedNilAPI *fakeCredentialAPI
	for _, store := range []*CredentialManager{nilStore, {}, {api: typedNilAPI}} {
		if _, err := store.storeWithPayload(valid, encoded); err == nil || !strings.Contains(err.Error(), "credential manager API is nil") {
			t.Fatalf("storeWithPayload unavailable API error = %v, want fail-closed API error", err)
		}
	}
}

type fakeCredentialAPI struct {
	items          map[string][]byte
	writes         int
	deletes        int
	reads          int
	readErr        error
	readCredential *nativeCredential
	writeErr       error
	deleteErr      error
}

func (f *fakeCredentialAPI) read(target *uint16) (*nativeCredential, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	if f.readCredential != nil {
		return f.readCredential, nil
	}
	name := syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(target))[:])
	b, ok := f.items[name]
	if !ok {
		return nil, errorNotFound
	}
	copy := append([]byte(nil), b...)
	return &nativeCredential{CredentialBlobSize: uint32(len(copy)), CredentialBlob: &copy[0]}, nil
}

func TestCredentialManagerRotateRejectsInvalidValueBeforeNativeRead(t *testing.T) {
	api := &fakeCredentialAPI{items: map[string][]byte{}, readErr: errors.New("native read must not run")}
	s := &CredentialManager{api: api}
	if _, err := s.Rotate("controller/chatgpt", ""); err == nil || !strings.Contains(err.Error(), "secret value is empty") {
		t.Fatalf("invalid rotation value error = %v, want local validation", err)
	}
	if api.reads != 0 {
		t.Fatalf("invalid rotation value reached native read %d time(s)", api.reads)
	}
}

func (f *fakeCredentialAPI) write(c *nativeCredential) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	target := syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(c.TargetName))[:])
	f.items[target] = append([]byte(nil), unsafe.Slice(c.CredentialBlob, c.CredentialBlobSize)...)
	return nil
}

func (f *fakeCredentialAPI) delete(target *uint16) error {
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	name := syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(target))[:])
	if _, ok := f.items[name]; !ok {
		return errorNotFound
	}
	delete(f.items, name)
	return nil
}

func TestCredentialManagerNativeAPIErrorsAreOpaqueButClassifiable(t *testing.T) {
	cause := errors.New("secret-bearing credential diagnostic")
	for _, test := range []struct {
		name string
		call func(*CredentialManager) error
		api  *fakeCredentialAPI
		want string
	}{
		{
			name: "read",
			call: func(s *CredentialManager) error { _, err := s.Get("controller/chatgpt"); return err },
			api:  &fakeCredentialAPI{items: map[string][]byte{}, readErr: cause},
			want: "read",
		},
		{
			name: "write",
			call: func(s *CredentialManager) error { _, err := s.Put("controller/chatgpt", "secret"); return err },
			api:  &fakeCredentialAPI{items: map[string][]byte{}, writeErr: cause},
			want: "write",
		},
		{
			name: "delete",
			call: func(s *CredentialManager) error { return s.Delete("supervisor/credential-error") },
			api:  &fakeCredentialAPI{items: map[string][]byte{}, deleteErr: cause},
			want: "delete",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call(&CredentialManager{api: test.api})
			if err == nil || err.Error() != "native secure store "+test.want+" failed" {
				t.Fatalf("opaque %s error = %v", test.want, err)
			}
			if strings.Contains(err.Error(), "secret-bearing") || !errors.Is(err, cause) {
				t.Fatalf("opaque %s error = %v, want hidden diagnostic and preserved cause", test.want, err)
			}
		})
	}
}

func TestCredentialManagerContainsPanickingErrorClassification(t *testing.T) {
	for _, cause := range []error{
		panickingNativeError{panicIs: true},
		panickingNativeError{panicAs: true},
	} {
		api := &fakeCredentialAPI{items: map[string][]byte{}, readErr: cause}
		_, err := (&CredentialManager{api: api}).Get("controller/chatgpt")
		if err == nil || err.Error() != "native secure store read failed" {
			t.Fatalf("hostile Credential Manager read = %v, want opaque read failure", err)
		}
	}
}

func TestCredentialManagerStoreRejectsInvalidRecordBeforeAPIWrite(t *testing.T) {
	api := &fakeCredentialAPI{items: map[string][]byte{}}
	s := &CredentialManager{api: api}
	if _, err := s.store(credentialPayload{Name: "controller/chatgpt", Version: 1, Revoked: true, Value: "stale"}); err == nil {
		t.Fatal("accepted revoked credential payload with a value")
	}
	if api.writes != 0 {
		t.Fatal("invalid credential payload reached the native API")
	}
}

func TestCredentialManagerStoreWithPayloadRejectsMalformedOrMismatchedPayloadBeforeAPIWrite(t *testing.T) {
	const name = "controller/chatgpt"
	valid := credentialPayload{Name: name, Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}
	cases := []struct {
		name    string
		payload credentialPayload
		encoded credentialPayload
	}{
		{
			name:    "revoked record retains stale value",
			payload: credentialPayload{Name: name, Value: "stale", Version: 1, Revoked: true, UpdatedAt: valid.UpdatedAt},
			encoded: credentialPayload{Name: name, Value: "stale", Version: 1, Revoked: true, UpdatedAt: valid.UpdatedAt},
		},
		{
			name:    "encoded value differs from record",
			payload: valid,
			encoded: credentialPayload{Name: name, Value: "other-secret", Version: 1, UpdatedAt: valid.UpdatedAt},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeCredentialAPI{items: map[string][]byte{}}
			s := &CredentialManager{api: api}
			encoded, err := json.Marshal(tc.encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.storeWithPayload(tc.payload, encoded); err == nil {
				t.Fatal("accepted malformed or mismatched Credential Manager payload")
			}
			if api.writes != 0 {
				t.Fatalf("malformed or mismatched payload reached the native API: writes=%d", api.writes)
			}
		})
	}
}

func TestCredentialManagerRejectsVersionExhaustionBeforeAPIWrite(t *testing.T) {
	const name = "controller/chatgpt"
	payload, err := json.Marshal(credentialPayload{Name: name, Value: "secret", Version: ^uint64(0), UpdatedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeCredentialAPI{items: map[string][]byte{credentialTarget(name): payload}}
	s := &CredentialManager{api: api}
	if _, err := s.Rotate(name, "replacement"); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("Rotate at maximum version = %v, want ErrVersionExhausted", err)
	}
	if api.writes != 0 || string(api.items[credentialTarget(name)]) != string(payload) {
		t.Fatalf("version-exhausted rotation reached native API: writes=%d", api.writes)
	}
}

func TestCredentialManagerLifecycleAndValidation(t *testing.T) {
	s := &CredentialManager{api: &fakeCredentialAPI{items: map[string][]byte{}}}
	const name = "supervisor/credential-lifecycle"
	r, err := s.Put(name, "top-secret")
	if err != nil || r.Version != 1 {
		t.Fatalf("put: %#v %v", r, err)
	}
	if _, err = s.Rotate(name, "rotated"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(name); err != nil || got.Value != "rotated" || got.Version != 2 {
		t.Fatalf("get: %#v %v", got, err)
	}
	if err = s.Revoke(name); err != nil {
		t.Fatal(err)
	}
	if err = s.Revoke(name); err != nil {
		t.Fatalf("repeated revoke: %v", err)
	}
	if _, err = s.Get(name); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoke: %v", err)
	}
	if err = s.Delete(name); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err = s.Delete(name); err != nil {
		t.Fatalf("repeated delete: %v", err)
	}
	if _, err = s.Get(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete: %v", err)
	}
}

func TestCredentialManagerDeleteRejectsProductionNamespaceBeforeNativeDelete(t *testing.T) {
	api := &fakeCredentialAPI{items: map[string][]byte{credentialTarget("controller/chatgpt"): []byte("preserve")}}
	s := &CredentialManager{api: api}
	if err := s.Delete("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "supervisor/") {
		t.Fatalf("production delete error = %v, want dedicated-namespace rejection", err)
	}
	if api.deletes != 0 {
		t.Fatalf("production delete reached native API %d time(s)", api.deletes)
	}
}

func TestCredentialManagerPutIfAbsentRejectsProductionNamespaceBeforeNativeWrite(t *testing.T) {
	api := &fakeCredentialAPI{items: map[string][]byte{}}
	s := &CredentialManager{api: api}
	if _, owned, err := s.PutIfAbsent("controller/chatgpt", "secret"); err == nil || owned || !strings.Contains(err.Error(), "supervisor/") {
		t.Fatalf("production PutIfAbsent = owned=%t err=%v, want dedicated-namespace rejection", owned, err)
	}
	if len(api.items) != 0 {
		t.Fatalf("production PutIfAbsent reached native API with %d item(s)", len(api.items))
	}
}

func TestCredentialManagerRejectsMalformedPayload(t *testing.T) {
	f := &fakeCredentialAPI{items: map[string][]byte{credentialTarget("controller/chatgpt"): []byte(`{"name":"other","version":1}`)}}
	s := &CredentialManager{api: f}
	if _, err := s.Get("controller/chatgpt"); err == nil {
		t.Fatal("accepted mismatched credential")
	}
	if _, err := s.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestCredentialManagerReadRejectsMalformedBlobBeforeUnsafeCopy(t *testing.T) {
	s := &CredentialManager{api: &fakeCredentialAPI{
		readCredential: &nativeCredential{CredentialBlobSize: 1},
	}}
	if _, err := s.Get("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "credential payload is empty") {
		t.Fatalf("malformed credential blob error = %v, want bounded empty-payload error", err)
	}
}

func TestBoundedCredentialBlobRejectsBeforeAllocation(t *testing.T) {
	if _, err := boundedCredentialBlob(nil, maxPayloadSize+1); err == nil {
		t.Fatal("accepted oversized native credential blob")
	}
	if _, err := boundedCredentialBlob(nil, 1); err == nil {
		t.Fatal("accepted non-empty credential blob with nil pointer")
	}
	if got, err := boundedCredentialBlob(nil, 0); err != nil || got != nil {
		t.Fatalf("empty credential blob: %#v %v", got, err)
	}
}

func TestOwnedCredentialBlobDropsFreedNativePointers(t *testing.T) {
	blob := []byte(`{"name":"controller/chatgpt","value":"secret","version":1,"updated_at":"1970-01-01T00:00:01Z"}`)
	marker := uint16('x')
	src := &nativeCredential{
		TargetName:         &marker,
		Comment:            &marker,
		CredentialBlobSize: uint32(len(blob)),
		CredentialBlob:     &blob[0],
		Attributes:         1,
		TargetAlias:        &marker,
		UserName:           &marker,
	}
	owned, err := ownedCredentialBlob(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(unsafe.Slice(owned.CredentialBlob, owned.CredentialBlobSize)) != string(blob) {
		t.Fatalf("owned blob = %q, want %q", unsafe.Slice(owned.CredentialBlob, owned.CredentialBlobSize), blob)
	}
	if owned.TargetName != nil || owned.Comment != nil || owned.Attributes != 0 || owned.TargetAlias != nil || owned.UserName != nil {
		t.Fatalf("owned credential retained native pointers: %#v", owned)
	}
	blob[0] = 'X'
	if unsafe.Slice(owned.CredentialBlob, owned.CredentialBlobSize)[0] != '{' {
		t.Fatal("owned credential blob aliases native input")
	}
}
