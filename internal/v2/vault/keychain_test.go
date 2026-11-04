package vault

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeKeychainAPI struct {
	items       map[string][]byte
	readCalls   int
	deleteCalls int
	readErr     error
	writeErr    error
	deleteErr   error
	readPanic   bool
	writePanic  bool
	deletePanic bool
}

func (f *fakeKeychainAPI) read(account string) ([]byte, error) {
	f.readCalls++
	if f.readPanic {
		panic("secret-bearing keychain read panic")
	}
	if f.readErr != nil {
		return nil, f.readErr
	}
	b, ok := f.items[account]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), b...), nil
}

func TestKeychainRotateRejectsInvalidValueBeforeNativeRead(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}, readErr: errors.New("native read must not run")}
	s := &Keychain{api: api}
	if _, err := s.Rotate("controller/chatgpt", ""); err == nil || !strings.Contains(err.Error(), "secret value is empty") {
		t.Fatalf("invalid rotation value error = %v, want local validation", err)
	}
	if api.readCalls != 0 {
		t.Fatalf("invalid rotation value reached native read %d time(s)", api.readCalls)
	}
}

func (f *fakeKeychainAPI) write(account string, payload []byte) error {
	if f.writePanic {
		panic("secret-bearing keychain write panic")
	}
	if f.writeErr != nil {
		return f.writeErr
	}
	f.items[account] = append([]byte(nil), payload...)
	return nil
}

func (f *fakeKeychainAPI) delete(account string) error {
	f.deleteCalls++
	if f.deletePanic {
		panic("secret-bearing keychain delete panic")
	}
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.items[account]; !ok {
		return ErrNotFound
	}
	delete(f.items, account)
	return nil
}

func TestKeychainContainsNativeAPIPanics(t *testing.T) {
	for _, test := range []struct {
		name string
		call func(*Keychain) error
		api  *fakeKeychainAPI
		want string
	}{
		{
			name: "read",
			call: func(s *Keychain) error { _, err := s.Get("controller/chatgpt"); return err },
			api:  &fakeKeychainAPI{items: map[string][]byte{}, readPanic: true},
			want: "read",
		},
		{
			name: "write",
			call: func(s *Keychain) error { _, err := s.Put("controller/chatgpt", "secret"); return err },
			api:  &fakeKeychainAPI{items: map[string][]byte{}, writePanic: true},
			want: "write",
		},
		{
			name: "delete",
			call: func(s *Keychain) error { return s.Delete("supervisor/keychain-panic") },
			api:  &fakeKeychainAPI{items: map[string][]byte{}, deletePanic: true},
			want: "delete",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call(&Keychain{api: test.api})
			if err == nil || err.Error() != "native secure store "+test.want+" failed" {
				t.Fatalf("panic %s error = %v, want stable opaque error", test.want, err)
			}
			if strings.Contains(err.Error(), "secret-bearing") || strings.Contains(err.Error(), "panic") {
				t.Fatalf("panic %s detail escaped: %v", test.want, err)
			}
		})
	}
}

func TestKeychainNativeAPIErrorsAreOpaqueButClassifiable(t *testing.T) {
	cause := errors.New("secret-bearing keychain diagnostic")
	for _, test := range []struct {
		name string
		call func(*Keychain) error
		api  *fakeKeychainAPI
		want string
	}{
		{
			name: "read",
			call: func(s *Keychain) error { _, err := s.Get("controller/chatgpt"); return err },
			api:  &fakeKeychainAPI{items: map[string][]byte{}, readErr: cause},
			want: "read",
		},
		{
			name: "write",
			call: func(s *Keychain) error { _, err := s.Put("controller/chatgpt", "secret"); return err },
			api:  &fakeKeychainAPI{items: map[string][]byte{}, writeErr: cause},
			want: "write",
		},
		{
			name: "delete",
			call: func(s *Keychain) error { return s.Delete("supervisor/keychain-error") },
			api:  &fakeKeychainAPI{items: map[string][]byte{}, deleteErr: cause},
			want: "delete",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call(&Keychain{api: test.api})
			if err == nil || err.Error() != "native secure store "+test.want+" failed" {
				t.Fatalf("opaque %s error = %v", test.want, err)
			}
			if strings.Contains(err.Error(), "secret-bearing") || !errors.Is(err, cause) {
				t.Fatalf("opaque %s error = %v, want hidden diagnostic and preserved cause", test.want, err)
			}
		})
	}
}

func TestKeychainContainsPanickingErrorClassification(t *testing.T) {
	for _, cause := range []error{
		panickingNativeError{panicIs: true},
		panickingNativeError{panicAs: true},
	} {
		s := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{}, readErr: cause}}
		_, err := s.Get("controller/chatgpt")
		if err == nil || err.Error() != "native secure store read failed" {
			t.Fatalf("hostile keychain read = %v, want opaque read failure", err)
		}
	}
}

func TestKeychainLifecycleAndValidation(t *testing.T) {
	s := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{}}}
	const name = "supervisor/keychain-lifecycle"
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

func TestKeychainMissingReadPreservesNotFoundSentinel(t *testing.T) {
	s := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{}}}
	if _, err := s.Get("controller/missing"); err != ErrNotFound {
		t.Fatalf("missing keychain read = %v, want ErrNotFound", err)
	}
}

func TestKeychainDeleteRejectsProductionNamespaceBeforeNativeDelete(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{"controller/chatgpt": []byte("preserve")}}
	s := &Keychain{api: api}
	if err := s.Delete("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "supervisor/") {
		t.Fatalf("production delete error = %v, want dedicated-namespace rejection", err)
	}
	if api.deleteCalls != 0 {
		t.Fatalf("production delete reached native API %d time(s)", api.deleteCalls)
	}
}

func TestKeychainPutIfAbsentPreservesExistingAndRevokedItems(t *testing.T) {
	const name = "supervisor/create-only"
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	s := &Keychain{api: api}
	created, owned, err := s.PutIfAbsent(name, "first")
	if err != nil || !owned || created.Version != 1 {
		t.Fatalf("first PutIfAbsent = %#v/%t/%v, want version 1 and ownership", created, owned, err)
	}
	before := append([]byte(nil), api.items[name]...)
	if _, owned, err = s.PutIfAbsent(name, "replacement"); !errors.Is(err, ErrAlreadyExists) || owned {
		t.Fatalf("existing PutIfAbsent = owned=%t err=%v, want no ownership and ErrAlreadyExists", owned, err)
	}
	if string(api.items[name]) != string(before) {
		t.Fatal("existing item changed after rejected PutIfAbsent")
	}
	if err = s.Revoke(name); err != nil {
		t.Fatal(err)
	}
	before = append([]byte(nil), api.items[name]...)
	if _, owned, err = s.PutIfAbsent(name, "replacement"); !errors.Is(err, ErrAlreadyExists) || owned {
		t.Fatalf("revoked PutIfAbsent = owned=%t err=%v, want no ownership and ErrAlreadyExists", owned, err)
	}
	if string(api.items[name]) != string(before) {
		t.Fatal("revoked item changed after rejected PutIfAbsent")
	}
}

func TestKeychainPutIfAbsentRejectsProductionNamespaceBeforeNativeWrite(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	s := &Keychain{api: api}
	if _, owned, err := s.PutIfAbsent("controller/chatgpt", "secret"); err == nil || owned || !strings.Contains(err.Error(), "supervisor/") {
		t.Fatalf("production PutIfAbsent = owned=%t err=%v, want dedicated-namespace rejection", owned, err)
	}
	if len(api.items) != 0 {
		t.Fatalf("production PutIfAbsent reached native API with %d item(s)", len(api.items))
	}
}

func TestKeychainRejectsMalformedPayload(t *testing.T) {
	for _, payload := range []string{
		`{"name":"other","version":1,"value":"secret"}`,
		`{"name":"controller/chatgpt","version":1}`,
		`{"name":"controller/chatgpt","version":1,"value":"secret","revoked":true}`,
		``,
	} {
		s := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{"controller/chatgpt": []byte(payload)}}}
		if _, err := s.Get("controller/chatgpt"); err == nil {
			t.Fatalf("accepted malformed keychain record: %s", payload)
		}
	}
}

func TestKeychainRejectsOversizedSecret(t *testing.T) {
	s := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{}}}
	if _, err := s.Put("controller/chatgpt", strings.Repeat("x", maxSecretValue+1)); err == nil {
		t.Fatal("accepted oversized secret")
	}
}

func TestKeychainStoreRejectsInvalidRecordBeforeAPIWrite(t *testing.T) {
	api := &fakeKeychainAPI{items: map[string][]byte{}}
	s := &Keychain{api: api}
	if _, err := s.store(keychainPayload{Name: "controller/chatgpt", Version: 1, Revoked: true, Value: "stale"}); err == nil {
		t.Fatal("accepted revoked keychain payload with a value")
	}
	if len(api.items) != 0 {
		t.Fatal("invalid keychain payload reached the native API")
	}
}

func TestKeychainStoreWithPayloadRejectsMalformedOrMismatchedPayloadBeforeAPIWrite(t *testing.T) {
	const name = "controller/chatgpt"
	valid := keychainPayload{Name: name, Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}
	cases := []struct {
		name    string
		payload keychainPayload
		encoded keychainPayload
	}{
		{
			name:    "revoked record retains stale value",
			payload: keychainPayload{Name: name, Value: "stale", Version: 1, Revoked: true, UpdatedAt: valid.UpdatedAt},
			encoded: keychainPayload{Name: name, Value: "stale", Version: 1, Revoked: true, UpdatedAt: valid.UpdatedAt},
		},
		{
			name:    "encoded value differs from record",
			payload: valid,
			encoded: keychainPayload{Name: name, Value: "other-secret", Version: 1, UpdatedAt: valid.UpdatedAt},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeKeychainAPI{items: map[string][]byte{}}
			s := &Keychain{api: api}
			encoded, err := json.Marshal(tc.encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.storeWithPayload(tc.payload, encoded); err == nil {
				t.Fatal("accepted malformed or mismatched Keychain payload")
			}
			if len(api.items) != 0 {
				t.Fatal("malformed or mismatched payload reached the native API")
			}
		})
	}
}

func TestKeychainRejectsVersionExhaustionBeforeAPIWrite(t *testing.T) {
	const name = "controller/chatgpt"
	payload, err := json.Marshal(keychainPayload{Name: name, Value: "secret", Version: ^uint64(0), UpdatedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeKeychainAPI{items: map[string][]byte{name: payload}}
	s := &Keychain{api: api}
	if _, err := s.Rotate(name, "replacement"); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("Rotate at maximum version = %v, want ErrVersionExhausted", err)
	}
	if string(api.items[name]) != string(payload) {
		t.Fatal("version-exhausted rotation reached the native API")
	}
}

func TestKeychainSerializesVersionedWrites(t *testing.T) {
	s := &Keychain{api: &fakeKeychainAPI{items: map[string][]byte{}}}
	const writers = 32
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Put("controller/chatgpt", "secret"); err != nil {
				t.Errorf("put: %v", err)
			}
		}()
	}
	wg.Wait()
	got, err := s.Get("controller/chatgpt")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != writers {
		t.Fatalf("version = %d, want %d", got.Version, writers)
	}
}

func TestKeychainProbeClassification(t *testing.T) {
	if err := classifyKeychainProbeStatus(errSecSuccess); err != nil {
		t.Fatalf("success classified as failure: %v", err)
	}
	if err := classifyKeychainProbeStatus(errSecNoSuchKeychain); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing keychain = %v, want ErrUnavailable", err)
	}
	const status = -128
	err := classifyKeychainProbeStatus(status)
	if err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("unexpected Security.framework failure was hidden: %v", err)
	}
	if err.Error() != "macOS Keychain probe failed" || strings.Contains(err.Error(), "128") {
		t.Fatalf("probe status exposed native diagnostic: %v", err)
	}
	var classified interface{ Status() int }
	if !errors.As(err, &classified) || classified.Status() != status {
		t.Fatalf("probe status = %v, want errors.As status %d", err, status)
	}
}

func TestKeychainAPIStatusErrorsAreOpaqueButClassifiable(t *testing.T) {
	const status = -25299
	err := classifyKeychainAPIStatus("read", status)
	if err == nil || err.Error() != "macOS Keychain read failed" {
		t.Fatalf("status error = %v, want stable opaque text", err)
	}
	if strings.Contains(err.Error(), "25299") {
		t.Fatalf("status error exposed native numeric diagnostic: %v", err)
	}
	var classified interface{ Status() int }
	if !errors.As(err, &classified) || classified.Status() != status {
		t.Fatalf("status error = %v, want errors.As status %d", err, status)
	}
	wrapped := redactNativeStoreError("read", err)
	if wrapped.Error() != "native secure store read failed" {
		t.Fatalf("redacted status error = %v, want stable store text", wrapped)
	}
	if !errors.As(wrapped, &classified) || classified.Status() != status {
		t.Fatalf("redacted status error lost status %d: %v", status, wrapped)
	}
}

func TestKeychainRejectsNilAPI(t *testing.T) {
	var nilStore *Keychain
	var typedNilAPI *fakeKeychainAPI
	for _, store := range []*Keychain{{}, nilStore, {api: typedNilAPI}} {
		if _, err := store.Get("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "keychain API is nil") {
			t.Fatalf("Get nil API error = %v", err)
		}
		if _, err := store.Put("controller/chatgpt", "secret"); err == nil || !strings.Contains(err.Error(), "keychain API is nil") {
			t.Fatalf("Put nil API error = %v", err)
		}
		if _, err := store.Rotate("controller/chatgpt", "secret"); err == nil || !strings.Contains(err.Error(), "keychain API is nil") {
			t.Fatalf("Rotate nil API error = %v", err)
		}
		if err := store.Revoke("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "keychain API is nil") {
			t.Fatalf("Revoke nil API error = %v", err)
		}
		if err := store.Delete("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "keychain API is nil") {
			t.Fatalf("Delete nil API error = %v", err)
		}
	}
}

func TestKeychainStoreWithPayloadRejectsUnavailableAPI(t *testing.T) {
	valid := keychainPayload{Name: "controller/chatgpt", Value: "secret", Version: 1, UpdatedAt: time.Unix(1, 0).UTC()}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var nilStore *Keychain
	var typedNilAPI *fakeKeychainAPI
	for _, store := range []*Keychain{nilStore, {}, {api: typedNilAPI}} {
		if _, err := store.storeWithPayload(valid, encoded); err == nil || !strings.Contains(err.Error(), "keychain API is nil") {
			t.Fatalf("storeWithPayload unavailable API error = %v, want fail-closed API error", err)
		}
	}
}

func TestKeychainGetRejectsUnavailableAPIAtReadBoundary(t *testing.T) {
	var nilStore *Keychain
	var typedNilAPI *fakeKeychainAPI
	for _, store := range []*Keychain{nilStore, {}, {api: typedNilAPI}} {
		if _, err := store.get("controller/chatgpt"); err == nil || !strings.Contains(err.Error(), "keychain API is nil") {
			t.Fatalf("get unavailable API error = %v, want fail-closed API error", err)
		}
	}
}
