package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRecordFormattingRedactsValue(t *testing.T) {
	record := Record{
		Name:      "controller/chatgpt",
		Value:     "top-secret-value",
		Version:   2,
		UpdatedAt: time.Unix(2, 0).UTC(),
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		t.Run(format, func(t *testing.T) {
			got := fmt.Sprintf(format, record)
			if strings.Contains(got, record.Value) {
				t.Fatalf("format %q disclosed secret: %s", format, got)
			}
			if !strings.Contains(got, "[REDACTED]") {
				t.Fatalf("format %q omitted redaction marker: %s", format, got)
			}
		})
	}

	revoked := record
	revoked.Revoked = true
	revoked.Value = "stale-secret"
	if got := fmt.Sprintf("%v", revoked); strings.Contains(got, revoked.Value) || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("revoked format disclosed stale secret or omitted marker: %s", got)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDecodeSingleJSONRejectsTrailingAndUnknownFields(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	for _, tc := range []struct {
		name string
		data string
	}{
		{"trailing value", `{"name":"ok"}{"name":"again"}`},
		{"unknown field", `{"name":"ok","extra":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got payload
			if err := decodeSingleJSON([]byte(tc.data), &got); err == nil {
				t.Fatal("accepted non-canonical JSON")
			}
		})
	}
	var got payload
	if err := decodeSingleJSON([]byte(` {"name":"ok"} `), &got); err != nil || got.Name != "ok" {
		t.Fatalf("rejected valid single document: %v %#v", err, got)
	}
}

func TestDecodeSingleJSONRejectsInvalidUTF8BeforeNormalization(t *testing.T) {
	var decoded map[string]string
	data := []byte{'{', '"', 'v', 'a', 'l', 'u', 'e', '"', ':', '"', 0xff, '"', '}'}
	if err := decodeSingleJSON(data, &decoded); err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
		t.Fatalf("accepted invalid UTF-8 JSON: %v", err)
	}
	if decoded != nil {
		t.Fatalf("invalid UTF-8 was decoded before rejection: %#v", decoded)
	}
}

func TestRecordVersionExhaustionFailsClosed(t *testing.T) {
	if got, err := nextRecordVersion(41); err != nil || got != 42 {
		t.Fatalf("next version = %d, %v; want 42, nil", got, err)
	}
	if got, err := nextRecordVersion(^uint64(0)); !errors.Is(err, ErrVersionExhausted) || got != 0 {
		t.Fatalf("exhausted version = %d, %v; want zero and ErrVersionExhausted", got, err)
	}

	const name = "controller/chatgpt"
	old := Record{Name: name, Value: "secret", Version: ^uint64(0), UpdatedAt: time.Unix(1, 0).UTC()}
	v := &FileVault{records: map[string]Record{name: old}}
	if _, err := v.Put(name, "replacement"); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("Put at maximum version = %v, want ErrVersionExhausted", err)
	}
	if got := v.records[name]; got != old {
		t.Fatalf("Put changed exhausted record: %#v, want %#v", got, old)
	}
	if _, err := v.Rotate(name, "replacement"); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("Rotate at maximum version = %v, want ErrVersionExhausted", err)
	}
	if got := v.records[name]; got != old {
		t.Fatalf("Rotate changed exhausted record: %#v, want %#v", got, old)
	}
}

func recordSet(count int) map[string]Record {
	records := make(map[string]Record, count)
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("item/%04x", i)
		records[name] = Record{
			Name:      name,
			Value:     "value",
			Version:   1,
			UpdatedAt: time.Unix(int64(i+1), 0).UTC(),
		}
	}
	return records
}

func TestFileVaultRecordLimitPreservesLiveStateAndRejectsOversizedMigration(t *testing.T) {
	d := privateTempDir(t)
	v := &FileVault{records: recordSet(maxRecords)}
	if _, err := v.Put("controller/new", "value"); !errors.Is(err, ErrRecordLimit) {
		t.Fatalf("Put at record limit = %v, want ErrRecordLimit", err)
	}
	if len(v.records) != maxRecords {
		t.Fatalf("Put changed record count to %d, want %d", len(v.records), maxRecords)
	}

	legacy := filepath.Join(d, "legacy.json")
	if err := os.WriteFile(legacy, []byte(`{"controller/new":"value"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := v.Migrate(legacy); !errors.Is(err, ErrRecordLimit) {
		t.Fatalf("Migrate at record limit = %v, want ErrRecordLimit", err)
	}
	if len(v.records) != maxRecords {
		t.Fatalf("Migrate changed record count to %d, want %d", len(v.records), maxRecords)
	}
	if _, ok := v.records["controller/new"]; ok {
		t.Fatal("rejected migration left a new record in the live map")
	}
}

func TestFileVaultRejectsOversizedAuthenticatedRecordMap(t *testing.T) {
	d := privateTempDir(t)
	path, keyPath := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	key := make([]byte, 32)
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(envelope{Version: 1, Records: recordSet(maxRecords + 1)})
	if err != nil {
		t.Fatal(err)
	}
	nonce, data, err := encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := json.Marshal(diskEnvelope{Version: 1, Nonce: nonce, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, disk, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, keyPath); !errors.Is(err, ErrRecordLimit) {
		t.Fatalf("accepted oversized authenticated record map: %v", err)
	}
}

func TestDecodeSingleJSONRejectsDuplicateKeys(t *testing.T) {
	var got map[string]any
	for _, data := range []string{
		`{"name":"first","name":"last"}`,
		`{"outer":{"name":"first","name":"last"}}`,
	} {
		if err := decodeSingleJSON([]byte(data), &got); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
			t.Fatalf("accepted duplicate JSON key %s: %v", data, err)
		}
	}
}

func TestDecodeSingleJSONRejectsExcessiveNesting(t *testing.T) {
	data := strings.Repeat("[", maxJSONDepth+1) + "0" + strings.Repeat("]", maxJSONDepth+1)
	var got any
	if err := decodeSingleJSON([]byte(data), &got); err == nil || !strings.Contains(err.Error(), "JSON nesting exceeds limit") {
		t.Fatalf("accepted excessive JSON nesting: %v", err)
	}
}

func TestFileVaultLifecycleAndRecovery(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	v, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := v.Put("controller/chatgpt", "top-secret")
	if err != nil || r.Version != 1 {
		t.Fatalf("put: %#v %v", r, err)
	}
	if _, err = v.Rotate("controller/chatgpt", "rotated"); err != nil {
		t.Fatal(err)
	}
	if got, err := v.Get("controller/chatgpt"); err != nil || got.Value != "rotated" || got.Version != 2 {
		t.Fatalf("get: %#v %v", got, err)
	}
	if err = v.Revoke("controller/chatgpt"); err != nil {
		t.Fatal(err)
	}
	if _, err = v.Get("controller/chatgpt"); err != ErrRevoked {
		t.Fatalf("revoke: %v", err)
	}
	if err = os.WriteFile(path, []byte(`{"version":1,"nonce":"bad","data":"bad"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("tamper accepted: %v", err)
	}
}

func TestFileVaultInstancesPreserveLatestCheckpoint(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	first, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Put("controller/first", "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Put("controller/second", "two"); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"controller/first":  "one",
		"controller/second": "two",
	} {
		got, err := reopened.Get(name)
		if err != nil || got.Value != want {
			t.Fatalf("reopened %q = %#v, %v; want %q", name, got, err, want)
		}
	}
}

func TestFileVaultRejectsBusySidecarWithoutMutatingState(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	v, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := openVaultLock(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer closeVaultLock(lock)
	if _, err := v.Put("controller/busy", "secret"); !errors.Is(err, ErrVaultBusy) {
		t.Fatalf("Put while sidecar is held = %v, want ErrVaultBusy", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("busy Put changed vault path: %v", err)
	}
}

func TestFileVaultRejectsLockAliasesBeforeReadingOrCreating(t *testing.T) {
	d := privateTempDir(t)
	path := filepath.Join(d, "vault.json")
	key := filepath.Join(d, "vault.key")
	lock := path + ".lock"

	if err := os.WriteFile(path, []byte("checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, lock); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "same file") {
		t.Fatalf("accepted vault/lock hard-link alias: %v", err)
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created key after rejecting vault/lock alias: %v", err)
	}

	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("key material"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, lock); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "same file") {
		t.Fatalf("accepted key/lock hard-link alias: %v", err)
	}
}

func TestFileVaultRejectsDirectLockPathAliasBeforeCreatingKey(t *testing.T) {
	d := privateTempDir(t)
	path := filepath.Join(d, "vault.json")
	if _, err := OpenFile(path, path+".lock"); err == nil || !strings.Contains(err.Error(), "key path must be distinct from lock path") {
		t.Fatalf("accepted direct key/lock alias: %v", err)
	}
}

func TestFileVaultRejectsReplacedSidecarBeforeMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit replacing an open lock pathname")
	}
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	v, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("controller/keep", "one"); err != nil {
		t.Fatal(err)
	}
	lockPath := path + ".lock"
	v.beforeLockedOperation = func() error {
		if err := os.Rename(lockPath, lockPath+".replaced"); err != nil {
			return err
		}
		return os.WriteFile(lockPath, nil, 0600)
	}
	_, err = v.Put("controller/replaced", "two")
	v.beforeLockedOperation = nil
	if !errors.Is(err, ErrVaultBusy) {
		t.Fatalf("Put after sidecar replacement = %v, want ErrVaultBusy", err)
	}
	if _, err := v.Get("controller/replaced"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replaced-sidecar Put changed records: %v", err)
	}
	if got, err := v.Get("controller/keep"); err != nil || got.Value != "one" {
		t.Fatalf("existing record after replaced-sidecar rejection = %#v, %v", got, err)
	}
}

func TestWithVaultLockRejectsReplacedSidecarAfterCallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit replacing an open lock pathname")
	}
	path := filepath.Join(privateTempDir(t), "vault.json")
	lockPath := path + ".lock"
	err := withVaultLock(path, func(*os.File) error {
		if err := os.Rename(lockPath, lockPath+".replaced"); err != nil {
			return err
		}
		if err := os.WriteFile(lockPath, nil, 0600); err != nil {
			return err
		}
		return nil
	})
	if !errors.Is(err, ErrVaultBusy) {
		t.Fatalf("withVaultLock after sidecar replacement = %v, want ErrVaultBusy", err)
	}
}

func TestFileVaultRejectsUnsupportedEnvelopeVersion(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	if _, err := OpenFile(path, key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"nonce":"","data":""}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "unsupported vault envelope version") {
		t.Fatalf("accepted unsupported envelope version: %v", err)
	}
}

func TestFileVaultDoesNotCreateMissingKeyForExistingEnvelope(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	if err := os.WriteFile(path, []byte(`{"version":1,"nonce":"bad","data":"bad"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key error = %v, want os.ErrNotExist", err)
	}
	if _, err := os.Lstat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key was created: %v", err)
	}
}

func TestMigrationRedactionAndProtectedFiles(t *testing.T) {
	d := privateTempDir(t)
	legacy := filepath.Join(d, "legacy.json")
	if err := os.WriteFile(legacy, []byte(`{"legacy/api":"value"}`), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := OpenFile(filepath.Join(d, "vault.json"), filepath.Join(d, "key"))
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Migrate(legacy); err != nil {
		t.Fatal(err)
	}
	r, err := v.Get("legacy/api")
	if err != nil || r.Value != "value" {
		t.Fatalf("migration: %#v %v", r, err)
	}
	redacted := Redact([]Record{r})
	if redacted[0].Value != "[REDACTED]" {
		t.Fatal("secret was not redacted")
	}
	for _, p := range []string{filepath.Join(d, "vault.json"), filepath.Join(d, "key")} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %o", p, info.Mode().Perm())
		}
	}
}

func TestMigrationRejectsVaultAndKeyAliasesBeforeReading(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	v, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("controller/chatgpt", "existing"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		source string
		want   string
	}{
		{name: "vault path", source: path, want: "distinct from vault path"},
		{name: "key path", source: key, want: "distinct from key path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := v.Migrate(tc.source); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("migration alias error = %v, want %q", err, tc.want)
			}
		})
	}

	alias := filepath.Join(d, "legacy-alias.json")
	if err := os.Link(key, alias); err != nil {
		t.Fatal(err)
	}
	if err := v.Migrate(alias); err == nil || !strings.Contains(err.Error(), "same file") {
		t.Fatalf("migration hard-link alias error = %v, want same-file rejection", err)
	}
	if got, err := v.Get("controller/chatgpt"); err != nil || got.Value != "existing" || got.Version != 1 {
		t.Fatalf("rejected migration changed live state: %#v %v", got, err)
	}
}

func TestRedactPreservesRevokedRecordInvariant(t *testing.T) {
	records := []Record{
		{Name: "active", Value: "secret", Version: 2, UpdatedAt: time.Unix(2, 0).UTC()},
		{Name: "revoked", Value: "stale-secret", Revoked: true, Version: 3, UpdatedAt: time.Unix(3, 0).UTC()},
	}

	redacted := Redact(records)
	if len(redacted) != 2 {
		t.Fatalf("redacted record count = %d, want 2", len(redacted))
	}
	if redacted[0].Name != "active" || redacted[0].Value != "[REDACTED]" {
		t.Fatalf("active record was not redacted: %+v", redacted[0])
	}
	if redacted[1].Name != "revoked" || !redacted[1].Revoked || redacted[1].Value != "" {
		t.Fatalf("revoked record invariant changed: %+v", redacted[1])
	}
	for _, record := range redacted {
		if err := validateRecord(record.Name, record); err != nil {
			t.Fatalf("redacted record is invalid: %v", err)
		}
	}
	if records[0].Value != "secret" {
		t.Fatal("redaction mutated input records")
	}
}

func TestMigrationRejectsTrailingJSON(t *testing.T) {
	d := privateTempDir(t)
	legacy := filepath.Join(d, "legacy.json")
	if err := os.WriteFile(legacy, []byte(`{"legacy/api":"value"}{"unexpected":"data"}`), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := OpenFile(filepath.Join(d, "vault.json"), filepath.Join(d, "key"))
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Migrate(legacy); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("accepted trailing JSON: %v", err)
	}
}

func TestMigrationRejectsNullDocument(t *testing.T) {
	d := privateTempDir(t)
	legacy := filepath.Join(d, "legacy.json")
	if err := os.WriteFile(legacy, []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := OpenFile(filepath.Join(d, "vault.json"), filepath.Join(d, "key"))
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Migrate(legacy); err == nil || !strings.Contains(err.Error(), "expected a JSON object") {
		t.Fatalf("accepted null legacy document: %v", err)
	}
	if _, err = v.Get("legacy/api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("null migration changed vault: %v", err)
	}
}

func TestMigrationCannotOverwriteRevokedRecord(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	v, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Put("controller/chatgpt", "old-secret"); err != nil {
		t.Fatal(err)
	}
	if err = v.Revoke("controller/chatgpt"); err != nil {
		t.Fatal(err)
	}

	legacy := filepath.Join(d, "legacy.json")
	if err = os.WriteFile(legacy, []byte(`{"controller/chatgpt":"new-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = v.Migrate(legacy); err == nil || !strings.Contains(err.Error(), "is revoked") {
		t.Fatalf("migration overwrote revoked record: %v", err)
	}
	if _, err = v.Get("controller/chatgpt"); err != ErrRevoked {
		t.Fatalf("revoked record changed after rejected migration: %v", err)
	}
	if reopened, openErr := OpenFile(path, key); openErr != nil {
		t.Fatal(openErr)
	} else if _, getErr := reopened.Get("controller/chatgpt"); getErr != ErrRevoked {
		t.Fatalf("rejected migration was not durable: %v", getErr)
	}
}

func TestMigrationFailureRestoresLiveAndDurableCheckpoint(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	v, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Put("controller/chatgpt", "original"); err != nil {
		t.Fatal(err)
	}

	legacy := filepath.Join(d, "legacy.json")
	if err = os.WriteFile(legacy, []byte(`{"controller/chatgpt":"migrated","controller/gemini":"new"}`), 0600); err != nil {
		t.Fatal(err)
	}

	// Inject a durable-write failure. The candidate migration must not leak into
	// memory or replace the last valid durable checkpoint.
	v.saveHook = func() error { return errors.New("injected durable write failure") }
	if err = v.Migrate(legacy); err == nil {
		t.Fatal("migration unexpectedly succeeded")
	}
	if got, err := v.Get("controller/chatgpt"); err != nil || got.Value != "original" || got.Version != 1 {
		t.Fatalf("live record changed after failed migration: %#v %v", got, err)
	}
	if _, err := v.Get("controller/gemini"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed migration left new live record: %v", err)
	}

	reopened, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Get("controller/chatgpt"); err != nil || got.Value != "original" || got.Version != 1 {
		t.Fatalf("durable record changed after failed migration: %#v %v", got, err)
	}
	if _, err := reopened.Get("controller/gemini"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed migration changed durable checkpoint: %v", err)
	}
}

func TestNamesAndSeparateKey(t *testing.T) {
	if _, err := OpenFile("same", "same"); err == nil {
		t.Fatal("accepted shared vault/key path")
	}
	if err := validName("../escape"); err == nil {
		t.Fatal("accepted traversal")
	}
}

func TestFileVaultRejectsEquivalentUncreatedPathsBeforeKeyCreation(t *testing.T) {
	d := privateTempDir(t)
	path := filepath.Join(d, "vault.json")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeAlias, err := filepath.Rel(cwd, path)
	if err != nil {
		t.Fatal(err)
	}
	if same, err := sameConfiguredPath(path, relativeAlias); err != nil || !same {
		t.Fatalf("path identity = %v, %v; want equivalent paths", same, err)
	}
	if _, err := OpenFile(path, relativeAlias); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("accepted equivalent uncreated paths: %v", err)
	}
	if _, err := os.Stat(relativeAlias); !os.IsNotExist(err) {
		t.Fatalf("key path side effect after equivalent-path rejection: %v", err)
	}
}

func TestFileVaultRejectsHardLinkedVaultAndKey(t *testing.T) {
	d := privateTempDir(t)
	path := filepath.Join(d, "vault.json")
	key := filepath.Join(d, "vault.key")
	if err := os.WriteFile(path, []byte("placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, key); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "same file") {
		t.Fatalf("accepted hard-linked vault/key paths: %v", err)
	}
}

func TestFileVaultRejectsNilReceiver(t *testing.T) {
	var v *FileVault
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"get", func() error { _, err := v.Get("controller/chatgpt"); return err }},
		{"put", func() error { _, err := v.Put("controller/chatgpt", "secret"); return err }},
		{"rotate", func() error { _, err := v.Rotate("controller/chatgpt", "secret"); return err }},
		{"revoke", func() error { return v.Revoke("controller/chatgpt") }},
		{"migrate", func() error { return v.Migrate("legacy.json") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil || !strings.Contains(err.Error(), "file vault is nil") {
				t.Fatalf("nil receiver error = %v", err)
			}
		})
	}
}

func TestSecretValuesRejectInvalidUTF8(t *testing.T) {
	if err := validValue(string([]byte{'s', 0xff, 'e', 'c', 'r', 'e', 't'})); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 value accepted: %v", err)
	}
}

func TestValidateRecordInvariants(t *testing.T) {
	tests := []struct {
		name   string
		record Record
	}{
		{"missing version", Record{Name: "controller/chatgpt", Value: "secret"}},
		{"missing timestamp", Record{Name: "controller/chatgpt", Version: 1, Value: "secret"}},
		{"empty live value", Record{Name: "controller/chatgpt", Version: 1}},
		{"revoked value", Record{Name: "controller/chatgpt", Version: 1, Revoked: true, Value: "secret"}},
		{"mismatched name", Record{Name: "other", Version: 1, Value: "secret"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRecord("controller/chatgpt", tt.record); err == nil {
				t.Fatal("accepted invalid record")
			}
		})
	}
	validAt := time.Unix(1, 0).UTC()
	if err := validateRecord("controller/chatgpt", Record{Name: "controller/chatgpt", Version: 1, Value: "secret", UpdatedAt: validAt}); err != nil {
		t.Fatalf("rejected valid record: %v", err)
	}
	if err := validateRecord("controller/chatgpt", Record{Name: "controller/chatgpt", Version: 1, Revoked: true, UpdatedAt: validAt}); err != nil {
		t.Fatalf("rejected valid revoked record: %v", err)
	}
}

func TestFileVaultRejectsMalformedLiveRecordBeforeLifecycleMutation(t *testing.T) {
	name := "controller/chatgpt"
	malformed := Record{Name: name, Version: 0, Value: "stale-secret", UpdatedAt: time.Unix(1, 0).UTC()}
	for _, tc := range []struct {
		name string
		call func(*FileVault) error
	}{
		{"get", func(v *FileVault) error { _, err := v.Get(name); return err }},
		{"put", func(v *FileVault) error { _, err := v.Put(name, "replacement"); return err }},
		{"rotate", func(v *FileVault) error { _, err := v.Rotate(name, "replacement"); return err }},
		{"revoke", func(v *FileVault) error { return v.Revoke(name) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &FileVault{records: map[string]Record{name: malformed}}
			if err := tc.call(v); err == nil || !strings.Contains(err.Error(), "vault record is invalid") {
				t.Fatalf("malformed live record error = %v", err)
			}
			if got := v.records[name]; got != malformed {
				t.Fatalf("malformed live record changed after %s: %#v", tc.name, got)
			}
		})
	}
}

func TestFileVaultMigrationRejectsMalformedExistingRecordBeforeVersioning(t *testing.T) {
	name := "controller/chatgpt"
	malformed := Record{Name: name, Version: 0, Value: "stale-secret", UpdatedAt: time.Unix(1, 0).UTC()}
	v := &FileVault{records: map[string]Record{name: malformed}}
	legacy := filepath.Join(privateTempDir(t), "legacy.json")
	if err := os.WriteFile(legacy, []byte(`{"controller/chatgpt":"replacement"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := v.Migrate(legacy); err == nil || !strings.Contains(err.Error(), "vault record is invalid") {
		t.Fatalf("malformed migration record error = %v", err)
	}
	if got := v.records[name]; got != malformed {
		t.Fatalf("malformed live record changed after migration: %#v", got)
	}
}

func TestFileVaultRejectsUnprotectedExistingFiles(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	if err := os.WriteFile(key, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "not private") {
		t.Fatalf("accepted unprotected key: %v", err)
	}

	if err := os.Chmod(key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "not private") {
		t.Fatalf("accepted unprotected vault: %v", err)
	}
}

func TestAtomicProtectedWriteRejectsUnsafeParent(t *testing.T) {
	d := privateTempDir(t)
	parent := filepath.Join(d, "shared")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0770); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "vault.json")
	if err := atomicProtectedWrite(path, []byte("secret")); err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("atomic write accepted unsafe parent: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("atomic write created target after rejecting parent: %v", err)
	}
}

func TestSecretAndPayloadLimits(t *testing.T) {
	d := privateTempDir(t)
	v, err := OpenFile(filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Put("large", strings.Repeat("x", maxSecretValue+1)); err == nil {
		t.Fatal("accepted oversized secret")
	}
	if err = validPayload(make([]byte, maxPayloadSize+1)); err == nil {
		t.Fatal("accepted oversized payload")
	}
}

func TestFileVaultRejectsOversizedInputsBeforeParsing(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	if err := os.WriteFile(key, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, maxDiskEnvelopeSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil || !strings.Contains(err.Error(), "vault envelope exceeds limit") {
		t.Fatalf("accepted oversized disk envelope: %v", err)
	}

	legacy := filepath.Join(d, "legacy.json")
	if err := os.WriteFile(legacy, make([]byte, maxPayloadSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := OpenFile(filepath.Join(d, "other.json"), filepath.Join(d, "other.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Migrate(legacy); err == nil || !strings.Contains(err.Error(), "legacy vault exceeds limit") {
		t.Fatalf("accepted oversized legacy input: %v", err)
	}

	overbigKey := filepath.Join(d, "oversized.key")
	if err := os.WriteFile(overbigKey, make([]byte, 33), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(filepath.Join(d, "third.json"), overbigKey); err == nil || !strings.Contains(err.Error(), "vault key must be 32 bytes") {
		t.Fatalf("accepted oversized key: %v", err)
	}
}

func TestRevokeFailureRestoresLiveRecord(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	v, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Put("controller/chatgpt", "top-secret"); err != nil {
		t.Fatal(err)
	}

	// Inject a durable-write failure without touching an external service.
	v.saveHook = func() error { return errors.New("injected durable write failure") }
	if err = v.Revoke("controller/chatgpt"); err == nil {
		t.Fatal("revoke unexpectedly succeeded")
	}
	got, err := v.Get("controller/chatgpt")
	if err != nil || got.Value != "top-secret" || got.Version != 1 || got.Revoked {
		t.Fatalf("live record changed after failed revoke: %#v %v", got, err)
	}
}

func TestPutAndRotateFailureRestoreDurableRecord(t *testing.T) {
	d := privateTempDir(t)
	path, key := filepath.Join(d, "vault.json"), filepath.Join(d, "vault.key")
	v, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Put("controller/chatgpt", "original"); err != nil {
		t.Fatal(err)
	}

	// Each failed update must leave both the live map and the last valid
	// checkpoint intact.
	v.saveHook = func() error { return errors.New("injected durable write failure") }
	if _, err = v.Put("controller/chatgpt", "put-attempt"); err == nil {
		t.Fatal("put unexpectedly succeeded")
	}
	if _, err = v.Rotate("controller/chatgpt", "rotate-attempt"); err == nil {
		t.Fatal("rotate unexpectedly succeeded")
	}

	got, err := v.Get("controller/chatgpt")
	if err != nil || got.Value != "original" || got.Version != 1 || got.Revoked {
		t.Fatalf("live record changed after failed updates: %#v %v", got, err)
	}
	reopened, err := OpenFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err = reopened.Get("controller/chatgpt"); err != nil || got.Value != "original" || got.Version != 1 {
		t.Fatalf("durable record changed after failed updates: %#v %v", got, err)
	}
}
