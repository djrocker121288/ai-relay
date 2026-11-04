package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStoreAppendListPruneAndReopen(t *testing.T) {
	path := filepath.Join(privateAuditTestDir(t), "audit.json")
	store, err := OpenFile(path, validAuditPolicy)
	if err != nil {
		t.Fatal(err)
	}
	old := validAuditRecord
	old.ID = "old"
	old.OccurredAt = time.Unix(100, 0).UTC()
	oldAt := old.OccurredAt.Add(time.Hour)
	if err := store.AppendAt(old, oldAt); err != nil {
		t.Fatalf("append old record: %v", err)
	}
	now := oldAt.Add(validAuditPolicy.Retention - time.Hour - time.Minute)
	current := validAuditRecord
	current.ID = "current"
	current.OccurredAt = now.Add(-time.Minute)
	if err := store.AppendAt(current, now); err != nil {
		t.Fatalf("append current record: %v", err)
	}

	records, err := store.List(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records before expiry = %#v, want 2", records)
	}
	removed, err := store.Prune(now.Add(2 * time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("prune removed=%d err=%v, want 1/nil", removed, err)
	}

	reopened, err := OpenFile(path, validAuditPolicy)
	if err != nil {
		t.Fatal(err)
	}
	records, err = reopened.List(now.Add(2 * time.Hour))
	if err != nil || len(records) != 1 || records[0].ID != "current" {
		t.Fatalf("reopened records = %#v err=%v, want current record", records, err)
	}
}

func TestFileStoreRejectsExpiredFutureAndOversizedRecords(t *testing.T) {
	path := filepath.Join(privateAuditTestDir(t), "audit.json")
	store, err := OpenFile(path, validAuditPolicy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	expired := validAuditRecord
	expired.OccurredAt = now.Add(-validAuditPolicy.Retention)
	if err := store.AppendAt(expired, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired append error = %v, want ErrExpired", err)
	}
	future := validAuditRecord
	future.OccurredAt = now.Add(time.Second)
	if err := store.AppendAt(future, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("future append error = %v, want ErrInvalid", err)
	}
	large := validAuditRecord
	large.Resource = strings.Repeat("r", maxResourceBytes)
	policy := validAuditPolicy
	policy.MaxRecordBytes = minRecordBytes
	limited, err := OpenFile(filepath.Join(privateAuditTestDir(t), "limited.json"), policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := limited.AppendAt(large, now); err == nil {
		t.Fatal("oversized record unexpectedly appended")
	}
}

func TestFileStoreRejectsMalformedPersistedState(t *testing.T) {
	path := filepath.Join(privateAuditTestDir(t), "audit.json")
	for _, content := range []string{
		`{"version":1,"records":[],"extra":true}`,
		`{"version":1,"records":[]} {}`,
		`{"version":2,"records":[]}`,
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFile(path, validAuditPolicy); !errors.Is(err, ErrInvalid) {
			t.Fatalf("content %q error = %v, want ErrInvalid", content, err)
		}
	}
}

func TestFileStoreNilReceiverAndNoWriteOnEmptyOpen(t *testing.T) {
	var store *FileStore
	if err := store.Append(validAuditRecord); err == nil {
		t.Fatal("nil store append unexpectedly succeeded")
	}
	path := filepath.Join(privateAuditTestDir(t), "nested", "audit.json")
	if _, err := OpenFile(path, validAuditPolicy); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty open path error = %v, want absent file", err)
	}
}

func TestFileStoreCrossProcessLockIsFailClosed(t *testing.T) {
	path := filepath.Join(privateAuditTestDir(t), "audit.json")
	first, err := openAuditLock(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuditLock(first)

	second, err := openAuditLock(path + ".lock")
	if second != nil {
		_ = closeAuditLock(second)
		t.Fatal("second audit writer lock unexpectedly acquired")
	}
	if !errors.Is(err, ErrWriterBusy) {
		t.Fatalf("second audit writer lock error = %v, want ErrWriterBusy", err)
	}
}

func TestFileStoreReloadsLatestCheckpointBeforeAppend(t *testing.T) {
	path := filepath.Join(privateAuditTestDir(t), "audit.json")
	first, err := OpenFile(path, validAuditPolicy)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenFile(path, validAuditPolicy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(4000, 0).UTC()
	left := validAuditRecord
	left.ID = "left"
	left.OccurredAt = now.Add(-time.Minute)
	right := validAuditRecord
	right.ID = "right"
	right.OccurredAt = now.Add(-2 * time.Minute)
	if err := first.AppendAt(left, now); err != nil {
		t.Fatal(err)
	}
	if err := second.AppendAt(right, now); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFile(path, validAuditPolicy)
	if err != nil {
		t.Fatal(err)
	}
	records, err := reopened.List(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].ID != "left" || records[1].ID != "right" {
		t.Fatalf("reopened records = %#v, want left and right", records)
	}
}

func TestBoundStoreBindsIdentityAndScopesRetention(t *testing.T) {
	path := filepath.Join(privateAuditTestDir(t), "audit.json")
	store, err := OpenFile(path, validAuditPolicy)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := Bind(store, "controller-a", "resource-a")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000, 0).UTC()
	if err := bound.AppendAt(Event{ID: "bound", OccurredAt: now.Add(-time.Minute), Action: "read", Outcome: "ok"}, now); err != nil {
		t.Fatalf("bound append: %v", err)
	}
	other := validAuditRecord
	other.ID = "other"
	other.Controller = "controller-b"
	other.Resource = "resource-b"
	other.OccurredAt = now.Add(-2 * validAuditPolicy.Retention)
	persistAuditRecords(t, store, append(store.records, other))

	records, err := bound.List(now)
	if err != nil || len(records) != 1 || records[0].Controller != "controller-a" || records[0].Resource != "resource-a" {
		t.Fatalf("bound list = %#v, err=%v", records, err)
	}
	removed, err := bound.Prune(now)
	if err != nil || removed != 0 {
		t.Fatalf("bound prune removed=%d err=%v, want 0/nil", removed, err)
	}
	if len(store.records) != 2 {
		t.Fatalf("store records after bound prune = %#v, want both records", store.records)
	}
}

func TestBoundStorePruneDoesNotDeleteOtherIdentity(t *testing.T) {
	path := filepath.Join(privateAuditTestDir(t), "audit.json")
	store, err := OpenFile(path, validAuditPolicy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(3000, 0).UTC()
	records := []Record{
		{ID: "a", OccurredAt: now.Add(-2 * validAuditPolicy.Retention), Controller: "controller-a", Action: "read", Outcome: "expired", Resource: "resource-a"},
		{ID: "b", OccurredAt: now.Add(-2 * validAuditPolicy.Retention), Controller: "controller-b", Action: "read", Outcome: "expired", Resource: "resource-b"},
	}
	persistAuditRecords(t, store, records)
	bound, err := Bind(store, "controller-a", "resource-a")
	if err != nil {
		t.Fatal(err)
	}
	removed, err := bound.Prune(now)
	if err != nil || removed != 1 {
		t.Fatalf("bound prune removed=%d err=%v, want 1/nil", removed, err)
	}
	if len(store.records) != 1 || store.records[0].ID != "b" {
		t.Fatalf("remaining records = %#v, want other identity", store.records)
	}
}

func TestBindRejectsInvalidIdentityAndNilReceiver(t *testing.T) {
	store := &FileStore{}
	for _, candidate := range [][2]string{{"", "resource"}, {"controller", "resource\n"}} {
		if _, err := Bind(store, candidate[0], candidate[1]); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Bind(%q, %q) = %v, want ErrInvalid", candidate[0], candidate[1], err)
		}
	}
	if _, err := Bind(nil, "controller", "resource"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Bind(nil) = %v, want ErrInvalid", err)
	}
	var bound *BoundStore
	if err := bound.Append(Event{ID: "event", OccurredAt: time.Unix(1, 0), Action: "read", Outcome: "ok"}); err == nil {
		t.Fatal("nil bound append unexpectedly succeeded")
	}
}

func privateAuditTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func persistAuditRecords(t *testing.T, store *FileStore, records []Record) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := withAuditWriteLock(store.path, func() error {
		store.records = append([]Record(nil), records...)
		return store.saveLocked()
	}); err != nil {
		t.Fatal(err)
	}
}
