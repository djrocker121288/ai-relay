package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	storeVersion     = 1
	maxStoredRecords = 4096
	maxStoreBytes    = 8 << 20
)

var (
	ErrExpired    = errors.New("audit record is outside retention")
	ErrStoreLimit = errors.New("audit store limit exceeded")
)

type fileEnvelope struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

// FileStore is a bounded local audit-record store. It validates records and
// applies retention, but it does not authenticate Controller or Resource;
// callers must bind those fields to an already-authenticated request before
// calling Append.
type FileStore struct {
	mu      sync.Mutex
	path    string
	policy  Policy
	records []Record
}

// Event is the caller-controlled portion of an audit record. Controller and
// Resource are intentionally absent: a BoundStore supplies those fields from
// its already-authenticated construction boundary.
type Event struct {
	ID         string
	OccurredAt time.Time
	Action     string
	Outcome    string
}

// BoundStore binds audit writes and reads to one already-authenticated
// controller and resource. Bind does not authenticate either value; the
// caller must pass values verified by its transport or identity adapter.
//
// Retention operations through BoundStore affect only records with the exact
// bound controller and resource, so one authenticated caller cannot prune a
// different caller's records in a shared local store.
type BoundStore struct {
	store      *FileStore
	controller string
	resource   string
}

// Bind creates an owner-bound audit adapter. The underlying FileStore remains
// responsible for persistence and size/retention policy.
func Bind(store *FileStore, controller, resource string) (*BoundStore, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: audit store is required", ErrInvalid)
	}
	if err := validText("controller", controller, maxIDBytes); err != nil {
		return nil, err
	}
	if err := validText("resource", resource, maxResourceBytes); err != nil {
		return nil, err
	}
	return &BoundStore{store: store, controller: controller, resource: resource}, nil
}

// Append records an event for the bound identity using the current UTC time.
func (s *BoundStore) Append(event Event) error {
	return s.AppendAt(event, time.Now().UTC())
}

// AppendAt is the deterministic form of Append. The caller cannot substitute
// controller or resource fields because they are not part of Event.
func (s *BoundStore) AppendAt(event Event, now time.Time) error {
	if err := s.ensureReady(); err != nil {
		return err
	}
	return s.store.appendAt(s.record(event), now, s.owns)
}

// List returns only non-expired records for the bound identity.
func (s *BoundStore) List(now time.Time) ([]Record, error) {
	if err := s.ensureReady(); err != nil {
		return nil, err
	}
	records, err := s.store.List(now)
	if err != nil {
		return nil, err
	}
	filtered := make([]Record, 0, len(records))
	for _, record := range records {
		if s.owns(record) {
			filtered = append(filtered, record)
		}
	}
	return filtered, nil
}

// Prune removes only expired records owned by the bound identity.
func (s *BoundStore) Prune(now time.Time) (int, error) {
	if err := s.ensureReady(); err != nil {
		return 0, err
	}
	return s.store.pruneAt(now, s.owns)
}

func (s *BoundStore) ensureReady() error {
	if s == nil || s.store == nil {
		return errors.New("audit bound store is nil")
	}
	return nil
}

func (s *BoundStore) record(event Event) Record {
	return Record{
		ID:         event.ID,
		OccurredAt: event.OccurredAt,
		Controller: s.controller,
		Action:     event.Action,
		Outcome:    event.Outcome,
		Resource:   s.resource,
	}
}

func (s *BoundStore) owns(record Record) bool {
	return record.Controller == s.controller && record.Resource == s.resource
}

// OpenFile opens an existing audit store or prepares a new one. The store is
// written only after the first successful append or prune operation.
func OpenFile(path string, policy Policy) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: audit path is required", ErrInvalid)
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if err := ensurePrivateAuditParent(path); err != nil {
		return nil, err
	}
	store := &FileStore{path: path, policy: policy}
	data, err := readAuditFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	store.records, err = decodeAuditEnvelope(data)
	if err != nil {
		return nil, err
	}
	return store, nil
}

// Append stores one record after pruning records outside the current
// retention window. now is explicit so callers can use the same trusted clock
// for policy and audit evidence; Append uses the current UTC time.
func (s *FileStore) Append(record Record) error {
	return s.AppendAt(record, time.Now().UTC())
}

// AppendAt is the deterministic form of Append used by bounded integrations
// and tests. It does not accept a record that is already expired or too large
// for the configured policy.
func (s *FileStore) AppendAt(record Record, now time.Time) error {
	return s.appendAt(record, now, nil)
}

func (s *FileStore) appendAt(record Record, now time.Time, owns func(Record) bool) error {
	if err := s.ensureReady(); err != nil {
		return err
	}
	if err := s.policy.Validate(); err != nil {
		return err
	}
	if err := record.Validate(); err != nil {
		return err
	}
	if now.IsZero() {
		return fmt.Errorf("%w: current time is required", ErrInvalid)
	}
	accepted, err := s.policy.Accepts(record, now)
	if err != nil {
		return err
	}
	if !accepted {
		return ErrExpired
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return withAuditWriteLock(s.path, func() error {
		if err := s.reloadLocked(); err != nil {
			return err
		}
		old := append([]Record(nil), s.records...)
		if _, err := s.pruneLocked(now, owns); err != nil {
			return err
		}
		if len(s.records) >= maxStoredRecords {
			s.records = old
			return ErrStoreLimit
		}
		s.records = append(s.records, record)
		if err := s.saveLocked(); err != nil {
			s.records = old
			return err
		}
		return nil
	})
}

// List returns records that are still within retention at now. Expired
// records remain on disk until Prune or a later append, so a read does not
// unexpectedly rewrite the audit file.
func (s *FileStore) List(now time.Time) ([]Record, error) {
	if err := s.ensureReady(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, fmt.Errorf("%w: current time is required", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []Record
	err := withAuditReadLock(s.path, func() error {
		if err := s.reloadLocked(); err != nil {
			return err
		}
		result = make([]Record, 0, len(s.records))
		for _, record := range s.records {
			accepted, err := s.policy.Accepts(record, now)
			if err != nil {
				return err
			}
			if accepted {
				result = append(result, record)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Prune removes records outside retention and atomically checkpoints the
// remaining records. It returns the number removed and never deletes the
// backing file when no records are expired.
func (s *FileStore) Prune(now time.Time) (int, error) {
	return s.pruneAt(now, nil)
}

func (s *FileStore) pruneAt(now time.Time, owns func(Record) bool) (int, error) {
	if err := s.ensureReady(); err != nil {
		return 0, err
	}
	if now.IsZero() {
		return 0, fmt.Errorf("%w: current time is required", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	err := withAuditWriteLock(s.path, func() error {
		if err := s.reloadLocked(); err != nil {
			return err
		}
		old := append([]Record(nil), s.records...)
		var err error
		removed, err = s.pruneLocked(now, owns)
		if err != nil || removed == 0 {
			return err
		}
		if err := s.saveLocked(); err != nil {
			s.records = old
			removed = 0
			return err
		}
		return nil
	})
	return removed, err
}

func (s *FileStore) ensureReady() error {
	if s == nil {
		return errors.New("audit store is nil")
	}
	return nil
}

// reloadLocked refreshes the in-memory snapshot while the caller owns the
// sidecar lock. Without this reload, two processes could each read the same
// old envelope and the later atomic replacement would discard the earlier
// process's append.
func (s *FileStore) reloadLocked() error {
	data, err := readAuditFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.records = nil
		return nil
	}
	if err != nil {
		return err
	}
	records, err := decodeAuditEnvelope(data)
	if err != nil {
		return err
	}
	s.records = records
	return nil
}

func (s *FileStore) pruneLocked(now time.Time, owns func(Record) bool) (int, error) {
	kept := s.records[:0]
	removed := 0
	for _, record := range s.records {
		if owns != nil && !owns(record) {
			kept = append(kept, record)
			continue
		}
		accepted, err := s.policy.Accepts(record, now)
		if err != nil {
			return 0, err
		}
		if accepted {
			kept = append(kept, record)
		} else {
			removed++
		}
	}
	s.records = kept
	return removed, nil
}

func (s *FileStore) saveLocked() error {
	data, err := encodeAuditEnvelope(s.records)
	if err != nil {
		return err
	}
	if len(data) > maxStoreBytes {
		return ErrStoreLimit
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".audit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
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
	if err := replaceAuditFile(tmpName, s.path); err != nil {
		return err
	}
	return syncAuditDirectory(dir)
}

func readAuditFile(path string) ([]byte, error) {
	f, err := openAuditRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStoreBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxStoreBytes {
		return nil, ErrStoreLimit
	}
	return data, nil
}

func decodeAuditEnvelope(data []byte) ([]Record, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty audit store", ErrInvalid)
	}
	if !bytes.Equal(bytes.TrimSpace(data), data) {
		// Whitespace around a persisted document is harmless, but a blank file is
		// still rejected by the decoder below.
		data = bytes.TrimSpace(data)
	}
	var envelope fileEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("%w: audit store: %v", ErrInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%w: audit store contains multiple JSON values", ErrInvalid)
		}
		return nil, fmt.Errorf("%w: audit store has trailing data", ErrInvalid)
	}
	if envelope.Version != storeVersion || len(envelope.Records) > maxStoredRecords {
		return nil, fmt.Errorf("%w: unsupported or oversized audit store", ErrInvalid)
	}
	for _, record := range envelope.Records {
		if err := record.Validate(); err != nil {
			return nil, err
		}
	}
	return envelope.Records, nil
}

func encodeAuditEnvelope(records []Record) ([]byte, error) {
	if len(records) > maxStoredRecords {
		return nil, ErrStoreLimit
	}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			return nil, err
		}
	}
	data, err := json.Marshal(fileEnvelope{Version: storeVersion, Records: records})
	if err != nil {
		return nil, fmt.Errorf("%w: audit store encoding failed", ErrInvalid)
	}
	return data, nil
}
