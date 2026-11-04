// Package vault provides the v2 secret-storage boundary.
//
// The file implementation is a portability fallback. It keeps the encryption
// key in a separate protected file and authenticates the complete vault
// envelope with AES-GCM. Native stores are intentionally selected by the
// platform integration layer, not silently emulated here.
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrNotFound         = errors.New("vault secret not found")
	ErrRevoked          = errors.New("vault secret revoked")
	ErrUnavailable      = errors.New("native secure store unavailable")
	ErrVersionExhausted = errors.New("vault record version exhausted")
	ErrAlreadyExists    = errors.New("vault secret already exists")
	ErrRecordLimit      = errors.New("vault record limit exceeded")
	ErrVaultBusy        = errors.New("vault is busy")
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)

const nativeVerificationPrefix = "supervisor/"

// Keep native keyring blobs and command output bounded. The value limit leaves
// room for the versioned JSON envelope and metadata under maxPayloadSize.
const (
	maxPayloadSize = 64 << 10
	maxSecretValue = 48 << 10
	// Keep malformed persisted/native JSON from turning a bounded payload into
	// unbounded recursive scanner work or parser stack growth.
	maxJSONDepth = 128
	// The encrypted disk envelope contains base64 text and JSON framing around
	// a payload bounded by maxPayloadSize. Keep malformed files from causing an
	// unbounded allocation before the payload limit is checked.
	maxDiskEnvelopeSize = 128 << 10
	// Bound map entries separately from the byte limit so a small-record
	// envelope or migration cannot force disproportionate map allocation.
	maxRecords = 512
)

// Store is the narrow secret-storage contract used by 2.0 callers. Native
// stores and the encrypted-file fallback implement the same lifecycle.
type Store interface {
	Get(name string) (Record, error)
	Put(name, value string) (Record, error)
	Rotate(name, value string) (Record, error)
	Revoke(name string) error
}

// NativeCleanup is an optional cleanup boundary for supervisor verification.
// It is deliberately not part of Store: revocation is the normal lifecycle
// operation, while deletion is reserved for removing a uniquely named test
// item after a native-session check. The encrypted-file fallback does not
// implement this destructive boundary.
type NativeCleanup interface {
	Delete(name string) error
}

// NativeCreateOnly is the supervisor-verification boundary for creating a
// uniquely named native item. The boolean reports whether this invocation
// passed the absence check and therefore may have created an item that the
// caller is responsible for cleaning up if the native write returns an
// ambiguous error. A false boolean means no mutation was attempted.
// Native adapters serialize this check with their writes for one process;
// cross-process races remain a supervisor-host limitation.
type NativeCreateOnly interface {
	PutIfAbsent(name, value string) (Record, bool, error)
}

// Keep the portable fallback's lifecycle surface checked at compile time.
var _ Store = (*FileVault)(nil)

type Record struct {
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Version   uint64    `json:"version"`
	Revoked   bool      `json:"revoked"`
	UpdatedAt time.Time `json:"updated_at"`
}

// String keeps the secret value out of ordinary formatted diagnostics. Callers
// that need structured output should use Redact, which preserves the record
// shape while applying the same value-less revoked-record invariant.
func (r Record) String() string {
	return fmt.Sprintf("Record{Name:%q, Version:%d, Revoked:%t, UpdatedAt:%q, Value:%q}", r.Name, r.Version, r.Revoked, r.UpdatedAt.UTC().Format(time.RFC3339Nano), "[REDACTED]")
}

// GoString keeps %#v diagnostics safe as well; formatting a record must not
// become an accidental secret disclosure path during an error or test report.
func (r Record) GoString() string { return r.String() }

type envelope struct {
	Version int               `json:"version"`
	Records map[string]Record `json:"records"`
}

type diskEnvelope struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
}

type FileVault struct {
	mu      sync.Mutex
	path    string
	keyPath string
	key     []byte
	records map[string]Record
	// saveHook is an internal failure-injection seam for transactional tests.
	saveHook func() error
	// beforeLockedOperation is an internal seam for testing a lock-path
	// replacement between lock acquisition/state reload and mutation.
	beforeLockedOperation func() error
	// lockValidation is installed only while a live sidecar lock is held. The
	// durable write checks it again immediately before replacement so a lock
	// pathname swap during an operation cannot admit a second writer.
	lockValidation func() error
}

func (v *FileVault) ensureReady() error {
	if v == nil {
		return errors.New("file vault is nil")
	}
	return nil
}

// OpenFile opens or creates a vault. Existing files are never overwritten
// except by an atomic update after successful authenticated decryption.
func OpenFile(path, keyPath string) (*FileVault, error) {
	if path == "" || keyPath == "" {
		return nil, errors.New("vault and key paths must be distinct")
	}
	lockPath := path + ".lock"
	for _, pair := range []struct {
		leftLabel  string
		leftPath   string
		rightLabel string
		rightPath  string
	}{
		{leftLabel: "vault", leftPath: path, rightLabel: "key", rightPath: keyPath},
		{leftLabel: "vault", leftPath: path, rightLabel: "lock", rightPath: lockPath},
		{leftLabel: "key", leftPath: keyPath, rightLabel: "lock", rightPath: lockPath},
	} {
		samePath, err := sameConfiguredPath(pair.leftPath, pair.rightPath)
		if err != nil {
			return nil, fmt.Errorf("compare %s and %s paths: %w", pair.leftLabel, pair.rightLabel, err)
		}
		if samePath {
			if pair.leftLabel == "vault" && pair.rightLabel == "key" {
				return nil, errors.New("vault and key paths must be distinct")
			}
			return nil, fmt.Errorf("%s path must be distinct from %s path", pair.leftLabel, pair.rightLabel)
		}
		if err := rejectAliasedFilesNamed(pair.leftLabel, pair.leftPath, pair.rightLabel, pair.rightPath); err != nil {
			return nil, fmt.Errorf("compare %s and %s files: %w", pair.leftLabel, pair.rightLabel, err)
		}
	}
	// Validate the configured vault path before creating or reading key
	// material. A rejected symlink or non-regular path must not cause a
	// side-effect at the separate key path.
	if err := requireProtectedFile(path); err != nil {
		return nil, err
	}
	// Validate the key path before reading it. A rejected symlink or
	// non-regular key must never be followed, even transiently, by the
	// fallback's read path.
	if err := requireProtectedFile(keyPath); err != nil {
		return nil, err
	}
	if err := rejectAliasedFiles(path, keyPath); err != nil {
		return nil, err
	}
	// A pre-existing envelope without its separate key is not a new vault. Do
	// not create unrelated key material before the inevitable authentication
	// failure; that would leave a misleading recovery artifact behind.
	var vault *FileVault
	if err := withVaultLock(path, func(lock *os.File) error {
		vaultExists, err := protectedPathExists(path)
		if err != nil {
			return err
		}
		if err := validateVaultLockFile(path+".lock", lock); err != nil {
			return err
		}
		key, err := loadOrCreateKey(keyPath, !vaultExists)
		if err != nil {
			return err
		}
		vault = &FileVault{path: path, keyPath: keyPath, key: key, records: map[string]Record{}}
		if err := validateVaultLockFile(path+".lock", lock); err != nil {
			return err
		}
		if err := vault.load(); err != nil {
			return err
		}
		return validateVaultLockFile(path+".lock", lock)
	}); err != nil {
		return nil, err
	}
	return vault, nil
}

// sameConfiguredPath catches aliases before either path exists. filepath.Clean
// alone misses relative-versus-absolute spellings, and Windows paths are
// case-insensitive. Existing files are checked separately with os.SameFile so
// hard links and other filesystem aliases are rejected too.
func sameConfiguredPath(path, keyPath string) (bool, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	absoluteKeyPath, err := filepath.Abs(keyPath)
	if err != nil {
		return false, err
	}
	absolutePath = filepath.Clean(absolutePath)
	absoluteKeyPath = filepath.Clean(absoluteKeyPath)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(absolutePath, absoluteKeyPath), nil
	}
	return absolutePath == absoluteKeyPath, nil
}

// rejectAliasedFiles enforces physical separation of ciphertext and key
// material, not just distinct path strings. A hard link could otherwise make
// the key file and encrypted envelope the same inode while both paths pass
// the regular/private-file checks.
func rejectAliasedFiles(path, keyPath string) error {
	return rejectAliasedFilesNamed("vault", path, "key", keyPath)
}

func rejectAliasedFilesNamed(leftLabel, path, rightLabel, rightPath string) error {
	pathInfo, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	keyInfo, err := os.Stat(rightPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if os.SameFile(pathInfo, keyInfo) {
		return fmt.Errorf("%s and %s paths must not reference the same file", leftLabel, rightLabel)
	}
	return nil
}

func (v *FileVault) Get(name string) (Record, error) {
	if err := v.ensureReady(); err != nil {
		return Record{}, err
	}
	if err := validName(name); err != nil {
		return Record{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	var result Record
	err := v.withLocked(func() error {
		r, ok := v.records[name]
		if !ok {
			return ErrNotFound
		}
		if err := validateLiveRecord(name, r); err != nil {
			return err
		}
		if r.Revoked {
			return ErrRevoked
		}
		result = r
		return nil
	})
	return result, err
}

func (v *FileVault) Put(name, value string) (Record, error) { return v.write(name, value) }

func (v *FileVault) Rotate(name, value string) (Record, error) {
	if err := v.ensureReady(); err != nil {
		return Record{}, err
	}
	if err := validName(name); err != nil {
		return Record{}, err
	}
	if err := validValue(value); err != nil {
		return Record{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	var result Record
	err := v.withLocked(func() error {
		old, ok := v.records[name]
		if !ok {
			return ErrNotFound
		}
		if err := validateLiveRecord(name, old); err != nil {
			return err
		}
		if old.Revoked {
			return ErrRevoked
		}
		version, err := nextRecordVersion(old.Version)
		if err != nil {
			return err
		}
		r := Record{Name: name, Value: value, Version: version, UpdatedAt: time.Now().UTC()}
		v.records[name] = r
		if err := v.save(); err != nil {
			delete(v.records, name)
			v.records[name] = old
			return err
		}
		result = r
		return nil
	})
	return result, err
}

func (v *FileVault) Revoke(name string) error {
	if err := v.ensureReady(); err != nil {
		return err
	}
	if err := validName(name); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.withLocked(func() error {
		r, ok := v.records[name]
		if !ok {
			return ErrNotFound
		}
		if err := validateLiveRecord(name, r); err != nil {
			return err
		}
		if r.Revoked {
			return nil
		}
		old := r
		r.Revoked, r.Value, r.UpdatedAt = true, "", time.Now().UTC()
		v.records[name] = r
		if err := v.save(); err != nil {
			v.records[name] = old
			return err
		}
		return nil
	})
}

// Migrate imports a legacy JSON object of string values. The source is read
// only and remains available for operator-controlled rollback until removed.
func (v *FileVault) Migrate(path string) error {
	if err := v.ensureReady(); err != nil {
		return err
	}
	// A legacy source is an operator-supplied read-only input, but it must not
	// be allowed to name either protected vault component. Reject configured
	// path aliases and existing inode aliases before opening the source so an
	// accidental key/checkpoint selection cannot reach the read boundary.
	if err := v.rejectMigrationAlias(path); err != nil {
		return err
	}
	// Validate the read-only source before opening it. Migration must not
	// follow an indirect secret path even though it does not write the source.
	if err := requireProtectedFile(path); err != nil {
		return err
	}
	b, err := readBoundedFile(path, maxPayloadSize, "legacy vault")
	if err != nil {
		return err
	}
	var legacy map[string]string
	if err := decodeSingleJSON(b, &legacy); err != nil {
		return fmt.Errorf("legacy vault: %w", err)
	}
	if legacy == nil {
		return errors.New("legacy vault: expected a JSON object")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.withLocked(func() error {
		// Build a candidate map off to the side. Validation failures therefore
		// cannot transiently change the live map, and the original map remains
		// available for rollback if the single durable checkpoint fails.
		candidate := cloneRecords(v.records)
		names := make([]string, 0, len(legacy))
		for name := range legacy {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			value := legacy[name]
			if err := validName(name); err != nil || validValue(value) != nil {
				return fmt.Errorf("legacy vault entry %q is invalid", name)
			}
			version := uint64(1)
			if r, ok := candidate[name]; ok {
				if err := validateLiveRecord(name, r); err != nil {
					return err
				}
				if r.Revoked {
					return fmt.Errorf("legacy vault entry %q is revoked", name)
				}
				version, err = nextRecordVersion(r.Version)
				if err != nil {
					return fmt.Errorf("legacy vault entry %q: %w", name, err)
				}
			} else if len(candidate) >= maxRecords {
				return ErrRecordLimit
			}
			candidate[name] = Record{Name: name, Value: value, Version: version, UpdatedAt: time.Now().UTC()}
		}
		old := v.records
		v.records = candidate
		if err := v.save(); err != nil {
			v.records = old
			return err
		}
		return nil
	})
}

func (v *FileVault) rejectMigrationAlias(path string) error {
	for label, protected := range map[string]string{
		"vault": v.path,
		"key":   v.keyPath,
	} {
		samePath, err := sameConfiguredPath(path, protected)
		if err != nil {
			return fmt.Errorf("compare legacy source with %s path: %w", label, err)
		}
		if samePath {
			return fmt.Errorf("legacy vault source must be distinct from %s path", label)
		}
		if err := rejectAliasedFiles(path, protected); err != nil {
			return fmt.Errorf("compare legacy source with %s file: %w", label, err)
		}
	}
	return nil
}

func cloneRecords(records map[string]Record) map[string]Record {
	clone := make(map[string]Record, len(records))
	for name, record := range records {
		clone[name] = record
	}
	return clone
}

// Redact replaces secret values while retaining names, versions, and status.
func Redact(records []Record) []Record {
	out := append([]Record(nil), records...)
	for i := range out {
		// Revoked records are deliberately value-less. Clear even malformed
		// input so diagnostics cannot copy a stale secret from a revoked record.
		if out[i].Revoked {
			out[i].Value = ""
		} else {
			out[i].Value = "[REDACTED]"
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (v *FileVault) write(name, value string) (Record, error) {
	if err := v.ensureReady(); err != nil {
		return Record{}, err
	}
	if err := validName(name); err != nil {
		return Record{}, err
	}
	if err := validValue(value); err != nil {
		return Record{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	var result Record
	err := v.withLocked(func() error {
		if old, ok := v.records[name]; ok {
			if err := validateLiveRecord(name, old); err != nil {
				return err
			}
			if old.Revoked {
				return ErrRevoked
			}
		}
		if _, ok := v.records[name]; !ok && len(v.records) >= maxRecords {
			return ErrRecordLimit
		}
		version := uint64(1)
		if old, ok := v.records[name]; ok {
			var err error
			version, err = nextRecordVersion(old.Version)
			if err != nil {
				return err
			}
		}
		r := Record{Name: name, Value: value, Version: version, UpdatedAt: time.Now().UTC()}
		old, existed := v.records[name]
		v.records[name] = r
		if err := v.save(); err != nil {
			if existed {
				v.records[name] = old
			} else {
				delete(v.records, name)
			}
			return err
		}
		result = r
		return nil
	})
	return result, err
}

// nextRecordVersion preserves the monotonic record-version invariant without
// allowing a successful write to wrap back to zero.
func nextRecordVersion(version uint64) (uint64, error) {
	if version == ^uint64(0) {
		return 0, ErrVersionExhausted
	}
	return version + 1, nil
}

func (v *FileVault) load() error {
	b, err := readBoundedFile(v.path, maxDiskEnvelopeSize, "vault envelope")
	if errors.Is(err, os.ErrNotExist) {
		v.records = map[string]Record{}
		return nil
	}
	if err != nil {
		return err
	}
	var d diskEnvelope
	if err := decodeSingleJSON(b, &d); err != nil {
		return fmt.Errorf("vault envelope: %w", err)
	}
	if d.Version != 1 {
		return errors.New("unsupported vault envelope version")
	}
	plain, err := decrypt(v.key, d.Nonce, d.Data)
	if err != nil {
		return fmt.Errorf("vault authentication failed: %w", err)
	}
	if err := validPayload(plain); err != nil {
		return err
	}
	var e envelope
	if err := decodeSingleJSON(plain, &e); err != nil {
		return err
	}
	if e.Version != 1 || e.Records == nil {
		return errors.New("unsupported vault version")
	}
	if err := validateRecords(e.Records); err != nil {
		return fmt.Errorf("invalid vault records: %w", err)
	}
	v.records = e.Records
	return nil
}

func (v *FileVault) save() error {
	if v.lockValidation != nil {
		if err := v.lockValidation(); err != nil {
			return err
		}
	}
	if v.saveHook != nil {
		return v.saveHook()
	}
	if err := validateRecords(v.records); err != nil {
		return err
	}
	plain, err := json.Marshal(envelope{Version: 1, Records: v.records})
	if err != nil {
		return err
	}
	if err := validPayload(plain); err != nil {
		return err
	}
	nonce, data, err := encrypt(v.key, plain)
	if err != nil {
		return err
	}
	b, err := json.Marshal(diskEnvelope{Version: 1, Nonce: nonce, Data: data})
	if err != nil {
		return err
	}
	return atomicProtectedWrite(v.path, b)
}

func loadOrCreateKey(path string, allowCreate bool) ([]byte, error) {
	b, err := readBoundedFile(path, 33, "vault key")
	if errors.Is(err, os.ErrNotExist) {
		if !allowCreate {
			return nil, err
		}
		b = make([]byte, 32)
		if _, err = io.ReadFull(rand.Reader, b); err != nil {
			return nil, err
		}
		if err = atomicProtectedWrite(path, b); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := requireProtectedFile(path); err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("vault key must be 32 bytes")
	}
	return b, nil
}

func protectedPathExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("vault file must be regular")
	}
	return true, nil
}

// readBoundedFile reads at most limit+1 bytes so callers can reject oversized
// inputs before handing them to JSON or cryptographic parsers.
func readBoundedFile(path string, limit int, label string) ([]byte, error) {
	f, err := openProtectedRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%s exceeds limit", label)
	}
	return b, nil
}

// requireProtectedFile prevents the fallback from silently using a readable
// secret or key on Unix-like hosts. Windows ACLs are not represented by the
// portable mode bits, so native ACL verification remains a platform gate.
func requireProtectedFile(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if err := requireProtectedParent(path); err != nil {
		return err
	}
	// Do not follow symlinks: the configured path must itself be the protected
	// file, and atomic replacement later replaces that path rather than its
	// target.
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("vault file must be regular")
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("vault file %q is not private", path)
	}
	return nil
}

// requireProtectedParent prevents an attacker who can write a containing
// directory or redirect an ancestor from changing where an atomic replacement
// lands between preflight and rename. Existing parent directories may be
// searchable by other users, but they must not be writable by group/other and
// must not be symlinks. Sticky shared directories such as /tmp are allowed;
// the private directory below them remains the ownership boundary.
func requireProtectedParent(path string) error {
	parent := filepath.Dir(path)
	absolute, err := filepath.Abs(parent)
	if err != nil {
		return err
	}
	for current := filepath.Clean(absolute); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if filepath.Dir(current) == current {
				return nil // atomicProtectedWrite creates missing parents as 0700.
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if current == absolute {
				return errors.New("vault parent must be a directory")
			}
			return errors.New("vault parent must not be a symlink")
		}
		if !info.IsDir() {
			return errors.New("vault parent must be a directory")
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("vault parent %q is writable by group or other", current)
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func atomicProtectedWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	previous, existed, err := protectedReplacementBackup(path)
	if err != nil {
		return err
	}
	// Create missing components one at a time. MkdirAll follows an existing
	// symlink in an ancestor before the later protection check can reject it,
	// which could create an unintended descendant as a side effect.
	if err := ensureProtectedDirectory(dir); err != nil {
		return err
	}
	// Recheck the immediate parent at the write boundary as well as during
	// OpenFile. This keeps callers of the helper fail-closed if the parent was
	// changed after initial path preflight and before temporary-file creation.
	if err := requireProtectedParent(path); err != nil {
		return err
	}
	if err := writeProtectedReplacement(dir, path, data); err != nil {
		var syncErr *protectedReplacementSyncError
		if !errors.As(err, &syncErr) {
			return err
		}
		if restoreErr := restoreProtectedReplacement(dir, path, previous, existed); restoreErr != nil {
			return errors.Join(syncErr.cause, fmt.Errorf("restore prior vault checkpoint: %w", restoreErr))
		}
		return syncErr.cause
	}
	return nil
}

type protectedReplacementSyncError struct{ cause error }

func (e *protectedReplacementSyncError) Error() string {
	return "protected replacement directory sync failed"
}

func (e *protectedReplacementSyncError) Unwrap() error { return e.cause }

// protectedReplacementBackup snapshots the bounded ciphertext/key bytes that
// are about to be replaced. It is used only to recover from a directory-sync
// failure after rename; the key and envelope remain encrypted or opaque bytes
// and are never included in an error.
func protectedReplacementBackup(path string) ([]byte, bool, error) {
	b, err := readBoundedFile(path, maxDiskEnvelopeSize, "existing protected checkpoint")
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func writeProtectedReplacement(dir, path string, data []byte) error {
	// Recovery calls this helper after the initial replacement has already
	// happened. Recheck the ownership boundary for every replacement attempt so
	// a changed parent cannot redirect the bounded restoration write.
	if err := requireProtectedParent(path); err != nil {
		return err
	}
	tmp, tmpName, cleanup, err := createProtectedTemp(dir)
	if err != nil {
		return err
	}
	defer cleanup()
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
	directory, err := replaceProtectedFile(tmpName, path)
	if err != nil {
		return err
	}
	if directory != nil {
		defer directory.Close()
	}
	if err := syncVaultDirectory(dir, directory); err != nil {
		return &protectedReplacementSyncError{cause: err}
	}
	return nil
}

func restoreProtectedReplacement(dir, path string, previous []byte, existed bool) error {
	if existed {
		return writeProtectedReplacement(dir, path, previous)
	} else {
		// Removing a newly created checkpoint is also a path mutation. Recheck
		// the ownership boundary before it so a changed parent cannot redirect
		// recovery cleanup outside the configured vault directory.
		if err := requireProtectedParent(path); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return syncVaultDirectory(dir, nil)
}

// ensureProtectedDirectory creates missing directory components without
// following an existing symlink. Existing components are checked with the
// same ownership boundary as requireProtectedParent before any child is
// created. Windows ACL verification remains a supervisor-host gate, so its
// native directory creation keeps the platform's existing behavior.
func ensureProtectedDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return os.MkdirAll(path, 0700)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	var missing []string
	for current := filepath.Clean(absolute); ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			missing = append(missing, current)
			if filepath.Dir(current) == current {
				break
			}
			continue
		}
		if statErr != nil {
			return statErr
		}
		if err := validateProtectedDirectory(current, info); err != nil {
			return err
		}
		break
	}

	for i := len(missing) - 1; i >= 0; i-- {
		current := missing[i]
		if err := os.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return statErr
		}
		if err := validateProtectedDirectory(current, info); err != nil {
			return err
		}
	}
	return nil
}

func validateProtectedDirectory(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("vault parent must not be a symlink")
	}
	if !info.IsDir() {
		return errors.New("vault parent must be a directory")
	}
	if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("vault parent %q is writable by group or other", path)
	}
	return nil
}

func encrypt(key, plain []byte) (string, string, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}
	return base64.RawStdEncoding.EncodeToString(nonce), base64.RawStdEncoding.EncodeToString(a.Seal(nil, nonce, plain, []byte("ai-relay-v2-vault"))), nil
}

func decrypt(key []byte, nonceText, dataText string) ([]byte, error) {
	nonce, err := base64.RawStdEncoding.DecodeString(nonceText)
	if err != nil {
		return nil, err
	}
	data, err := base64.RawStdEncoding.DecodeString(dataText)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	if len(nonce) != a.NonceSize() {
		return nil, errors.New("invalid vault nonce")
	}
	return a.Open(nil, nonce, data, []byte("ai-relay-v2-vault"))
}

func validName(name string) error {
	if !nameRE.MatchString(name) || strings.Contains(name, "..") {
		return errors.New("invalid secret name")
	}
	return nil
}

// ValidateName checks a vault item name without opening a backend. Supervisor
// tools should call it before probing a native store so malformed input cannot
// trigger a keyring/session interaction.
func ValidateName(name string) error {
	return validName(name)
}

// ValidateNativeVerificationName restricts the destructive cleanup boundary
// used by supervisor-only native checks to a dedicated namespace. This keeps
// an operator typo from selecting a production controller item even when the
// name is otherwise syntactically valid.
func ValidateNativeVerificationName(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	if !strings.HasPrefix(name, nativeVerificationPrefix) || name == nativeVerificationPrefix {
		return errors.New("native verification name must use a non-empty supervisor/ namespace")
	}
	return nil
}

func validValue(value string) error {
	if value == "" {
		return errors.New("secret value is empty")
	}
	// JSON encoders replace invalid UTF-8 with U+FFFD. Reject it at the
	// contract boundary so a value cannot change across persistence or native
	// backend round trips.
	if !utf8.ValidString(value) {
		return errors.New("secret value is not valid UTF-8")
	}
	if len([]byte(value)) > maxSecretValue {
		return errors.New("secret value exceeds limit")
	}
	return nil
}

func validPayload(b []byte) error {
	if len(b) > maxPayloadSize {
		return errors.New("secret payload exceeds limit")
	}
	return nil
}

func validateRecords(records map[string]Record) error {
	if len(records) > maxRecords {
		return ErrRecordLimit
	}
	for name, record := range records {
		if err := validateRecord(name, record); err != nil {
			return fmt.Errorf("record %q: %w", name, err)
		}
	}
	return nil
}

// validateLiveRecord keeps the in-process lifecycle seam aligned with the
// durable/native read boundaries. Opened vaults reload through load, but
// zero-path fixtures and future internal callers can hold live records without
// a durable reload; they must not classify malformed state or derive a new
// version from it before a later save catches the damage.
func validateLiveRecord(name string, record Record) error {
	if err := validateRecord(name, record); err != nil {
		return errors.New("vault record is invalid")
	}
	return nil
}

// decodeSingleJSON accepts exactly one JSON document and rejects unknown
// struct fields and trailing values. Every persisted/native read boundary uses
// this helper so parsers fail closed consistently across backends.
func decodeSingleJSON(data []byte, dst any) error {
	// encoding/json replaces invalid UTF-8 in JSON strings with U+FFFD. That
	// would let a malformed persisted/native payload change during decoding and
	// then pass validValue, so reject the raw document before parsing it.
	if !utf8.Valid(data) {
		return errors.New("JSON document is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("trailing data: %w", err)
	}
	return nil
}

// rejectDuplicateJSONKeys prevents parser differentials at every vault
// persistence/native boundary. encoding/json otherwise accepts duplicate
// object members and keeps the last value, while another parser or policy
// layer may keep the first one. Reject duplicates recursively so migration,
// encrypted checkpoints, and native stores all consume one unambiguous
// document. The depth bound keeps the pre-scan bounded independently of the
// decoder's implementation details.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return scanJSONValue(dec, 0)
}

func scanJSONValue(dec *json.Decoder, depth int) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			if depth >= maxJSONDepth {
				return errors.New("JSON nesting exceeds limit")
			}
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = struct{}{}
				if err := scanJSONValue(dec, depth+1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return errors.New("JSON object is not closed")
			}
		case '[':
			if depth >= maxJSONDepth {
				return errors.New("JSON nesting exceeds limit")
			}
			for dec.More() {
				if err := scanJSONValue(dec, depth+1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return errors.New("JSON array is not closed")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
	}
	return nil
}

func validateRecord(name string, r Record) error {
	if err := validName(name); err != nil || r.Name != name {
		return errors.New("record name is invalid")
	}
	if r.Version == 0 {
		return errors.New("record version is invalid")
	}
	if r.UpdatedAt.IsZero() {
		return errors.New("record timestamp is invalid")
	}
	if r.Revoked {
		if r.Value != "" {
			return errors.New("revoked record contains a value")
		}
		return nil
	}
	if err := validValue(r.Value); err != nil {
		return fmt.Errorf("record value: %w", err)
	}
	return nil
}

// Digest returns a non-secret stable identifier useful in audit records.
func Digest(name string, version uint64) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%d", name, version))))
}
