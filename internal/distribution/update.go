package distribution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Version is the public client version. Release builds may override it with -ldflags.
var Version = "0.1.0"

const (
	maxUpdateArtifactBytes int64 = 512 << 20
	maxUpdateManifestBytes int64 = 128 << 10
)

type UpdateManifest struct {
	Version      string `json:"version"`
	ReleaseNotes string `json:"release_notes"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	ArtifactURL  string `json:"artifact_url"`
	SHA256       string `json:"sha256"`
	PublishedAt  string `json:"published_at,omitempty"`
	Signature    string `json:"signature"`
}

func (m UpdateManifest) signedBytes() ([]byte, error) {
	type unsigned UpdateManifest
	u := unsigned(m)
	u.Signature = ""
	return json.Marshal(u)
}

func DecodePinnedKey(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if b, err := hex.DecodeString(raw); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	b, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("pinned update key must be 32-byte hex or base64")
	}
	return ed25519.PublicKey(b), nil
}

func (m UpdateManifest) Verify(pub ed25519.PublicKey, current string) error {
	if len(pub) != ed25519.PublicKeySize || m.Signature == "" {
		return errors.New("update manifest has no valid pinned signature")
	}
	b, err := base64.RawStdEncoding.DecodeString(m.Signature)
	if err != nil || !ed25519.Verify(pub, must(m.signedBytes()), b) {
		return errors.New("update manifest signature verification failed")
	}
	if m.Version == "" || m.Platform == "" || m.Architecture == "" || m.ArtifactURL == "" || !isSHA256(m.SHA256) {
		return errors.New("update manifest is incomplete")
	}
	if current != "" && CompareVersions(m.Version, current) <= 0 {
		return fmt.Errorf("refusing non-upgrade version %q over %q", m.Version, current)
	}
	u, err := url.Parse(m.ArtifactURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("update artifact must use HTTPS")
	}
	return nil
}

func isSHA256(s string) bool {
	_, err := hex.DecodeString(s)
	return len(s) == sha256.Size*2 && err == nil
}
func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func CompareVersions(a, b string) int {
	parse := func(s string) []int {
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		parts := strings.SplitN(s, "+", 2)[0]
		parts = strings.SplitN(parts, "-", 2)[0]
		var out []int
		for _, p := range strings.Split(parts, ".") {
			var n int
			fmt.Sscanf(p, "%d", &n)
			out = append(out, n)
		}
		for len(out) < 3 {
			out = append(out, 0)
		}
		return out
	}
	x, y := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}

type Client struct {
	HTTP      *http.Client
	Origin    string
	PublicKey ed25519.PublicKey
}

func (c Client) Check(ctx context.Context, current string) (UpdateManifest, error) {
	if c.HTTP == nil {
		c.HTTP = http.DefaultClient
	}
	u, err := url.Parse(strings.TrimRight(c.Origin, "/") + "/v1/updates/" + runtime.GOOS + "/" + runtime.GOARCH)
	if err != nil || u.Scheme != "https" {
		return UpdateManifest{}, errors.New("update origin must be HTTPS")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return UpdateManifest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return UpdateManifest{}, fmt.Errorf("update check: %s", resp.Status)
	}
	m, err := decodeUpdateManifest(resp.Body)
	if err != nil {
		return m, err
	}
	if err := m.Verify(c.PublicKey, current); err != nil {
		return m, err
	}
	if m.Platform != runtime.GOOS || m.Architecture != runtime.GOARCH {
		return m, fmt.Errorf("update target %s/%s does not match this agent %s/%s", m.Platform, m.Architecture, runtime.GOOS, runtime.GOARCH)
	}
	return m, nil
}

func decodeUpdateManifest(r io.Reader) (UpdateManifest, error) {
	var m UpdateManifest
	b, err := io.ReadAll(io.LimitReader(r, maxUpdateManifestBytes+1))
	if err != nil {
		return m, err
	}
	if int64(len(b)) > maxUpdateManifestBytes {
		return m, fmt.Errorf("update manifest exceeds %d bytes", maxUpdateManifestBytes)
	}
	if err := json.Unmarshal(bytes.TrimSpace(b), &m); err != nil {
		return m, err
	}
	return m, nil
}

func (c Client) Download(ctx context.Context, m UpdateManifest) ([]byte, error) {
	u, err := url.Parse(m.ArtifactURL)
	if err != nil || u.Scheme != "https" {
		return nil, errors.New("artifact URL must be HTTPS")
	}
	if err := m.Verify(c.PublicKey, ""); err != nil {
		return nil, err
	}
	// Download is an independently callable mutation-adjacent boundary. Do not
	// rely on Check having selected the manifest: a signed artifact for another
	// platform must not be fetched merely because an in-process caller bypassed
	// the update-check flow.
	if m.Platform != runtime.GOOS || m.Architecture != runtime.GOARCH {
		return nil, fmt.Errorf("update target %s/%s does not match this agent %s/%s", m.Platform, m.Architecture, runtime.GOOS, runtime.GOARCH)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	h := c.HTTP
	if h == nil {
		h = http.DefaultClient
	}
	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update download: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxUpdateArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxUpdateArtifactBytes {
		return nil, fmt.Errorf("update artifact exceeds %d bytes", maxUpdateArtifactBytes)
	}
	sum := sha256.Sum256(b)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), m.SHA256) {
		return nil, errors.New("update artifact hash verification failed")
	}
	return b, nil
}

// ValidateInstall checks the local replacement boundary without changing any
// filesystem state. It is the shared dry-run gate for callers that have
// already verified a signed manifest and artifact hash.
func ValidateInstall(path string, artifactSize int64, version, current string) error {
	if CompareVersions(version, current) <= 0 {
		return fmt.Errorf("refusing downgrade from %s to %s", current, version)
	}
	if artifactSize <= 0 || artifactSize > maxUpdateArtifactBytes {
		return fmt.Errorf("update artifact size is outside the 1..%d byte bound", maxUpdateArtifactBytes)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("current executable is not a regular file")
	}
	if info.Mode().Perm() == 0 {
		return errors.New("current executable has no usable permissions")
	}
	return nil
}

// Install atomically replaces path and keeps one rollback copy. It is only called after approval.
func Install(path string, artifact []byte, version, current string) error {
	if err := ValidateInstall(path, int64(len(artifact)), version, current); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode().Perm() == 0 {
		return errors.New("current executable is not a regular file")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ai-relay-update-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(st.Mode().Perm()); err == nil {
		_, err = tmp.Write(artifact)
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
	backup := path + ".previous"
	stagedBackup := tmpName + ".previous"
	hadBackup, err := stageRollbackImage(backup, stagedBackup)
	if err != nil {
		return err
	}
	if err = os.Rename(path, backup); err != nil {
		return errors.Join(err, restoreStagedRollback(backup, stagedBackup, hadBackup))
	}
	if err = os.Rename(tmpName, path); err != nil {
		restoreErr := os.Rename(backup, path)
		return errors.Join(err, restoreErr, restoreStagedRollback(backup, stagedBackup, hadBackup))
	}
	if err = syncUpdateDirectory(dir); err != nil {
		restoreErr := restoreInstalledUpdate(path, backup, stagedBackup, hadBackup, tmpName)
		return errors.Join(err, restoreErr)
	}
	if hadBackup {
		// The new active/rollback pair is already durable. The staged image is
		// obsolete; cleanup is intentionally outside the replacement sequence.
		if err := os.Remove(stagedBackup); err != nil {
			return fmt.Errorf("update installed but obsolete rollback cleanup failed: %w", err)
		}
	}
	return nil
}

func stageRollbackImage(backup, staged string) (bool, error) {
	info, err := os.Lstat(backup)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() == 0 {
		return false, errors.New("existing rollback image is not a usable regular file")
	}
	if err := os.Rename(backup, staged); err != nil {
		return false, err
	}
	return true, nil
}

func restoreStagedRollback(backup, staged string, existed bool) error {
	if !existed {
		return nil
	}
	return os.Rename(staged, backup)
}

func restoreInstalledUpdate(path, backup, staged string, hadBackup bool, tempName string) error {
	failed := tempName + ".failed"
	if err := os.Rename(path, failed); err != nil {
		return err
	}
	if err := os.Rename(backup, path); err != nil {
		_ = os.Rename(failed, path)
		return err
	}
	if err := restoreStagedRollback(backup, staged, hadBackup); err != nil {
		return err
	}
	if err := syncUpdateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return os.Remove(failed)
}

func Rollback(path string) error {
	backup := path + ".previous"
	currentInfo, err := os.Lstat(path)
	if err != nil || currentInfo.Mode()&os.ModeSymlink != 0 || !currentInfo.Mode().IsRegular() {
		return errors.New("current executable is not a regular file")
	}
	backupInfo, err := os.Lstat(backup)
	if err != nil {
		return errors.New("no rollback image available")
	}
	if backupInfo.Mode()&os.ModeSymlink != 0 || !backupInfo.Mode().IsRegular() || backupInfo.Mode().Perm() == 0 {
		return errors.New("rollback image is not a usable regular file")
	}
	tmp := path + ".rollback-tmp"
	if _, err := os.Lstat(tmp); err == nil {
		return errors.New("rollback temporary path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(path, tmp); err != nil {
		return err
	}
	if err := os.Rename(backup, path); err != nil {
		_ = os.Rename(tmp, path)
		return err
	}
	if err := syncUpdateDirectory(filepath.Dir(path)); err != nil {
		var restoreErrs []error
		if restoreErr := os.Rename(path, backup); restoreErr != nil {
			restoreErrs = append(restoreErrs, restoreErr)
		}
		if restoreErr := os.Rename(tmp, path); restoreErr != nil {
			restoreErrs = append(restoreErrs, restoreErr)
		}
		if restoreSyncErr := syncUpdateDirectory(filepath.Dir(path)); restoreSyncErr != nil {
			restoreErrs = append(restoreErrs, restoreSyncErr)
		}
		return errors.Join(append([]error{err}, restoreErrs...)...)
	}
	if err := os.Remove(tmp); err != nil {
		return fmt.Errorf("rollback installed but old executable cleanup failed: %w", err)
	}
	return nil
}

func ManifestSignature(m UpdateManifest, private ed25519.PrivateKey) string {
	b, _ := m.signedBytes()
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, b))
}
