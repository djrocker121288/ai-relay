package arpl

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type ReleaseArtifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type ReleaseManifest struct {
	Version   string            `json:"version"`
	BuildID   string            `json:"build_id"`
	Created   time.Time         `json:"created"`
	Artifacts []ReleaseArtifact `json:"artifacts"`
	Signer    string            `json:"signer"`
	Signature string            `json:"signature"`
}

func HashArtifact(path string) (ReleaseArtifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return ReleaseArtifact{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return ReleaseArtifact{}, err
	}
	return ReleaseArtifact{Name: filepath.Base(path), SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}
func (m ReleaseManifest) signingBytes() []byte {
	c := m
	c.Signature = ""
	b, _ := json.Marshal(c)
	return b
}
func (m *ReleaseManifest) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("release signing key is invalid")
	}
	m.Signer = hex.EncodeToString(ed25519.PublicKey(priv))
	m.Signature = hex.EncodeToString(ed25519.Sign(priv, m.signingBytes()))
	return nil
}
func (m ReleaseManifest) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("release verification key is invalid")
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, m.signingBytes(), sig) {
		return errors.New("release signature verification failed")
	}
	if m.Signer != "" && m.Signer != hex.EncodeToString(pub) {
		return errors.New("release signer mismatch")
	}
	return nil
}
func VerifyArtifact(path string, a ReleaseArtifact) error {
	got, err := HashArtifact(path)
	if err != nil {
		return err
	}
	if got.Size != a.Size || !strings.EqualFold(got.SHA256, a.SHA256) {
		return fmt.Errorf("artifact hash mismatch for %s", a.Name)
	}
	return nil
}

type UpdateOptions struct {
	Target      string
	Backup      string
	Health      func(string) error
	Restart     func() error
	BackupPaths []string
	Keep        int
}

func StageAndActivateUpdate(artifact string, manifest ReleaseManifest, pub ed25519.PublicKey, opt UpdateOptions) error {
	if err := manifest.Verify(pub); err != nil {
		return err
	}
	var found *ReleaseArtifact
	for i := range manifest.Artifacts {
		if manifest.Artifacts[i].Name == filepath.Base(artifact) {
			found = &manifest.Artifacts[i]
			break
		}
	}
	if found == nil {
		return errors.New("artifact missing from release manifest")
	}
	if err := VerifyArtifact(artifact, *found); err != nil {
		return err
	}
	if opt.Target == "" {
		return errors.New("update target is required")
	}
	if opt.Keep <= 0 {
		opt.Keep = 2
	}
	if err := os.MkdirAll(filepath.Dir(opt.Target), 0700); err != nil {
		return err
	}
	stage, err := os.CreateTemp(filepath.Dir(opt.Target), ".arpl-update-")
	if err != nil {
		return err
	}
	stagePath := stage.Name()
	src, err := os.Open(artifact)
	if err != nil {
		stage.Close()
		os.Remove(stagePath)
		return err
	}
	if _, err = io.Copy(stage, src); err != nil {
		_ = src.Close()
		stage.Close()
		os.Remove(stagePath)
		return err
	}
	_ = src.Close()
	if err = stage.Close(); err != nil {
		os.Remove(stagePath)
		return err
	}
	if opt.Backup == "" {
		opt.Backup = opt.Target + ".rollback"
	}
	hadOld := false
	if old, err := os.ReadFile(opt.Target); err == nil {
		hadOld = true
		if err = os.WriteFile(opt.Backup, old, 0700); err != nil {
			os.Remove(stagePath)
			return err
		}
	}
	pathBackups := make(map[string][]byte)
	pathExisted := make(map[string]bool)
	for _, path := range opt.BackupPaths {
		if path == "" || path == opt.Target {
			continue
		}
		if b, readErr := os.ReadFile(path); readErr == nil {
			pathBackups[path] = b
			pathExisted[path] = true
			_ = os.WriteFile(path+".rollback", b, 0600)
		} else if os.IsNotExist(readErr) {
			pathExisted[path] = false
		}
	}
	restore := func() {
		if old, e := os.ReadFile(opt.Backup); e == nil && hadOld {
			_ = os.WriteFile(opt.Target, old, 0755)
		} else if !hadOld {
			_ = os.Remove(opt.Target)
		}
		for path, existed := range pathExisted {
			if existed {
				_ = os.WriteFile(path, pathBackups[path], 0600)
			} else {
				_ = os.Remove(path)
			}
		}
		if opt.Restart != nil {
			_ = opt.Restart()
		}
	}
	if err = os.Rename(stagePath, opt.Target); err != nil {
		os.Remove(stagePath)
		return err
	}
	if err := os.Chmod(opt.Target, 0755); err != nil {
		return err
	}
	if opt.Restart != nil {
		if err := opt.Restart(); err != nil {
			restore()
			return fmt.Errorf("update restart failed; rollback completed: %w", err)
		}
	}
	if opt.Health != nil {
		if err := opt.Health(opt.Target); err != nil {
			restore()
			return fmt.Errorf("update health failed; rollback completed: %w", err)
		}
	}
	return nil
}

func PlatformArtifactName(version string) string {
	return fmt.Sprintf("ai-relay-arpl_%s_%s_%s", version, runtime.GOOS, runtime.GOARCH)
}
