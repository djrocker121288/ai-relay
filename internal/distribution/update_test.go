package distribution

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func signedManifest(t *testing.T, version string, private ed25519.PrivateKey) UpdateManifest {
	t.Helper()
	m := UpdateManifest{Version: version, ReleaseNotes: "notes", Platform: "linux", Architecture: "amd64", ArtifactURL: "https://relay.example.invalid/artifacts/ai-relay", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	m.Signature = ManifestSignature(m, private)
	return m
}
func TestManifestSignatureFailure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := signedManifest(t, "1.1.0", priv)
	m.ReleaseNotes = "tampered"
	if err := m.Verify(pub, "1.0.0"); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}
func TestInstallRejectsDowngradeAndRollsBack(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "agent")
	if err := os.WriteFile(p, []byte("old"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := Install(p, []byte("new"), "1.0.0", "1.1.0"); err == nil {
		t.Fatal("downgrade accepted")
	}
	if err := Install(p, []byte("new"), "1.2.0", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "new" {
		t.Fatal(string(b))
	}
	if err := Rollback(p); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p)
	if string(b) != "old" {
		t.Fatal(string(b))
	}
}

func TestValidateInstallIsDryRunAndRejectsUnsafeTargets(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "agent")
	if err := os.WriteFile(p, []byte("old"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstall(p, int64(len("new")), "1.2.0", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "old" {
		t.Fatalf("dry run changed executable: %q, %v", got, err)
	}
	if _, err := os.Stat(p + ".previous"); !os.IsNotExist(err) {
		t.Fatalf("dry run created rollback image: %v", err)
	}
	if err := ValidateInstall(p, 0, "1.2.0", "1.1.0"); err == nil {
		t.Fatal("empty artifact accepted")
	}
	if err := ValidateInstall(p, maxUpdateArtifactBytes+1, "1.2.0", "1.1.0"); err == nil {
		t.Fatal("oversized artifact accepted")
	}

	link := filepath.Join(d, "agent-link")
	if err := os.Symlink(p, link); err == nil {
		if err := ValidateInstall(link, int64(len("new")), "1.2.0", "1.1.0"); err == nil {
			t.Fatal("symlink target accepted")
		}
	}
}

func TestInstallRejectsUnsafeExistingRollbackWithoutMutation(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "agent")
	outside := filepath.Join(d, "outside")
	if err := os.WriteFile(p, []byte("current"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	backup := p + ".previous"
	if err := os.Symlink(outside, backup); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	if err := Install(p, []byte("replacement"), "1.2.0", "1.1.0"); err == nil {
		t.Fatal("unsafe existing rollback image accepted")
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "current" {
		t.Fatalf("active executable changed after rejected install: %q, %v", got, err)
	}
	info, err := os.Lstat(backup)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("rollback image changed after rejected install: %v", err)
	}
}

func TestInstallKeepsPriorRollbackUntilReplacementIsDurable(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "agent")
	backup := p + ".previous"
	if err := os.WriteFile(p, []byte("current"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("older"), 0700); err != nil {
		t.Fatal(err)
	}

	if err := Install(p, []byte("replacement"), "1.2.0", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "replacement" {
		t.Fatalf("active executable = %q, %v", got, err)
	}
	got, err = os.ReadFile(backup)
	if err != nil || string(got) != "current" {
		t.Fatalf("rollback executable = %q, %v", got, err)
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".previous") && entry.Name() != filepath.Base(backup) {
			t.Fatalf("staged rollback image left behind: %q", entry.Name())
		}
	}
}

func TestRollbackRejectsUntrustedImageWithoutChangingFiles(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "agent")
	linkTarget := filepath.Join(d, "outside")
	if err := os.WriteFile(p, []byte("current"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(linkTarget, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	backup := p + ".previous"
	if err := os.Symlink(linkTarget, backup); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	if err := Rollback(p); err == nil {
		t.Fatal("symlink rollback image accepted")
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "current" {
		t.Fatalf("rollback changed executable: %q, %v", got, err)
	}
	info, err := os.Lstat(backup)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("rollback image was changed: %v", err)
	}
}

func TestRollbackRejectsExistingTemporaryPathWithoutMutation(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "agent")
	backup := p + ".previous"
	tmp := p + ".rollback-tmp"
	if err := os.WriteFile(p, []byte("current"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("previous"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := Rollback(p); err == nil {
		t.Fatal("rollback overwrote an existing temporary path")
	}
	for name, want := range map[string]string{p: "current", backup: "previous", tmp: "stale"} {
		got, err := os.ReadFile(name)
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
}

func TestCheckRejectsSignedManifestForAnotherPlatform(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := signedManifest(t, "1.1.0", priv)
	m.Platform = "windows"
	if runtime.GOOS == "windows" {
		m.Platform = "linux"
	}
	m.Signature = ManifestSignature(m, priv)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(m)
	}))
	defer server.Close()

	client := Client{HTTP: server.Client(), Origin: server.URL, PublicKey: pub}
	_, err := client.Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("signed manifest for another platform accepted")
	}
	if m.Platform == runtime.GOOS && m.Architecture == runtime.GOARCH {
		t.Fatal("test manifest did not target another platform")
	}
}

func TestDownloadRejectsSignedManifestForAnotherPlatformBeforeRequest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := signedManifest(t, "1.1.0", priv)
	m.Platform = "windows"
	if runtime.GOOS == "windows" {
		m.Platform = "linux"
	}
	m.Signature = ManifestSignature(m, priv)
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte("unexpected artifact"))
	}))
	defer server.Close()
	m.ArtifactURL = server.URL + "/artifact"
	m.Signature = ManifestSignature(m, priv)

	client := Client{HTTP: server.Client(), PublicKey: pub}
	if _, err := client.Download(context.Background(), m); err == nil {
		t.Fatal("Download accepted a signed artifact for another platform")
	}
	if requests != 0 {
		t.Fatalf("Download made %d artifact requests before rejecting the target", requests)
	}
}

func TestCheckRejectsOversizedOrTrailingManifestDocument(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := signedManifest(t, "1.1.0", priv)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body string
	}{
		{name: "trailing document", body: string(raw) + "{}"},
		{name: "oversized body", body: strings.Repeat(" ", int(maxUpdateManifestBytes)+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			client := Client{HTTP: server.Client(), Origin: server.URL, PublicKey: pub}
			if _, err := client.Check(context.Background(), "1.0.0"); err == nil {
				t.Fatalf("accepted %s", test.name)
			}
		})
	}
}
