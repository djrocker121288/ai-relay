package security

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSignVerifyAndExpiry(t *testing.T) {
	sig := Sign("secret", "ai-relay/v1", "r", "d", time.Now().Unix(), "n", "exec", []byte(`{"x":1}`))
	if !Verify("secret", sig, "ai-relay/v1", "r", "d", time.Now().Unix(), "n", "exec", []byte(`{"x":1}`)) {
		t.Fatal("valid signature rejected")
	}
	if Verify("wrong", sig, "ai-relay/v1", "r", "d", time.Now().Unix(), "n", "exec", []byte(`{"x":1}`)) {
		t.Fatal("wrong key accepted")
	}
}

func TestCredentialFileAndLoopbackHTTP(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "secret")
	if err := os.WriteFile(p, []byte("value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ProtectFile(p); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadSecretFile(p); err != nil || got != "value" {
		t.Fatalf("read secret: %q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSecretFile(p); err == nil {
			t.Fatal("accepted group-readable credential")
		}
	}
	if err := LoopbackHTTP("http://127.0.0.1:8743"); err != nil {
		t.Fatal(err)
	}
	if err := LoopbackHTTP("http://192.0.2.1:8743"); err == nil {
		t.Fatal("accepted non-loopback plaintext HTTP")
	}
	if err := LoopbackHTTP("https://192.0.2.1:8743"); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialRejectsDirectory(t *testing.T) {
	if _, err := ReadSecretFile(t.TempDir()); err == nil {
		t.Fatal("directory accepted as credential")
	}
}

func TestGatewayEndpointCanonicalSlash(t *testing.T) {
	for _, base := range []string{"http://127.0.0.1:8743", "http://127.0.0.1:8743/", "http://127.0.0.1:8743///"} {
		if got := GatewayEndpoint(base, "/v1/agent/poll"); got != "http://127.0.0.1:8743/v1/agent/poll" {
			t.Fatalf("noncanonical endpoint %q", got)
		}
	}
}
