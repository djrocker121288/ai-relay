package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

func Random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, e := io.ReadFull(rand.Reader, b)
	return b, e
}
func Token(n int) (string, error) {
	b, e := Random(n)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func Secret() (string, error) { b, e := Random(32); return hex.EncodeToString(b), e }

// ReadSecretFile reads a single-line secret without accepting group/world-readable files.
func ReadSecretFile(path string) (string, error) {
	if err := CheckProtectedFile(path); err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("credential file %s is empty", path)
	}
	return v, nil
}

func LoopbackHTTP(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid gateway URL")
	}
	if u.Scheme != "http" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("plaintext HTTP is permitted only to a loopback gateway")
	}
	return nil
}
func Sign(secret, version, id, device string, ts int64, nonce, method string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(h, "%s\n%s\n%s\n%d\n%s\n%s\n", version, id, device, ts, nonce, method)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
func Verify(secret, sig, version, id, device string, ts int64, nonce, method string, body []byte) bool {
	want := Sign(secret, version, id, device, ts, nonce, method, body)
	got, e := hex.DecodeString(sig)
	if e != nil {
		return false
	}
	wb, _ := hex.DecodeString(want)
	return hmac.Equal(got, wb) && time.Now().Unix()-ts < 300 && ts-time.Now().Unix() < 300
}

func ConstantTimeEqual(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }

// GatewayEndpoint preserves POST routes when configured base URLs end in a
// slash, including canonical absolute URIs emitted by Windows installers.
func GatewayEndpoint(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}
