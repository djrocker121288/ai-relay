package lifecycle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type nonSnapshotableTLSPrivateKey struct{}

func (nonSnapshotableTLSPrivateKey) Public() crypto.PublicKey { return nil }

func (nonSnapshotableTLSPrivateKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestMCPHTTPHandlerRequiresSecureJSONPOST(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	called := false
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		called = true
		return Principal{ID: "owner", Scopes: []string{ScopeProjectWrite}}, nil
	}, RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		method string
		tls    bool
		media  string
		want   int
	}{
		{"wrong method", http.MethodGet, true, "application/json", http.StatusMethodNotAllowed},
		{"plaintext", http.MethodPost, false, "application/json", http.StatusForbidden},
		{"wrong media type", http.MethodPost, true, "text/plain", http.StatusUnsupportedMediaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			scheme := "https"
			if !tc.tls {
				scheme = "http"
			}
			req := httptest.NewRequest(tc.method, scheme+"://relay.invalid/lifecycle", strings.NewReader("{}"))
			req.Header.Set("Content-Type", tc.media)
			if tc.tls {
				req.TLS = &tlsStateForTest
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
			assertHTTPBoundaryHeaders(t, response)
			if called {
				t.Fatal("principal resolver called before transport validation")
			}
		})
	}

}

func TestNewDirectHTTPSHandlerRequiresReviewedListenPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		config  *tls.Config
		wantErr string
	}{
		{
			name:    "public address",
			address: "192.0.2.10:8743",
			config:  &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}},
			wantErr: "loopback",
		},
		{
			name:    "implicit TLS defaults",
			address: "127.0.0.1:8743",
			config:  &tls.Config{},
			wantErr: "TLS 1.2",
		},
		{
			name:    "unbound port",
			address: "127.0.0.1:0",
			config:  &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}},
			wantErr: "bound non-zero port",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewDirectHTTPSHandler(nil, nil, tc.address, tc.config); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewDirectHTTPSHandler error = %v, want %q", err, tc.wantErr)
			}
		})
	}

	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	handler, err := NewDirectHTTPSHandler(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, "127.0.0.1:8743", config)
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil {
		t.Fatal("NewDirectHTTPSHandler returned a nil handler")
	}
	if config.MinVersion != tls.VersionTLS12 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatal("NewDirectHTTPSHandler mutated the supplied TLS config")
	}

	request := httptest.NewRequest(http.MethodPost, "http://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("plaintext direct handler status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestNewDirectHTTPSHandlerRejectsMatchingAttackerHostAndOrigin(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	resolverCalls := 0
	handler, err := NewDirectHTTPSHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, "127.0.0.1:8743", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://attacker.invalid:8743/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://attacker.invalid:8743")
	request.TLS = &tlsStateForTest
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("matching attacker host/origin status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if resolverCalls != 0 {
		t.Fatalf("resolver calls = %d, want 0 before bound-authority approval", resolverCalls)
	}

	request = httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8743/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://127.0.0.1:8743")
	request.Header.Set("Accept", "application/json")
	request.TLS = &tlsStateForTest
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("matching bound host/origin status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if resolverCalls != 1 {
		t.Fatalf("resolver calls after bound host/origin = %d, want 1", resolverCalls)
	}

	defaultPortHandler, err := NewDirectHTTPSHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, "127.0.0.1:443", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "https://127.0.0.1/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://127.0.0.1")
	request.Header.Set("Accept", "application/json")
	request.TLS = &tlsStateForTest
	response = httptest.NewRecorder()
	defaultPortHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("omitted default HTTPS port status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if resolverCalls != 2 {
		t.Fatalf("resolver calls after omitted default port = %d, want 2", resolverCalls)
	}
}

func TestListenDirectHTTPSBindsOnlyAfterReviewedPolicy(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	listener, err := ListenDirectHTTPS("127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().String()
	if err := ValidateLoopbackListenAddress(address); err != nil {
		t.Fatalf("bound address %q is not a reviewed loopback address: %v", address, err)
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := accepted.(*tls.Conn); !ok {
		t.Fatalf("accepted connection type = %T, want *tls.Conn", accepted)
	}
	accepted.Close()

	config.MinVersion = tls.VersionTLS13
	if config.MaxVersion != tls.VersionTLS13 {
		t.Fatal("ListenDirectHTTPS changed the caller's TLS config")
	}
}

func TestListenDirectHTTPSRejectsPolicyBeforeBinding(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	for _, tc := range []struct {
		name    string
		address string
		config  *tls.Config
	}{
		{name: "public address", address: "192.0.2.10:0", config: config},
		{name: "implicit TLS", address: "127.0.0.1:0", config: &tls.Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := ListenDirectHTTPS(tc.address, tc.config)
			if err == nil {
				listener.Close()
				t.Fatal("ListenDirectHTTPS accepted an invalid policy")
			}
		})
	}
}

func TestListenDirectHTTPSRejectsNilConfigWithoutBinding(t *testing.T) {
	listener, err := ListenDirectHTTPS("127.0.0.1:0", nil)
	if err == nil || !strings.Contains(err.Error(), "TLS config is required") {
		t.Fatalf("ListenDirectHTTPS(nil) error = %v, want nil-config rejection", err)
	}
	if listener != nil {
		t.Fatalf("ListenDirectHTTPS(nil) returned listener %v", listener)
	}
}

func TestBindDirectHTTPSUsesOneReviewedHandlerAndListener(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	resolver := func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}

	handler, listener, err := BindDirectHTTPS(store, resolver, "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if handler == nil {
		t.Fatal("BindDirectHTTPS returned a nil handler")
	}
	if listener == nil {
		t.Fatal("BindDirectHTTPS returned a nil listener")
	}
	reviewedListener, ok := listener.(*reviewedDirectHTTPSListener)
	if !ok || reviewedListener.config == nil || handler.directTLSConfig != reviewedListener.config {
		t.Fatal("BindDirectHTTPS did not retain one private TLS snapshot for both handoffs")
	}
	if err := ValidateLoopbackListenAddress(listener.Addr().String()); err != nil {
		t.Fatalf("bound address %q is not reviewed loopback: %v", listener.Addr(), err)
	}
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if _, ok := accepted.(*tls.Conn); !ok {
		t.Fatalf("accepted connection type = %T, want *tls.Conn", accepted)
	}
	if config.MinVersion != tls.VersionTLS12 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatal("BindDirectHTTPS mutated the caller's TLS config")
	}
}

func TestBindDirectHTTPSReturnsNoListenerWhenHandlerConstructionFails(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	handler, listener, err := BindDirectHTTPS(nil, nil, "127.0.0.1:0", config)
	if err == nil {
		t.Fatal("BindDirectHTTPS accepted missing handler dependencies")
	}
	if handler != nil || listener != nil {
		t.Fatalf("failed binding returned handler=%v listener=%v", handler, listener)
	}
}

func TestCloneDirectTLSConfigSnapshotsReviewedCollections(t *testing.T) {
	certificate := tls.Certificate{
		Certificate:                  [][]byte{{1, 2, 3}},
		OCSPStaple:                   []byte{4, 5},
		SignedCertificateTimestamps:  [][]byte{{6, 7}},
		SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.PKCS1WithSHA256},
	}
	config := &tls.Config{
		MinVersion:        tls.VersionTLS12,
		MaxVersion:        tls.VersionTLS13,
		ClientAuth:        tls.RequireAnyClientCert,
		Certificates:      []tls.Certificate{certificate},
		NameToCertificate: map[string]*tls.Certificate{"relay.invalid": &certificate},
		NextProtos:        []string{"mcp"},
		CipherSuites:      []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		CurvePreferences:  []tls.CurveID{tls.CurveP256},
		ClientCAs:         x509.NewCertPool(),
	}
	config.NameToCertificate["relay.invalid"] = &config.Certificates[0]

	cloned, err := cloneDirectTLSConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if cloned == config || &cloned.Certificates[0] == &config.Certificates[0] {
		t.Fatal("TLS config snapshot retained caller-owned certificate storage")
	}
	if cloned.NameToCertificate["relay.invalid"] != &cloned.Certificates[0] {
		t.Fatal("TLS name mapping was not rebound to the snapshot")
	}
	if cloned.ClientCAs == config.ClientCAs {
		t.Fatal("TLS config snapshot retained caller-owned client CAs")
	}

	config.Certificates[0].Certificate[0][0] = 99
	config.Certificates[0].OCSPStaple[0] = 98
	config.Certificates[0].SignedCertificateTimestamps[0][0] = 97
	config.Certificates[0].SupportedSignatureAlgorithms[0] = tls.ECDSAWithSHA1
	config.NextProtos[0] = "mutated"
	config.CipherSuites[0] = tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
	config.CurvePreferences[0] = tls.X25519
	if cloned.Certificates[0].Certificate[0][0] == 99 ||
		cloned.Certificates[0].OCSPStaple[0] == 98 ||
		cloned.Certificates[0].SignedCertificateTimestamps[0][0] == 97 ||
		cloned.Certificates[0].SupportedSignatureAlgorithms[0] == tls.ECDSAWithSHA1 ||
		cloned.NextProtos[0] == "mutated" ||
		cloned.CipherSuites[0] == tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA ||
		cloned.CurvePreferences[0] == tls.X25519 {
		t.Fatal("TLS config snapshot retained mutable caller-owned collection data")
	}
}

func TestCloneDirectTLSConfigSnapshotsStandardPrivateKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{
			{PrivateKey: rsaKey},
			{PrivateKey: ecdsaKey},
			{PrivateKey: ed25519Key},
		},
	}

	cloned, err := cloneDirectTLSConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	clonedRSA, ok := cloned.Certificates[0].PrivateKey.(*rsa.PrivateKey)
	if !ok || clonedRSA == rsaKey {
		t.Fatal("RSA private key was not independently snapshotted")
	}
	clonedECDSA, ok := cloned.Certificates[1].PrivateKey.(*ecdsa.PrivateKey)
	if !ok || clonedECDSA == ecdsaKey {
		t.Fatal("ECDSA private key was not independently snapshotted")
	}
	clonedEd25519, ok := cloned.Certificates[2].PrivateKey.(ed25519.PrivateKey)
	if !ok || &clonedEd25519[0] == &ed25519Key[0] {
		t.Fatal("Ed25519 private key was not independently snapshotted")
	}

	rsaKey.D.SetInt64(1)
	ecdsaKey.D.SetInt64(1)
	ed25519Key[0] ^= 0xff
	if clonedRSA.D.Sign() == 0 || clonedRSA.D.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("RSA snapshot retained mutable caller key material")
	}
	if clonedECDSA.D.Sign() == 0 || clonedECDSA.D.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("ECDSA snapshot retained mutable caller key material")
	}
	if bytes.Equal([]byte(clonedEd25519), []byte(ed25519Key)) {
		t.Fatal("Ed25519 snapshot retained mutable caller key material")
	}
}

func TestValidateDirectTLSConfigRejectsNonSnapshotablePrivateKey(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{PrivateKey: nonSnapshotableTLSPrivateKey{}}},
	}
	if err := ValidateDirectTLSConfig(config); err == nil || !strings.Contains(err.Error(), "non-snapshotable") {
		t.Fatalf("ValidateDirectTLSConfig error = %v, want non-snapshotable private-key rejection", err)
	}
}

func TestValidateDirectTLSConfigContainsNestedValidationPanic(t *testing.T) {
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	err := validateDirectTLSConfigWith(config, func(*tls.Config) error {
		panic("malformed TLS certificate metadata")
	})
	if !errors.Is(err, ErrDirectTLSConfigInvalid) || !strings.Contains(err.Error(), "lifecycle TLS config validation failed") {
		t.Fatalf("validateDirectTLSConfigWith panic error = %v, want classified opaque validation failure", err)
	}
	if strings.Contains(err.Error(), "malformed TLS certificate metadata") {
		t.Fatalf("validation panic detail escaped boundary: %v", err)
	}
}

func TestValidateDirectTLSConfigChecksCertificateLeafPrivateKey(t *testing.T) {
	tests := []struct {
		name     string
		newKey   func() (crypto.Signer, error)
		cipher   uint16
		otherKey func() (crypto.Signer, error)
	}{
		{
			name: "RSA",
			newKey: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
			otherKey: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
			cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		{
			name: "ECDSA",
			newKey: func() (crypto.Signer, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
			otherKey: func() (crypto.Signer, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
			cipher: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leafKey, err := tc.newKey()
			if err != nil {
				t.Fatal(err)
			}
			otherKey, err := tc.otherKey()
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				NotBefore:             time.Unix(1, 0),
				NotAfter:              time.Unix(2_000_000_000, 0),
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageDigitalSignature,
				DNSNames:              []string{"relay.invalid"},
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, leafKey.Public(), leafKey)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			config := &tls.Config{
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS12,
				CipherSuites: []uint16{tc.cipher},
				Certificates: []tls.Certificate{{
					Certificate: [][]byte{der},
					PrivateKey:  otherKey,
					Leaf:        leaf,
				}},
			}
			if err := ValidateDirectTLSConfig(config); err == nil || !strings.Contains(err.Error(), "leaf/private-key mismatch") {
				t.Fatalf("ValidateDirectTLSConfig error = %v, want leaf/private-key mismatch", err)
			}

			config.Certificates[0].Leaf = nil
			if err := ValidateDirectTLSConfig(config); err == nil || !strings.Contains(err.Error(), "leaf/private-key mismatch") {
				t.Fatalf("ValidateDirectTLSConfig without optional Leaf error = %v, want leaf/private-key mismatch", err)
			}

			config.Certificates[0].PrivateKey = leafKey
			if err := ValidateDirectTLSConfig(config); err != nil {
				t.Fatalf("ValidateDirectTLSConfig rejected a matching DER leaf/private-key pair without optional Leaf: %v", err)
			}

			opaqueLeaf := *leaf
			opaqueLeaf.Raw = []byte{0x01, 0x02, 0x03}
			opaqueLeaf.RawTBSCertificate = []byte{0x01}
			config.Certificates[0] = tls.Certificate{
				Certificate: [][]byte{opaqueLeaf.Raw},
				PrivateKey:  leafKey,
				Leaf:        &opaqueLeaf,
			}
			if err := ValidateDirectTLSConfig(config); err == nil || !strings.Contains(err.Error(), "invalid certificate leaf") {
				t.Fatalf("ValidateDirectTLSConfig opaque DER error = %v, want invalid certificate leaf", err)
			}

			config.Certificates[0].Leaf = nil
			config.Certificates[0].Certificate = [][]byte{{0x30, 0x01, 0x00}}
			if err := ValidateDirectTLSConfig(config); err == nil || !strings.Contains(err.Error(), "invalid certificate leaf") {
				t.Fatalf("ValidateDirectTLSConfig malformed DER error = %v, want invalid certificate leaf", err)
			}

			config.Certificates[0].Certificate = [][]byte{der}
			if err := ValidateDirectTLSConfig(config); err != nil {
				t.Fatalf("ValidateDirectTLSConfig rejected matching %s leaf/private-key pair: %v", tc.name, err)
			}

			config.Certificates[0].Certificate = [][]byte{der, []byte{0x30, 0x01, 0x00}}
			if err := ValidateDirectTLSConfig(config); err == nil || !strings.Contains(err.Error(), "invalid certificate chain entry") {
				t.Fatalf("ValidateDirectTLSConfig malformed %s intermediate error = %v, want invalid certificate chain entry", tc.name, err)
			}
		})
	}
}

func TestCloneDirectTLSConfigDropsHiddenSessionTicketState(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	config.SetSessionTicketKeys([][32]byte{{1}})

	cloned, err := cloneDirectTLSConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	value := reflect.ValueOf(cloned).Elem()
	for _, fieldName := range []string{"sessionTicketKeys", "autoSessionTicketKeys"} {
		field := value.FieldByName(fieldName)
		if !field.IsValid() {
			t.Fatalf("tls.Config no longer exposes expected internal field %q", fieldName)
		}
		if field.Len() != 0 {
			t.Fatalf("TLS snapshot retained hidden %s state", fieldName)
		}
	}
}

func TestCloneDirectTLSConfigPreservesPresentEmptyPolicyVectors(t *testing.T) {
	config := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{{SupportedSignatureAlgorithms: []tls.SignatureScheme{}}},
		NextProtos:       []string{},
		CipherSuites:     []uint16{},
		CurvePreferences: []tls.CurveID{},
	}

	cloned, err := cloneDirectTLSConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if cloned.NextProtos == nil || cloned.CipherSuites == nil || cloned.CurvePreferences == nil || cloned.Certificates[0].SupportedSignatureAlgorithms == nil {
		t.Fatal("TLS snapshot collapsed present-empty policy vectors to nil")
	}
}

func TestCloneDirectTLSConfigRejectsOversizedPolicyBeforeSnapshot(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: make([]tls.Certificate, maxDirectTLSCertificateChains+1),
	}
	cloned, err := cloneDirectTLSConfig(config)
	if err == nil {
		t.Fatal("cloneDirectTLSConfig accepted an oversized certificate vector")
	}
	if cloned != nil {
		t.Fatalf("cloneDirectTLSConfig returned a snapshot after rejection: %v", cloned)
	}
}

func TestCloneDirectTLSConfigContainsSnapshotPanic(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	cloned, err := cloneDirectTLSConfigWith(config, func(*tls.Config) *tls.Config {
		panic("malformed TLS snapshot")
	})
	if cloned != nil {
		t.Fatalf("cloneDirectTLSConfigWith returned a snapshot after panic: %v", cloned)
	}
	if !errors.Is(err, ErrDirectTLSConfigInvalid) || !strings.Contains(err.Error(), "lifecycle TLS config snapshot failed") {
		t.Fatalf("cloneDirectTLSConfigWith panic error = %v, want classified opaque snapshot failure", err)
	}
	if strings.Contains(err.Error(), "malformed TLS snapshot") {
		t.Fatalf("snapshot panic detail escaped boundary: %v", err)
	}
}

func TestCloneDirectTLSConfigClassifiesSnapshotErrors(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	cloned, err := cloneDirectTLSConfigWith(config, func(*tls.Config) *tls.Config {
		return nil
	})
	if cloned != nil {
		t.Fatalf("cloneDirectTLSConfigWith returned a snapshot after nil clone: %v", cloned)
	}
	if !errors.Is(err, ErrDirectTLSConfigInvalid) || !strings.Contains(err.Error(), "lifecycle TLS config snapshot is nil") {
		t.Fatalf("cloneDirectTLSConfigWith error = %v, want classified nil snapshot failure", err)
	}
}

func TestBindDirectHTTPSRejectsNilConfigWithoutPartialBinding(t *testing.T) {
	handler, listener, err := BindDirectHTTPS(nil, nil, "127.0.0.1:0", nil)
	if err == nil || !strings.Contains(err.Error(), "TLS config is required") {
		t.Fatalf("BindDirectHTTPS(nil config) error = %v, want nil-config rejection", err)
	}
	if handler != nil || listener != nil {
		t.Fatalf("BindDirectHTTPS(nil config) returned handler=%v listener=%v", handler, listener)
	}
}

func TestBindDirectHTTPSReturnsNoBindingWhenListenFails(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	handler, listener, err := BindDirectHTTPS(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, occupied.Addr().String(), config)
	if err == nil {
		t.Fatal("BindDirectHTTPS succeeded on an occupied address")
	}
	if handler != nil || listener != nil {
		t.Fatalf("failed listen returned handler=%v listener=%v", handler, listener)
	}
}

func TestBindDirectHTTPSServerUsesBoundedReviewedHandoff(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	resolver := func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}

	server, listener, err := BindDirectHTTPSServer(store, resolver, "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if server == nil || server.Handler == nil {
		t.Fatalf("server handoff = %#v, want server with handler", server)
	}
	if _, ok := server.Handler.(*MCPHTTPHandler); !ok {
		t.Fatalf("server handler type = %T, want *MCPHTTPHandler", server.Handler)
	}
	if listener == nil {
		t.Fatal("server handoff returned nil listener")
	}
	if err := ValidateLoopbackListenAddress(listener.Addr().String()); err != nil {
		t.Fatalf("bound address %q is not reviewed loopback: %v", listener.Addr(), err)
	}
	if server.ReadHeaderTimeout != directHTTPSReadHeaderTimeout ||
		server.ReadTimeout != directHTTPSReadTimeout ||
		server.WriteTimeout != directHTTPSWriteTimeout ||
		server.IdleTimeout != directHTTPSIdleTimeout ||
		server.MaxHeaderBytes != directHTTPSMaxHeaderBytes {
		t.Fatalf("server resource limits = %#v, want reviewed defaults", server)
	}
	if config.MinVersion != tls.VersionTLS12 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatal("BindDirectHTTPSServer mutated the caller's TLS config")
	}
}

func TestBindDirectHTTPSServerReturnsNoPartialBinding(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	server, listener, err := BindDirectHTTPSServer(nil, nil, "127.0.0.1:0", config)
	if err == nil {
		t.Fatal("BindDirectHTTPSServer accepted missing handler dependencies")
	}
	if server != nil || listener != nil {
		t.Fatalf("failed server binding returned server=%v listener=%v", server, listener)
	}
}

func TestServeDirectHTTPSServerServesLoopbackTLSAndStopsByContext(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(leaf)
	serverName := "localhost"
	if len(leaf.DNSNames) > 0 {
		serverName = leaf.DNSNames[0]
	} else if len(leaf.IPAddresses) > 0 {
		serverName = leaf.IPAddresses[0].String()
	}

	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	server, listener, err := BindDirectHTTPSServer(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- ServeDirectHTTPSServer(ctx, server, listener)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: serverName,
	}}}
	request, err := http.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		cancel()
		listener.Close()
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		cancel()
		listener.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		cancel()
		listener.Close()
		t.Fatalf("served direct HTTPS status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	cancel()
	select {
	case err := <-serveResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ServeDirectHTTPSServer cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		listener.Close()
		t.Fatal("ServeDirectHTTPSServer did not stop after context cancellation")
	}
}

func TestServeDirectHTTPSServerReportsForcedShutdown(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(leaf)
	serverName := "localhost"
	if len(leaf.DNSNames) > 0 {
		serverName = leaf.DNSNames[0]
	} else if len(leaf.IPAddresses) > 0 {
		serverName = leaf.IPAddresses[0].String()
	}

	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	server, listener, err := BindDirectHTTPSServer(store, func(*http.Request) (Principal, error) {
		close(started)
		<-release
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- ServeDirectHTTPSServer(ctx, server, listener)
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: serverName,
	}}}
	request, err := http.NewRequest(http.MethodPost, "https://"+listener.Addr().String()+"/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	clientResult := make(chan error, 1)
	go func() {
		response, err := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
		clientResult <- err
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		close(release)
		cancel()
		t.Fatal("direct HTTPS request did not reach the blocking resolver")
	}
	cancel()

	select {
	case err := <-serveResult:
		if !errors.Is(err, ErrDirectHTTPSServeShutdownTimeout) {
			t.Fatalf("forced direct HTTPS shutdown error = %v, want timeout sentinel", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("forced direct HTTPS shutdown error = %v, want deadline cause", err)
		}
	case <-time.After(8 * time.Second):
		close(release)
		t.Fatal("ServeDirectHTTPSServer did not force-close the stalled request")
	}
	close(release)

	select {
	case <-clientResult:
	case <-time.After(2 * time.Second):
		t.Fatal("stalled direct HTTPS client did not finish after forced close")
	}
}

func TestServeDirectHTTPSServerReportsListenerCleanupWithoutTimeout(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	server, listener, err := BindDirectHTTPSServer(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	reviewed, ok := listener.(*reviewedDirectHTTPSListener)
	if !ok {
		listener.Close()
		t.Fatalf("listener type = %T, want reviewed listener", listener)
	}
	cleanupErr := errors.New("reviewed listener cleanup failed")
	delegate := &blockingCloseErrorListener{
		accepted: make(chan struct{}),
		closed:   make(chan struct{}),
		closeErr: cleanupErr,
	}
	reviewed.listener = delegate
	reviewed.expectedListener = delegate
	// This fixture substitutes an in-process listener solely to exercise
	// cleanup-error reporting; its synthetic :0 address is not the OS-bound
	// authority retained by the production constructor.
	reviewed.expectedHost = ""
	reviewed.expectedPort = ""
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- ServeDirectHTTPSServer(ctx, server, listener)
	}()

	select {
	case <-delegate.accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeDirectHTTPSServer did not enter listener Accept")
	}
	cancel()

	select {
	case err := <-serveResult:
		if !errors.Is(err, ErrDirectHTTPSListenerCleanup) {
			t.Fatalf("listener cleanup error = %v, want cleanup sentinel", err)
		}
		if !errors.Is(err, cleanupErr) {
			t.Fatalf("listener cleanup error = %v, want delegate error", err)
		}
		if errors.Is(err, ErrDirectHTTPSServeShutdownTimeout) {
			t.Fatalf("listener cleanup error = %v, must not be labeled shutdown timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeDirectHTTPSServer did not report listener cleanup")
	}
}

func TestAwaitDirectHTTPSServerOperationBoundsUncooperativeListenerWait(t *testing.T) {
	result := make(chan error, 1)
	deadline := time.Now().Add(20 * time.Millisecond)

	started := time.Now()
	if err, timedOut := awaitDirectHTTPSServerOperation(result, deadline); err != nil || !timedOut {
		t.Fatalf("awaitDirectHTTPSServerOperation() = (%v, %t), want (nil, true)", err, timedOut)
	}
	if elapsed := time.Since(started); elapsed < 15*time.Millisecond || elapsed > time.Second {
		t.Fatalf("awaitDirectHTTPSServerOperation elapsed %s, want bounded wait near 20ms", elapsed)
	}

	result <- context.Canceled
	if err, timedOut := awaitDirectHTTPSServerOperation(result, time.Now().Add(time.Second)); !errors.Is(err, context.Canceled) || timedOut {
		t.Fatalf("completed operation = (%v, %t), want context.Canceled, false", err, timedOut)
	}
}

func TestDirectHTTPSServerShutdownOperationsContainPanics(t *testing.T) {
	for _, test := range []struct {
		name string
		call func(*http.Server) error
	}{
		{name: "shutdown", call: func(server *http.Server) error {
			return invokeDirectHTTPSServerShutdown(server, context.Background())
		}},
		{name: "close", call: invokeDirectHTTPSServerClose},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call(nil)
			if !errors.Is(err, ErrDirectHTTPSServeShutdownPanic) {
				t.Fatalf("nil-server operation error = %v, want shutdown-panic sentinel", err)
			}
			if strings.Contains(err.Error(), "nil pointer") {
				t.Fatalf("panic detail escaped boundary: %v", err)
			}
		})
	}
}

func TestDirectHTTPSServeShutdownResultClassifiesOnlyActualTimeouts(t *testing.T) {
	shutdownErr := errors.New("shutdown failed")
	serveErr := errors.New("serve failed")
	for _, test := range []struct {
		name              string
		shutdownErr       error
		shutdownTimedOut  bool
		closeErr          error
		closeTimedOut     bool
		serveErr          error
		serveTimedOut     bool
		wantTimeout       bool
		wantDeadline      bool
		wantShutdownPanic bool
		wantClosePanic    bool
		wantShutdownError error
		wantCloseError    error
		wantServeError    error
	}{
		{
			name:              "shutdown panic is not timeout",
			shutdownErr:       ErrDirectHTTPSServeShutdownPanic,
			wantShutdownPanic: true,
		},
		{
			name:              "close panic is not timeout",
			shutdownErr:       shutdownErr,
			closeErr:          ErrDirectHTTPSServeShutdownPanic,
			wantClosePanic:    true,
			wantShutdownError: shutdownErr,
		},
		{
			name:           "deadline preserves operation causes",
			shutdownErr:    context.DeadlineExceeded,
			closeErr:       ErrDirectHTTPSServeShutdownPanic,
			serveErr:       serveErr,
			wantTimeout:    true,
			wantDeadline:   true,
			wantClosePanic: true,
			wantServeError: serveErr,
		},
		{
			name:          "operation timeout without error",
			shutdownErr:   shutdownErr,
			closeTimedOut: true,
			wantTimeout:   true,
			wantDeadline:  true,
		},
		{
			name:              "shutdown timeout preserves operation cause",
			shutdownErr:       shutdownErr,
			shutdownTimedOut:  true,
			wantTimeout:       true,
			wantDeadline:      true,
			wantShutdownError: shutdownErr,
		},
		{
			name:          "serve wait timeout preserves deadline cause",
			serveTimedOut: true,
			wantTimeout:   true,
			wantDeadline:  true,
		},
		{
			name:          "forced close timeout preserves deadline cause",
			closeErr:      errors.New("close failed"),
			closeTimedOut: true,
			wantTimeout:   true,
			wantDeadline:  true,
		},
		{
			name:              "server closed is ignored",
			shutdownErr:       shutdownErr,
			serveErr:          http.ErrServerClosed,
			wantShutdownError: shutdownErr,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := directHTTPSServeShutdownResult(test.shutdownErr, test.shutdownTimedOut, test.closeErr, test.closeTimedOut, test.serveErr, test.serveTimedOut)
			if (err != nil) != (test.wantTimeout || test.wantShutdownPanic || test.wantClosePanic || test.wantShutdownError != nil || test.wantCloseError != nil || test.wantServeError != nil) {
				t.Fatalf("directHTTPSServeShutdownResult() = %v, want error presence consistent with case", err)
			}
			if got := errors.Is(err, ErrDirectHTTPSServeShutdownTimeout); got != test.wantTimeout {
				t.Fatalf("timeout classification = %t, want %t: %v", got, test.wantTimeout, err)
			}
			if got := errors.Is(err, context.DeadlineExceeded); got != test.wantDeadline {
				t.Fatalf("deadline cause = %t, want %t: %v", got, test.wantDeadline, err)
			}
			if test.wantShutdownPanic && !errors.Is(err, ErrDirectHTTPSServeShutdownPanic) {
				t.Fatalf("shutdown panic = %v, want shutdown panic sentinel", err)
			}
			if test.wantClosePanic && !errors.Is(err, ErrDirectHTTPSServeShutdownPanic) {
				t.Fatalf("close panic = %v, want shutdown panic sentinel", err)
			}
			for _, want := range []error{test.wantShutdownError, test.wantCloseError, test.wantServeError} {
				if want != nil && !errors.Is(err, want) {
					t.Fatalf("result = %v, want cause %v", err, want)
				}
			}
		})
	}
}

func TestServeDirectHTTPSServerRejectsInvalidInputs(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{}
	for _, tc := range []struct {
		name     string
		ctx      context.Context
		server   *http.Server
		listener net.Listener
		wantErr  string
	}{
		{name: "nil context", server: server, listener: listener, wantErr: "context is invalid"},
		{name: "nil server", ctx: context.Background(), listener: listener, wantErr: "server is required"},
		{name: "nil listener", ctx: context.Background(), server: server, wantErr: "listener is required"},
		{name: "plaintext listener", ctx: context.Background(), server: server, listener: listener, wantErr: "reviewed TLS listener is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ServeDirectHTTPSServer(tc.ctx, tc.server, tc.listener); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ServeDirectHTTPSServer error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestServeDirectHTTPSServerRejectsMalformedContextBeforeBinding(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{}
	closed := make(chan struct{})
	close(closed)
	var typedNil *typedNilMCPContext
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		wantErr error
	}{
		{name: "literal nil", ctx: nil, wantErr: ErrDirectHTTPSServeContextInvalid},
		{name: "typed nil", ctx: typedNil, wantErr: ErrDirectHTTPSServeContextInvalid},
		{name: "panicking Err", ctx: panickingMCPContext{}, wantErr: ErrDirectHTTPSServeContextInvalid},
		{name: "panicking Done", ctx: panickingDoneMCPContext{}, wantErr: ErrDirectHTTPSServeContextInvalid},
		{name: "changing Done", ctx: changingDoneMCPContext{}, wantErr: ErrDirectHTTPSServeContextInvalid},
		{name: "closed Done with nil Err", ctx: closedDoneNilErrMCPContext{done: closed}, wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ServeDirectHTTPSServer(tc.ctx, server, listener)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ServeDirectHTTPSServer error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDirectHTTPSServeContextStateRechecksErrAfterNilDoneProbe(t *testing.T) {
	ctx := &serveErrAfterDoneProbeContext{}
	done, err := directHTTPSServeContextState(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("direct serving context error = %v, want context.Canceled", err)
	}
	if done != nil {
		t.Fatalf("direct serving Done channel = %v, want nil", done)
	}
	if ctx.inspections != 2 {
		t.Fatalf("context Err inspections = %d, want initial and post-Done checks", ctx.inspections)
	}
}

func TestReviewedDirectHTTPSListenerRejectsSelfReferentialDelegate(t *testing.T) {
	listener := &reviewedDirectHTTPSListener{}
	listener.listener = listener

	connection, err := listener.Accept()
	if !errors.Is(err, ErrDirectHTTPSListenerInvalid) {
		t.Fatalf("self-referential Accept error = %v, want invalid-listener sentinel", err)
	}
	if connection != nil {
		t.Fatal("self-referential Accept returned a connection")
	}
	if address := listener.Addr(); address != nil {
		t.Fatalf("self-referential Addr = %v, want nil", address)
	}
	if err := validateReviewedDirectHTTPSListener(listener); err == nil {
		t.Fatal("self-referential serving validation succeeded")
	}
}

func TestServeDirectHTTPSServerRejectsContextChannelReplacementBeforeServing(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	server, listener, err := BindDirectHTTPSServer(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx := &alternatingDoneMCPContext{
		first:  make(chan struct{}),
		second: make(chan struct{}),
	}
	err = ServeDirectHTTPSServer(ctx, server, listener)
	if !errors.Is(err, ErrDirectHTTPSServeContextInvalid) {
		t.Fatalf("ServeDirectHTTPSServer error = %v, want invalid-context sentinel", err)
	}
	handler, ok := server.Handler.(*MCPHTTPHandler)
	if !ok {
		t.Fatal("server handler was replaced")
	}
	handler.directServeMu.Lock()
	claimed := handler.directServing || handler.directServed
	handler.directServeMu.Unlock()
	if claimed {
		t.Fatal("replaced context channel claimed the serving binding")
	}
}

func TestServeDirectHTTPSServerCanonicalizesContextErrors(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{}
	secret := "context implementation detail"
	for _, tc := range []struct {
		name    string
		err     error
		wantErr error
	}{
		{name: "unexpected error", err: errors.New(secret), wantErr: ErrDirectHTTPSServeContextInvalid},
		{name: "wrapped cancellation", err: fmt.Errorf("wrapped context detail: %w", context.Canceled), wantErr: context.Canceled},
		{name: "wrapped deadline", err: fmt.Errorf("wrapped context detail: %w", context.DeadlineExceeded), wantErr: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ServeDirectHTTPSServer(nonCanonicalServeContext{err: tc.err}, server, listener)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ServeDirectHTTPSServer error = %v, want %v", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("ServeDirectHTTPSServer exposed context detail: %v", err)
			}
		})
	}
}

type nonCanonicalServeContext struct {
	err error
}

func (nonCanonicalServeContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (nonCanonicalServeContext) Done() <-chan struct{}       { return nil }
func (c nonCanonicalServeContext) Err() error                { return c.err }
func (nonCanonicalServeContext) Value(any) any               { return nil }

type serveErrAfterDoneProbeContext struct {
	inspections int
}

func (*serveErrAfterDoneProbeContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*serveErrAfterDoneProbeContext) Done() <-chan struct{}       { return nil }
func (c *serveErrAfterDoneProbeContext) Err() error {
	c.inspections++
	if c.inspections >= 2 {
		return context.Canceled
	}
	return nil
}
func (*serveErrAfterDoneProbeContext) Value(any) any { return nil }

type changingDoneMCPContext struct{}

func (changingDoneMCPContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (changingDoneMCPContext) Done() <-chan struct{}       { return make(chan struct{}) }
func (changingDoneMCPContext) Err() error                  { return nil }
func (changingDoneMCPContext) Value(any) any               { return nil }

type alternatingDoneMCPContext struct {
	first  <-chan struct{}
	second <-chan struct{}
	calls  atomic.Int32
}

func (*alternatingDoneMCPContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *alternatingDoneMCPContext) Done() <-chan struct{} {
	if c.calls.Add(1) <= 2 {
		return c.first
	}
	return c.second
}
func (*alternatingDoneMCPContext) Err() error    { return nil }
func (*alternatingDoneMCPContext) Value(any) any { return nil }

func TestServeDirectHTTPSServerRejectsReplacedHandlerBeforeServing(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	listener, err := ListenDirectHTTPS("127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	generic, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: generic}
	err = ServeDirectHTTPSServer(context.Background(), server, listener)
	if err == nil || !strings.Contains(err.Error(), "direct HTTPS handler is required") {
		t.Fatalf("ServeDirectHTTPSServer replaced-handler error = %v, want fail-closed handler rejection", err)
	}
}

func TestServeDirectHTTPSServerRejectsUnpairedDirectHandoffs(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	resolver := func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}
	handler, err := NewDirectHTTPSHandler(store, resolver, "127.0.0.1:8743", config)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ListenDirectHTTPS("127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: directHTTPSReadHeaderTimeout,
		ReadTimeout:       directHTTPSReadTimeout,
		WriteTimeout:      directHTTPSWriteTimeout,
		IdleTimeout:       directHTTPSIdleTimeout,
		MaxHeaderBytes:    directHTTPSMaxHeaderBytes,
	}
	err = ServeDirectHTTPSServer(context.Background(), server, listener)
	if err == nil || !strings.Contains(err.Error(), "server binding is required") {
		t.Fatalf("ServeDirectHTTPSServer unpaired handoff error = %v, want fail-closed pairing rejection", err)
	}
}

func TestServeDirectHTTPSServerRejectsMismatchedReviewedHandoffs(t *testing.T) {
	resolver := func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	storeA, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer storeA.Close()
	storeB, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer storeB.Close()
	serverA, listenerA, err := BindDirectHTTPSServer(storeA, resolver, "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listenerA.Close()
	serverB, listenerB, err := BindDirectHTTPSServer(storeB, resolver, "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listenerB.Close()

	if serverA == serverB || listenerA == listenerB {
		t.Fatal("test bindings unexpectedly share an object")
	}
	err = ServeDirectHTTPSServer(context.Background(), serverA, listenerB)
	if err == nil || !strings.Contains(err.Error(), "server binding is required") {
		t.Fatalf("ServeDirectHTTPSServer mismatched handoff error = %v, want fail-closed pairing rejection", err)
	}
}

func TestServeDirectHTTPSServerRejectsResourceLimitDriftBeforeServing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*http.Server)
	}{
		{name: "header timeout", mutate: func(server *http.Server) { server.ReadHeaderTimeout = 0 }},
		{name: "read timeout", mutate: func(server *http.Server) { server.ReadTimeout = 0 }},
		{name: "write timeout", mutate: func(server *http.Server) { server.WriteTimeout = 0 }},
		{name: "idle timeout", mutate: func(server *http.Server) { server.IdleTimeout = 0 }},
		{name: "header bytes", mutate: func(server *http.Server) { server.MaxHeaderBytes = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			config := &tls.Config{
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS13,
				CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			}
			server, listener, err := BindDirectHTTPSServer(store, func(*http.Request) (Principal, error) {
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, "127.0.0.1:0", config)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			tc.mutate(server)
			err = ServeDirectHTTPSServer(context.Background(), server, listener)
			if err == nil || !strings.Contains(err.Error(), "resource limits were changed") {
				t.Fatalf("ServeDirectHTTPSServer resource-drift error = %v, want fail-closed rejection", err)
			}
		})
	}
}

func TestServeDirectHTTPSServerRejectsExecutionPolicyDriftBeforeServing(t *testing.T) {
	protocols := http.Protocols{}
	for _, tc := range []struct {
		name   string
		mutate func(*http.Server)
	}{
		{name: "address", mutate: func(server *http.Server) { server.Addr = "127.0.0.1:0" }},
		{name: "general options", mutate: func(server *http.Server) { server.DisableGeneralOptionsHandler = true }},
		{name: "TLS config", mutate: func(server *http.Server) { server.TLSConfig = &tls.Config{} }},
		{name: "TLS protocol takeover", mutate: func(server *http.Server) {
			server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
		}},
		{name: "connection state hook", mutate: func(server *http.Server) {
			server.ConnState = func(net.Conn, http.ConnState) {}
		}},
		{name: "error logger", mutate: func(server *http.Server) {
			server.ErrorLog = log.New(io.Discard, "", 0)
		}},
		{name: "base context hook", mutate: func(server *http.Server) {
			server.BaseContext = func(net.Listener) context.Context { return context.Background() }
		}},
		{name: "connection context hook", mutate: func(server *http.Server) {
			server.ConnContext = func(ctx context.Context, _ net.Conn) context.Context { return ctx }
		}},
		{name: "HTTP2 policy", mutate: func(server *http.Server) { server.HTTP2 = &http.HTTP2Config{} }},
		{name: "protocol policy", mutate: func(server *http.Server) { server.Protocols = &protocols }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			config := &tls.Config{
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS13,
				CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			}
			server, listener, err := BindDirectHTTPSServer(store, func(*http.Request) (Principal, error) {
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, "127.0.0.1:0", config)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			tc.mutate(server)
			err = ServeDirectHTTPSServer(context.Background(), server, listener)
			if err == nil || !strings.Contains(err.Error(), "execution policy was changed") {
				t.Fatalf("ServeDirectHTTPSServer execution-policy error = %v, want fail-closed rejection", err)
			}
		})
	}
}

func TestServeDirectHTTPSServerEnforcesSingleUse(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	server, listener, err := BindDirectHTTPSServer(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}

	handler, ok := server.Handler.(*MCPHTTPHandler)
	if !ok {
		listener.Close()
		t.Fatalf("server handler type = %T, want *MCPHTTPHandler", server.Handler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- ServeDirectHTTPSServer(ctx, server, listener)
	}()

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		handler.directServeMu.Lock()
		serving := handler.directServing
		handler.directServeMu.Unlock()
		if serving {
			break
		}
		select {
		case <-deadline.C:
			listener.Close()
			t.Fatal("ServeDirectHTTPSServer did not claim the binding")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	if err := ServeDirectHTTPSServer(context.Background(), server, listener); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("concurrent ServeDirectHTTPSServer error = %v, want single-use rejection", err)
	}
	cancel()
	select {
	case err := <-serveResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ServeDirectHTTPSServer cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		listener.Close()
		t.Fatal("ServeDirectHTTPSServer did not stop after context cancellation")
	}
	if err := ServeDirectHTTPSServer(context.Background(), server, listener); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("reused ServeDirectHTTPSServer error = %v, want single-use rejection", err)
	}
}

func TestServeDirectHTTPSServerContainsListenerPanic(t *testing.T) {
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	err := invokeDirectHTTPSServe(server, panicListener{})
	if !errors.Is(err, ErrDirectHTTPSServePanic) {
		t.Fatalf("listener panic error = %v, want opaque serve-panic error", err)
	}
	if strings.Contains(err.Error(), "listener panic") {
		t.Fatalf("listener panic detail escaped boundary: %v", err)
	}
}

func TestReviewedDirectHTTPSListenerRejectsNilDelegate(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func() *reviewedDirectHTTPSListener
	}{
		{name: "nil receiver", make: func() *reviewedDirectHTTPSListener { return nil }},
		{name: "nil delegate", make: func() *reviewedDirectHTTPSListener { return &reviewedDirectHTTPSListener{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener := tc.make()
			if _, err := listener.Accept(); !errors.Is(err, errDirectHTTPSListenerInvalid) {
				t.Fatalf("Accept error = %v, want invalid-listener sentinel", err)
			}
			if err := listener.Close(); !errors.Is(err, errDirectHTTPSListenerInvalid) {
				t.Fatalf("Close error = %v, want invalid-listener sentinel", err)
			}
			if addr := listener.Addr(); addr != nil {
				t.Fatalf("Addr = %v, want nil for invalid listener", addr)
			}
		})
	}
}

func TestReviewedDirectHTTPSListenerContainsAcceptPanic(t *testing.T) {
	listener := &reviewedDirectHTTPSListener{listener: panicListener{}}
	if connection, err := listener.Accept(); connection != nil || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept result = (%v, %v), want nil connection and invalid-listener sentinel", connection, err)
	}
}

func TestReviewedDirectHTTPSListenerRejectsPlaintextConnection(t *testing.T) {
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	listener := &reviewedDirectHTTPSListener{listener: oneConnectionListener{
		connection: serverConnection,
		address:    fixedAddr("127.0.0.1:0"),
	}}
	if connection, err := listener.Accept(); connection != nil || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept result = (%v, %v), want nil connection and invalid-listener sentinel", connection, err)
	}
}

func TestReviewedDirectHTTPSListenerCleansDelegateAfterMalformedAccept(t *testing.T) {
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	closeCalls := 0
	delegate := &malformedAcceptListener{
		connection: serverConnection,
		closeCalls: &closeCalls,
		address:    fixedAddr("127.0.0.1:0"),
	}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

	if connection, err := listener.Accept(); connection != nil || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept result = (%v, %v), want nil connection and invalid-listener sentinel", connection, err)
	}
	if closeCalls != 1 {
		t.Fatalf("delegate Close calls after malformed Accept = %d, want one", closeCalls)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("Close after malformed Accept error = %v, want nil", err)
	}
	if closeCalls != 1 {
		t.Fatalf("delegate Close calls after cleanup retry = %d, want one", closeCalls)
	}
}

func TestReviewedDirectHTTPSListenerRejectsNilConnectionAndCleansDelegate(t *testing.T) {
	closeErr := errors.New("approved delegate close failed after nil connection")
	delegate := &nilConnectionListener{closeErr: closeErr, address: fixedAddr("127.0.0.1:0")}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

	connection, err := listener.Accept()
	if connection != nil {
		t.Fatalf("Accept connection = %v, want nil", connection)
	}
	if !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept error = %v, want invalid-listener sentinel", err)
	}
	if !errors.Is(err, ErrDirectHTTPSListenerCleanup) || !errors.Is(err, closeErr) {
		t.Fatalf("Accept error = %v, want opaque cleanup and delegate causes", err)
	}
	if delegate.closeCalls != 1 {
		t.Fatalf("delegate Close calls after nil connection = %d, want one", delegate.closeCalls)
	}
	if err := listener.Close(); !errors.Is(err, ErrDirectHTTPSListenerCleanup) || !errors.Is(err, closeErr) {
		t.Fatalf("cleanup retry error = %v, want the same cleanup evidence", err)
	}
	if delegate.closeCalls != 1 {
		t.Fatalf("delegate Close calls after cleanup retry = %d, want one", delegate.closeCalls)
	}
}

func TestReviewedDirectHTTPSListenerRejectsConnectionAndErrorTogether(t *testing.T) {
	acceptErr := errors.New("malformed accept detail")
	connectionCloseCalls := 0
	delegateCloseCalls := 0
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	delegate := &malformedAcceptErrorListener{
		connection: &countingConn{Conn: serverConnection, closeCalls: &connectionCloseCalls},
		closeCalls: &delegateCloseCalls,
		err:        acceptErr,
		address:    fixedAddr("127.0.0.1:0"),
	}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

	connection, err := listener.Accept()
	if connection != nil {
		t.Fatalf("Accept connection = %v, want nil", connection)
	}
	if !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept error = %v, want invalid-listener sentinel", err)
	}
	if errors.Is(err, acceptErr) || strings.Contains(err.Error(), "malformed accept detail") {
		t.Fatalf("malformed Accept detail escaped boundary: %v", err)
	}
	if connectionCloseCalls != 1 {
		t.Fatalf("returned connection Close calls = %d, want one", connectionCloseCalls)
	}
	if delegateCloseCalls != 1 {
		t.Fatalf("reviewed delegate Close calls = %d, want one", delegateCloseCalls)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("cleanup retry error = %v, want nil", err)
	}
	if delegateCloseCalls != 1 {
		t.Fatalf("reviewed delegate Close calls after cleanup retry = %d, want one", delegateCloseCalls)
	}
}

func TestReviewedDirectHTTPSListenerPreservesAcceptedConnectionCleanupFailure(t *testing.T) {
	acceptErr := errors.New("malformed accept detail")
	connectionCloseErr := errors.New("accepted connection close failed")
	delegateCloseCalls := 0
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	delegate := &malformedAcceptErrorListener{
		connection: &errorCloseConn{Conn: serverConnection, err: connectionCloseErr},
		closeCalls: &delegateCloseCalls,
		err:        acceptErr,
		address:    fixedAddr("127.0.0.1:0"),
	}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

	connection, err := listener.Accept()
	if connection != nil {
		t.Fatalf("Accept connection = %v, want nil", connection)
	}
	if !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept error = %v, want invalid-listener sentinel", err)
	}
	if !errors.Is(err, ErrDirectHTTPSListenerCleanup) || !errors.Is(err, connectionCloseErr) {
		t.Fatalf("Accept error = %v, want accepted-connection cleanup evidence", err)
	}
	if errors.Is(err, acceptErr) || strings.Contains(err.Error(), "malformed accept detail") {
		t.Fatalf("malformed Accept detail escaped boundary: %v", err)
	}
	if delegateCloseCalls != 1 {
		t.Fatalf("reviewed delegate Close calls = %d, want one", delegateCloseCalls)
	}
}

func TestReviewedDirectHTTPSListenerContainsAcceptedConnectionClosePanic(t *testing.T) {
	acceptErr := errors.New("malformed accept detail")
	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	delegateCloseCalls := 0
	delegate := &malformedAcceptErrorListener{
		connection: &panicCloseConn{Conn: serverConnection},
		closeCalls: &delegateCloseCalls,
		err:        acceptErr,
		address:    fixedAddr("127.0.0.1:0"),
	}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

	connection, err := listener.Accept()
	if connection != nil {
		t.Fatalf("Accept connection = %v, want nil", connection)
	}
	if !errors.Is(err, ErrDirectHTTPSListenerCleanup) || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept error = %v, want opaque cleanup classification", err)
	}
	if strings.Contains(err.Error(), "accepted connection close detail") || errors.Is(err, acceptErr) {
		t.Fatalf("connection-close panic or malformed Accept detail escaped boundary: %v", err)
	}
	if delegateCloseCalls != 1 {
		t.Fatalf("reviewed delegate Close calls = %d, want one", delegateCloseCalls)
	}
}

func TestReviewedDirectHTTPSListenerCleansDelegateAfterAcceptPanic(t *testing.T) {
	closeErr := errors.New("panic delegate close failed")
	delegate := &panicAcceptListener{closeErr: closeErr, address: fixedAddr("127.0.0.1:0")}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

	if connection, err := listener.Accept(); connection != nil || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept result = (%v, %v), want invalid-listener sentinel", connection, err)
	} else {
		if !errors.Is(err, ErrDirectHTTPSListenerCleanup) {
			t.Fatalf("Accept cleanup error = %v, want cleanup sentinel", err)
		}
		if !errors.Is(err, closeErr) {
			t.Fatalf("Accept cleanup error = %v, want delegate close error", err)
		}
	}
	if delegate.closeCalls != 1 {
		t.Fatalf("delegate Close calls after Accept panic = %d, want one", delegate.closeCalls)
	}
}

func TestReviewedDirectHTTPSListenerRejectsTLSConnectionWithoutUnderlying(t *testing.T) {
	listener := &reviewedDirectHTTPSListener{listener: oneConnectionListener{
		connection: tls.Server(nil, &tls.Config{}),
		address:    fixedAddr("127.0.0.1:0"),
	}}
	if connection, err := listener.Accept(); connection != nil || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept result = (%v, %v), want nil connection and invalid-listener sentinel", connection, err)
	}
}

func TestReviewedDirectHTTPSListenerRejectsTLSConnectionWithNonLoopbackLocalAddress(t *testing.T) {
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	connection := tls.Server(addressedConn{
		Conn:      serverConnection,
		localAddr: fixedAddr("192.0.2.1:443"),
	}, &tls.Config{})
	listener := &reviewedDirectHTTPSListener{listener: oneConnectionListener{
		connection: connection,
		address:    fixedAddr("127.0.0.1:0"),
	}}
	if accepted, err := listener.Accept(); accepted != nil || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept result = (%v, %v), want nil connection and invalid-listener sentinel", accepted, err)
	}
}

func TestReviewedDirectHTTPSListenerRejectsReplacedDelegateBeforeAccept(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	listener, err := ListenDirectHTTPS("127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	reviewed, ok := listener.(*reviewedDirectHTTPSListener)
	if !ok {
		listener.Close()
		t.Fatalf("listener type = %T, want reviewed listener", listener)
	}
	defer reviewed.expectedListener.Close()

	accepts := 0
	reviewed.listener = countingAcceptListener{count: &accepts, address: fixedAddr("127.0.0.1:0")}
	if connection, err := reviewed.Accept(); connection != nil || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept result = (%v, %v), want nil connection and invalid-listener sentinel", connection, err)
	}
	if accepts != 0 {
		t.Fatalf("replacement delegate Accept calls = %d, want 0", accepts)
	}
}

func TestReviewedDirectHTTPSListenerClosesReviewedDelegateAfterReplacement(t *testing.T) {
	closeCalls := 0
	reviewedDelegate := &trackingListener{closeCalls: &closeCalls, address: fixedAddr("127.0.0.1:0")}
	replacementAccepts := 0
	listener := &reviewedDirectHTTPSListener{
		listener:         countingAcceptListener{count: &replacementAccepts, address: fixedAddr("127.0.0.1:0")},
		expectedListener: reviewedDelegate,
	}
	if connection, err := listener.Accept(); connection != nil || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept result = (%v, %v), want nil connection and invalid-listener sentinel", connection, err)
	}
	if replacementAccepts != 0 {
		t.Fatalf("replacement delegate Accept calls = %d, want 0", replacementAccepts)
	}
	if closeCalls != 1 {
		t.Fatalf("reviewed delegate Close calls = %d, want 1", closeCalls)
	}
	if err := listener.Close(); !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Close after replacement error = %v, want invalid-listener sentinel", err)
	}
	if closeCalls != 1 {
		t.Fatalf("reviewed delegate Close calls after cleanup retry = %d, want 1", closeCalls)
	}
}

func TestReviewedDirectHTTPSListenerAddrCleansReviewedDelegateAfterReplacement(t *testing.T) {
	reviewedCloseCalls := 0
	reviewedDelegate := &trackingListener{closeCalls: &reviewedCloseCalls, address: fixedAddr("127.0.0.1:0")}
	replacementCloseCalls := 0
	listener := &reviewedDirectHTTPSListener{
		listener:         &trackingListener{closeCalls: &replacementCloseCalls, address: fixedAddr("127.0.0.1:0")},
		expectedListener: reviewedDelegate,
	}

	if address := listener.Addr(); address != nil {
		t.Fatalf("Addr after replacement = %v, want nil", address)
	}
	if reviewedCloseCalls != 1 {
		t.Fatalf("reviewed delegate Close calls after Addr = %d, want 1", reviewedCloseCalls)
	}
	if replacementCloseCalls != 0 {
		t.Fatalf("replacement delegate Close calls after Addr = %d, want 0", replacementCloseCalls)
	}
	if err := listener.Close(); !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Close after replacement Addr error = %v, want invalid-listener result", err)
	}
	if reviewedCloseCalls != 1 {
		t.Fatalf("reviewed delegate Close calls after cleanup retry = %d, want 1", reviewedCloseCalls)
	}
}

func TestReviewedDirectHTTPSListenerReportsCleanupFailureAfterReplacement(t *testing.T) {
	cleanupErr := errors.New("reviewed delegate close failed")
	reviewedDelegate := &errorCloseListener{err: cleanupErr, address: fixedAddr("127.0.0.1:0")}
	replacementAccepts := 0
	listener := &reviewedDirectHTTPSListener{
		listener:         countingAcceptListener{count: &replacementAccepts, address: fixedAddr("127.0.0.1:0")},
		expectedListener: reviewedDelegate,
	}

	if connection, err := listener.Accept(); connection != nil || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept result = (%v, %v), want invalid-listener result", connection, err)
	} else {
		if !errors.Is(err, ErrDirectHTTPSListenerCleanup) {
			t.Fatalf("Accept cleanup error = %v, want cleanup sentinel", err)
		}
		if !errors.Is(err, cleanupErr) {
			t.Fatalf("Accept cleanup error = %v, want delegate error", err)
		}
	}
	if replacementAccepts != 0 {
		t.Fatalf("replacement delegate Accept calls = %d, want 0", replacementAccepts)
	}
	if err := listener.Close(); !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Close after replacement error = %v, want invalid-listener result", err)
	} else {
		if !errors.Is(err, ErrDirectHTTPSListenerCleanup) {
			t.Fatalf("Close cleanup error = %v, want cleanup sentinel", err)
		}
		if !errors.Is(err, cleanupErr) {
			t.Fatalf("Close cleanup error = %v, want same delegate error", err)
		}
	}
}

func TestReviewedDirectHTTPSListenerCloseCleansReviewedDelegateOnce(t *testing.T) {
	reviewedCloseCalls := 0
	replacementCloseCalls := 0
	listener := &reviewedDirectHTTPSListener{
		listener:         &trackingListener{closeCalls: &replacementCloseCalls, address: fixedAddr("127.0.0.1:0")},
		expectedListener: &trackingListener{closeCalls: &reviewedCloseCalls, address: fixedAddr("127.0.0.1:0")},
	}
	if err := listener.Close(); !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Close error = %v, want invalid-listener sentinel", err)
	}
	if err := listener.Close(); !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("repeated Close error = %v, want invalid-listener sentinel", err)
	}
	if reviewedCloseCalls != 1 {
		t.Fatalf("reviewed delegate Close calls = %d, want 1", reviewedCloseCalls)
	}
	if replacementCloseCalls != 0 {
		t.Fatalf("replacement delegate Close calls = %d, want 0", replacementCloseCalls)
	}
}

func TestReviewedDirectHTTPSListenerNormalCloseDoesNotRepeatAfterReplacement(t *testing.T) {
	reviewedCloseCalls := 0
	reviewedDelegate := &trackingListener{closeCalls: &reviewedCloseCalls, address: fixedAddr("127.0.0.1:0")}
	replacementCloseCalls := 0
	listener := &reviewedDirectHTTPSListener{
		listener:         reviewedDelegate,
		expectedListener: reviewedDelegate,
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("normal Close error = %v, want nil", err)
	}
	listener.listener = &trackingListener{closeCalls: &replacementCloseCalls, address: fixedAddr("127.0.0.1:0")}
	if err := listener.Close(); !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Close after replacement error = %v, want invalid-listener sentinel", err)
	}
	if reviewedCloseCalls != 1 {
		t.Fatalf("reviewed delegate Close calls = %d, want 1", reviewedCloseCalls)
	}
	if replacementCloseCalls != 0 {
		t.Fatalf("replacement delegate Close calls = %d, want 0", replacementCloseCalls)
	}
}

func TestReviewedDirectHTTPSListenerNormalCloseIsIdempotent(t *testing.T) {
	closeCalls := 0
	delegate := &trackingListener{closeCalls: &closeCalls, address: fixedAddr("127.0.0.1:0")}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}
	if err := listener.Close(); err != nil {
		t.Fatalf("first Close error = %v, want nil", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("repeated Close error = %v, want nil", err)
	}
	if closeCalls != 1 {
		t.Fatalf("delegate Close calls = %d, want 1", closeCalls)
	}
}

func TestReviewedDirectHTTPSListenerConcurrentCloseWaitsForResult(t *testing.T) {
	closeStarted := make(chan struct{})
	allowClose := make(chan struct{})
	closeErr := errors.New("delegate close failed")
	delegate := &blockingCloseListener{
		closeStarted: closeStarted,
		allowClose:   allowClose,
		err:          closeErr,
	}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

	firstResult := make(chan error, 1)
	go func() { firstResult <- listener.Close() }()
	<-closeStarted

	secondResult := make(chan error, 1)
	go func() { secondResult <- listener.Close() }()
	select {
	case err := <-secondResult:
		t.Fatalf("concurrent Close returned before delegate completion: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(allowClose)
	if err := <-firstResult; !errors.Is(err, closeErr) {
		t.Fatalf("first Close error = %v, want delegate error", err)
	}
	if err := <-secondResult; !errors.Is(err, closeErr) {
		t.Fatalf("concurrent Close error = %v, want same delegate error", err)
	}
	if calls := delegate.closeCalls.Load(); calls != 1 {
		t.Fatalf("delegate Close calls = %d, want one", calls)
	}
}

func TestReviewedDirectHTTPSListenerRejectsNonComparableDelegateIdentity(t *testing.T) {
	listener := &reviewedDirectHTTPSListener{
		listener:         nonComparableListener{marker: []byte("replacement")},
		expectedListener: nonComparableListener{marker: []byte("reviewed")},
	}
	if connection, err := listener.Accept(); connection != nil || !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Accept result = (%v, %v), want nil connection and invalid-listener sentinel", connection, err)
	}
}

func TestReviewedDirectHTTPSListenerContainsClosePanic(t *testing.T) {
	listener := &reviewedDirectHTTPSListener{listener: panicCloseListener{}}
	if err := listener.Close(); !errors.Is(err, errDirectHTTPSListenerInvalid) {
		t.Fatalf("Close error = %v, want invalid-listener sentinel", err)
	}
	if err := listener.Close(); !errors.Is(err, ErrDirectHTTPSListenerCleanup) {
		t.Fatalf("repeated Close error = %v, want cleanup sentinel", err)
	}
}

func TestReviewedDirectHTTPSListenerContainsAddrPanic(t *testing.T) {
	listener := &reviewedDirectHTTPSListener{listener: panicAddrListener{}}
	if addr := listener.Addr(); addr != nil {
		t.Fatalf("Addr = %v, want nil after delegate panic", addr)
	}
}

func TestReviewedDirectHTTPSListenerCleansDelegateAfterAddrPanic(t *testing.T) {
	cleanupErr := errors.New("reviewed delegate close failed after address panic")
	delegate := &panicAddrCloseListener{closeErr: cleanupErr, address: fixedAddr("127.0.0.1:0")}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

	if address := listener.Addr(); address != nil {
		t.Fatalf("Addr = %v, want nil after delegate panic", address)
	}
	if delegate.closeCalls != 1 {
		t.Fatalf("delegate Close calls after Addr panic = %d, want one", delegate.closeCalls)
	}
	if err := listener.Close(); !errors.Is(err, ErrDirectHTTPSListenerCleanup) {
		t.Fatalf("Close after Addr panic error = %v, want cleanup sentinel", err)
	} else if !errors.Is(err, cleanupErr) {
		t.Fatalf("Close after Addr panic error = %v, want delegate close error", err)
	}
}

func TestReviewedDirectHTTPSListenerRejectsMalformedAddrAndCleansDelegate(t *testing.T) {
	tests := []struct {
		name    string
		address net.Addr
	}{
		{name: "nil address", address: nil},
		{name: "typed nil address", address: (*fixedAddr)(nil)},
		{name: "public address", address: fixedAddr("192.0.2.1:443")},
		{name: "malformed address", address: fixedAddr("not-an-endpoint")},
		{name: "panicking address string", address: panicStringAddr{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closeCalls := 0
			delegate := &trackingListener{closeCalls: &closeCalls, address: test.address}
			listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

			if address := listener.Addr(); address != nil {
				t.Fatalf("Addr = %v, want nil for malformed live address", address)
			}
			if closeCalls != 1 {
				t.Fatalf("delegate Close calls after Addr = %d, want one", closeCalls)
			}
			if err := listener.Close(); err != nil {
				t.Fatalf("cleanup retry error = %v, want idempotent success", err)
			}
			if closeCalls != 1 {
				t.Fatalf("delegate Close calls after cleanup retry = %d, want one", closeCalls)
			}
		})
	}
}

func TestReviewedDirectHTTPSListenerAddrPreservesCleanupFailure(t *testing.T) {
	cleanupErr := errors.New("approved delegate close failed after malformed address")
	delegate := &errorCloseListener{err: cleanupErr, address: fixedAddr("192.0.2.1:443")}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

	if address := listener.Addr(); address != nil {
		t.Fatalf("Addr = %v, want nil after invalid address", address)
	}
	if err := listener.Close(); !errors.Is(err, ErrDirectHTTPSListenerCleanup) {
		t.Fatalf("Close after Addr = %v, want cleanup sentinel", err)
	} else if !errors.Is(err, cleanupErr) {
		t.Fatalf("Close after Addr = %v, want delegate close error", err)
	}
}

func TestReviewedDirectHTTPSListenerCleansDelegateAfterNilReplacement(t *testing.T) {
	tests := []struct {
		name    string
		call    func(*reviewedDirectHTTPSListener) error
		wantErr func(error) bool
	}{
		{name: "Accept", call: func(listener *reviewedDirectHTTPSListener) error {
			_, err := listener.Accept()
			return err
		}, wantErr: func(err error) bool { return errors.Is(err, errDirectHTTPSListenerInvalid) }},
		{name: "Addr", call: func(listener *reviewedDirectHTTPSListener) error {
			if address := listener.Addr(); address != nil {
				return fmt.Errorf("Addr = %v, want nil", address)
			}
			return nil
		}, wantErr: func(err error) bool { return err == nil }},
		{name: "Close", call: func(listener *reviewedDirectHTTPSListener) error {
			return listener.Close()
		}, wantErr: func(err error) bool { return errors.Is(err, errDirectHTTPSListenerInvalid) }},
		{name: "serving validation", call: validateReviewedDirectHTTPSListener,
			wantErr: func(err error) bool { return strings.Contains(err.Error(), "delegate was replaced") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closeCalls := 0
			reviewedDelegate := &trackingListener{closeCalls: &closeCalls, address: fixedAddr("127.0.0.1:0")}
			listener := &reviewedDirectHTTPSListener{expectedListener: reviewedDelegate}

			if err := test.call(listener); !test.wantErr(err) {
				t.Fatalf("%s error = %v, want contract-specific result", test.name, err)
			}
			if closeCalls != 1 {
				t.Fatalf("reviewed delegate Close calls after %s = %d, want one", test.name, closeCalls)
			}
			if err := listener.Close(); !errors.Is(err, errDirectHTTPSListenerInvalid) {
				t.Fatalf("cleanup retry error = %v, want invalid-listener sentinel", err)
			}
			if closeCalls != 1 {
				t.Fatalf("reviewed delegate Close calls after cleanup retry = %d, want one", closeCalls)
			}
		})
	}
}

func TestServeDirectHTTPSServerRejectsMalformedLiveListenerAddress(t *testing.T) {
	for _, tc := range []struct {
		name     string
		listener net.Listener
		wantText string
	}{
		{name: "nil address", listener: nilAddrListener{}, wantText: "loopback listener address is required"},
		{name: "typed nil address", listener: typedNilAddrListener{}, wantText: "loopback listener address is required"},
		{name: "public address", listener: fixedAddrListener{address: fixedAddr("192.0.2.1:443")}, wantText: "loopback listener address is invalid"},
		{name: "panicking address string", listener: fixedAddrListener{address: panicStringAddr{}}, wantText: "loopback listener address is invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			config := &tls.Config{
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS13,
				CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			}
			server, listener, err := BindDirectHTTPSServer(store, func(*http.Request) (Principal, error) {
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, "127.0.0.1:0", config)
			if err != nil {
				t.Fatal(err)
			}
			reviewed, ok := listener.(*reviewedDirectHTTPSListener)
			if !ok {
				listener.Close()
				t.Fatalf("listener type = %T, want reviewed listener", listener)
			}
			// Disable construction provenance so this table exercises the
			// lower-level live-address validator rather than replacement
			// rejection, which has dedicated coverage above.
			reviewed.expectedListener = nil
			reviewed.listener = tc.listener
			defer listener.Close()

			err = ServeDirectHTTPSServer(context.Background(), server, listener)
			if err == nil || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("ServeDirectHTTPSServer error = %v, want %q", err, tc.wantText)
			}
			handler, ok := server.Handler.(*MCPHTTPHandler)
			if !ok {
				t.Fatal("server handler was replaced")
			}
			handler.directServeMu.Lock()
			claimed := handler.directServing || handler.directServed
			handler.directServeMu.Unlock()
			if claimed {
				t.Fatal("malformed listener address claimed the serving binding")
			}
		})
	}
}

func TestServeDirectHTTPSServerRevalidatesListenerBeforeServe(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	server, listener, err := BindDirectHTTPSServer(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	reviewed, ok := listener.(*reviewedDirectHTTPSListener)
	if !ok {
		t.Fatalf("listener type = %T, want reviewed listener", listener)
	}
	if err := reviewed.expectedListener.Close(); err != nil {
		t.Fatalf("close construction listener before seam replacement: %v", err)
	}
	delegate := &flippingAddrListener{}
	reviewed.listener = delegate
	reviewed.expectedListener = delegate
	// This fixture deliberately exercises the lower-level live-address
	// revalidation with a synthetic :0-to-public drift. The construction-time
	// exact bound-authority contract has dedicated coverage below.
	reviewed.expectedHost = ""
	reviewed.expectedPort = ""

	err = ServeDirectHTTPSServer(context.Background(), server, listener)
	if err == nil || !strings.Contains(err.Error(), "loopback listener address is invalid") {
		t.Fatalf("ServeDirectHTTPSServer error = %v, want final live-address rejection", err)
	}
	if calls := delegate.addrCalls.Load(); calls != 2 {
		t.Fatalf("delegate Addr calls = %d, want initial and final validation", calls)
	}
	if calls := delegate.closeCalls.Load(); calls != 1 {
		t.Fatalf("delegate Close calls = %d, want one cleanup", calls)
	}
	handler, ok := server.Handler.(*MCPHTTPHandler)
	if !ok {
		t.Fatal("server handler was replaced")
	}
	handler.directServeMu.Lock()
	claimed := handler.directServing || handler.directServed
	handler.directServeMu.Unlock()
	if claimed {
		t.Fatal("final live-address drift claimed the serving binding")
	}
}

func TestValidateReviewedDirectHTTPSListenerCleansApprovedDelegateAfterAddressFailure(t *testing.T) {
	tests := []struct {
		name    string
		address net.Addr
	}{
		{name: "nil address", address: nil},
		{name: "typed nil address", address: (*fixedAddr)(nil)},
		{name: "public address", address: fixedAddr("192.0.2.1:443")},
		{name: "malformed address", address: fixedAddr("not-an-endpoint")},
		{name: "panicking address string", address: panicStringAddr{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closeCalls := 0
			delegate := &trackingListener{closeCalls: &closeCalls, address: test.address}
			listener := &reviewedDirectHTTPSListener{
				listener:         delegate,
				expectedListener: delegate,
			}

			err := validateReviewedDirectHTTPSListener(listener)
			if err == nil {
				t.Fatal("validateReviewedDirectHTTPSListener returned nil for invalid address")
			}
			if closeCalls != 1 {
				t.Fatalf("approved delegate Close calls = %d, want one", closeCalls)
			}
			if err := listener.Close(); err != nil {
				t.Fatalf("cleanup retry error = %v, want idempotent success", err)
			}
			if closeCalls != 1 {
				t.Fatalf("approved delegate Close calls after cleanup retry = %d, want one", closeCalls)
			}
		})
	}
}

func TestValidateReviewedDirectHTTPSListenerPreservesAddressCleanupFailure(t *testing.T) {
	cleanupErr := errors.New("approved delegate close failed after address rejection")
	delegate := &errorCloseListener{err: cleanupErr, address: fixedAddr("192.0.2.1:443")}
	listener := &reviewedDirectHTTPSListener{listener: delegate, expectedListener: delegate}

	err := validateReviewedDirectHTTPSListener(listener)
	if err == nil || !errors.Is(err, ErrDirectHTTPSListenerCleanup) || !errors.Is(err, cleanupErr) {
		t.Fatalf("address validation error = %v, want cleanup and delegate causes", err)
	}
}

func TestValidateReviewedDirectHTTPSListenerRejectsBoundAuthorityDrift(t *testing.T) {
	closeCalls := 0
	delegate := &trackingListener{
		closeCalls: &closeCalls,
		address:    fixedAddr("127.0.0.1:8743"),
	}
	listener := &reviewedDirectHTTPSListener{
		listener:         delegate,
		expectedListener: delegate,
		expectedHost:     "127.0.0.1",
		expectedPort:     "8744",
	}

	err := validateReviewedDirectHTTPSListener(listener)
	if err == nil || !strings.Contains(err.Error(), "bound address changed") {
		t.Fatalf("bound-authority drift error = %v, want exact-address rejection", err)
	}
	if closeCalls != 1 {
		t.Fatalf("drifted delegate Close calls = %d, want one", closeCalls)
	}
}

type nilAddrListener struct{}

func (nilAddrListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (nilAddrListener) Close() error              { return nil }
func (nilAddrListener) Addr() net.Addr            { return nil }

type typedNilAddrListener struct{}

func (typedNilAddrListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (typedNilAddrListener) Close() error              { return nil }
func (typedNilAddrListener) Addr() net.Addr            { var address *net.TCPAddr; return address }

type fixedAddrListener struct {
	address net.Addr
}

func (fixedAddrListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (fixedAddrListener) Close() error              { return nil }
func (listener fixedAddrListener) Addr() net.Addr   { return listener.address }

type flippingAddrListener struct {
	addrCalls  atomic.Int32
	closeCalls atomic.Int32
}

func (listener *flippingAddrListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (listener *flippingAddrListener) Close() error {
	listener.closeCalls.Add(1)
	return nil
}
func (listener *flippingAddrListener) Addr() net.Addr {
	if listener.addrCalls.Add(1) == 1 {
		return fixedAddr("127.0.0.1:0")
	}
	return fixedAddr("192.0.2.1:443")
}

type oneConnectionListener struct {
	connection net.Conn
	address    net.Addr
}

func (listener oneConnectionListener) Accept() (net.Conn, error) { return listener.connection, nil }
func (oneConnectionListener) Close() error                       { return nil }
func (listener oneConnectionListener) Addr() net.Addr            { return listener.address }

type malformedAcceptListener struct {
	connection net.Conn
	closeCalls *int
	address    net.Addr
}

func (listener *malformedAcceptListener) Accept() (net.Conn, error) { return listener.connection, nil }
func (listener *malformedAcceptListener) Close() error {
	*listener.closeCalls++
	return nil
}
func (listener *malformedAcceptListener) Addr() net.Addr { return listener.address }

type malformedAcceptErrorListener struct {
	connection net.Conn
	closeCalls *int
	err        error
	address    net.Addr
}

func (listener *malformedAcceptErrorListener) Accept() (net.Conn, error) {
	return listener.connection, listener.err
}
func (listener *malformedAcceptErrorListener) Close() error {
	*listener.closeCalls++
	return nil
}
func (listener *malformedAcceptErrorListener) Addr() net.Addr { return listener.address }

type nilConnectionListener struct {
	closeErr   error
	closeCalls int
	address    net.Addr
}

func (*nilConnectionListener) Accept() (net.Conn, error) { return nil, nil }
func (listener *nilConnectionListener) Close() error {
	listener.closeCalls++
	return listener.closeErr
}
func (listener *nilConnectionListener) Addr() net.Addr { return listener.address }

type panicAcceptListener struct {
	closeErr   error
	address    net.Addr
	closeCalls int
}

func (*panicAcceptListener) Accept() (net.Conn, error) { panic("malformed accept") }
func (listener *panicAcceptListener) Close() error {
	listener.closeCalls++
	return listener.closeErr
}
func (listener *panicAcceptListener) Addr() net.Addr { return listener.address }

type countingAcceptListener struct {
	count   *int
	address net.Addr
}

func (listener countingAcceptListener) Accept() (net.Conn, error) {
	(*listener.count)++
	return nil, io.EOF
}
func (countingAcceptListener) Close() error            { return nil }
func (listener countingAcceptListener) Addr() net.Addr { return listener.address }

type trackingListener struct {
	closeCalls *int
	address    net.Addr
}

func (listener *trackingListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (listener *trackingListener) Close() error {
	*listener.closeCalls++
	return nil
}
func (listener *trackingListener) Addr() net.Addr { return listener.address }

type errorCloseListener struct {
	err     error
	address net.Addr
}

func (listener *errorCloseListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (listener *errorCloseListener) Close() error              { return listener.err }
func (listener *errorCloseListener) Addr() net.Addr            { return listener.address }

type blockingCloseListener struct {
	closeStarted chan struct{}
	allowClose   <-chan struct{}
	err          error
	closeCalls   atomic.Int32
}

func (listener *blockingCloseListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (listener *blockingCloseListener) Close() error {
	if listener.closeCalls.Add(1) == 1 {
		close(listener.closeStarted)
	}
	<-listener.allowClose
	return listener.err
}
func (listener *blockingCloseListener) Addr() net.Addr { return fixedAddr("127.0.0.1:0") }

type blockingCloseErrorListener struct {
	accepted  chan struct{}
	closed    chan struct{}
	closeErr  error
	closeOnce sync.Once
}

func (listener *blockingCloseErrorListener) Accept() (net.Conn, error) {
	select {
	case <-listener.accepted:
	default:
		close(listener.accepted)
	}
	<-listener.closed
	return nil, net.ErrClosed
}

func (listener *blockingCloseErrorListener) Close() error {
	listener.closeOnce.Do(func() { close(listener.closed) })
	return listener.closeErr
}

func (listener *blockingCloseErrorListener) Addr() net.Addr { return fixedAddr("127.0.0.1:0") }

type nonComparableListener struct {
	marker []byte
}

func (nonComparableListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (nonComparableListener) Close() error              { return nil }
func (nonComparableListener) Addr() net.Addr            { return fixedAddr("127.0.0.1:0") }

type addressedConn struct {
	net.Conn
	localAddr net.Addr
}

func (connection addressedConn) LocalAddr() net.Addr { return connection.localAddr }

type countingConn struct {
	net.Conn
	closeCalls *int
}

func (connection *countingConn) Close() error {
	*connection.closeCalls++
	return connection.Conn.Close()
}

type errorCloseConn struct {
	net.Conn
	err error
}

func (connection *errorCloseConn) Close() error {
	_ = connection.Conn.Close()
	return connection.err
}

type panicCloseConn struct {
	net.Conn
}

func (*panicCloseConn) Close() error { panic("accepted connection close detail") }

type fixedAddr string

func (address fixedAddr) Network() string { return "tcp" }
func (address fixedAddr) String() string  { return string(address) }

type panicStringAddr struct{}

func (panicStringAddr) Network() string { return "tcp" }
func (panicStringAddr) String() string  { panic("listener address detail") }

type panicListener struct{}

func (panicListener) Accept() (net.Conn, error) { panic("listener panic detail") }
func (panicListener) Close() error              { return nil }
func (panicListener) Addr() net.Addr            { return panicListenerAddr{} }

type panicListenerAddr struct{}

func (panicListenerAddr) Network() string { return "panic" }
func (panicListenerAddr) String() string  { return "panic" }

type panicCloseListener struct{}

func (panicCloseListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (panicCloseListener) Close() error              { panic("listener close detail") }
func (panicCloseListener) Addr() net.Addr            { return panicListenerAddr{} }

type panicAddrListener struct{}

func (panicAddrListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (panicAddrListener) Close() error              { return nil }
func (panicAddrListener) Addr() net.Addr            { panic("listener address detail") }

type panicAddrCloseListener struct {
	closeErr   error
	closeCalls int
	address    net.Addr
}

func (listener *panicAddrCloseListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (listener *panicAddrCloseListener) Close() error {
	listener.closeCalls++
	return listener.closeErr
}
func (*panicAddrCloseListener) Addr() net.Addr { panic("listener address detail") }

func TestMCPHTTPHandlerRejectsUnicodeTransportControlsButPreservesOrdinaryUTF8(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	malformed := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle/\u202e", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	malformed.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, malformed)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("Unicode format character status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("callbacks called for Unicode format metadata: secure=%d resolver=%d", secureCalls, resolverCalls)
	}

	layoutSeparator := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle/\u2028", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	layoutSeparator.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, layoutSeparator)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("Unicode layout separator status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("callbacks called for Unicode layout metadata: secure=%d resolver=%d", secureCalls, resolverCalls)
	}

	ordinary := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle/café", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	ordinary.Header.Set("Content-Type", "application/json")
	ordinary.Pattern = "/lifecycle/{name}"
	ordinary.SetPathValue("name", "café")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, ordinary)
	if response.Code != http.StatusOK {
		t.Fatalf("ordinary UTF-8 status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if secureCalls != 1 || resolverCalls != 1 {
		t.Fatalf("ordinary UTF-8 callbacks = secure %d resolver %d, want one each", secureCalls, resolverCalls)
	}
}

func TestMCPHTTPHandlerRejectsPrincipalResolverRequestMutation(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{
			name: "context",
			mutate: func(r *http.Request) {
				*r = *r.WithContext(context.Background())
			},
		},
		{
			name: "header",
			mutate: func(r *http.Request) {
				r.Header.Set("X-Resolver-Mutation", "changed")
			},
		},
		{
			name: "body read",
			mutate: func(r *http.Request) {
				_, _ = io.ReadAll(r.Body)
			},
		},
		{
			name: "body close",
			mutate: func(r *http.Request) {
				_ = r.Body.Close()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(r *http.Request) (Principal, error) {
				resolverCalls++
				tc.mutate(r)
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool { return true })
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			req = req.WithContext(context.WithValue(context.Background(), struct{}{}, "original"))
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("resolver %s mutation status = %d, want %d: %s", tc.name, response.Code, http.StatusBadRequest, response.Body.String())
			}
			if resolverCalls != 1 {
				t.Fatalf("resolver calls = %d, want 1", resolverCalls)
			}
		})
	}
}

func TestRequireDirectTLSRejectsLegacyTLS(t *testing.T) {
	plaintextURL := httptest.NewRequest(http.MethodPost, "http://relay.invalid/lifecycle", nil)
	plaintextURL.TLS = &tlsStateForTest
	httpsURL := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	httpsURL.TLS = &tlsStateForTest
	absoluteHTTPTarget := *httpsURL
	absoluteHTTPTarget.RequestURI = "http://relay.invalid/lifecycle"
	matchingAbsoluteTarget := *httpsURL
	matchingAbsoluteTarget.RequestURI = "https://relay.invalid/lifecycle"
	mismatchedAbsoluteTarget := *httpsURL
	mismatchedAbsoluteTarget.RequestURI = "https://other.invalid/lifecycle"
	userinfoAbsoluteTarget := *httpsURL
	userinfoAbsoluteTarget.RequestURI = "https://user@relay.invalid/lifecycle"
	malformedHTTPAbsoluteTarget := *httpsURL
	malformedHTTPAbsoluteTarget.RequestURI = "http:/relay.invalid/lifecycle"
	malformedAbsoluteTarget := *httpsURL
	malformedAbsoluteTarget.RequestURI = "https://relay.invalid/%zz"
	missingAuthorityTarget := *httpsURL
	missingAuthorityTarget.RequestURI = "https:/relay.invalid/lifecycle"
	originFormTarget := *httpsURL
	originFormTarget.RequestURI = "/lifecycle"
	mismatchedOriginPathTarget := *httpsURL
	mismatchedOriginPathTarget.RequestURI = "/other"
	mismatchedOriginQueryTarget := *httpsURL
	mismatchedOriginQueryTarget.RequestURI = "/lifecycle?other=value"
	serverFormTarget := *httpsURL
	serverFormURL := *httpsURL.URL
	serverFormURL.Scheme = ""
	serverFormTarget.URL = &serverFormURL
	serverFormTarget.RequestURI = "/lifecycle"
	serverAbsoluteTarget := serverFormTarget
	serverAbsoluteTarget.RequestURI = "https://relay.invalid/lifecycle"
	serverMismatchedAbsoluteTarget := serverFormTarget
	serverMismatchedAbsoluteTarget.RequestURI = "https://other.invalid/lifecycle"
	absoluteFragmentTarget := *httpsURL
	absoluteFragmentTarget.RequestURI = "https://relay.invalid/lifecycle#fragment"
	originFragmentTarget := *httpsURL
	originFragmentTarget.RequestURI = "/lifecycle#fragment"
	encodedHashURL := *httpsURL.URL
	encodedHashURL.Path = "/lifecycle#fragment"
	encodedHashTarget := *httpsURL
	encodedHashTarget.URL = &encodedHashURL
	encodedHashTarget.RequestURI = "/lifecycle%23fragment"
	hostlessHTTPSURL := *httpsURL.URL
	hostlessHTTPSURL.Host = ""
	opaqueHTTPSURL := *httpsURL.URL
	opaqueHTTPSURL.Host = ""
	opaqueHTTPSURL.Opaque = "relay.invalid/lifecycle"
	controlCharacterAuthorityURL := *httpsURL.URL
	controlCharacterAuthorityURL.Host = "relay.invalid\n"
	invalidPortAuthorityURL := *httpsURL.URL
	invalidPortAuthorityURL.Host = "relay.invalid:not-a-port"
	outOfRangePortAuthorityURL := *httpsURL.URL
	outOfRangePortAuthorityURL.Host = "relay.invalid:65536"
	leadingZeroPortAuthorityURL := *httpsURL.URL
	leadingZeroPortAuthorityURL.Host = "relay.invalid:08743"
	userinfoAuthorityURL := *httpsURL.URL
	userinfoAuthorityURL.Host = "user@relay.invalid"
	parsedUserinfoURL := httptest.NewRequest(http.MethodPost, "https://user@relay.invalid/lifecycle", nil)
	parsedUserinfoURL.TLS = &tlsStateForTest
	for _, tc := range []struct {
		name    string
		request *http.Request
		want    bool
	}{
		{name: "nil request", request: nil, want: false},
		{name: "plaintext", request: &http.Request{}, want: false},
		{name: "TLS 1.0", request: &http.Request{TLS: &tls.ConnectionState{Version: tls.VersionTLS10}}, want: false},
		{name: "TLS 1.1", request: &http.Request{TLS: &tls.ConnectionState{Version: tls.VersionTLS11}}, want: false},
		{name: "unknown future TLS version", request: &http.Request{TLS: &tls.ConnectionState{Version: tls.VersionTLS13 + 1, HandshakeComplete: true}}, want: false},
		{name: "incomplete TLS 1.3", request: &http.Request{TLS: &tls.ConnectionState{Version: tls.VersionTLS13}}, want: false},
		{name: "missing URL", request: &http.Request{TLS: &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}}, want: false},
		{name: "explicit plaintext URL with TLS metadata", request: plaintextURL, want: false},
		{name: "contradictory plaintext absolute request target", request: &absoluteHTTPTarget, want: false},
		{name: "matching absolute request target", request: &matchingAbsoluteTarget, want: true},
		{name: "mismatched absolute request target authority", request: &mismatchedAbsoluteTarget, want: false},
		{name: "absolute request target with embedded userinfo", request: &userinfoAbsoluteTarget, want: false},
		{name: "malformed plaintext absolute request target", request: &malformedHTTPAbsoluteTarget, want: false},
		{name: "malformed absolute request target", request: &malformedAbsoluteTarget, want: false},
		{name: "absolute request target without authority", request: &missingAuthorityTarget, want: false},
		{name: "mismatched origin-form request target path", request: &mismatchedOriginPathTarget, want: false},
		{name: "mismatched origin-form request target query", request: &mismatchedOriginQueryTarget, want: false},
		{name: "explicit HTTPS URL without authority", request: &http.Request{URL: &hostlessHTTPSURL, TLS: &tlsStateForTest}, want: false},
		{name: "opaque HTTPS URL", request: &http.Request{URL: &opaqueHTTPSURL, TLS: &tlsStateForTest}, want: false},
		{name: "authority with control character", request: &http.Request{URL: &controlCharacterAuthorityURL, TLS: &tlsStateForTest}, want: false},
		{name: "authority with invalid port", request: &http.Request{URL: &invalidPortAuthorityURL, TLS: &tlsStateForTest}, want: false},
		{name: "authority with out-of-range port", request: &http.Request{URL: &outOfRangePortAuthorityURL, TLS: &tlsStateForTest}, want: false},
		{name: "authority with non-canonical leading-zero port", request: &http.Request{URL: &leadingZeroPortAuthorityURL, TLS: &tlsStateForTest}, want: false},
		{name: "authority with embedded userinfo", request: &http.Request{URL: &userinfoAuthorityURL, TLS: &tlsStateForTest}, want: false},
		{name: "parsed URL userinfo", request: parsedUserinfoURL, want: false},
		{name: "normal origin-form request target", request: &originFormTarget, want: true},
		{name: "normal server origin-form request target", request: &serverFormTarget, want: true},
		{name: "matching server absolute request target", request: &serverAbsoluteTarget, want: true},
		{name: "mismatched server absolute request target authority", request: &serverMismatchedAbsoluteTarget, want: false},
		{name: "absolute request target with fragment", request: &absoluteFragmentTarget, want: false},
		{name: "origin-form request target with fragment", request: &originFragmentTarget, want: false},
		{name: "origin-form request target with encoded hash", request: &encodedHashTarget, want: true},
		{name: "completed TLS 1.2 with explicit HTTPS URL", request: &http.Request{URL: httpsURL.URL, TLS: &tls.ConnectionState{Version: tls.VersionTLS12, HandshakeComplete: true, CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLSUnique: bytes.Repeat([]byte{1}, 12), NegotiatedProtocolIsMutual: true}}, want: true},
		{name: "completed TLS 1.3", request: httpsURL, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RequireDirectTLS(tc.request); got != tc.want {
				t.Fatalf("RequireDirectTLS() = %t, want %t", got, tc.want)
			}
		})
	}

}

func TestRequireDirectTLSContainsValidationPanics(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tlsStateForTest
	if requireDirectTLSWithPanicBoundary(request, func(*tls.ConnectionState) bool {
		panic("malformed direct TLS metadata")
	}) {
		t.Fatal("RequireDirectTLS panic boundary accepted malformed validation")
	}
}

func TestRequireDirectTLSValidatesOrigin(t *testing.T) {
	base := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	base.TLS = &tlsStateForTest
	tests := []struct {
		name   string
		mutate func(*http.Request)
		want   bool
	}{
		{name: "absent for non-browser client", want: true},
		{name: "matching origin", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "https://relay.invalid")
		}, want: true},
		{name: "matching origin with default port", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "https://relay.invalid:443")
		}, want: true},
		{name: "cross-origin", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "https://attacker.invalid")
		}, want: false},
		{name: "plaintext origin", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "http://relay.invalid")
		}, want: false},
		{name: "path in origin", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "https://relay.invalid/other")
		}, want: false},
		{name: "empty query delimiter in origin", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "https://relay.invalid?")
		}, want: false},
		{name: "empty fragment delimiter in origin", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "https://relay.invalid#")
		}, want: false},
		{name: "null origin", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "null")
		}, want: false},
		{name: "duplicate origins", mutate: func(r *http.Request) {
			r.Header["origin"] = []string{"https://relay.invalid"}
			r.Header["Origin"] = []string{"https://relay.invalid"}
		}, want: false},
		{name: "empty origin field", mutate: func(r *http.Request) {
			r.Header["Origin"] = nil
		}, want: false},
		{name: "oversized origin", mutate: func(r *http.Request) {
			r.Header.Set("Origin", "https://"+strings.Repeat("h", maxMCPOriginBytes))
		}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base.Clone(base.Context())
			if test.mutate != nil {
				test.mutate(request)
			}
			if got := RequireDirectTLS(request); got != test.want {
				t.Fatalf("RequireDirectTLS() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestRequireDirectTLSRejectsNonTransportURLMetadata(t *testing.T) {
	base := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	base.TLS = &tlsStateForTest

	fragmentURL := *base.URL
	fragmentURL.Fragment = "not-sent"
	fragmentRequest := &http.Request{URL: &fragmentURL, TLS: &tlsStateForTest}

	invalidRawPathURL := *base.URL
	invalidRawPathURL.RawPath = "/%zz"
	invalidRawPathRequest := &http.Request{URL: &invalidRawPathURL, TLS: &tlsStateForTest}

	mismatchedRawPathURL := *base.URL
	mismatchedRawPathURL.RawPath = "/different"
	mismatchedRawPathRequest := &http.Request{URL: &mismatchedRawPathURL, TLS: &tlsStateForTest}

	escapedPathURL := *base.URL
	escapedPathURL.Path = "/life/cycle"
	escapedPathURL.RawPath = "/life%2Fcycle"
	escapedPathRequest := &http.Request{URL: &escapedPathURL, TLS: &tlsStateForTest}

	controlPathURL := *base.URL
	controlPathURL.Path = "/life\ncycle"
	controlPathRequest := &http.Request{URL: &controlPathURL, TLS: &tlsStateForTest}
	controlQueryURL := *base.URL
	controlQueryURL.RawQuery = "q=bad\x00value"
	controlQueryRequest := &http.Request{URL: &controlQueryURL, TLS: &tlsStateForTest}
	rawPathFragmentURL := *base.URL
	rawPathFragmentURL.RawPath = "/lifecycle#fragment"
	rawPathFragmentRequest := &http.Request{URL: &rawPathFragmentURL, TLS: &tlsStateForTest}
	rawQueryFragmentURL := *base.URL
	rawQueryFragmentURL.RawQuery = "q=value#fragment"
	rawQueryFragmentRequest := &http.Request{URL: &rawQueryFragmentURL, TLS: &tlsStateForTest}
	controlOpaqueURL := *base.URL
	controlOpaqueURL.Scheme = ""
	controlOpaqueURL.Host = ""
	controlOpaqueURL.Opaque = "relay.invalid/\x7flifecycle"
	controlOpaqueRequest := &http.Request{URL: &controlOpaqueURL, TLS: &tlsStateForTest}
	plainOpaqueURL := *base.URL
	plainOpaqueURL.Scheme = ""
	plainOpaqueURL.Host = ""
	plainOpaqueURL.Opaque = "relay.invalid/lifecycle"
	plainOpaqueRequest := &http.Request{URL: &plainOpaqueURL, TLS: &tlsStateForTest}
	controlHostRequest := *base
	controlHostRequest.Host = "relay.invalid\n"
	userinfoHostRequest := *base
	userinfoHostRequest.Host = "user@relay.invalid"
	oversizedHostRequest := *base
	oversizedHostRequest.Host = strings.Repeat("h", maxMCPRequestTargetBytes+1)
	mismatchedHostRequest := *base
	mismatchedHostRequest.Host = "other.invalid"

	for _, tc := range []struct {
		name    string
		request *http.Request
		want    bool
	}{
		{name: "fragment", request: fragmentRequest, want: false},
		{name: "invalid escaped path", request: invalidRawPathRequest, want: false},
		{name: "mismatched escaped path", request: mismatchedRawPathRequest, want: false},
		{name: "valid escaped path", request: escapedPathRequest, want: true},
		{name: "control byte in path", request: controlPathRequest, want: false},
		{name: "control byte in query", request: controlQueryRequest, want: false},
		{name: "raw fragment delimiter in escaped path", request: rawPathFragmentRequest, want: false},
		{name: "raw fragment delimiter in query", request: rawQueryFragmentRequest, want: false},
		{name: "control byte in opaque URL", request: controlOpaqueRequest, want: false},
		{name: "opaque URL without scheme", request: plainOpaqueRequest, want: false},
		{name: "request Host with control byte", request: &controlHostRequest, want: false},
		{name: "request Host with embedded userinfo", request: &userinfoHostRequest, want: false},
		{name: "oversized request Host", request: &oversizedHostRequest, want: false},
		{name: "request Host mismatches URL authority", request: &mismatchedHostRequest, want: false},
		{name: "matching request Host authority", request: base, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RequireDirectTLS(tc.request); got != tc.want {
				t.Fatalf("RequireDirectTLS() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestRequireDirectTLSRejectsMalformedMethodMetadata(t *testing.T) {
	base := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	base.TLS = &tlsStateForTest

	for _, tc := range []struct {
		name   string
		method string
	}{
		{name: "control byte", method: "POST\n"},
		{name: "separator", method: "POST /lifecycle"},
		{name: "oversized", method: strings.Repeat("M", maxMCPMethodBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := *base
			request.Method = tc.method
			if RequireDirectTLS(&request) {
				t.Fatalf("RequireDirectTLS accepted malformed method %q", tc.method)
			}
		})
	}
}

func TestRequireDirectTLSRequiresCoherentConnectionCloseMetadata(t *testing.T) {
	base := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	base.TLS = &tlsStateForTest

	for _, tc := range []struct {
		name       string
		proto      string
		major      int
		minor      int
		close      bool
		connection string
		want       bool
	}{
		{name: "HTTP/1.1 default keep-alive", proto: "HTTP/1.1", major: 1, minor: 1, want: true},
		{name: "HTTP/1.1 close header", proto: "HTTP/1.1", major: 1, minor: 1, close: true, connection: "cLoSe", want: true},
		{name: "HTTP/1.1 close token with whitespace neighbor", proto: "HTTP/1.1", major: 1, minor: 1, close: true, connection: "close ;extension", want: true},
		{name: "HTTP/1.1 close flag without header", proto: "HTTP/1.1", major: 1, minor: 1, close: true},
		{name: "HTTP/1.1 header without close flag", proto: "HTTP/1.1", major: 1, minor: 1, connection: "close"},
		{name: "HTTP/1.0 default close", proto: "HTTP/1.0", major: 1, minor: 0, close: true, want: true},
		{name: "HTTP/1.0 keep-alive", proto: "HTTP/1.0", major: 1, minor: 0, connection: "keep-alive", want: true},
		{name: "HTTP/1.0 keep-alive token with whitespace neighbor", proto: "HTTP/1.0", major: 1, minor: 0, connection: "keep-alive\t;extension", want: true},
		{name: "HTTP/1.0 keep-alive with close flag", proto: "HTTP/1.0", major: 1, minor: 0, close: true, connection: "keep-alive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := *base
			request.Proto = tc.proto
			request.ProtoMajor = tc.major
			request.ProtoMinor = tc.minor
			request.Close = tc.close
			request.Header = make(http.Header)
			if tc.connection != "" {
				request.Header.Set("Connection", tc.connection)
			}
			if got := RequireDirectTLS(&request); got != tc.want {
				t.Fatalf("RequireDirectTLS() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestRequireDirectTLSRejectsRawTrailerHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tlsStateForTest
	request.Header.Set("Trailer", "X-Declared-Trailer")
	request.Trailer = http.Header{"X-Declared-Trailer": nil}
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted an unnormalized raw Trailer header")
	}
}

func TestRequireDirectTLSRejectsAliasedHeaderAndTrailerMaps(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tlsStateForTest
	request.Trailer = request.Header
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted aliased Header and Trailer maps")
	}
}

func TestMCPHTTPHandlerRejectsMalformedDirectHostMetadataBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	transportCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		transportCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "missing URL", mutate: func(request *http.Request) { request.URL = nil }},
		{name: "control byte", mutate: func(request *http.Request) { request.Host = "relay.invalid\n" }},
		{name: "userinfo", mutate: func(request *http.Request) { request.Host = "user@relay.invalid" }},
		{name: "mismatch", mutate: func(request *http.Request) { request.Host = "other.invalid" }},
		{name: "parsed URL userinfo", mutate: func(request *http.Request) {
			request.URL.User = url.UserPassword("user", "password")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transportCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			tc.mutate(request)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if transportCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called: transport=%d resolver=%d", transportCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsMalformedDirectFramingBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	transportCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		transportCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{
			name: "conflicting content length",
			mutate: func(request *http.Request) {
				request.Header.Set("Content-Length", "not-a-length")
			},
		},
		{
			name: "unsupported transfer encoding",
			mutate: func(request *http.Request) {
				request.Header.Set("Transfer-Encoding", "gzip")
				request.TransferEncoding = []string{"gzip"}
			},
		},
		{
			name: "invalid negative content length",
			mutate: func(request *http.Request) {
				request.ContentLength = -2
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transportCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			tc.mutate(request)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if transportCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called: transport=%d resolver=%d", transportCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsDirectURLFragmentsBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	transportCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		transportCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "parsed fragment", mutate: func(request *http.Request) { request.URL.Fragment = "not-sent" }},
		{name: "raw fragment in request target", mutate: func(request *http.Request) { request.RequestURI = "/lifecycle#fragment" }},
		{name: "raw fragment in escaped path", mutate: func(request *http.Request) { request.URL.RawPath = "/lifecycle#fragment" }},
		{name: "raw fragment in query", mutate: func(request *http.Request) { request.URL.RawQuery = "q=value#fragment" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transportCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			tc.mutate(request)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if transportCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called: transport=%d resolver=%d", transportCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsMalformedDirectURLStructureBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "invalid escaped path", mutate: func(request *http.Request) {
			request.RequestURI = ""
			request.URL.RawPath = "/%zz"
		}},
		{name: "mismatched escaped path", mutate: func(request *http.Request) {
			request.RequestURI = ""
			request.URL.RawPath = "/other"
		}},
		{name: "invalid query escape", mutate: func(request *http.Request) {
			request.RequestURI = ""
			request.URL.RawQuery = "q=%zz"
		}},
		{name: "opaque URL", mutate: func(request *http.Request) {
			request.RequestURI = ""
			request.URL.Scheme = ""
			request.URL.Host = ""
			request.URL.Opaque = "relay.invalid/lifecycle"
		}},
		{name: "scheme without authority", mutate: func(request *http.Request) {
			request.RequestURI = ""
			request.URL.Host = ""
			request.URL.Scheme = "https"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			tc.mutate(request)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsInconsistentRequestTargetBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "origin-form path", mutate: func(request *http.Request) {
			request.RequestURI = "/other"
		}},
		{name: "origin-form query", mutate: func(request *http.Request) {
			request.RequestURI = "/lifecycle?other=value"
		}},
		{name: "absolute-form authority", mutate: func(request *http.Request) {
			request.RequestURI = "https://other.invalid/lifecycle"
		}},
		{name: "absolute-form scheme", mutate: func(request *http.Request) {
			request.RequestURI = "http://relay.invalid/lifecycle"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			tc.mutate(request)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestRequireDirectTLSRejectsOversizedMetadata(t *testing.T) {
	base := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	base.TLS = &tlsStateForTest

	oversizedTarget := *base
	oversizedTarget.RequestURI = strings.Repeat("/", maxMCPRequestTargetBytes+1)

	oversizedURL := *base.URL
	oversizedURL.RawQuery = strings.Repeat("q", maxMCPRequestTargetBytes)
	oversizedURL.Path = strings.Repeat("/path", maxMCPRequestTargetBytes)
	oversizedURLRequest := &http.Request{URL: &oversizedURL, TLS: &tlsStateForTest}
	oversizedHeader := *base
	oversizedHeader.Header = http.Header{
		strings.Repeat("x", maxMCPHeaderNameBytes+1): []string{"value"},
	}

	for _, tc := range []struct {
		name    string
		request *http.Request
	}{
		{name: "request target", request: &oversizedTarget},
		{name: "aggregate URL components", request: oversizedURLRequest},
		{name: "header field map", request: &oversizedHeader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if RequireDirectTLS(tc.request) {
				t.Fatal("RequireDirectTLS accepted oversized direct-call metadata")
			}
		})
	}
}

func TestRequireDirectTLSRejectsMalformedCertificateMetadata(t *testing.T) {
	base := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	base.TLS = &tlsStateForTest
	policy, err := x509.OIDFromInts([]uint64{2, 5, 29, 32, 0})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		certificate *x509.Certificate
	}{
		{name: "DNS name format control", certificate: &x509.Certificate{DNSNames: []string{"relay\u202e.invalid"}}},
		{name: "URI format control", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "relay.invalid", Path: "/cert\u200b"}}}},
		{name: "URI username format control", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "relay.invalid", User: url.User("alice\u200b")}}}},
		{name: "URI password control", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "relay.invalid", User: url.UserPassword("alice", "secret\n")}}}},
		{name: "URI invalid raw path escape", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "relay.invalid", Path: "/cert", RawPath: "/%zz"}}}},
		{name: "URI mismatched raw path", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "relay.invalid", Path: "/cert", RawPath: "/other"}}}},
		{name: "URI invalid raw query escape", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "relay.invalid", RawQuery: "q=%zz"}}}},
		{name: "URI raw fragment delimiter in path", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "relay.invalid", Path: "/cert#fragment", RawPath: "/cert#fragment"}}}},
		{name: "URI raw fragment delimiter in query", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "relay.invalid", RawQuery: "q=value#fragment"}}}},
		{name: "URI raw fragment delimiter in fragment", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "relay.invalid", Fragment: "fragment", RawFragment: "fragment#suffix"}}}},
		{name: "URI raw fragment delimiter in opaque data", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "urn", Opaque: "example:foo#fragment"}}}},
		{name: "URI raw query delimiter in opaque data", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "urn", Opaque: "example:foo?query"}}}},
		{name: "URI raw query delimiter in escaped path", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "relay.invalid", Path: "/cert?query", RawPath: "/cert?query"}}}},
		{name: "URI invalid opaque escape", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "urn", Opaque: "example:%zz"}}}},
		{name: "URI contradictory opaque path", certificate: &x509.Certificate{URIs: []*url.URL{{Scheme: "urn", Opaque: "example:foo", Path: "/unexpected"}}}},
		{name: "non-canonical IP length", certificate: &x509.Certificate{IPAddresses: []net.IP{{1, 2, 3, 4, 5}}}},
		{name: "negative extension OID arc", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, -1}, Value: []byte{1}}}}},
		{name: "duplicate extension OID", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}, {Id: []int{2, 5, 29, 17}}}}},
		{name: "duplicate extra-extension OID", certificate: &x509.Certificate{ExtraExtensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}, {Id: []int{2, 5, 29, 17}}}}},
		{name: "negative unhandled-critical OID arc", certificate: &x509.Certificate{UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{2, 5, -1}}}},
		{name: "zero policy OID", certificate: &x509.Certificate{Policies: []x509.OID{{}}}},
		{name: "zero policy-mapping OID", certificate: &x509.Certificate{PolicyMappings: []x509.PolicyMapping{{}}}},
		{name: "anyPolicy issuer policy-mapping OID", certificate: &x509.Certificate{PolicyMappings: []x509.PolicyMapping{{
			IssuerDomainPolicy:  mustCertificateOID(t, "2.5.29.32.0"),
			SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.4"),
		}}}},
		{name: "anyPolicy subject policy-mapping OID", certificate: &x509.Certificate{PolicyMappings: []x509.PolicyMapping{{
			IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
			SubjectDomainPolicy: mustCertificateOID(t, "2.5.29.32.0"),
		}}}},
		{name: "oversized extra extension", certificate: &x509.Certificate{ExtraExtensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: bytes.Repeat([]byte{1}, maxMCPTLSCertificateBytes+1)}}}},
		{name: "invalid policy constraint", certificate: &x509.Certificate{InhibitAnyPolicy: -2}},
		{name: "policy constraint marker without matching extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}}, InhibitAnyPolicy: 1}},
		{name: "policy constraint extension without marker", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 54}}}}},
		{name: "policy constraints marker without matching extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}}, RequireExplicitPolicy: 1}},
		{name: "policy constraints extension without marker", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 36}}}}},
		{name: "policy constraints value mismatch", certificate: &x509.Certificate{
			Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 36}, Value: mustMarshalCertificatePolicyConstraints(t, ptrToInt64(4), ptrToInt64(3))}},
			RequireExplicitPolicy: 5,
			InhibitPolicyMapping:  3,
		}},
		{name: "inhibit any policy value mismatch", certificate: &x509.Certificate{
			Extensions:       []pkix.Extension{{Id: []int{2, 5, 29, 54}, Value: mustMarshalCertificateValue(t, int64(4))}},
			InhibitAnyPolicy: 5,
		}},
		{name: "malformed policy constraints source value", certificate: &x509.Certificate{
			Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 36}, Value: []byte{0x30, 0x02, 0x80}}},
			RequireExplicitPolicy: 1,
		}},
		{name: "malformed inhibit any policy source value", certificate: &x509.Certificate{
			Extensions:       []pkix.Extension{{Id: []int{2, 5, 29, 54}, Value: []byte{0x02, 0x02, 0x01}}},
			InhibitAnyPolicy: 1,
		}},
		{name: "policy mapping without parsed extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}}, PolicyMappings: []x509.PolicyMapping{{
			IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
			SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
		}}}},
		{name: "v1 certificate with parsed extensions", certificate: &x509.Certificate{Version: 1, Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}}}},
		{name: "v2 certificate with parsed extensions", certificate: &x509.Certificate{Version: 2, Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}}}},
		{name: "critical subject key identifier extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 14}, Critical: true}}}},
		{name: "critical authority key identifier extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 35}, Critical: true}}}},
		{name: "subject key identifier without source extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}}, SubjectKeyId: []byte{1, 2, 3}}},
		{name: "authority key identifier without source extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}}, AuthorityKeyId: []byte{4, 5, 6}}},
		{name: "subject key identifier value mismatch", certificate: &x509.Certificate{
			Extensions:   []pkix.Extension{{Id: []int{2, 5, 29, 14}, Value: mustMarshalCertificateValue(t, []byte{9, 9, 9})}},
			SubjectKeyId: []byte{1, 2, 3},
		}},
		{name: "authority key identifier value mismatch", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 35}, Value: mustMarshalCertificateValue(t, struct {
				ID []byte `asn1:"optional,tag:0"`
			}{ID: []byte{9, 9, 9}})}},
			AuthorityKeyId: []byte{4, 5, 6},
		}},
		{name: "malformed subject key identifier source value", certificate: &x509.Certificate{
			Extensions:   []pkix.Extension{{Id: []int{2, 5, 29, 14}, Value: []byte{0x04, 0x02, 0x01}}},
			SubjectKeyId: []byte{1, 2, 3},
		}},
		{name: "malformed authority key identifier source value", certificate: &x509.Certificate{
			Extensions:     []pkix.Extension{{Id: []int{2, 5, 29, 35}, Value: []byte{0x30, 0x02, 0x80}}},
			AuthorityKeyId: []byte{4, 5, 6},
		}},
		{name: "malformed empty subject key identifier source value", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 14}, Value: []byte{0x04, 0x01}}},
		}},
		{name: "malformed empty authority key identifier source value", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 35}, Value: []byte{0x30, 0x01, 0xa0}}},
		}},
		{name: "key usage value mismatch", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 15}, Value: mustMarshalCertificateKeyUsage(t, x509.KeyUsageDigitalSignature)}},
			KeyUsage:   x509.KeyUsageCertSign,
		}},
		{name: "malformed key usage source value", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 15}, Value: []byte{0x03, 0x02, 0x07}}},
			KeyUsage:   x509.KeyUsageDigitalSignature,
		}},
		{name: "malformed empty key usage source value", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 15}, Value: []byte{0x03, 0x01, 0x07}}},
		}},
		{name: "DER TBS source without complete certificate", certificate: &x509.Certificate{
			RawTBSCertificate: []byte{0x30, 0x00},
		}},
		{name: "extended key usage value mismatch", certificate: &x509.Certificate{
			Extensions:  []pkix.Extension{{Id: []int{2, 5, 29, 37}, Value: mustMarshalCertificateExtendedKeyUsages(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})}},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}},
		{name: "unknown extended key usage value mismatch", certificate: &x509.Certificate{
			Extensions:         []pkix.Extension{{Id: []int{2, 5, 29, 37}, Value: mustMarshalCertificateExtendedKeyUsages(t, []asn1.ObjectIdentifier{{1, 2, 3, 4}})}},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3, 5}},
		}},
		{name: "malformed extended key usage source value", certificate: &x509.Certificate{
			Extensions:  []pkix.Extension{{Id: []int{2, 5, 29, 37}, Value: []byte{0x30, 0x02, 0x06}}},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}},
		{name: "malformed empty extended key usage source value", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 37}, Value: []byte{0x30, 0x01, 0x06}}},
		}},
		{name: "malformed empty authority information access source value", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: []byte{0x30, 0x01, 0x30}}},
		}},
		{name: "authority information access value mismatch", certificate: &x509.Certificate{
			Extensions:            []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: mustMarshalCertificateAuthorityInfoAccess(t, []string{"https://ocsp.relay.invalid"}, []string{"https://ca.relay.invalid/issuer.crt"})}},
			OCSPServer:            []string{"https://ocsp.attacker.invalid"},
			IssuingCertificateURL: []string{"https://ca.relay.invalid/issuer.crt"},
		}},
		{name: "malformed authority information access source value", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: []byte{0x30, 0x01, 0x30}}},
			OCSPServer: []string{"https://ocsp.relay.invalid"},
		}},
		{name: "constructed authority information access location", certificate: func() *x509.Certificate {
			method := mustMarshalCertificateValue(t, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1})
			location := mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 6, IsCompound: true, Bytes: []byte("https://ocsp.relay.invalid")})
			description := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: append(method, location...)})
			value := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: description})
			return &x509.Certificate{
				Extensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: value}},
				OCSPServer: []string{"https://ocsp.relay.invalid"},
			}
		}()},
		{name: "CRL distribution point value mismatch", certificate: &x509.Certificate{
			Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 31}, Value: mustMarshalCertificateCRLDistributionPoints(t, "https://crl.relay.invalid/root.crl")}},
			CRLDistributionPoints: []string{"https://crl.relay.invalid/other.crl"},
		}},
		{name: "malformed CRL distribution point source value", certificate: &x509.Certificate{
			Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 31}, Value: []byte{0x30, 0x01, 0x30}}},
			CRLDistributionPoints: []string{"https://crl.relay.invalid/root.crl"},
		}},
		{name: "constructed CRL distribution-point URI", certificate: func() *x509.Certificate {
			uri := mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 6, IsCompound: true, Bytes: []byte("https://crl.relay.invalid/root.crl")})
			fullName := mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: uri})
			distributionName := mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: fullName})
			distributionPoint := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: distributionName})
			value := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: distributionPoint})
			return &x509.Certificate{
				Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 31}, Value: value}},
				CRLDistributionPoints: []string{"https://crl.relay.invalid/root.crl"},
			}
		}()},
		{name: "policy mapping value mismatch", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: mustMarshalCertificatePolicyMappings(t, []x509.PolicyMapping{{
				IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
				SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
			}})}},
			PolicyMappings: []x509.PolicyMapping{{
				IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
				SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.6"),
			}},
		}},
		{name: "malformed policy mapping source value", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: []byte{0x30, 0x01, 0x30}}},
			PolicyMappings: []x509.PolicyMapping{{
				IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
				SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
			}},
		}},
		{name: "constructed policy-mapping OID", certificate: func() *x509.Certificate {
			issuer := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 6, IsCompound: true, Bytes: []byte{42, 3, 4}})
			subject := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 6, Bytes: []byte{42, 3, 5}})
			mapping := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: append(issuer, subject...)})
			value := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: mapping})
			return &x509.Certificate{
				Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: value}},
				PolicyMappings: []x509.PolicyMapping{{
					IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
					SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
				}},
			}
		}()},
		{name: "SAN value mismatch", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: mustMarshalCertificateSubjectAltNames(t, []string{"relay.invalid"}, nil, nil, nil)}},
			DNSNames:   []string{"other.invalid"},
		}},
		{name: "malformed SAN source value", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: []byte{0x30, 0x01, 0x82}}},
			DNSNames:   []string{"relay.invalid"},
		}},
		{name: "malformed empty SAN source value", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: []byte{0x30, 0x01, 0x82}}},
		}},
		{name: "constructed SAN dNSName", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: mustMarshalCertificateValue(t, []asn1.RawValue{{Class: 2, Tag: 2, IsCompound: true, Bytes: []byte("relay.invalid")}})}},
			DNSNames:   []string{"relay.invalid"},
		}},
		{name: "DNS name without source extension", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			DNSNames:   []string{"relay.invalid"},
		}},
		{name: "email name without source extension", certificate: &x509.Certificate{
			Extensions:     []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			EmailAddresses: []string{"owner@relay.invalid"},
		}},
		{name: "IP address without source extension", certificate: &x509.Certificate{
			Extensions:  []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}},
		{name: "URI without source extension", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			URIs:       []*url.URL{{Scheme: "https", Host: "relay.invalid"}},
		}},
		{name: "OCSP server without source extension", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			OCSPServer: []string{"https://ocsp.relay.invalid"},
		}},
		{name: "issuing certificate URL without source extension", certificate: &x509.Certificate{
			Extensions:            []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			IssuingCertificateURL: []string{"https://ca.relay.invalid/issuer.crt"},
		}},
		{name: "CRL distribution point without source extension", certificate: &x509.Certificate{
			Extensions:            []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			CRLDistributionPoints: []string{"https://crl.relay.invalid/root.crl"},
		}},
		{name: "key usage without source extension", certificate: &x509.Certificate{
			Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			KeyUsage:   x509.KeyUsageDigitalSignature,
		}},
		{name: "extended key usage without source extension", certificate: &x509.Certificate{
			Extensions:  []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}},
		{name: "unknown extended key usage without source extension", certificate: &x509.Certificate{
			Extensions:         []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
		}},
		{name: "critical authority information access extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Critical: true}}}},
		{name: "invalid negative path length", certificate: &x509.Certificate{MaxPathLen: -2}},
		{name: "path length zero flag mismatch", certificate: &x509.Certificate{MaxPathLen: 2, MaxPathLenZero: true}},
		{name: "path length without valid basic constraints", certificate: &x509.Certificate{MaxPathLenZero: true}},
		{name: "non-CA positive path length", certificate: &x509.Certificate{BasicConstraintsValid: true, MaxPathLen: 1}},
		{name: "basic constraints marker without parsed extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}}, BasicConstraintsValid: true}},
		{name: "basic constraints extension without parsed marker", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 19}}}}},
		{name: "basic constraints value mismatch", certificate: &x509.Certificate{
			Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 19}, Value: mustMarshalCertificateBasicConstraints(t, true, 2)}},
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
		}},
		{name: "malformed basic constraints source value", certificate: &x509.Certificate{
			Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 19}, Value: []byte{0x30, 0x02, 0x01}}},
			BasicConstraintsValid: true,
		}},
		{name: "constructed subject key identifier source value", certificate: &x509.Certificate{
			Extensions:   []pkix.Extension{{Id: []int{2, 5, 29, 14}, Value: mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 4, IsCompound: true, Bytes: []byte{1, 2, 3}})}},
			SubjectKeyId: []byte{1, 2, 3},
		}},
		{name: "critical name constraints without parsed data", certificate: &x509.Certificate{PermittedDNSDomainsCritical: true}},
		{name: "critical name constraints marker without parsed extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}}, PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"trusted.invalid"}}},
		{name: "name constraints criticality mismatch", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 30}, Critical: true}}, PermittedDNSDomains: []string{"trusted.invalid"}}},
		{name: "name constraints non-criticality mismatch", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 30}}}, PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"trusted.invalid"}}},
		{name: "name constraints without source extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}}}, PermittedDNSDomains: []string{"trusted.invalid"}}},
		{name: "name constraints value mismatch", certificate: &x509.Certificate{
			Extensions:          []pkix.Extension{{Id: []int{2, 5, 29, 30}, Value: mustMarshalCertificateNameConstraints(t, []string{"trusted.invalid"}, nil, nil, nil, nil, nil, nil, nil)}},
			PermittedDNSDomains: []string{"attacker.invalid"},
		}},
		{name: "malformed name constraints source value", certificate: &x509.Certificate{
			Extensions:          []pkix.Extension{{Id: []int{2, 5, 29, 30}, Value: []byte{0x30, 0x01, 0xa0}}},
			PermittedDNSDomains: []string{"trusted.invalid"},
		}},
		{name: "malformed exact mailbox name constraint", certificate: &x509.Certificate{
			Extensions:              []pkix.Extension{{Id: []int{2, 5, 29, 30}, Value: mustMarshalCertificateNameConstraints(t, nil, nil, nil, nil, []string{"owner..name@trusted.invalid"}, nil, nil, nil)}},
			PermittedEmailAddresses: []string{"owner..name@trusted.invalid"},
		}},
		{name: "malformed marker-only name constraints source value", certificate: &x509.Certificate{
			Extensions:                  []pkix.Extension{{Id: []int{2, 5, 29, 30}, Critical: true, Value: []byte{0x30, 0x00}}},
			PermittedDNSDomainsCritical: true,
			UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{2, 5, 29, 30}},
		}},
		{name: "zero serial number", certificate: &x509.Certificate{SerialNumber: big.NewInt(0)}},
		{name: "negative serial number", certificate: &x509.Certificate{SerialNumber: big.NewInt(-1)}},
		{name: "unknown key-usage bit", certificate: &x509.Certificate{KeyUsage: x509.KeyUsage(1 << 15)}},
		{name: "unknown extended key-usage value", certificate: &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsage(255)}}},
		{name: "known OID in unknown extended key-usage", certificate: &x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}}}},
		{name: "unhandled critical OID absent from extensions", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}}, UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{1, 2, 3, 5}}}},
		{name: "unhandled critical OID references non-critical extension", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}}, UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{1, 2, 3, 4}}}},
		{name: "critical unknown extension missing unhandled marker", certificate: &x509.Certificate{Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true}}}},
		{name: "unknown signature algorithm", certificate: &x509.Certificate{SignatureAlgorithm: x509.SignatureAlgorithm(255)}},
		{name: "unknown public-key algorithm", certificate: &x509.Certificate{PublicKeyAlgorithm: x509.PublicKeyAlgorithm(255)}},
		{name: "RSA signature with Ed25519 public-key algorithm", certificate: &x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA, PublicKeyAlgorithm: x509.Ed25519}},
		{name: "RSA algorithm with Ed25519 key", certificate: &x509.Certificate{PublicKeyAlgorithm: x509.RSA, PublicKey: ed25519.PublicKey(bytes.Repeat([]byte{1}, ed25519.PublicKeySize))}},
		{name: "validity interval with only NotBefore", certificate: &x509.Certificate{NotBefore: time.Unix(10, 0)}},
		{name: "validity interval with only NotAfter", certificate: &x509.Certificate{NotAfter: time.Unix(20, 0)}},
		{name: "inverted validity interval", certificate: &x509.Certificate{NotBefore: time.Unix(20, 0), NotAfter: time.Unix(10, 0)}},
		{name: "missing derived policy identifier", certificate: &x509.Certificate{Policies: []x509.OID{policy}}},
		{name: "contradictory derived policy identifier", certificate: &x509.Certificate{Policies: []x509.OID{policy}, PolicyIdentifiers: []asn1.ObjectIdentifier{{2, 5, 29, 32, 1}}}},
		{name: "oversized subject common name", certificate: &x509.Certificate{Subject: pkix.Name{CommonName: strings.Repeat("n", maxMCPTLSCertificateStringBytes+1)}}},
		{name: "invalid policy OID arc", certificate: &x509.Certificate{PolicyIdentifiers: []asn1.ObjectIdentifier{{2, 5, -1}}}},
		{name: "oversized permitted DNS constraint", certificate: &x509.Certificate{PermittedDNSDomains: []string{strings.Repeat("d", maxMCPTLSCertificateStringBytes+1)}}},
		{name: "invalid permitted IP constraint", certificate: &x509.Certificate{PermittedIPRanges: []*net.IPNet{{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPMask{0xff, 0xff, 0xff}}}}},
		{name: "non-contiguous permitted IP mask", certificate: &x509.Certificate{PermittedIPRanges: []*net.IPNet{{IP: net.IPv4(127, 0, 0, 0), Mask: net.IPMask{0xff, 0x01, 0, 0}}}}},
		{name: "mismatched permitted IP mask width", certificate: &x509.Certificate{PermittedIPRanges: []*net.IPNet{{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.IPMask{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}}}},
		{name: "nil RSA public key modulus", certificate: &x509.Certificate{PublicKey: &rsa.PublicKey{E: 3}}},
		{name: "unsupported public key type", certificate: &x509.Certificate{PublicKey: struct{}{}}},
		{name: "wrong Ed25519 public key size", certificate: &x509.Certificate{PublicKey: ed25519.PublicKey{1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := *base
			state := tlsStateForTest
			state.PeerCertificates = []*x509.Certificate{tc.certificate}
			request.TLS = &state
			if RequireDirectTLS(&request) {
				t.Fatal("RequireDirectTLS accepted malformed certificate metadata")
			}
		})
	}
}

func mustCertificateOID(t *testing.T, value string) x509.OID {
	t.Helper()
	oid, err := x509.ParseOID(value)
	if err != nil {
		t.Fatalf("parse certificate OID %q: %v", value, err)
	}
	return oid
}

func mustMarshalCertificateValue(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("marshal certificate value: %v", err)
	}
	return encoded
}

func mustMarshalCertificateName(t *testing.T, name pkix.Name) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(name.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustMarshalCertificateNameWithTrailingOuterField(t *testing.T, name pkix.Name, trailing []byte) []byte {
	t.Helper()
	encoded := mustMarshalCertificateName(t, name)
	return append(append([]byte(nil), encoded...), trailing...)
}

func mustParseCertificateName(t *testing.T, encoded []byte) pkix.Name {
	t.Helper()
	var sequence pkix.RDNSequence
	remaining, err := asn1.Unmarshal(encoded, &sequence)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("parse certificate name: %v", err)
	}
	var name pkix.Name
	name.FillFromRDNSequence(&sequence)
	return name
}

func ptrToInt64(value int64) *int64 {
	return &value
}

func mustMarshalCertificatePolicyConstraints(t *testing.T, requireExplicitPolicy, inhibitPolicyMapping *int64) []byte {
	t.Helper()
	var fields []byte
	appendField := func(tag int, value *int64) {
		if value == nil {
			return
		}
		encoded, err := asn1.Marshal(*value)
		if err != nil {
			t.Fatalf("marshal policy constraint integer: %v", err)
		}
		var integer asn1.RawValue
		if rest, err := asn1.Unmarshal(encoded, &integer); err != nil || len(rest) != 0 {
			t.Fatalf("decode policy constraint integer: %v", err)
		}
		fields = append(fields, mustMarshalCertificateValue(t, asn1.RawValue{
			Class: 2, Tag: tag, Bytes: integer.Bytes,
		})...)
	}
	appendField(0, requireExplicitPolicy)
	appendField(1, inhibitPolicyMapping)
	return mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: fields})
}

func mustMarshalCertificateKeyUsage(t *testing.T, usage x509.KeyUsage) []byte {
	t.Helper()
	var bytesValue [2]byte
	bytesValue[0] = reverseCertificateKeyUsageBits(byte(usage))
	bytesValue[1] = reverseCertificateKeyUsageBits(byte(usage >> 8))
	length := 1
	if bytesValue[1] != 0 {
		length = 2
	}
	bitLength := length * 8
	for index := length - 1; index >= 0; index-- {
		for bit := 0; bit < 8 && bytesValue[index]&(1<<uint(bit)) == 0; bit++ {
			bitLength--
		}
		if bitLength != (index * 8) {
			break
		}
	}
	return mustMarshalCertificateValue(t, asn1.BitString{
		Bytes:     bytesValue[:length],
		BitLength: bitLength,
	})
}

func mustMarshalCertificateExtendedKeyUsages(t *testing.T, usages []asn1.ObjectIdentifier) []byte {
	t.Helper()
	return mustMarshalCertificateValue(t, usages)
}

func mustMarshalCertificateExtendedKeyUsagesWithTrailingOuterField(t *testing.T, usages []asn1.ObjectIdentifier, trailing []byte) []byte {
	t.Helper()
	value := mustMarshalCertificateExtendedKeyUsages(t, usages)
	return append(append([]byte(nil), value...), trailing...)
}

func mustMarshalCertificateAuthorityInfoAccess(t *testing.T, ocspServers, issuingCertificateURLs []string) []byte {
	t.Helper()
	var accessDescriptions []byte
	appendAccessDescription := func(method asn1.ObjectIdentifier, location string) {
		methodDER := mustMarshalCertificateValue(t, method)
		locationDER := mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(location)})
		content := append(append([]byte(nil), methodDER...), locationDER...)
		accessDescriptions = append(accessDescriptions, mustMarshalCertificateValue(t, asn1.RawValue{
			Class: 0, Tag: 16, IsCompound: true, Bytes: content,
		})...)
	}
	for _, location := range ocspServers {
		appendAccessDescription(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}, location)
	}
	for _, location := range issuingCertificateURLs {
		appendAccessDescription(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}, location)
	}
	return mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: accessDescriptions})
}

func mustMarshalCertificateAuthorityInfoAccessWithTrailingOuterField(t *testing.T, ocspServers, issuingCertificateURLs []string, trailing []byte) []byte {
	t.Helper()
	value := mustMarshalCertificateAuthorityInfoAccess(t, ocspServers, issuingCertificateURLs)
	return append(append([]byte(nil), value...), trailing...)
}

func mustMarshalCertificateIgnoredAuthorityInfoAccessLocation(t *testing.T) []byte {
	t.Helper()
	method := mustMarshalCertificateValue(t, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1})
	accessDescription := mustMarshalCertificateValue(t, asn1.RawValue{
		Class:      0,
		Tag:        16,
		IsCompound: true,
		Bytes:      append(method, 0x85, 0x02, 0x01),
	})
	return mustMarshalCertificateValue(t, asn1.RawValue{
		Class:      0,
		Tag:        16,
		IsCompound: true,
		Bytes:      accessDescription,
	})
}

func mustMarshalCertificateIgnoredCRLDistributionPointName(t *testing.T) []byte {
	t.Helper()
	fullName := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 2, Tag: 0, IsCompound: true,
		Bytes: []byte{0x85, 0x02, 0x01},
	})
	distributionName := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 2, Tag: 0, IsCompound: true, Bytes: fullName,
	})
	distributionPoint := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 16, IsCompound: true, Bytes: distributionName,
	})
	return mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 16, IsCompound: true, Bytes: distributionPoint,
	})
}

func reverseCertificateKeyUsageBits(value byte) byte {
	var reversed byte
	for bit := 0; bit < 8; bit++ {
		reversed |= (value >> uint(bit) & 1) << uint(7-bit)
	}
	return reversed
}

func mustMarshalCertificateCRLDistributionPoints(t *testing.T, uris ...string) []byte {
	t.Helper()
	generalNamesDER := make([]byte, 0)
	for _, uri := range uris {
		generalNamesDER = append(generalNamesDER, mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(uri)})...)
	}
	fullNameDER := mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: generalNamesDER})
	distributionNameDER := mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: fullNameDER})
	distributionPointDER := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: distributionNameDER})
	return mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: distributionPointDER})
}

func mustMarshalCertificateCRLDistributionPointsWithTrailingOuterField(t *testing.T, uris []string, trailing []byte) []byte {
	t.Helper()
	value := mustMarshalCertificateCRLDistributionPoints(t, uris...)
	return append(append([]byte(nil), value...), trailing...)
}

func mustMarshalCertificateBasicConstraints(t *testing.T, isCA bool, maxPathLen int) []byte {
	t.Helper()
	type basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	value, err := asn1.Marshal(basicConstraints{IsCA: isCA, MaxPathLen: maxPathLen})
	if err != nil {
		t.Fatalf("marshal basic constraints: %v", err)
	}
	return value
}

func mustMarshalCertificatePolicyMappings(t *testing.T, mappings []x509.PolicyMapping) []byte {
	t.Helper()
	var encodedMappings []byte
	for _, mapping := range mappings {
		issuer, err := mapping.IssuerDomainPolicy.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal issuer policy OID: %v", err)
		}
		subject, err := mapping.SubjectDomainPolicy.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal subject policy OID: %v", err)
		}
		issuerDER := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 6, Bytes: issuer})
		subjectDER := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 6, Bytes: subject})
		encodedMappings = append(encodedMappings, mustMarshalCertificateValue(t, asn1.RawValue{
			Class: 0, Tag: 16, IsCompound: true,
			Bytes: append(append([]byte(nil), issuerDER...), subjectDER...),
		})...)
	}
	return mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: encodedMappings})
}

func mustMarshalCertificatePolicyMappingsWithTrailingOuterField(t *testing.T, mappings []x509.PolicyMapping, trailing []byte) []byte {
	t.Helper()
	value := mustMarshalCertificatePolicyMappings(t, mappings)
	return append(append([]byte(nil), value...), trailing...)
}

func mustMarshalCertificatePolicyMappingWithTrailingField(t *testing.T, mapping x509.PolicyMapping, trailing []byte) []byte {
	t.Helper()
	issuer, err := mapping.IssuerDomainPolicy.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal issuer policy OID: %v", err)
	}
	subject, err := mapping.SubjectDomainPolicy.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal subject policy OID: %v", err)
	}
	issuerDER := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 6, Bytes: issuer})
	subjectDER := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 6, Bytes: subject})
	mappingDER := append(append(append([]byte(nil), issuerDER...), subjectDER...), trailing...)
	encodedMapping := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: mappingDER})
	return mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: encodedMapping})
}

func mustMarshalCertificatePolicies(t *testing.T, policies []x509.OID) []byte {
	t.Helper()
	var encodedPolicies []byte
	for _, policy := range policies {
		der, err := policy.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal certificate policy OID: %v", err)
		}
		policyOID := mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 6, Bytes: der})
		encodedPolicies = append(encodedPolicies, mustMarshalCertificateValue(t, asn1.RawValue{
			Class: 0, Tag: 16, IsCompound: true, Bytes: policyOID,
		})...)
	}
	return mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: encodedPolicies})
}

func mustMarshalCertificatePoliciesWithTrailingOuterField(t *testing.T, policies []x509.OID, trailing []byte) []byte {
	t.Helper()
	value := mustMarshalCertificatePolicies(t, policies)
	return append(append([]byte(nil), value...), trailing...)
}

func mustMarshalCertificateSubjectAltNames(t *testing.T, dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) []byte {
	t.Helper()
	values := make([]asn1.RawValue, 0, len(dnsNames)+len(emailAddresses)+len(ipAddresses)+len(uris))
	for _, value := range emailAddresses {
		values = append(values, asn1.RawValue{Class: 2, Tag: 1, Bytes: []byte(value)})
	}
	for _, value := range dnsNames {
		values = append(values, asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(value)})
	}
	for _, value := range uris {
		values = append(values, asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(value.String())})
	}
	for _, value := range ipAddresses {
		values = append(values, asn1.RawValue{Class: 2, Tag: 7, Bytes: []byte(value)})
	}
	return mustMarshalCertificateValue(t, values)
}

func mustMarshalCertificateSubjectAltNamesWithTrailingOuterField(t *testing.T, dnsNames []string, trailing []byte) []byte {
	t.Helper()
	value := mustMarshalCertificateSubjectAltNames(t, dnsNames, nil, nil, nil)
	return append(append([]byte(nil), value...), trailing...)
}

func mustMarshalCertificateNameConstraints(t *testing.T, permittedDNS, excludedDNS []string,
	permittedIPs, excludedIPs []*net.IPNet, permittedEmails, excludedEmails,
	permittedURIs, excludedURIs []string) []byte {
	t.Helper()
	marshalSubtrees := func(dnsNames, emailAddresses, uriDomains []string, ipRanges []*net.IPNet) []byte {
		var subtrees []byte
		for _, name := range emailAddresses {
			subtrees = append(subtrees, mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 1, Bytes: []byte(name)})...)
		}
		for _, name := range dnsNames {
			subtrees = append(subtrees, mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(name)})...)
		}
		for _, name := range uriDomains {
			subtrees = append(subtrees, mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(name)})...)
		}
		for _, network := range ipRanges {
			if network == nil {
				t.Fatal("nil name-constraint network")
			}
			value := append(append([]byte(nil), network.IP...), network.Mask...)
			subtrees = append(subtrees, mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 7, Bytes: value})...)
		}
		var encoded []byte
		for remaining := subtrees; len(remaining) > 0; {
			base, rest, err := readASN1ElementForTest(remaining)
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded, mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: base})...)
			remaining = rest
		}
		return mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: encoded})
	}

	var fields []byte
	if len(permittedDNS)+len(permittedEmails)+len(permittedURIs)+len(permittedIPs) > 0 {
		value := marshalSubtrees(permittedDNS, permittedEmails, permittedURIs, permittedIPs)
		fields = append(fields, mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: certificateSequenceContentForTest(t, value)})...)
	}
	if len(excludedDNS)+len(excludedEmails)+len(excludedURIs)+len(excludedIPs) > 0 {
		value := marshalSubtrees(excludedDNS, excludedEmails, excludedURIs, excludedIPs)
		fields = append(fields, mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: certificateSequenceContentForTest(t, value)})...)
	}
	return mustMarshalCertificateValue(t, asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: fields})
}

func mustMarshalCertificateNameConstraintsWithTrailingOuterField(t *testing.T, permittedDNS []string, trailing []byte) []byte {
	t.Helper()
	value := mustMarshalCertificateNameConstraints(t, permittedDNS, nil, nil, nil, nil, nil, nil, nil)
	return append(append([]byte(nil), value...), trailing...)
}

func mustMarshalCertificateNameConstraintsWithEmptySide(t *testing.T, emptyTag, populatedTag int, domain string) []byte {
	t.Helper()
	base := mustMarshalCertificateValue(t, asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(domain)})
	subtree := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 16, IsCompound: true, Bytes: base,
	})
	subtrees := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 16, IsCompound: true, Bytes: subtree,
	})
	empty := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 2, Tag: emptyTag, IsCompound: true,
	})
	populated := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 2, Tag: populatedTag, IsCompound: true,
		Bytes: certificateSequenceContentForTest(t, subtrees),
	})
	fields := make([]byte, 0, len(empty)+len(populated))
	for tag := 0; tag <= 1; tag++ {
		if tag == emptyTag {
			fields = append(fields, empty...)
		} else {
			fields = append(fields, populated...)
		}
	}
	return mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 16, IsCompound: true, Bytes: fields,
	})
}

func certificateSequenceContentForTest(t *testing.T, value []byte) []byte {
	t.Helper()
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(value, &raw)
	if err != nil || len(rest) != 0 || raw.Class != 0 || raw.Tag != 16 || !raw.IsCompound {
		t.Fatalf("invalid test sequence: %x", value)
	}
	return raw.Bytes
}

func readASN1ElementForTest(value []byte) ([]byte, []byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(value, &raw)
	if err != nil {
		return nil, nil, err
	}
	return raw.FullBytes, rest, nil
}

func TestRequireDirectTLSAcceptsValidCertificateMetadata(t *testing.T) {
	dnsNames := []string{"relay.invalid"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1").To4()}
	uris := []*url.URL{{Scheme: "https", Host: "relay.invalid", Path: "/cert"}}
	for _, certificate := range []*x509.Certificate{
		{
			DNSNames:    dnsNames,
			IPAddresses: ipAddresses,
			URIs:        uris,
			Extensions:  []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: mustMarshalCertificateSubjectAltNames(t, dnsNames, nil, ipAddresses, uris)}},
		},
		{
			SignatureAlgorithm: x509.SHA256WithRSA,
			PublicKeyAlgorithm: x509.RSA,
		},
		{
			NotBefore: time.Unix(10, 0),
			NotAfter:  time.Unix(20, 0),
		},
		{
			PermittedDNSDomainsCritical: true,
			UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{2, 5, 29, 30}},
		},
		{
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
		},
	} {
		request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
		state := tlsStateForTest
		state.PeerCertificates = []*x509.Certificate{certificate}
		request.TLS = &state
		if !RequireDirectTLS(request) {
			t.Fatal("RequireDirectTLS rejected parser-compatible certificate metadata")
		}
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleCertificateNameSources(t *testing.T) {
	encoded := mustMarshalCertificateName(t, pkix.Name{CommonName: "relay.invalid", Organization: []string{"AI Relay"}})
	name := mustParseCertificateName(t, encoded)
	certificate := &x509.Certificate{
		RawSubject: encoded,
		RawIssuer:  encoded,
		Subject:    name,
		Issuer:     name,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{certificate}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible DER certificate names")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleCertificateNameOuterTrailingField(t *testing.T) {
	name := pkix.Name{CommonName: "relay.invalid", Organization: []string{"AI Relay"}}
	encoded := mustMarshalCertificateName(t, name)
	name = mustParseCertificateName(t, encoded)
	trailing := mustMarshalCertificateValue(t, int64(7))
	certificate := &x509.Certificate{
		RawSubject: mustMarshalCertificateNameWithTrailingOuterField(t, name, trailing),
		RawIssuer:  mustMarshalCertificateNameWithTrailingOuterField(t, name, trailing),
		Subject:    name,
		Issuer:     name,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{certificate}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible trailing certificate name fields")
	}
}

func TestRequireDirectTLSRejectsMismatchedCertificateNameSource(t *testing.T) {
	want := mustParseCertificateName(t, mustMarshalCertificateName(t, pkix.Name{CommonName: "relay.invalid"}))
	other := mustParseCertificateName(t, mustMarshalCertificateName(t, pkix.Name{CommonName: "attacker.invalid"}))
	for _, tc := range []struct {
		name       string
		rawSubject []byte
		rawIssuer  []byte
		subject    pkix.Name
		issuer     pkix.Name
	}{
		{name: "subject", rawSubject: mustMarshalCertificateName(t, other), subject: want},
		{name: "issuer", rawIssuer: mustMarshalCertificateName(t, other), issuer: want},
		{name: "malformed subject", rawSubject: []byte{0x30, 0x01, 0x00}},
		{name: "malformed issuer", rawIssuer: []byte{0x30, 0x01, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certificate := &x509.Certificate{
				RawSubject: tc.rawSubject,
				RawIssuer:  tc.rawIssuer,
				Subject:    tc.subject,
				Issuer:     tc.issuer,
			}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			state := tlsStateForTest
			state.PeerCertificates = []*x509.Certificate{certificate}
			request.TLS = &state
			if RequireDirectTLS(request) {
				t.Fatal("RequireDirectTLS accepted incoherent DER certificate name metadata")
			}
		})
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleCertificatePublicKeySource(t *testing.T) {
	key := &rsa.PublicKey{N: big.NewInt(3233), E: 17}
	raw, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		RawSubjectPublicKeyInfo: raw,
		PublicKeyAlgorithm:      x509.RSA,
		PublicKey:               key,
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible DER public-key source")
	}
}

func TestRequireDirectTLSRejectsMismatchedCertificatePublicKeySource(t *testing.T) {
	sourceKey := &rsa.PublicKey{N: big.NewInt(3233), E: 17}
	otherKey := &rsa.PublicKey{N: big.NewInt(65537), E: 17}
	raw, err := x509.MarshalPKIXPublicKey(sourceKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		key  *rsa.PublicKey
	}{
		{name: "mismatched key", raw: raw, key: otherKey},
		{name: "malformed source", raw: []byte{0x30, 0x01, 0x00}, key: sourceKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			state := tlsStateForTest
			state.PeerCertificates = []*x509.Certificate{{
				RawSubjectPublicKeyInfo: tc.raw,
				PublicKeyAlgorithm:      x509.RSA,
				PublicKey:               tc.key,
			}}
			request.TLS = &state
			if RequireDirectTLS(request) {
				t.Fatal("RequireDirectTLS accepted incoherent DER public-key source")
			}
		})
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleCompleteCertificateSource(t *testing.T) {
	certificate := mustCreateParsedCertificate(t)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{certificate}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible complete certificate source")
	}
}

func TestRequireDirectTLSRejectsIncoherentCompleteCertificateSource(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{name: "malformed DER", mutate: func(certificate *x509.Certificate) {
			certificate.Raw = []byte{0x30, 0x01, 0x00}
		}},
		{name: "mismatched parsed subject", mutate: func(certificate *x509.Certificate) {
			certificate.Subject.CommonName = "attacker.invalid"
		}},
		{name: "mismatched TBS source", mutate: func(certificate *x509.Certificate) {
			certificate.RawTBSCertificate = append([]byte(nil), certificate.RawTBSCertificate...)
			certificate.RawTBSCertificate[len(certificate.RawTBSCertificate)-1] ^= 0x01
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certificate := mustCreateParsedCertificate(t)
			tc.mutate(certificate)
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			state := tlsStateForTest
			state.PeerCertificates = []*x509.Certificate{certificate}
			request.TLS = &state
			if RequireDirectTLS(request) {
				t.Fatal("RequireDirectTLS accepted incoherent complete certificate source")
			}
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedCompleteCertificateSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	certificate := mustCreateParsedCertificate(t)
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Subject.CommonName = "attacker.invalid"
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated complete certificate status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated complete certificate: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedCertificateTBSSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{RawTBSCertificate: []byte{0x01, 0x02, 0x03}}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.RawTBSCertificate = []byte{0x30, 0x00}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated TBS source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated TBS source: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func mustCreateParsedCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.invalid"},
		NotBefore:    time.Unix(10, 0).UTC(),
		NotAfter:     time.Unix(20, 0).UTC(),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestRequireDirectTLSAcceptsEmptyParserCompatibleCertificateKeyIdentifiers(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{
			{Id: []int{2, 5, 29, 14}, Value: []byte{0x04, 0x00}},
			{Id: []int{2, 5, 29, 35}, Value: []byte{0x30, 0x00}},
		},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible empty key-identifier sources")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleSubjectAltNameRepresentation(t *testing.T) {
	dnsNames := []string{"relay.invalid"}
	emailAddresses := []string{"owner@relay.invalid"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1").To4()}
	uris := []*url.URL{{Scheme: "https", Host: "relay.invalid"}}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:     []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: mustMarshalCertificateSubjectAltNames(t, dnsNames, emailAddresses, ipAddresses, uris)}},
		DNSNames:       dnsNames,
		EmailAddresses: emailAddresses,
		IPAddresses:    ipAddresses,
		URIs:           uris,
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible Subject Alternative Name representation")
	}
}

func TestRequireDirectTLSRejectsLeadingDotSubjectAltNameURIHost(t *testing.T) {
	uri := &url.URL{Scheme: "https", Host: ".relay.invalid"}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 17},
			Value: mustMarshalCertificateSubjectAltNames(t, nil, nil, nil, []*url.URL{uri}),
		}},
		URIs: []*url.URL{uri},
	}}
	request.TLS = &state
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted a leading-dot Subject Alternative Name URI host")
	}
}

func TestRequireDirectTLSAcceptsEmptyParserCompatibleSubjectAltName(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: mustMarshalCertificateSubjectAltNames(t, nil, nil, nil, nil)}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected an empty parser-compatible Subject Alternative Name")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleSubjectAltNameOuterTrailingField(t *testing.T) {
	dnsNames := []string{"relay.invalid"}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 17},
			Value: mustMarshalCertificateSubjectAltNamesWithTrailingOuterField(t, dnsNames, mustMarshalCertificateValue(t, int64(7))),
		}},
		DNSNames: dnsNames,
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible outer Subject Alternative Name trailing field")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleExtendedKeyUsageRepresentation(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 37},
			Value: mustMarshalCertificateValue(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}, {1, 2, 3, 4}}),
		}},
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible extended key usage representation")
	}
}

func TestRequireDirectTLSAcceptsEmptyParserCompatibleExtendedKeyUsage(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 37}, Value: []byte{0x30, 0x00}}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected an empty parser-compatible Extended Key Usage")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleExtendedKeyUsageOuterTrailingField(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 37},
			Value: mustMarshalCertificateExtendedKeyUsagesWithTrailingOuterField(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}}, mustMarshalCertificateValue(t, int64(7))),
		}},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible outer Extended Key Usage trailing field")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleKeyUsageRepresentation(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 15}, Value: mustMarshalCertificateKeyUsage(t, x509.KeyUsageDigitalSignature)}},
		KeyUsage:   x509.KeyUsageDigitalSignature,
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible key usage representation")
	}
}

func TestRequireDirectTLSAcceptsEmptyParserCompatibleKeyUsage(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 15}, Value: []byte{0x03, 0x01, 0x00}}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected an empty parser-compatible Key Usage")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleAuthorityInfoAccessRepresentation(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:            []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: mustMarshalCertificateAuthorityInfoAccess(t, []string{"https://ocsp.relay.invalid"}, []string{"https://ca.relay.invalid/issuer.crt"})}},
		OCSPServer:            []string{"https://ocsp.relay.invalid"},
		IssuingCertificateURL: []string{"https://ca.relay.invalid/issuer.crt"},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible Authority Information Access representation")
	}
}

func TestRequireDirectTLSAcceptsEmptyParserCompatibleAuthorityInfoAccess(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: []byte{0x30, 0x00}}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected an empty parser-compatible Authority Information Access value")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleAuthorityInfoAccessOuterTrailingField(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1},
			Value: mustMarshalCertificateAuthorityInfoAccessWithTrailingOuterField(t,
				[]string{"https://ocsp.relay.invalid"}, nil, mustMarshalCertificateValue(t, int64(7))),
		}},
		OCSPServer: []string{"https://ocsp.relay.invalid"},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible outer Authority Information Access trailing field")
	}
}

func TestRequireDirectTLSAcceptsIgnoredMalformedAuthorityInfoAccessLocation(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: mustMarshalCertificateIgnoredAuthorityInfoAccessLocation(t)}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected a parser-compatible ignored AIA location")
	}
}

func TestRequireDirectTLSAcceptsIgnoredMalformedCRLDistributionPointName(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 31}, Value: mustMarshalCertificateIgnoredCRLDistributionPointName(t)}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected a parser-compatible ignored CRL distribution-point name")
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedIgnoredAuthorityInfoAccessLocationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{Extensions: []pkix.Extension{{
		Id:    []int{1, 3, 6, 1, 5, 5, 7, 1, 1},
		Value: mustMarshalCertificateIgnoredAuthorityInfoAccessLocation(t),
	}}}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x30, 0x03, 0x30, 0x01, 0x86}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated ignored AIA location status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated ignored AIA location: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedIgnoredCRLDistributionPointNameBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{Extensions: []pkix.Extension{{
		Id:    []int{2, 5, 29, 31},
		Value: mustMarshalCertificateIgnoredCRLDistributionPointName(t),
	}}}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x30, 0x09, 0x30, 0x07, 0xa0, 0x05, 0xa0, 0x03, 0x86, 0x02, 0x01}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated ignored CRL distribution-point name status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated ignored CRL distribution-point name: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestRequireDirectTLSAcceptsParserCompatibleCRLDistributionPointValues(t *testing.T) {
	uris := []string{"https://crl.relay.invalid/root.crl", "https://crl.relay.invalid/intermediate.crl"}
	encoded := mustMarshalCertificateCRLDistributionPoints(t, uris...)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 31}, Value: encoded}},
		CRLDistributionPoints: append([]string(nil), uris...),
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible CRL distribution-point values")
	}
}

func TestRequireDirectTLSAcceptsEmptyCRLDistributionPointValues(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 31}, Value: []byte{0x30, 0x00}}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected an empty parser-visible CRL distribution-point list")
	}
}

func TestRequireDirectTLSRejectsMalformedEmptyCRLDistributionPointSource(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 31}, Value: []byte{0x30, 0x01, 0x30}}},
	}}
	request.TLS = &state
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted a malformed empty CRL distribution-point source")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleCRLDistributionPointRepresentation(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 31}, Value: mustMarshalCertificateCRLDistributionPoints(t, "https://crl.relay.invalid/root.crl")}},
		CRLDistributionPoints: []string{"https://crl.relay.invalid/root.crl"},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible CRL distribution-point representation")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleCRLDistributionPointOuterTrailingField(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	uris := []string{"https://crl.relay.invalid/root.crl"}
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 31},
			Value: mustMarshalCertificateCRLDistributionPointsWithTrailingOuterField(t, uris, mustMarshalCertificateValue(t, int64(7))),
		}},
		CRLDistributionPoints: append([]string(nil), uris...),
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible outer CRL distribution-point trailing field")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleBasicConstraintsMetadata(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 19}, Value: []byte{0x30, 0x00}}},
		BasicConstraintsValid: true,
		MaxPathLen:            -1,
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible basic constraints metadata")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleBasicConstraintsValues(t *testing.T) {
	for _, test := range []struct {
		name        string
		isCA        bool
		maxPathLen  int
		maxPathZero bool
	}{
		{name: "CA without path limit", isCA: true, maxPathLen: -1},
		{name: "CA with zero path limit", isCA: true, maxPathLen: 0, maxPathZero: true},
		{name: "non-CA defaults", isCA: false, maxPathLen: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			state := tlsStateForTest
			state.PeerCertificates = []*x509.Certificate{{
				Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 19}, Value: mustMarshalCertificateBasicConstraints(t, test.isCA, test.maxPathLen)}},
				BasicConstraintsValid: true,
				IsCA:                  test.isCA,
				MaxPathLen:            test.maxPathLen,
				MaxPathLenZero:        test.maxPathZero,
			}}
			request.TLS = &state
			if !RequireDirectTLS(request) {
				t.Fatal("RequireDirectTLS rejected parser-compatible basic constraints values")
			}
		})
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleNameConstraintsRepresentation(t *testing.T) {
	for _, certificate := range []*x509.Certificate{
		{
			Extensions:                  []pkix.Extension{{Id: []int{2, 5, 29, 30}, Critical: true, Value: mustMarshalCertificateNameConstraints(t, []string{"trusted.invalid"}, nil, nil, nil, nil, nil, nil, nil)}},
			PermittedDNSDomainsCritical: true,
			PermittedDNSDomains:         []string{"trusted.invalid"},
		},
		{
			Extensions:          []pkix.Extension{{Id: []int{2, 5, 29, 30}, Value: mustMarshalCertificateNameConstraints(t, nil, []string{"blocked.invalid"}, nil, nil, nil, nil, []string{"uri.invalid"}, nil)}},
			ExcludedDNSDomains:  []string{"blocked.invalid"},
			PermittedURIDomains: []string{"uri.invalid"},
		},
		{
			Extensions:              []pkix.Extension{{Id: []int{2, 5, 29, 30}, Value: mustMarshalCertificateNameConstraints(t, nil, nil, nil, nil, []string{"owner@relay.invalid"}, nil, nil, nil)}},
			PermittedEmailAddresses: []string{"owner@relay.invalid"},
		},
		{
			Extensions:              []pkix.Extension{{Id: []int{2, 5, 29, 30}, Value: mustMarshalCertificateNameConstraints(t, nil, nil, nil, nil, []string{"\"owner name\"@relay.invalid"}, nil, nil, nil)}},
			PermittedEmailAddresses: []string{"\"owner name\"@relay.invalid"},
		},
	} {
		request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
		state := tlsStateForTest
		state.PeerCertificates = []*x509.Certificate{certificate}
		request.TLS = &state
		if !RequireDirectTLS(request) {
			t.Fatal("RequireDirectTLS rejected parser-compatible name constraints representation")
		}
	}
}

func TestRequireDirectTLSAcceptsAsymmetricEmptyNameConstraintsSide(t *testing.T) {
	for _, test := range []struct {
		name              string
		emptyTag          int
		populatedTag      int
		certificateFields func(*x509.Certificate)
	}{
		{
			name:         "empty permitted",
			emptyTag:     0,
			populatedTag: 1,
			certificateFields: func(certificate *x509.Certificate) {
				certificate.ExcludedDNSDomains = []string{"blocked.invalid"}
			},
		},
		{
			name:         "empty excluded",
			emptyTag:     1,
			populatedTag: 0,
			certificateFields: func(certificate *x509.Certificate) {
				certificate.PermittedDNSDomains = []string{"blocked.invalid"}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate := &x509.Certificate{
				Extensions: []pkix.Extension{{
					Id:    []int{2, 5, 29, 30},
					Value: mustMarshalCertificateNameConstraintsWithEmptySide(t, test.emptyTag, test.populatedTag, "blocked.invalid"),
				}},
			}
			test.certificateFields(certificate)
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			state := tlsStateForTest
			state.PeerCertificates = []*x509.Certificate{certificate}
			request.TLS = &state
			if !RequireDirectTLS(request) {
				t.Fatal("RequireDirectTLS rejected parser-compatible asymmetric empty Name Constraints side")
			}
		})
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleNameConstraintsOuterTrailingField(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 30},
			Value: mustMarshalCertificateNameConstraintsWithTrailingOuterField(t, []string{"trusted.invalid"}, mustMarshalCertificateValue(t, int64(7))),
		}},
		PermittedDNSDomains: []string{"trusted.invalid"},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible outer Name Constraints trailing field")
	}
}

func TestRequireDirectTLSAcceptsParserCompatiblePolicyConstraintsRepresentation(t *testing.T) {
	for _, certificate := range []*x509.Certificate{
		{
			Extensions:       []pkix.Extension{{Id: []int{2, 5, 29, 54}, Value: mustMarshalCertificateValue(t, int64(1))}},
			InhibitAnyPolicy: 1,
		},
		{
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 36}, Value: []byte{0x30, 0x00}}},
		},
		{
			Extensions:                []pkix.Extension{{Id: []int{2, 5, 29, 36}, Value: mustMarshalCertificatePolicyConstraints(t, ptrToInt64(0), nil)}},
			RequireExplicitPolicy:     0,
			RequireExplicitPolicyZero: true,
		},
	} {
		request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
		state := tlsStateForTest
		state.PeerCertificates = []*x509.Certificate{certificate}
		request.TLS = &state
		if !RequireDirectTLS(request) {
			t.Fatal("RequireDirectTLS rejected parser-compatible policy constraints representation")
		}
	}
}

func TestRequireDirectTLSAcceptsParserCompatiblePolicyConstraintValues(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{
			{Id: []int{2, 5, 29, 36}, Value: mustMarshalCertificatePolicyConstraints(t, ptrToInt64(4), ptrToInt64(3))},
			{Id: []int{2, 5, 29, 54}, Value: mustMarshalCertificateValue(t, int64(2))},
		},
		RequireExplicitPolicy: 4,
		InhibitPolicyMapping:  3,
		InhibitAnyPolicy:      2,
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible policy constraint values")
	}
}

func TestRequireDirectTLSAcceptsParserCompatiblePolicyMappingsRepresentation(t *testing.T) {
	mappings := []x509.PolicyMapping{{
		IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
		SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
	}}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:     []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: mustMarshalCertificatePolicyMappings(t, mappings)}},
		PolicyMappings: mappings,
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible policy-mapping representation")
	}
}

func TestRequireDirectTLSAcceptsParserCompatiblePolicyMappingTrailingFields(t *testing.T) {
	mappings := []x509.PolicyMapping{{
		IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
		SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
	}}
	value := mustMarshalCertificatePolicyMappingWithTrailingField(t, mappings[0], mustMarshalCertificateValue(t, int64(7)))
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:     []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: value}},
		PolicyMappings: mappings,
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible trailing policy-mapping field")
	}
}

func TestRequireDirectTLSAcceptsParserCompatiblePolicyMappingOuterTrailingField(t *testing.T) {
	mappings := []x509.PolicyMapping{{
		IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
		SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
	}}
	value := mustMarshalCertificatePolicyMappingsWithTrailingOuterField(t, mappings, mustMarshalCertificateValue(t, int64(7)))
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:     []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: value}},
		PolicyMappings: mappings,
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible outer policy-mapping trailing field")
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedParserCompatiblePolicyMappingTrailingField(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	mappings := []x509.PolicyMapping{{
		IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
		SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
	}}
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions:     []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: mustMarshalCertificatePolicyMappings(t, mappings)}},
		PolicyMappings: mappings,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = mustMarshalCertificatePolicyMappingsWithTrailingOuterField(t, mappings, mustMarshalCertificateValue(t, int64(7)))
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced parser-compatible policy-mapping trailing field status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after parser-compatible body mutation: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestRequireDirectTLSAcceptsEmptyParserCompatiblePolicyMappingsSource(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: mustMarshalCertificatePolicyMappings(t, nil)}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected an empty parser-compatible policy-mapping source")
	}
}

func TestRequireDirectTLSRejectsMalformedEmptyPolicyMappingsSource(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: []byte{0x30, 0x01, 0x30}}},
	}}
	request.TLS = &state
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted a malformed empty policy-mapping source")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleCertificateVersionRepresentation(t *testing.T) {
	for _, version := range []int{0, 3} {
		request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
		state := tlsStateForTest
		state.PeerCertificates = []*x509.Certificate{{
			Version:    version,
			Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: []byte{1}}},
		}}
		request.TLS = &state
		if !RequireDirectTLS(request) {
			t.Fatalf("RequireDirectTLS rejected parser-compatible certificate version %d representation", version)
		}
	}
}

func TestRequireDirectTLSAcceptsNonCriticalCertificateKeyIdentifiers(t *testing.T) {
	subjectKeyID := []byte{1, 2, 3}
	authorityKeyID := []byte{4, 5, 6}
	for _, certificate := range []*x509.Certificate{
		{
			Extensions: []pkix.Extension{
				{Id: []int{2, 5, 29, 14}, Critical: false},
				{Id: []int{2, 5, 29, 35}, Critical: false},
			},
		},
		{
			Extensions: []pkix.Extension{
				{Id: []int{2, 5, 29, 14}, Critical: false, Value: mustMarshalCertificateValue(t, subjectKeyID)},
				{Id: []int{2, 5, 29, 35}, Critical: false, Value: mustMarshalCertificateValue(t, struct {
					ID []byte `asn1:"optional,tag:0"`
				}{ID: authorityKeyID})},
			},
			SubjectKeyId:   subjectKeyID,
			AuthorityKeyId: authorityKeyID,
		},
	} {
		request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
		state := tlsStateForTest
		state.PeerCertificates = []*x509.Certificate{certificate}
		request.TLS = &state
		if !RequireDirectTLS(request) {
			t.Fatal("RequireDirectTLS rejected parser-compatible key-identifier representation")
		}
	}
}

func TestRequireDirectTLSAcceptsNonCriticalAuthorityInfoAccess(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Critical: false}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible authority-information-access criticality")
	}
}

func TestRequireDirectTLSAcceptsDistinctCertificatePolicies(t *testing.T) {
	policy, err := x509.OIDFromInts([]uint64{2, 5, 29, 32, 0})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:        []pkix.Extension{{Id: []int{2, 5, 29, 32}, Value: mustMarshalCertificatePolicies(t, []x509.OID{policy})}},
		Policies:          []x509.OID{policy},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{2, 5, 29, 32, 0}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible certificate policy representations")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleCertificatePolicyOuterTrailingField(t *testing.T) {
	policy := mustCertificateOID(t, "2.5.29.32.0")
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 32},
			Value: mustMarshalCertificatePoliciesWithTrailingOuterField(t, []x509.OID{policy}, mustMarshalCertificateValue(t, int64(7))),
		}},
		Policies:          []x509.OID{policy},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{2, 5, 29, 32, 0}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected parser-compatible outer certificate-policy trailing field")
	}
}

func TestRequireDirectTLSRejectsCertificatePolicySourceMismatch(t *testing.T) {
	policy := mustCertificateOID(t, "2.5.29.32.0")
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 32},
			Value: mustMarshalCertificatePolicies(t, []x509.OID{mustCertificateOID(t, "1.2.3.4")}),
		}},
		Policies:          []x509.OID{policy},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{2, 5, 29, 32, 0}},
	}}
	request.TLS = &state
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted a certificate-policy source mismatch")
	}
}

func TestRequireDirectTLSRejectsUnboundCertificatePolicyIdentifiers(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:        []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: []byte{0x30, 0x00}}},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}}
	request.TLS = &state
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted policy identifiers without a certificate-policy source")
	}
}

func TestRequireDirectTLSRejectsMismatchedCertificatePolicyIdentifiers(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 32},
			Value: mustMarshalCertificatePolicies(t, []x509.OID{mustCertificateOID(t, "1.2.3.4")}),
		}},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 5}},
	}}
	request.TLS = &state
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted mismatched legacy policy identifiers")
	}
}

func TestRequireDirectTLSAcceptsPartialCertificatePolicyIdentifiers(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected omitted-list partial policy identifiers")
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedCertificatePolicyIdentifiersBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	policy := mustCertificateOID(t, "1.2.3.4")
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 32},
			Value: mustMarshalCertificatePolicies(t, []x509.OID{policy}),
		}},
		Policies:          []x509.OID{policy},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.PolicyIdentifiers = []asn1.ObjectIdentifier{{1, 2, 3, 5}}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated policy identifiers status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated policy identifiers: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedCertificatePolicyOuterTrailingFieldBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	policy := mustCertificateOID(t, "1.2.3.4")
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw: []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 32},
			Value: mustMarshalCertificatePolicies(t, []x509.OID{policy}),
		}},
		Policies:          []x509.OID{policy},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = mustMarshalCertificatePoliciesWithTrailingOuterField(t, []x509.OID{policy}, mustMarshalCertificateValue(t, int64(7)))
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated outer certificate-policy trailing field status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated outer certificate-policy trailing field: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestRequireDirectTLSAcceptsEmptyCertificatePolicySource(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 32}, Value: []byte{0x30, 0x00}}},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected an empty parser-compatible certificate-policy source")
	}
}

func TestRequireDirectTLSRejectsMalformedEmptyCertificatePolicySource(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 32}, Value: []byte{0x30, 0x01, 0x06}}},
	}}
	request.TLS = &state
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted a malformed empty certificate-policy source")
	}
}

func TestRequireDirectTLSRejectsConstructedCertificatePolicyOID(t *testing.T) {
	policy := mustCertificateOID(t, "1.2.3.4")
	constructedOID := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 6, IsCompound: true, Bytes: []byte{0x2a, 0x03, 0x04},
	})
	policyInformation := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 16, IsCompound: true, Bytes: constructedOID,
	})
	policyExtension := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 16, IsCompound: true, Bytes: policyInformation,
	})
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions:        []pkix.Extension{{Id: []int{2, 5, 29, 32}, Value: policyExtension}},
		Policies:          []x509.OID{policy},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}}
	request.TLS = &state
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted a constructed certificate-policy OID")
	}
}

func TestRequireDirectTLSAcceptsOpaqueCertificatePolicyWithoutLegacyIdentifier(t *testing.T) {
	policy, err := x509.ParseOID("2.5.29.32.999999999999999999999")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{Policies: []x509.OID{policy}}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected an opaque policy that cannot fit PolicyIdentifiers")
	}
}

func TestRequireDirectTLSAcceptsOpaqueCertificatePolicySourceWithoutLegacyIdentifier(t *testing.T) {
	policy, err := x509.ParseOID("2.5.29.32.999999999999999999999")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 32},
			Value: mustMarshalCertificatePolicies(t, []x509.OID{policy}),
		}},
		Policies: []x509.OID{policy},
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected an opaque policy source whose legacy identifier is intentionally omitted")
	}
}

func TestRequireDirectTLSRejectsDuplicateCertificatePolicies(t *testing.T) {
	policy, err := x509.OIDFromInts([]uint64{2, 5, 29, 32, 0})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{Policies: []x509.OID{policy, policy}}}
	request.TLS = &state
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted duplicate certificate policy OIDs")
	}
}

func TestRequireDirectTLSAcceptsDistinctCertificateExtensionRepresentations(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	state.PeerCertificates = []*x509.Certificate{{
		Extensions: []pkix.Extension{
			{Id: []int{2, 5, 29, 17}, Value: []byte{1}},
			{Id: []int{2, 5, 29, 19}, Value: mustMarshalCertificateBasicConstraints(t, false, -1)},
		},
		ExtraExtensions: []pkix.Extension{
			{Id: []int{2, 5, 29, 17}, Value: []byte{3}},
			{Id: []int{2, 5, 29, 19}, Value: []byte{4}},
		},
		BasicConstraintsValid: true,
		MaxPathLen:            -1,
	}}
	request.TLS = &state
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected distinct extension IDs in separate certificate representations")
	}
}

func TestRequireDirectTLSAcceptsParserCompatibleUnhandledCriticalExtension(t *testing.T) {
	for _, certificate := range []*x509.Certificate{
		{
			Extensions:                  []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true}},
			UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
		},
		{
			Extensions:                  []pkix.Extension{{Id: []int{2, 5, 29, 17}, Critical: true}},
			UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{2, 5, 29, 17}},
		},
		{
			Extensions:                  []pkix.Extension{{Id: []int{2, 5, 29, 30}, Critical: true}},
			PermittedDNSDomainsCritical: true,
			UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{2, 5, 29, 30}},
		},
	} {
		request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
		state := tlsStateForTest
		state.PeerCertificates = []*x509.Certificate{certificate}
		request.TLS = &state
		if !RequireDirectTLS(request) {
			t.Fatalf("RequireDirectTLS rejected parser-compatible unhandled critical extension metadata: %#v", certificate.Extensions)
		}
	}
}

func TestRequireDirectTLSRejectsAggregateCertificateSerialMetadata(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	state := tlsStateForTest
	serial := new(big.Int).Lsh(big.NewInt(1), uint(maxMCPTLSCertificateBytes*8/2))
	state.PeerCertificates = []*x509.Certificate{
		{SerialNumber: new(big.Int).Set(serial)},
		{SerialNumber: new(big.Int).Set(serial)},
	}
	request.TLS = &state
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted certificate serial metadata over the aggregate budget")
	}
}

func TestRequireDirectTLSAcceptsSupportedPublicKeyTypes(t *testing.T) {
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	ecdhKey, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	// The standard library accepts these concrete key forms in certificates;
	// the lifecycle boundary keeps their serialized or scalar representation
	// bounded without accepting arbitrary PublicKey object graphs.
	keys := []struct {
		name string
		key  any
	}{
		{name: "RSA", key: &rsa.PublicKey{N: big.NewInt(3233), E: 17}},
		{name: "ECDSA", key: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}},
		{name: "Ed25519", key: ed25519.PublicKey(bytes.Repeat([]byte{1}, ed25519.PublicKeySize))},
		{name: "ECDH", key: ecdhKey},
		{name: "DSA", key: &dsa.PublicKey{Parameters: dsa.Parameters{P: big.NewInt(23), Q: big.NewInt(11), G: big.NewInt(2)}, Y: big.NewInt(4)}},
	}
	for _, tc := range keys {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			state := tlsStateForTest
			state.PeerCertificates = []*x509.Certificate{{PublicKey: tc.key}}
			request.TLS = &state
			if !RequireDirectTLS(request) {
				t.Fatal("RequireDirectTLS rejected supported public key type")
			}
		})
	}
}

func TestRequireDirectTLSRejectsInvalidCipherSuite(t *testing.T) {
	base := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	for _, tc := range []struct {
		name        string
		cipherSuite uint16
		version     uint16
		tlsUnique   []byte
		want        bool
	}{
		{name: "missing suite", version: tls.VersionTLS13},
		{name: "unknown suite", cipherSuite: 0xffff, version: tls.VersionTLS13},
		{name: "TLS 1.2 suite with TLS 1.3", cipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, version: tls.VersionTLS13},
		{name: "TLS 1.3 suite with TLS 1.2", cipherSuite: tls.TLS_AES_128_GCM_SHA256, version: tls.VersionTLS12},
		{name: "secure TLS 1.2 suite", cipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, version: tls.VersionTLS12, tlsUnique: bytes.Repeat([]byte{1}, 12), want: true},
		{name: "secure TLS 1.3 suite", cipherSuite: tls.TLS_AES_128_GCM_SHA256, version: tls.VersionTLS13, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := *base
			request.TLS = &tls.ConnectionState{
				Version:                    tc.version,
				HandshakeComplete:          true,
				CipherSuite:                tc.cipherSuite,
				TLSUnique:                  tc.tlsUnique,
				NegotiatedProtocolIsMutual: true,
			}
			if got := RequireDirectTLS(&request); got != tc.want {
				t.Fatalf("RequireDirectTLS() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestRequireDirectTLSRejectsIncoherentServerConnectionState(t *testing.T) {
	base := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	peerLeaf := &x509.Certificate{}
	otherLeaf := &x509.Certificate{}
	for _, tc := range []struct {
		name  string
		state tls.ConnectionState
	}{
		{
			name: "client-side ECH acceptance",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				ECHAccepted:       true,
			},
		},
		{
			name: "trailing-dot SNI name",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				ServerName:        "service.example.",
			},
		},
		{
			name: "TLS 1.3 tls-unique channel binding",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				TLSUnique:         []byte{1},
			},
		},
		{
			name: "TLS 1.3 present but empty tls-unique channel binding",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				TLSUnique:         []byte{},
			},
		},
		{
			name: "non-resumed TLS 1.2 missing tls-unique channel binding",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS12,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
		{
			name: "non-resumed TLS 1.2 empty tls-unique channel binding",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS12,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLSUnique:         []byte{},
			},
		},
		{
			name: "verified chain without peer leaf",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				VerifiedChains:    [][]*x509.Certificate{{peerLeaf}},
			},
		},
		{
			name: "present empty verified-chain collection",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				VerifiedChains:    [][]*x509.Certificate{},
			},
		},
		{
			name: "present empty peer-certificate collection",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				PeerCertificates:  []*x509.Certificate{},
			},
		},
		{
			name: "present empty OCSP response",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				OCSPResponse:      []byte{},
			},
		},
		{
			name: "empty verified chain",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				PeerCertificates:  []*x509.Certificate{peerLeaf},
				VerifiedChains:    [][]*x509.Certificate{{}},
			},
		},
		{
			name: "verified chain leaf differs from peer leaf",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				PeerCertificates:  []*x509.Certificate{peerLeaf},
				VerifiedChains:    [][]*x509.Certificate{{otherLeaf}},
			},
		},
		{
			name: "duplicate peer certificate pointer",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				PeerCertificates:  []*x509.Certificate{peerLeaf, peerLeaf},
			},
		},
		{
			name: "duplicate verified-chain certificate pointer",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				PeerCertificates:  []*x509.Certificate{peerLeaf},
				VerifiedChains:    [][]*x509.Certificate{{peerLeaf, peerLeaf}},
			},
		},
		{
			name: "empty signed certificate timestamp",
			state: tls.ConnectionState{
				Version:                     tls.VersionTLS13,
				HandshakeComplete:           true,
				CipherSuite:                 tls.TLS_AES_128_GCM_SHA256,
				SignedCertificateTimestamps: [][]byte{{}},
			},
		},
		{
			name: "duplicate signed certificate timestamp",
			state: tls.ConnectionState{
				Version:                     tls.VersionTLS13,
				HandshakeComplete:           true,
				CipherSuite:                 tls.TLS_AES_128_GCM_SHA256,
				SignedCertificateTimestamps: [][]byte{{1}, {1}},
			},
		},
		{
			name: "oversized signed certificate timestamp",
			state: tls.ConnectionState{
				Version:                     tls.VersionTLS13,
				HandshakeComplete:           true,
				CipherSuite:                 tls.TLS_AES_128_GCM_SHA256,
				SignedCertificateTimestamps: [][]byte{make([]byte, maxDirectTLSSCTBytes+1)},
			},
		},
		{
			name: "oversized signed certificate timestamp vector",
			state: tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
				SignedCertificateTimestamps: [][]byte{
					make([]byte, maxDirectTLSSCTBytes/2+1),
					make([]byte, maxDirectTLSSCTBytes/2+1),
				},
			},
		},
		{
			name: "signed certificate timestamp entry leaves no room for vector prefixes",
			state: tls.ConnectionState{
				Version:                     tls.VersionTLS13,
				HandshakeComplete:           true,
				CipherSuite:                 tls.TLS_AES_128_GCM_SHA256,
				SignedCertificateTimestamps: [][]byte{make([]byte, maxDirectTLSSCTBytes-2*tlsVectorLengthBytes+1)},
			},
		},
		{
			name: "oversized negotiated ALPN protocol",
			state: tls.ConnectionState{
				Version:            tls.VersionTLS13,
				HandshakeComplete:  true,
				CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
				NegotiatedProtocol: strings.Repeat("p", maxDirectTLSALPNProtocolBytes+1),
			},
		},
		{
			name: "non-mutual negotiated ALPN protocol",
			state: tls.ConnectionState{
				Version:                    tls.VersionTLS13,
				HandshakeComplete:          true,
				CipherSuite:                tls.TLS_AES_128_GCM_SHA256,
				NegotiatedProtocol:         "h2",
				NegotiatedProtocolIsMutual: false,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := *base
			request.TLS = &tc.state
			if RequireDirectTLS(&request) {
				t.Fatal("RequireDirectTLS accepted incoherent direct-server TLS state")
			}
		})
	}
}

func TestRequireDirectTLSAcceptsNonTrailingDotServerName(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		ServerName:        "Service.Example",
	}
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected a valid non-trailing-dot SNI name")
	}
}

func TestRequireDirectTLSRejectsDuplicateParsedCertificateIdentity(t *testing.T) {
	certificate := mustCreateParsedCertificate(t)
	duplicate := *certificate
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates:  []*x509.Certificate{certificate, &duplicate},
	}
	if RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS accepted duplicate parsed certificate identity")
	}
}

func TestRequireDirectTLSAcceptsDistinctCertificateSequence(t *testing.T) {
	peerLeaf := &x509.Certificate{}
	intermediate := &x509.Certificate{}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates:  []*x509.Certificate{peerLeaf, intermediate},
		VerifiedChains:    [][]*x509.Certificate{{peerLeaf, intermediate}},
	}
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected distinct certificate sequence")
	}
}

func TestRequireDirectTLSAcceptsDistinctSignedCertificateTimestamps(t *testing.T) {
	for _, timestamps := range [][][]byte{
		nil,
		{},
		{{1}, {2}},
		{make([]byte, maxDirectTLSSCTBytes-2*tlsVectorLengthBytes)},
	} {
		request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
		request.TLS = &tls.ConnectionState{
			Version:                     tls.VersionTLS13,
			HandshakeComplete:           true,
			CipherSuite:                 tls.TLS_AES_128_GCM_SHA256,
			SignedCertificateTimestamps: timestamps,
		}
		if !RequireDirectTLS(request) {
			t.Fatalf("RequireDirectTLS rejected valid SCT collection %#v", timestamps)
		}
	}
}

func TestRequireDirectTLSAcceptsNonEmptyOCSPResponse(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		OCSPResponse:      []byte{1},
	}
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected a non-empty OCSP response")
	}
}

func TestRequireDirectTLSAcceptsOpaqueALPNAtWireLimit(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tls.ConnectionState{
		Version:                    tls.VersionTLS13,
		HandshakeComplete:          true,
		CipherSuite:                tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol:         "a" + strings.Repeat("é", (maxDirectTLSALPNProtocolBytes-1)/2),
		NegotiatedProtocolIsMutual: true,
	}
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected an opaque ALPN protocol at the wire limit")
	}
}

func TestRequireDirectTLSAcceptsResumedTLS12WithoutTLSUnique(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tls.ConnectionState{
		Version:           tls.VersionTLS12,
		HandshakeComplete: true,
		DidResume:         true,
		CipherSuite:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected a resumed TLS 1.2 state without TLSUnique")
	}
}

func TestRequireDirectTLSRejectsWrongLengthTLS12TLSUnique(t *testing.T) {
	for _, tc := range []struct {
		name      string
		didResume bool
		length    int
	}{
		{name: "full handshake short", length: 11},
		{name: "full handshake long", length: 13},
		{name: "resumed short", didResume: true, length: 11},
		{name: "resumed long", didResume: true, length: 13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.TLS = &tls.ConnectionState{
				Version:           tls.VersionTLS12,
				HandshakeComplete: true,
				DidResume:         tc.didResume,
				CipherSuite:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLSUnique:         bytes.Repeat([]byte{1}, tc.length),
			}
			if RequireDirectTLS(request) {
				t.Fatal("RequireDirectTLS accepted a TLS 1.2 TLSUnique with the wrong length")
			}
		})
	}
}

func TestRequireDirectTLSAcceptsUnspecifiedServerALPNMutuality(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		// Go documents NegotiatedProtocolIsMutual as unspecified on the
		// server side. A connection without negotiated ALPN may leave it false.
		NegotiatedProtocolIsMutual: false,
	}
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected a valid server state with no negotiated ALPN")
	}
}

func TestRequireDirectTLSAcceptsMutualNegotiatedALPN(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.TLS = &tls.ConnectionState{
		Version:                    tls.VersionTLS13,
		HandshakeComplete:          true,
		CipherSuite:                tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol:         "h2",
		NegotiatedProtocolIsMutual: true,
	}
	if !RequireDirectTLS(request) {
		t.Fatal("RequireDirectTLS rejected a mutually negotiated ALPN protocol")
	}
}

func TestValidateDirectTLSConfigRequiresExplicitSafeVersionRange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *tls.Config
		want   bool
	}{
		{name: "nil config", config: nil, want: false},
		{name: "implicit default", config: &tls.Config{}, want: false},
		{name: "TLS 1.0", config: &tls.Config{MinVersion: tls.VersionTLS10}, want: false},
		{name: "TLS 1.1", config: &tls.Config{MinVersion: tls.VersionTLS11}, want: false},
		{name: "unknown minimum", config: &tls.Config{MinVersion: 0xff00}, want: false},
		{name: "inverted range", config: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS12}, want: false},
		{name: "implicit maximum", config: &tls.Config{MinVersion: tls.VersionTLS12}, want: false},
		{name: "implicit TLS 1.2 cipher policy", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}, want: false},
		{name: "unknown maximum", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: 0xff00}, want: false},
		{name: "client renegotiation mode", config: &tls.Config{MinVersion: tls.VersionTLS12, Renegotiation: tls.RenegotiateOnceAsClient}, want: false},
		{name: "free renegotiation mode", config: &tls.Config{MinVersion: tls.VersionTLS12, Renegotiation: tls.RenegotiateFreelyAsClient}, want: false},
		{name: "unsupported client-auth mode", config: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.ClientAuthType(0xff)}, want: false},
		{name: "client CA pool with client certificates disabled", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, ClientCAs: x509.NewCertPool()}, want: false},
		{name: "client certificate callback", config: &tls.Config{MinVersion: tls.VersionTLS12, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, nil }}, want: false},
		{name: "client root pool", config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool()}, want: false},
		{name: "client server name", config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "relay.invalid"}, want: false},
		{name: "client insecure verification", config: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, want: false},
		{name: "client session cache", config: &tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(1)}, want: false},
		{name: "client ECH config list", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: []byte{0xff}}, want: false},
		{name: "client ECH rejection callback", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil }}, want: false},
		{name: "legacy server cipher preference is ignored", config: &tls.Config{MinVersion: tls.VersionTLS12, PreferServerCipherSuites: true}, want: false},
		{name: "per-client configuration callback", config: &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }}, want: false},
		{name: "dynamic certificate selection callback", config: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }}, want: false},
		{name: "peer certificate verification callback", config: &tls.Config{MinVersion: tls.VersionTLS12, VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return nil }}, want: false},
		{name: "connection verification callback", config: &tls.Config{MinVersion: tls.VersionTLS12, VerifyConnection: func(tls.ConnectionState) error { return nil }}, want: false},
		{name: "too many static certificate chains", config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: make([]tls.Certificate, maxDirectTLSCertificateChains+1)}, want: false},
		{name: "too many certificates in a static chain", config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: make([][]byte, maxDirectTLSCertificateChainEntries+1)}}}, want: false},
		{name: "too many static certificate signature algorithms", config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{SupportedSignatureAlgorithms: make([]tls.SignatureScheme, maxDirectTLSVectorEntries+1)}}}, want: false},
		{name: "unknown static certificate signature algorithm", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.SignatureScheme(0xffff)}}}}, want: false},
		{name: "duplicate static certificate signature algorithm", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP256AndSHA256}}}}, want: false},
		{name: "legacy static certificate signature algorithm remains allowed", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, Certificates: []tls.Certificate{{SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.PKCS1WithSHA1}}}}, want: true},
		{name: "empty static certificate chain entry", config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{{}}}}}, want: false},
		{name: "empty static certificate timestamp", config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{SignedCertificateTimestamps: [][]byte{{}}}}}, want: false},
		{name: "duplicate static certificate timestamp", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{SignedCertificateTimestamps: [][]byte{{0x01}, {0x01}}}}}, want: false},
		{name: "oversized static certificate metadata", config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{make([]byte, maxDirectTLSCertificateBytes+1)}}}}, want: false},
		{name: "too many static certificate name mappings", config: &tls.Config{MinVersion: tls.VersionTLS12, NameToCertificate: make(map[string]*tls.Certificate, maxDirectTLSNameMappings+1)}, want: false},
		{name: "empty static certificate name", config: &tls.Config{MinVersion: tls.VersionTLS12, NameToCertificate: map[string]*tls.Certificate{"": &tls.Certificate{}}}, want: false},
		{name: "oversized static certificate name", config: &tls.Config{MinVersion: tls.VersionTLS12, NameToCertificate: map[string]*tls.Certificate{strings.Repeat("n", maxDirectTLSNameBytes+1): &tls.Certificate{}}}, want: false},
		{name: "mixed-case static certificate name is not canonical", config: &tls.Config{MinVersion: tls.VersionTLS12, NameToCertificate: map[string]*tls.Certificate{"Service.example": &tls.Certificate{}}}, want: false},
		{name: "control byte in static certificate name", config: &tls.Config{MinVersion: tls.VersionTLS12, NameToCertificate: map[string]*tls.Certificate{"service\n.example": &tls.Certificate{}}}, want: false},
		{name: "unicode format character in static certificate name", config: &tls.Config{MinVersion: tls.VersionTLS12, NameToCertificate: map[string]*tls.Certificate{"service.\u202eexample": &tls.Certificate{}}}, want: false},
		{name: "unicode line separator in static certificate name", config: &tls.Config{MinVersion: tls.VersionTLS12, NameToCertificate: map[string]*tls.Certificate{"service.\u2028example": &tls.Certificate{}}}, want: false},
		{name: "unicode paragraph separator in static certificate name", config: &tls.Config{MinVersion: tls.VersionTLS12, NameToCertificate: map[string]*tls.Certificate{"service.\u2029example": &tls.Certificate{}}}, want: false},
		{name: "trailing-dot static certificate name", config: &tls.Config{MinVersion: tls.VersionTLS12, NameToCertificate: map[string]*tls.Certificate{"service.example.": &tls.Certificate{}}}, want: false},
		{name: "nil static certificate mapping", config: &tls.Config{MinVersion: tls.VersionTLS12, NameToCertificate: map[string]*tls.Certificate{"service.example": nil}}, want: false},
		{name: "unlisted static certificate mapping", config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{}}, NameToCertificate: map[string]*tls.Certificate{"service.example": &tls.Certificate{}}}, want: false},
		{name: "static certificate private key is not a signer", config: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{PrivateKey: struct{}{}}}}, want: false},
		{name: "typed nil static certificate signer", config: func() *tls.Config {
			var key *rsa.PrivateKey
			return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{PrivateKey: key}}}
		}(), want: false},
		{name: "custom session unwrap callback", config: &tls.Config{MinVersion: tls.VersionTLS12, UnwrapSession: func([]byte, tls.ConnectionState) (*tls.SessionState, error) { return nil, nil }}, want: false},
		{name: "custom session wrap callback", config: &tls.Config{MinVersion: tls.VersionTLS12, WrapSession: func(tls.ConnectionState, *tls.SessionState) ([]byte, error) { return nil, nil }}, want: false},
		{name: "static session ticket key", config: &tls.Config{MinVersion: tls.VersionTLS12, SessionTicketKey: [32]byte{1}}, want: false},
		{name: "disabled session tickets", config: &tls.Config{MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true}, want: false},
		{name: "disabled dynamic record sizing", config: &tls.Config{MinVersion: tls.VersionTLS12, DynamicRecordSizingDisabled: true}, want: false},
		{name: "server Encrypted Client Hello keys", config: &tls.Config{MinVersion: tls.VersionTLS12, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: []byte{1}, PrivateKey: []byte{2}}}}, want: false},
		{name: "custom randomness source", config: &tls.Config{MinVersion: tls.VersionTLS12, Rand: bytes.NewReader(nil)}, want: false},
		{name: "custom handshake clock", config: &tls.Config{MinVersion: tls.VersionTLS12, Time: func() time.Time { return time.Unix(0, 0) }}, want: false},
		{name: "session key log writer", config: &tls.Config{MinVersion: tls.VersionTLS12, KeyLogWriter: io.Discard}, want: false},
		{name: "TLS 1.2", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}, want: true},
		{name: "TLS 1.3", config: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, want: true},
		{name: "bounded TLS 1.2 to 1.3", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}, want: true},
		{name: "secure explicit TLS 1.2 suite", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}, want: true},
		{name: "insecure explicit suite", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}}, want: false},
		{name: "unknown explicit suite", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{0xffff}}, want: false},
		{name: "duplicate explicit suite", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}, want: false},
		{name: "TLS 1.3-only list cannot serve TLS 1.2", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256}}, want: false},
		{name: "TLS 1.3-only list cannot satisfy a TLS 1.2 floor", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256}}, want: false},
		{name: "TLS 1.2 and TLS 1.3 suites satisfy a bounded range", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256}}, want: true},
		{name: "TLS 1.3-only rejects ignored explicit cipher policy", config: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256}}, want: false},
		{name: "TLS 1.2 with supported explicit curve", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, CurvePreferences: []tls.CurveID{tls.CurveP256}}, want: true},
		{name: "TLS 1.2 with TLS 1.3-only curve", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}, want: false},
		{name: "TLS 1.3 with post-quantum curve", config: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}, want: true},
		{name: "unknown explicit curve", config: &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.CurveID(0xffff)}}, want: false},
		{name: "duplicate explicit curve", config: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP256}}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDirectTLSConfig(tc.config)
			if (err == nil) != tc.want {
				t.Fatalf("ValidateDirectTLSConfig() error = %v, want success = %t", err, tc.want)
			}
			if tc.want && err != nil {
				t.Fatalf("ValidateDirectTLSConfig() returned an error for a valid configuration: %v", err)
			}
			if !tc.want && !errors.Is(err, ErrDirectTLSConfigInvalid) {
				t.Fatalf("ValidateDirectTLSConfig() error = %v, want ErrDirectTLSConfigInvalid", err)
			}
		})
	}
}

func TestValidateDirectTLSConfigAcceptsDefinedCertificateSignatureAlgorithms(t *testing.T) {
	algorithms := []tls.SignatureScheme{
		tls.PKCS1WithSHA256,
		tls.PKCS1WithSHA384,
		tls.PKCS1WithSHA512,
		tls.PSSWithSHA256,
		tls.PSSWithSHA384,
		tls.PSSWithSHA512,
		tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512,
		tls.Ed25519,
		tls.PKCS1WithSHA1,
		tls.ECDSAWithSHA1,
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{
			SupportedSignatureAlgorithms: algorithms,
		}},
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected defined certificate signature algorithms: %v", err)
	}

}

func TestValidateDirectTLSConfigAcceptsDefinedClientAuthModes(t *testing.T) {
	for _, mode := range []tls.ClientAuthType{
		tls.NoClientCert,
		tls.RequestClientCert,
		tls.RequireAnyClientCert,
		tls.VerifyClientCertIfGiven,
		tls.RequireAndVerifyClientCert,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			config := &tls.Config{
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS13,
				CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				ClientAuth:   mode,
			}
			if mode >= tls.VerifyClientCertIfGiven {
				config.ClientCAs = x509.NewCertPool()
			}
			if err := ValidateDirectTLSConfig(config); err != nil {
				t.Fatalf("ValidateDirectTLSConfig() rejected defined client-auth mode %s: %v", mode, err)
			}
		})
	}
}

func TestValidateDirectTLSConfigRequiresExplicitClientCAsForVerification(t *testing.T) {
	for _, mode := range []tls.ClientAuthType{tls.VerifyClientCertIfGiven, tls.RequireAndVerifyClientCert} {
		t.Run(mode.String(), func(t *testing.T) {
			config := &tls.Config{
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS13,
				CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				ClientAuth:   mode,
			}
			if err := ValidateDirectTLSConfig(config); err == nil {
				t.Fatalf("ValidateDirectTLSConfig accepted %s without an explicit client CA pool", mode)
			}
			config.ClientCAs = x509.NewCertPool()
			if err := ValidateDirectTLSConfig(config); err != nil {
				t.Fatalf("ValidateDirectTLSConfig rejected %s with an explicit client CA pool: %v", mode, err)
			}
		})
	}
}

func TestValidateDirectTLSConfigBoundsClientCAs(t *testing.T) {
	poolWithSubjects := func(count, subjectBytes int) *x509.CertPool {
		t.Helper()
		pool := x509.NewCertPool()
		for index := 0; index < count; index++ {
			raw := []byte{0x30, byte(index >> 8), byte(index)}
			subject := bytes.Repeat([]byte{0x31}, subjectBytes)
			pool.AddCert(&x509.Certificate{Raw: raw, RawSubject: subject})
		}
		return pool
	}
	for _, mode := range []tls.ClientAuthType{
		tls.RequestClientCert,
		tls.RequireAnyClientCert,
		tls.VerifyClientCertIfGiven,
		tls.RequireAndVerifyClientCert,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			base := func(pool *x509.CertPool) *tls.Config {
				return &tls.Config{
					MinVersion:   tls.VersionTLS12,
					MaxVersion:   tls.VersionTLS13,
					CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
					ClientAuth:   mode,
					ClientCAs:    pool,
				}
			}

			if err := ValidateDirectTLSConfig(base(poolWithSubjects(maxDirectTLSClientCASubjects, 3))); err != nil {
				t.Fatalf("ValidateDirectTLSConfig rejected maximum-size client CA subject vector: %v", err)
			}
			if err := ValidateDirectTLSConfig(base(poolWithSubjects(maxDirectTLSClientCASubjects+1, 3))); err == nil {
				t.Fatal("ValidateDirectTLSConfig accepted too many client CA subjects")
			}
			if err := ValidateDirectTLSConfig(base(poolWithSubjects(1, maxDirectTLSClientCASubjectBytes+1))); err == nil {
				t.Fatal("ValidateDirectTLSConfig accepted an oversized client CA subject")
			}
			if err := ValidateDirectTLSConfig(base(poolWithSubjects(2, maxDirectTLSClientCABytes/2))); err == nil {
				t.Fatal("ValidateDirectTLSConfig accepted an oversized aggregate client CA subject vector")
			}
		})
	}
}

func TestValidateDirectTLSConfigDoesNotMutateConfig(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	beforeMin, beforeMax := config.MinVersion, config.MaxVersion
	if err := ValidateDirectTLSConfig(config); err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != beforeMin || config.MaxVersion != beforeMax {
		t.Fatal("ValidateDirectTLSConfig mutated the supplied config")
	}
}

func TestValidateDirectTLSConfigValidatesALPNBounds(t *testing.T) {
	oversizedVector := make([]string, 256)
	for index := range oversizedVector {
		oversizedVector[index] = strings.Repeat("p", 255)
	}
	for _, tc := range []struct {
		name      string
		protocols []string
		wantError bool
	}{
		{name: "omitted", protocols: nil},
		{name: "ordinary", protocols: []string{"h2", "http/1.1"}},
		{name: "opaque bytes remain allowed", protocols: []string{"h\x00"}},
		{name: "duplicate protocol", protocols: []string{"h2", "h2"}, wantError: true},
		{name: "empty protocol", protocols: []string{""}, wantError: true},
		{name: "protocol too large", protocols: []string{strings.Repeat("p", 256)}, wantError: true},
		{name: "protocol vector too large", protocols: oversizedVector, wantError: true},
		{name: "protocol count too large", protocols: make([]string, maxDirectTLSALPNProtocols+1), wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDirectTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, NextProtos: tc.protocols})
			if (err != nil) != tc.wantError {
				t.Fatalf("ValidateDirectTLSConfig() error = %v, want error = %t", err, tc.wantError)
			}
		})
	}
}

func TestValidateDirectTLSConfigBoundsCipherAndCurveVectors(t *testing.T) {
	tooManyCipherSuites := make([]uint16, maxDirectTLSVectorEntries+1)
	tooManyCurves := make([]tls.CurveID, maxDirectTLSVectorEntries+1)
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: tooManyCipherSuites,
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted an oversized cipher-suite vector")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: tooManyCurves,
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted an oversized supported-group vector")
	}

	// Distinct supported entries remain accepted, preserving compatibility for
	// explicitly constructed configurations without using duplicate fixtures.
	cipherSuites := tls.CipherSuites()
	distinctCipherSuites := make([]uint16, len(cipherSuites))
	for index, suite := range cipherSuites {
		distinctCipherSuites[index] = suite.ID
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: distinctCipherSuites,
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected a distinct valid cipher vector: %v", err)
	}
	distinctCurves := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519MLKEM768}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
		CipherSuites:     []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		CurvePreferences: distinctCurves,
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected a distinct valid supported-group vector: %v", err)
	}
}

func TestValidateDirectTLSConfigBoundsStaticCertificates(t *testing.T) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{Certificate: [][]byte{make([]byte, maxDirectTLSCertificateBytes)}}},
	}
	nameMappings := make(map[string]*tls.Certificate, maxDirectTLSNameMappings)
	for index := 0; index < maxDirectTLSNameMappings; index++ {
		nameMappings[fmt.Sprintf("service-%d.example", index)] = &config.Certificates[0]
	}
	config.NameToCertificate = nameMappings
	if err := ValidateDirectTLSConfig(config); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected maximum-size static certificate metadata: %v", err)
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{
			[]byte{0x30, 0x01, 0x00},
			[]byte{0x30, 0x01, 0x00},
		}}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted duplicate certificate chain entries")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{
			{Certificate: [][]byte{[]byte{0x30, 0x01, 0x00}}},
			{Certificate: [][]byte{[]byte{0x30, 0x01, 0x00}}},
		},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted duplicate static certificate chains")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{
			{Certificate: [][]byte{[]byte{0x30, 0x01, 0x00}}},
			{Certificate: [][]byte{[]byte{0x30, 0x01, 0x01}}},
		},
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected distinct static certificate chains: %v", err)
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{}, {}},
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected empty certificate provisioning placeholders: %v", err)
	}
	distinctSignatureAlgorithms := []tls.SignatureScheme{
		tls.PKCS1WithSHA256,
		tls.PSSWithSHA256,
		tls.ECDSAWithP256AndSHA256,
		tls.Ed25519,
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{
			SupportedSignatureAlgorithms: distinctSignatureAlgorithms,
		}},
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected a distinct certificate signature algorithm vector: %v", err)
	}

	maxNameConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{}},
	}
	maxNameConfig.NameToCertificate = map[string]*tls.Certificate{
		strings.Repeat("n", maxDirectTLSNameBytes): &maxNameConfig.Certificates[0],
	}
	if err := ValidateDirectTLSConfig(maxNameConfig); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected maximum-size static certificate name: %v", err)
	}
	wildcardNameConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{}},
	}
	wildcardNameConfig.NameToCertificate = map[string]*tls.Certificate{
		"*.service.example": &wildcardNameConfig.Certificates[0],
	}
	if err := ValidateDirectTLSConfig(wildcardNameConfig); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected an ordinary wildcard static certificate name: %v", err)
	}
	lowercaseNameConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{}},
	}
	lowercaseNameConfig.NameToCertificate = map[string]*tls.Certificate{
		"service.example": &lowercaseNameConfig.Certificates[0],
	}
	if err := ValidateDirectTLSConfig(lowercaseNameConfig); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected a canonical lowercase static certificate name: %v", err)
	}

	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{SignedCertificateTimestamps: make([][]byte, maxDirectTLSCertificateChainEntries+1)}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted too many static certificate timestamps")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{SignedCertificateTimestamps: [][]byte{{}}}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted an empty static certificate timestamp")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{OCSPStaple: []byte{}}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted an empty static OCSP response")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{OCSPStaple: []byte{0x01}}},
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected a non-empty static OCSP response: %v", err)
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{SignedCertificateTimestamps: [][]byte{{0x01}, {0x02}}}},
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected distinct non-empty static certificate timestamps: %v", err)
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{SignedCertificateTimestamps: [][]byte{{0x01}, {0x01}}}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted duplicate static certificate timestamps")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{
			{SignedCertificateTimestamps: [][]byte{{0x01}}},
			{SignedCertificateTimestamps: [][]byte{{0x01}}},
		},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted a static certificate timestamp repeated across chains")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{
			{SignedCertificateTimestamps: [][]byte{{0x01}}},
			{SignedCertificateTimestamps: [][]byte{{0x02}}},
		},
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected distinct static certificate timestamps across chains: %v", err)
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{SignedCertificateTimestamps: [][]byte{make([]byte, maxDirectTLSSCTBytes+1)}}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted an oversized static certificate timestamp")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{SignedCertificateTimestamps: [][]byte{make([]byte, maxDirectTLSSCTBytes-2*tlsVectorLengthBytes)}}},
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected an SCT vector at the encoded wire limit: %v", err)
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{SignedCertificateTimestamps: [][]byte{make([]byte, maxDirectTLSSCTBytes-2*tlsVectorLengthBytes+1)}}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted an SCT vector whose length prefixes exceed the wire limit")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{SignedCertificateTimestamps: [][]byte{
			make([]byte, maxDirectTLSSCTBytes/2+1),
			make([]byte, maxDirectTLSSCTBytes/2+1),
		}}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted an oversized static certificate timestamp vector")
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{PrivateKey: privateKey}},
	}); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected a standard signer private key: %v", err)
	}
	malformedRSA := *privateKey
	malformedRSA.Primes = append([]*big.Int(nil), privateKey.Primes...)
	malformedRSA.Primes[0] = big.NewInt(2)
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{PrivateKey: &malformedRSA}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted an RSA key with inconsistent prime material")
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	malformedECDSA := *ecdsaKey
	malformedECDSA.X = new(big.Int)
	malformedECDSA.Y = new(big.Int)
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{PrivateKey: &malformedECDSA}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted an ECDSA key whose public point does not match its private scalar")
	}
}

func TestValidateDirectTLSConfigValidatesStaticCertificateLeaf(t *testing.T) {
	leaf := mustCreateParsedCertificate(t)
	validConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, Leaf: leaf}},
	}
	if err := ValidateDirectTLSConfig(validConfig); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected a parsed leaf matching the first DER chain entry: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{name: "missing raw relationship", mutate: func(certificate *x509.Certificate) { certificate.Raw = nil }},
		{name: "mutated parsed field", mutate: func(certificate *x509.Certificate) { certificate.DNSNames = []string{"attacker.invalid"} }},
		{name: "oversized parsed vector", mutate: func(certificate *x509.Certificate) {
			certificate.DNSNames = make([]string, maxMCPTLSCertificateValues+1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := *leaf
			tc.mutate(&mutated)
			config := &tls.Config{
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS13,
				CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, Leaf: &mutated}},
			}
			if err := ValidateDirectTLSConfig(config); err == nil {
				t.Fatalf("ValidateDirectTLSConfig accepted %s", tc.name)
			}
		})
	}

	detached := mustCreateParsedCertificate(t)
	if bytes.Equal(detached.Raw, leaf.Raw) {
		t.Fatal("test certificates unexpectedly share the same DER")
	}
	if err := ValidateDirectTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, Leaf: detached}},
	}); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted a leaf detached from the first DER chain entry")
	}
}

func TestValidateDirectTLSConfigBoundsStaticCertificateLeafAggregate(t *testing.T) {
	baseLeaf := mustCreateParsedCertificate(t)
	leafWithExtraMetadata := func(size int) *x509.Certificate {
		leaf := *baseLeaf
		// Keep the aggregate-budget fixture in the validator's supported
		// opaque/partial metadata form so ExtraExtensions do not contradict
		// the fully DER-backed source fields of baseLeaf.
		leaf.Raw = []byte{0x01, byte(size >> 8), byte(size >> 16)}
		leaf.RawTBSCertificate = []byte{0x01}
		leaf.ExtraExtensions = []pkix.Extension{{Id: []int{1, 2, 3}, Value: make([]byte, size)}}
		return &leaf
	}
	configForLeaves := func(leaves ...*x509.Certificate) *tls.Config {
		certificates := make([]tls.Certificate, len(leaves))
		for index, leaf := range leaves {
			leafCopy := *leaf
			leafCopy.Raw = append(append([]byte(nil), leaf.Raw...), byte(index))
			certificates[index] = tls.Certificate{Certificate: [][]byte{leafCopy.Raw}, Leaf: &leafCopy}
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, Certificates: certificates}
	}

	if err := ValidateDirectTLSConfig(configForLeaves(
		leafWithExtraMetadata(maxMCPTLSCertificateBytes/4),
		leafWithExtraMetadata(maxMCPTLSCertificateBytes/4),
	)); err != nil {
		t.Fatalf("ValidateDirectTLSConfig rejected bounded aggregate leaf metadata: %v", err)
	}
	if err := ValidateDirectTLSConfig(configForLeaves(
		leafWithExtraMetadata(maxMCPTLSCertificateBytes/2),
		leafWithExtraMetadata(maxMCPTLSCertificateBytes/2),
	)); err == nil {
		t.Fatal("ValidateDirectTLSConfig accepted an oversized aggregate leaf metadata vector")
	}
}

func TestValidateDirectHTTPSListenPolicyRequiresLoopbackAndExplicitTLS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		config  *tls.Config
		wantErr bool
	}{
		{name: "loopback with TLS 1.2", address: "127.0.0.1:8743", config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}},
		{name: "ipv6 loopback with TLS 1.3", address: "[::1]:0", config: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}},
		{name: "public address", address: "192.0.2.10:8743", config: &tls.Config{MinVersion: tls.VersionTLS12}, wantErr: true},
		{name: "wildcard address", address: ":8743", config: &tls.Config{MinVersion: tls.VersionTLS12}, wantErr: true},
		{name: "implicit TLS default", address: "127.0.0.1:8743", config: &tls.Config{}, wantErr: true},
		{name: "legacy TLS", address: "127.0.0.1:8743", config: &tls.Config{MinVersion: tls.VersionTLS11}, wantErr: true},
		{name: "nil TLS config", address: "127.0.0.1:8743", config: nil, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDirectHTTPSListenPolicy(tc.address, tc.config)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateDirectHTTPSListenPolicy(%q, %#v) error = %v, want error = %t", tc.address, tc.config, err, tc.wantErr)
			}
		})
	}
}

func TestValidateDirectHTTPSListenPolicyDoesNotMutateTLSConfig(t *testing.T) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}
	if err := ValidateDirectHTTPSListenPolicy("[::1]:0", config); err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS12 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatal("ValidateDirectHTTPSListenPolicy mutated the supplied TLS config")
	}
}

func TestValidateLoopbackListenAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		wantErr bool
	}{
		{name: "ipv4 loopback", address: "127.0.0.1:8743"},
		{name: "ipv6 loopback", address: "[::1]:8743"},
		{name: "localhost hostname", address: "localhost:0", wantErr: true},
		{name: "uppercase localhost hostname", address: "LOCALHOST:0", wantErr: true},
		{name: "port zero", address: "127.0.0.1:0"},
		{name: "wildcard", address: ":8743", wantErr: true},
		{name: "public ipv4", address: "192.0.2.10:8743", wantErr: true},
		{name: "public ipv6", address: "[2001:db8::10]:8743", wantErr: true},
		{name: "hostname resolution is not attempted", address: "relay.invalid:8743", wantErr: true},
		{name: "service name is not accepted", address: "127.0.0.1:https", wantErr: true},
		{name: "port too large", address: "127.0.0.1:65536", wantErr: true},
		{name: "signed port", address: "127.0.0.1:+8743", wantErr: true},
		{name: "negative port", address: "127.0.0.1:-1", wantErr: true},
		{name: "leading-zero port", address: "127.0.0.1:08743", wantErr: true},
		{name: "unbracketed ipv6", address: "::1:8743", wantErr: true},
		{name: "zone identifier", address: "[::1%lo0]:8743", wantErr: true},
		{name: "whitespace", address: " 127.0.0.1:8743", wantErr: true},
		{name: "oversized", address: strings.Repeat("1", maxMCPListenAddressBytes+1), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateLoopbackListenAddress(tc.address)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateLoopbackListenAddress(%q) error = %v, want error = %t", tc.address, err, tc.wantErr)
			}
		})
	}
}

func TestMCPHTTPHandlerNegotiatesJSONResponse(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		values []string
		want   int
		calls  int
	}{
		{name: "json only", values: []string{"application/json"}, want: http.StatusOK, calls: 1},
		{name: "mcp json and sse", values: []string{"application/json, text/event-stream"}, want: http.StatusOK, calls: 1},
		{name: "wildcard", values: []string{"*/*"}, want: http.StatusOK, calls: 1},
		{name: "bounded quality", values: []string{"application/json;q=0.500"}, want: http.StatusOK, calls: 1},
		{name: "specific zero overrides wildcard", values: []string{"application/json;q=0, */*;q=1"}, want: http.StatusNotAcceptable, calls: 0},
		{name: "specific fractional quality overrides wildcard", values: []string{"application/json;q=0.001, */*;q=1"}, want: http.StatusOK, calls: 1},
		{name: "quality one with empty fraction", values: []string{"application/json;q=1."}, want: http.StatusOK, calls: 1},
		{name: "zero quality with empty fraction", values: []string{"application/json;q=0."}, want: http.StatusNotAcceptable, calls: 0},
		{name: "zero quality", values: []string{"application/json;q=0"}, want: http.StatusNotAcceptable, calls: 0},
		{name: "sse only", values: []string{"text/event-stream"}, want: http.StatusNotAcceptable, calls: 0},
		{name: "malformed", values: []string{"application/json,;"}, want: http.StatusBadRequest, calls: 0},
		{name: "non-finite quality", values: []string{"application/json;q=NaN"}, want: http.StatusBadRequest, calls: 0},
		{name: "quality exponent", values: []string{"application/json;q=1e0"}, want: http.StatusBadRequest, calls: 0},
		{name: "quality over precision", values: []string{"application/json;q=0.1234"}, want: http.StatusBadRequest, calls: 0},
		{name: "quality one with nonzero fraction", values: []string{"application/json;q=1.001"}, want: http.StatusBadRequest, calls: 0},
		{name: "oversized", values: []string{strings.Repeat("a", maxMCPAcceptBytes+1)}, want: http.StatusBadRequest, calls: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolverCalls = 0
			req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			req.Header.Set("Content-Type", "application/json")
			for _, value := range tc.values {
				req.Header.Add("Accept", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
			if resolverCalls != tc.calls {
				t.Fatalf("resolver calls = %d, want %d", resolverCalls, tc.calls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerValidatesOptionalProtocolVersionHeader(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, tc := range []struct {
		name       string
		configure  func(http.Header)
		wantStatus int
		wantSecure int
		wantAuth   int
	}{
		{name: "omitted for legacy initialization", wantStatus: http.StatusOK, wantSecure: 1, wantAuth: 1},
		{name: "supported case-insensitive field", configure: func(header http.Header) {
			header["mcp-protocol-version"] = []string{MCPProtocolVersion}
		}, wantStatus: http.StatusOK, wantSecure: 1, wantAuth: 1},
		{name: "unsupported version", configure: func(header http.Header) {
			header.Set("MCP-Protocol-Version", "2025-11-25")
		}, wantStatus: http.StatusBadRequest},
		{name: "duplicate values", configure: func(header http.Header) {
			header["MCP-Protocol-Version"] = []string{MCPProtocolVersion}
			header["mCp-PrOtOcOl-VeRsIoN"] = []string{MCPProtocolVersion}
		}, wantStatus: http.StatusBadRequest},
		{name: "empty value", configure: func(header http.Header) {
			header["MCP-Protocol-Version"] = nil
		}, wantStatus: http.StatusBadRequest},
		{name: "oversized value", configure: func(header http.Header) {
			header.Set("MCP-Protocol-Version", strings.Repeat("v", maxMCPProtocolVersionBytes+1))
		}, wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			if tc.configure != nil {
				tc.configure(request.Header)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tc.wantStatus)
			}
			if secureCalls != tc.wantSecure || resolverCalls != tc.wantAuth {
				t.Fatalf("callbacks = secure %d/auth %d, want %d/%d", secureCalls, resolverCalls, tc.wantSecure, tc.wantAuth)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsProtocolVersionMutationAfterTransportVerification(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(request *http.Request) bool {
		request.Header.Set("MCP-Protocol-Version", "2025-11-25")
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("MCP-Protocol-Version", MCPProtocolVersion)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalls != 0 {
		t.Fatal("principal resolver ran after transport changed protocol version")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerValidatesAuthorizationHeaderMultiplicity(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, tc := range []struct {
		name      string
		configure func(http.Header)
		want      int
		secure    int
		resolver  int
	}{
		{name: "omitted for non-bearer integration", want: http.StatusOK, secure: 1, resolver: 1},
		{name: "one value preserves resolver ownership", configure: func(header http.Header) {
			header.Set("Authorization", "Custom credential")
		}, want: http.StatusOK, secure: 1, resolver: 1},
		{name: "duplicate values", configure: func(header http.Header) {
			header.Set("Authorization", "Custom first")
			header.Add("Authorization", "Custom second")
		}, want: http.StatusBadRequest},
		{name: "case-insensitive duplicate values", configure: func(header http.Header) {
			header["authorization"] = []string{"Custom first"}
			header["AUTHORIZATION"] = []string{"Custom second"}
		}, want: http.StatusBadRequest},
		{name: "empty value", configure: func(header http.Header) {
			header["Authorization"] = nil
		}, want: http.StatusBadRequest},
		{name: "empty string", configure: func(header http.Header) {
			header.Set("Authorization", "")
		}, want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			if tc.configure != nil {
				tc.configure(request.Header)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
			if secureCalls != tc.secure || resolverCalls != tc.resolver {
				t.Fatalf("callbacks = secure %d/resolver %d, want %d/%d", secureCalls, resolverCalls, tc.secure, tc.resolver)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedAuthorizationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Custom first")
	request.ContentLength = int64(len(payload))
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.Header["authorization"] = []string{"Custom second"}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("callbacks = secure %d/resolver %d, want 1/0", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsEmptyAcceptHeaderEntry(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/literal}brace", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header = http.Header{
		"Content-Type": []string{"application/json"},
		"aCcEpT":       nil,
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("empty Accept header entry status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalls != 0 {
		t.Fatal("principal resolver called after empty Accept header entry")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerBoundsCaseInsensitiveHeaderCollections(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	tooMany := make([]string, maxMCPHeaderValues+1)
	for index := range tooMany {
		tooMany[index] = "application/json"
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header = http.Header{"content-type": tooMany}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized case-insensitive Content-Type collection status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalls != 0 {
		t.Fatal("principal resolver called after oversized Content-Type collection")
	}
	assertHTTPBoundaryHeaders(t, response)

	tooManyAccepts := make([]string, maxMCPHeaderValues+1)
	for index := range tooManyAccepts {
		tooManyAccepts[index] = "application/json"
	}
	request = httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header = http.Header{
		"Content-Type": []string{"application/json"},
		"ACCEPT":       tooManyAccepts,
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized Accept collection status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalls != 0 {
		t.Fatal("principal resolver called after oversized Accept collection")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsOversizedDirectRequestMetadataBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	transportCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		transportCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{
			name: "raw request target",
			mutate: func(request *http.Request) {
				request.RequestURI = strings.Repeat("/", maxMCPRequestTargetBytes+1)
			},
		},
		{
			name: "parsed URL components",
			mutate: func(request *http.Request) {
				request.RequestURI = ""
				request.URL.Path = strings.Repeat("/", maxMCPRequestTargetBytes+1)
			},
		},
		{
			name: "matched route pattern",
			mutate: func(request *http.Request) {
				request.Pattern = strings.Repeat("p", maxMCPPatternBytes+1)
			},
		},
		{
			name: "matched route pattern format control",
			mutate: func(request *http.Request) {
				request.Pattern = "/lifecycle/\u202e"
			},
		},
		{
			name: "too many route wildcards",
			mutate: func(request *http.Request) {
				var pattern strings.Builder
				for index := 0; index < maxMCPPatternWildcards+1; index++ {
					fmt.Fprintf(&pattern, "/{v%d}", index)
				}
				request.Pattern = pattern.String()
			},
		},
		{
			name: "duplicate Host header",
			mutate: func(request *http.Request) {
				request.Header.Set("Host", "attacker.invalid")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			transportCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			tc.mutate(request)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if transportCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called: transport=%d resolver=%d", transportCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsMalformedServeMuxPatternBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, pattern := range []string{
		"not-a-pattern",
		"M? /lifecycle",
		"relay{.invalid/lifecycle",
		"other.invalid/lifecycle",
		"GET /lifecycle//item",
		"POST /lifecycle/./item",
		"PUT /lifecycle/../item",
		"/prefix{item}",
		"/{item...}/tail",
		"/{item...}/",
		"/{item",
		"/{item}{other}",
		"/{$}/tail",
	} {
		t.Run(pattern, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Pattern = pattern
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("pattern %q status = %d, want %d", pattern, response.Code, http.StatusBadRequest)
			}
			if secureCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called for malformed pattern %q: secure=%d resolver=%d", pattern, secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}

	connectRequest := httptest.NewRequest(http.MethodConnect, "/lifecycle//item", nil)
	connectRequest.Host = "relay.invalid"
	connectRequest.Pattern = "CONNECT /lifecycle//item"
	if !validDirectRequestPattern(connectRequest) {
		t.Fatal("CONNECT pattern should retain the standard unclean-path exception")
	}
	connectHostFallback := httptest.NewRequest(http.MethodConnect, "/lifecycle", nil)
	connectHostFallback.URL.Host = "url-host.invalid"
	connectHostFallback.Host = "request-host.invalid"
	connectHostFallback.Pattern = "CONNECT request-host.invalid/lifecycle"
	if !validDirectRequestPattern(connectHostFallback) {
		t.Fatal("CONNECT pattern should retain ServeMux's Request.Host fallback")
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/literal}brace", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Pattern = "/literal}brace"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("literal closing-brace pattern status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
}

func TestMCPHTTPHandlerRejectsServeMuxPatternPathMismatchBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		requestURL string
		pattern    string
		pathValue  string
		wantStatus int
	}{
		{name: "matching literal", requestURL: "https://relay.invalid/lifecycle", pattern: "/lifecycle", wantStatus: http.StatusOK},
		{name: "matching wildcard", requestURL: "https://relay.invalid/lifecycle/task-1", pattern: "/lifecycle/{task}", pathValue: "task-1", wantStatus: http.StatusOK},
		{name: "matching escaped wildcard", requestURL: "https://relay.invalid/lifecycle/task%2F1", pattern: "/lifecycle/{task}", pathValue: "task/1", wantStatus: http.StatusOK},
		{name: "mismatched literal", requestURL: "https://relay.invalid/other", pattern: "/lifecycle", wantStatus: http.StatusBadRequest},
		{name: "mismatched wildcard", requestURL: "https://relay.invalid/lifecycle", pattern: "/lifecycle/{task}", wantStatus: http.StatusBadRequest},
		{name: "mismatched wildcard value", requestURL: "https://relay.invalid/lifecycle/task-1", pattern: "/lifecycle/{task}", pathValue: "task-2", wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, tc.requestURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Pattern = tc.pattern
			if tc.pathValue != "" {
				request.SetPathValue("task", tc.pathValue)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, tc.wantStatus, response.Body.String())
			}
			if tc.wantStatus == http.StatusOK {
				if secureCalls != 1 || resolverCalls != 1 {
					t.Fatalf("callbacks = secure %d resolver %d, want 1/1", secureCalls, resolverCalls)
				}
				return
			}
			if secureCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called for mismatched pattern: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
		})
	}
}

func TestMCPHTTPHandlerRejectsUndeclaredPathValueBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.SetPathValue("undeclared", "value")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("undeclared path value status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks called for undeclared path value: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsServeMuxPatternMethodMismatchBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	headRequest := httptest.NewRequest(http.MethodHead, "https://relay.invalid/lifecycle", nil)
	headRequest.Pattern = "GET /lifecycle"
	if !validDirectRequestPattern(headRequest) {
		t.Fatal("GET pattern should match HEAD under ServeMux method semantics")
	}
	connectRequest := httptest.NewRequest(http.MethodConnect, "/lifecycle//item", nil)
	connectRequest.Host = "relay.invalid"
	connectRequest.Pattern = "CONNECT /lifecycle//item"
	if !validDirectRequestPattern(connectRequest) {
		t.Fatal("CONNECT pattern should retain the standard unclean-path exception")
	}

	for _, tc := range []struct {
		name    string
		pattern string
		wantOK  bool
	}{
		{name: "matching POST", pattern: "POST /lifecycle", wantOK: true},
		{name: "unqualified pattern", pattern: "/lifecycle", wantOK: true},
		{name: "matching host-qualified pattern", pattern: "relay.invalid/lifecycle", wantOK: true},
		{name: "matching host-qualified pattern with request port", pattern: "relay.invalid/lifecycle", wantOK: true},
		{name: "host-qualified pattern mismatch", pattern: "other.invalid/lifecycle", wantOK: false},
		{name: "GET mismatches POST", pattern: "GET /lifecycle", wantOK: false},
		{name: "CONNECT mismatches POST", pattern: "CONNECT /lifecycle", wantOK: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			requestURL := "https://relay.invalid/lifecycle"
			if tc.name == "matching host-qualified pattern with request port" {
				requestURL = "https://relay.invalid:8443/lifecycle"
			}
			request := httptest.NewRequest(http.MethodPost, requestURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Pattern = tc.pattern
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if tc.wantOK {
				if response.Code != http.StatusOK {
					t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
				}
				if secureCalls != 1 || resolverCalls != 1 {
					t.Fatalf("callbacks = secure %d resolver %d, want 1/1", secureCalls, resolverCalls)
				}
				return
			}
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
		})
	}
}

func TestMCPHTTPHandlerRejectsOversizedDirectTransportMetadataBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{
			name: "protocol",
			mutate: func(request *http.Request) {
				request.Proto = strings.Repeat("p", maxMCPProtocolBytes+1)
			},
		},
		{
			name: "remote address",
			mutate: func(request *http.Request) {
				request.RemoteAddr = strings.Repeat("r", maxMCPRemoteAddrBytes+1)
			},
		},
		{
			name: "protocol control byte",
			mutate: func(request *http.Request) {
				request.Proto = "HTTP/1.1\x00"
			},
		},
		{
			name: "protocol version mismatch",
			mutate: func(request *http.Request) {
				request.ProtoMajor = 2
			},
		},
		{
			name: "protocol text mismatch",
			mutate: func(request *http.Request) {
				request.Proto = "HTTP/1.0"
			},
		},
		{
			name: "half-populated protocol version",
			mutate: func(request *http.Request) {
				request.Proto = ""
			},
		},
		{
			name: "remote address control byte",
			mutate: func(request *http.Request) {
				request.RemoteAddr = "127.0.0.1:1\n"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			tc.mutate(request)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsClientOnlyRequestFieldsBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "get body", mutate: func(request *http.Request) {
			request.GetBody = func() (io.ReadCloser, error) { return nil, nil }
		}},
		{name: "form", mutate: func(request *http.Request) {
			request.Form = url.Values{"field": {"value"}}
		}},
		{name: "post form", mutate: func(request *http.Request) {
			request.PostForm = url.Values{"field": {"value"}}
		}},
		{name: "multipart form", mutate: func(request *http.Request) {
			request.MultipartForm = &multipart.Form{}
		}},
		{name: "cancel channel", mutate: func(request *http.Request) {
			request.Cancel = make(chan struct{})
		}},
		{name: "redirect response", mutate: func(request *http.Request) {
			request.Response = &http.Response{StatusCode: http.StatusTemporaryRedirect}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			tc.mutate(request)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedClientOnlyRequestFieldsBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "get body", mutate: func(request *http.Request) {
			request.GetBody = func() (io.ReadCloser, error) { return nil, nil }
		}},
		{name: "form", mutate: func(request *http.Request) {
			request.Form = url.Values{"field": {"value"}}
		}},
		{name: "post form", mutate: func(request *http.Request) {
			request.PostForm = url.Values{"field": {"value"}}
		}},
		{name: "multipart form", mutate: func(request *http.Request) {
			request.MultipartForm = &multipart.Form{}
		}},
		{name: "cancel channel", mutate: func(request *http.Request) {
			request.Cancel = make(chan struct{})
		}},
		{name: "redirect response", mutate: func(request *http.Request) {
			request.Response = &http.Response{StatusCode: http.StatusTemporaryRedirect}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate:  tc.mutate,
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body mutation: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsOversizedDirectHeaderMapBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	header := make(http.Header, maxMCPHeaderFields+1)
	header.Set("Content-Type", "application/json")
	for index := 0; len(header) <= maxMCPHeaderFields; index++ {
		header.Set("X-Direct-Field-"+strconv.Itoa(index), "bounded")
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header = header
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized direct Header map status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalls != 0 {
		t.Fatal("principal resolver called after oversized direct Header map")
	}
	if secureCalls != 0 {
		t.Fatal("secure transport verifier called after oversized direct Header map")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsOversizedDirectTrailerMapBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	trailer := make(http.Header, maxMCPHeaderFields+1)
	for index := 0; len(trailer) <= maxMCPHeaderFields; index++ {
		trailer.Set("X-Direct-Trailer-"+strconv.Itoa(index), "bounded")
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Trailer = trailer
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized direct Trailer map status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalls != 0 || secureCalls != 0 {
		t.Fatalf("security callbacks called after oversized direct Trailer map: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsForbiddenTrailerFieldsBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, field := range []string{"Content-Length", "Transfer-Encoding", "Trailer"} {
		t.Run(field, func(t *testing.T) {
			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Trailer = http.Header{field: {"invalid"}}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsRawTrailerHeaderBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Trailer", "X-Declared-Trailer")
	request.Trailer = http.Header{"X-Declared-Trailer": nil}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("raw Trailer header status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks called for raw Trailer header: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsAliasedHeaderAndTrailerMapsBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Trailer = request.Header
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("aliased Header and Trailer status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks called for aliased Header and Trailer maps: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestRequireDirectTLSRejectsForbiddenTrailerFields(t *testing.T) {
	for _, field := range []string{"Content-Length", "Transfer-Encoding", "Trailer"} {
		t.Run(field, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.TLS = &tlsStateForTest
			request.Trailer = http.Header{field: {"invalid"}}
			if RequireDirectTLS(request) {
				t.Fatalf("RequireDirectTLS accepted forbidden trailer field %q", field)
			}
		})
	}
}

func TestMCPHTTPHandlerRejectsFramingTrailerMutationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		name         string
		mutate       func(*http.Request)
		secureMutate func(*http.Request)
	}{
		{
			name: "transport verifier",
			secureMutate: func(request *http.Request) {
				request.Trailer["Content-Length"] = []string{"0"}
			},
		},
		{
			name: "body reader",
			mutate: func(request *http.Request) {
				request.Trailer["Transfer-Encoding"] = []string{"chunked"}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(request *http.Request) bool {
				secureCalls++
				if tc.secureMutate != nil {
					tc.secureMutate(request)
				}
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.Trailer = http.Header{"X-Declared-Trailer": nil}
			if tc.mutate != nil {
				request.Body = &mutatingRequestBody{request: request, reader: bytes.NewReader(payload), mutate: tc.mutate}
			} else {
				request.Body = io.NopCloser(bytes.NewReader(payload))
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("callbacks after framing trailer mutation: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedTrailerBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			trailer := make(http.Header, maxMCPHeaderFields+1)
			for index := 0; len(trailer) <= maxMCPHeaderFields; index++ {
				trailer.Set("X-Body-Trailer-"+strconv.Itoa(index), "bounded")
			}
			request.Trailer = trailer
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated trailer status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated trailer: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedTrailerBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.Trailer = http.Header{"X-Introduced-Trailer": {"unexpected"}}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced trailer status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced trailer: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerAllowsDeclaredTrailerPopulation(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(request *http.Request) (Principal, error) {
		resolverCalls++
		if request.Trailer.Get("X-Declared-Trailer") != "complete" {
			t.Fatalf("resolver trailer = %q, want complete", request.Trailer.Get("X-Declared-Trailer"))
		}
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.Trailer = http.Header{"X-Declared-Trailer": nil}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.Trailer.Set("X-Declared-Trailer", "complete")
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("declared trailer response status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if resolverCalls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedTransportMetadataBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.TLS = nil
			request.Proto = "HTTP/1.0"
			request.ProtoMajor = 1
			request.ProtoMinor = 0
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated transport metadata status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated transport metadata: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsTransportVerifierMutationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(request *http.Request) bool {
		secureCalls++
		request.URL.Path = "/rewritten-by-verifier"
		request.Header.Set("X-Verifier-Mutation", "unexpected")
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("transport-verifier mutation status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("callbacks after transport-verifier mutation: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerBoundsTransportVerifierMetadataBeforeSnapshotComparison(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(request *http.Request) bool {
		secureCalls++
		header := make(http.Header, maxMCPHeaderFields+1)
		for index := 0; index <= maxMCPHeaderFields; index++ {
			header.Set("X-Verifier-Bounded-"+strconv.Itoa(index), "value")
		}
		request.Header = header
		request.TLS = &tls.ConnectionState{
			PeerCertificates: make([]*x509.Certificate, maxMCPTLSCertificates+1),
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized transport-verifier metadata status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("callbacks after oversized transport-verifier metadata: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsTransportVerifierBodyConsumptionBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(request *http.Request) bool {
		secureCalls++
		var consumed [1]byte
		_, _ = request.Body.Read(consumed[:])
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("transport-verifier body-consumption status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("callbacks after transport-verifier body consumption: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerDoesNotDoubleCloseBodyWhenTransportVerifierClosesIt(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	body := &countingCloseBody{ReadCloser: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))}
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		t.Fatal("principal resolver called after transport verifier closed body")
		return Principal{}, nil
	}, func(request *http.Request) bool {
		if err := request.Body.Close(); err != nil {
			t.Fatalf("transport verifier close: %v", err)
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", body)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("transport-verifier close status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if body.closeCount != 1 {
		t.Fatalf("underlying body close count = %d, want 1", body.closeCount)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerContainsTransportVerifierBodyClosePanic(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	body := &panicCountingCloseBody{ReadCloser: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))}
	var closeErr error
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		t.Fatal("principal resolver called after transport verifier body close panic")
		return Principal{}, nil
	}, func(request *http.Request) bool {
		closeErr = request.Body.Close()
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", body)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("transport-verifier close panic status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if !errors.Is(closeErr, errRequestBodyClosePanic) {
		t.Fatalf("transport-verifier close error = %v, want errRequestBodyClosePanic", closeErr)
	}
	if body.closeCount != 1 {
		t.Fatalf("underlying body close count = %d, want 1", body.closeCount)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsTransportVerifierTrailerMutationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(request *http.Request) bool {
		secureCalls++
		request.Trailer.Set("X-Declared-Trailer", "rewritten-by-verifier")
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Trailer = http.Header{"X-Declared-Trailer": nil}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("transport-verifier trailer mutation status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("callbacks after transport-verifier trailer mutation: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedPatternBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.Pattern = "/lifecycle"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.Pattern = "/mutated"
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated pattern status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated pattern: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyReplacementBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"ping"}`))
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-replaced request status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body replacement: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsTransportVerifierContextReplacementBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(request *http.Request) bool {
		secureCalls++
		*request = *request.WithContext(context.WithValue(context.Background(), contextKey("stage"), "transport"))
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), contextKey("stage"), "original"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("transport-context replacement status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after transport-context replacement: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyContextReplacementBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request = request.WithContext(context.WithValue(request.Context(), contextKey("stage"), "original"))
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			*request = *request.WithContext(context.WithValue(context.Background(), contextKey("stage"), "body"))
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-context replacement status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-context replacement: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsUncomparableRequestContextBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(uncomparableContext([]byte("direct")))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("uncomparable-context status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks after uncomparable context: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

type contextKey string

type uncomparableContext []byte

func (uncomparableContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (uncomparableContext) Done() <-chan struct{}       { return nil }
func (uncomparableContext) Err() error                  { return nil }
func (c uncomparableContext) Value(key any) any {
	if key == contextKey("kind") {
		return string(c)
	}
	return nil
}

func TestHTTPHeaderSnapshotPreservesValueSlicePresence(t *testing.T) {
	initial := http.Header{
		"X-Nil":   nil,
		"X-Empty": []string{},
		"X-Value": []string{"value"},
	}
	snapshot := cloneHTTPHeader(initial)
	if snapshot["X-Nil"] != nil || snapshot["X-Empty"] == nil || !equalHTTPHeader(initial, snapshot) {
		t.Fatal("header snapshot did not preserve nil-versus-present-empty value slices")
	}

	initial["X-Nil"] = []string{}
	if equalHTTPHeader(snapshot, initial) {
		t.Fatal("header snapshot accepted a present-empty value slice after an omitted one")
	}
	initial["X-Nil"] = nil
	initial["X-Empty"] = nil
	if equalHTTPHeader(snapshot, initial) {
		t.Fatal("header snapshot accepted an omitted value slice after a present-empty one")
	}
}

func TestHTTPHeaderSnapshotPreservesMapPresence(t *testing.T) {
	var omitted http.Header
	presentEmpty := http.Header{}
	if equalHTTPHeader(omitted, presentEmpty) {
		t.Fatal("header comparison collapsed omitted and present-empty maps")
	}
	if !equalHTTPHeader(omitted, nil) || !equalHTTPHeader(presentEmpty, http.Header{}) {
		t.Fatal("header comparison rejected unchanged map presence")
	}

	if equalTrailerAfterBody(omitted, nil, presentEmpty) || equalTrailerAfterBody(presentEmpty, nil, omitted) {
		t.Fatal("trailer comparison accepted an omitted/present-empty map transition")
	}
	if !equalTrailerAfterBody(omitted, nil, nil) || !equalTrailerAfterBody(presentEmpty, nil, http.Header{}) {
		t.Fatal("trailer comparison rejected unchanged map presence")
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedHeaderMapPresenceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.Header = nil
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated header map presence status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated header map presence: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedTrailerMapPresenceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		name  string
		start http.Header
		end   http.Header
	}{
		{name: "omitted to present-empty", start: nil, end: http.Header{}},
		{name: "present-empty to omitted", start: http.Header{}, end: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.Trailer = tc.start
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(request *http.Request) {
					request.Trailer = tc.end
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-mutated trailer map presence status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-mutated trailer map presence: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestTrailerSnapshotPreservesValueSlicePresenceAfterBody(t *testing.T) {
	initial := http.Header{
		"X-Nil":   nil,
		"X-Empty": []string{},
		"X-Value": []string{"value"},
	}
	names := snapshotHeaderNames(initial)
	if !equalTrailerAfterBody(initial, names, initial) {
		t.Fatal("trailer snapshot rejected unchanged value-slice presence")
	}

	mutated := cloneHTTPHeader(initial)
	mutated["X-Nil"] = []string{}
	if equalTrailerAfterBody(initial, names, mutated) {
		t.Fatal("trailer snapshot accepted omitted-to-present-empty mutation")
	}
	mutated = cloneHTTPHeader(initial)
	mutated["X-Empty"] = nil
	if equalTrailerAfterBody(initial, names, mutated) {
		t.Fatal("trailer snapshot accepted present-empty-to-omitted mutation")
	}

	mutated = cloneHTTPHeader(initial)
	mutated["X-Nil"] = []string{"complete"}
	mutated["X-Empty"] = []string{"complete"}
	if !equalTrailerAfterBody(initial, names, mutated) {
		t.Fatal("trailer snapshot rejected legitimate declared-trailer population")
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedHeaderValueSlicePresenceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		name   string
		before []string
		after  []string
	}{
		{name: "omitted to present-empty", before: nil, after: []string{}},
		{name: "present-empty to omitted", before: []string{}, after: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header = http.Header{
				"Content-Type": []string{"application/json"},
				"X-Optional":   tc.before,
			}
			request.ContentLength = int64(len(payload))
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(request *http.Request) {
					request.Header["X-Optional"] = tc.after
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-mutated header value-slice presence status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-mutated header value-slice presence: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedTrailerValueSlicePresenceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		name   string
		before []string
		after  []string
	}{
		{name: "omitted to present-empty", before: nil, after: []string{}},
		{name: "present-empty to omitted", before: []string{}, after: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.Trailer = http.Header{"X-Optional-Trailer": tc.before}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(request *http.Request) {
					request.Trailer["X-Optional-Trailer"] = tc.after
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-mutated trailer value-slice presence status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-mutated trailer value-slice presence: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestRequestSnapshotPreservesTransferEncodingPresence(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	snapshot := snapshotRequestBodyMetadata(request)
	if !equalOptionalStringSlice(snapshot.transferEncoding, nil) {
		t.Fatal("request snapshot did not preserve omitted transfer encoding")
	}
	request.TransferEncoding = []string{}
	if snapshot.matches(request) {
		t.Fatal("request snapshot accepted a present-empty transfer encoding after an omitted one")
	}

	request.TransferEncoding = []string{}
	snapshot = snapshotRequestBodyMetadata(request)
	if !snapshot.matches(request) {
		t.Fatal("request snapshot rejected unchanged present-empty transfer encoding")
	}
	request.TransferEncoding = nil
	if snapshot.matches(request) {
		t.Fatal("request snapshot accepted an omitted transfer encoding after a present-empty one")
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedTransferEncodingPresenceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		name   string
		before []string
		after  []string
	}{
		{name: "omitted to present-empty", before: nil, after: []string{}},
		{name: "present-empty to omitted", before: []string{}, after: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TransferEncoding = tc.before
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(request *http.Request) {
					request.TransferEncoding = tc.after
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-mutated transfer encoding presence status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-mutated transfer encoding presence: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedCertificateBytesBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{Raw: []byte{0x01, 0x02, 0x03}}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Raw[0] = 0xff
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedCertificateMetadataBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{Raw: []byte{0x01, 0x02, 0x03}, RawSubject: []byte{0x04, 0x05}}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.RawSubject[0] = 0xff
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate metadata status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate metadata: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedParsedCertificateMetadataBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:      []byte{0x01, 0x02, 0x03},
		DNSNames: []string{"trusted.invalid"},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.DNSNames[0] = "attacker.invalid"
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated parsed certificate metadata status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated parsed certificate metadata: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedCertificateURIReinterpretationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:  []byte{0x01, 0x02, 0x03},
		URIs: []*url.URL{{Scheme: "urn", Opaque: "example:foo"}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.URIs[0].Opaque = "example:foo?query"
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced certificate URI reinterpretation status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced certificate URI reinterpretation: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedCertificateNameSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	name := pkix.Name{CommonName: "relay.invalid"}
	nameDER := mustMarshalCertificateName(t, name)
	name = mustParseCertificateName(t, nameDER)
	certificate := &x509.Certificate{
		RawSubject: nameDER,
		Subject:    name,
	}
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Subject.CommonName = "attacker.invalid"
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate name status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate name: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedCertificateNameOuterTrailingFieldBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	name := pkix.Name{CommonName: "relay.invalid"}
	nameDER := mustMarshalCertificateName(t, name)
	name = mustParseCertificateName(t, nameDER)
	certificate := &x509.Certificate{
		RawSubject: nameDER,
		Subject:    name,
	}
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.RawSubject = mustMarshalCertificateNameWithTrailingOuterField(t, name, mustMarshalCertificateValue(t, int64(7)))
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced parser-compatible certificate-name trailing field status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after certificate-name source mutation: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedCertificatePublicKeySourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	key := &rsa.PublicKey{N: big.NewInt(3233), E: 17}
	raw, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		RawSubjectPublicKeyInfo: raw,
		PublicKeyAlgorithm:      x509.RSA,
		PublicKey:               key,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.PublicKey = &rsa.PublicKey{N: big.NewInt(65537), E: 17}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate public-key source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate public-key source: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedAuthorityInfoAccessRepresentationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.OCSPServer = []string{"https://ocsp.attacker.invalid"}
			certificate.IssuingCertificateURL = []string{"https://ca.attacker.invalid/issuer.crt"}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced Authority Information Access status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced Authority Information Access: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedAuthorityInfoAccessValuesBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: mustMarshalCertificateAuthorityInfoAccess(t, []string{"https://ocsp.relay.invalid"}, nil)}},
		OCSPServer: []string{"https://ocsp.relay.invalid"},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.OCSPServer = []string{"https://ocsp.attacker.invalid"}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated Authority Information Access value status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated Authority Information Access value: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedAuthorityInfoAccessOuterTrailingFieldBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	ocspServers := []string{"https://ocsp.relay.invalid"}
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{
			Id:    []int{1, 3, 6, 1, 5, 5, 7, 1, 1},
			Value: mustMarshalCertificateAuthorityInfoAccess(t, ocspServers, nil),
		}},
		OCSPServer: ocspServers,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = mustMarshalCertificateAuthorityInfoAccessWithTrailingOuterField(t,
				ocspServers, nil, mustMarshalCertificateValue(t, int64(7)))
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated outer Authority Information Access trailing field status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated outer Authority Information Access trailing field: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedCRLDistributionPointRepresentationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.CRLDistributionPoints = []string{"https://crl.attacker.invalid/root.crl"}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced CRL distribution-point status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced CRL distribution point: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedExtendedKeyUsageBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:         []byte{0x01, 0x02, 0x03},
		Extensions:  []pkix.Extension{{Id: []int{2, 5, 29, 37}, Value: mustMarshalCertificateExtendedKeyUsages(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})}},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Id = []int{1, 2, 3, 4}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced extended key usage status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced extended key usage: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedExtendedKeyUsageValueMismatchBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:         []byte{0x01, 0x02, 0x03},
		Extensions:  []pkix.Extension{{Id: []int{2, 5, 29, 37}, Value: mustMarshalCertificateExtendedKeyUsages(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})}},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.ExtKeyUsage[0] = x509.ExtKeyUsageClientAuth
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated extended key usage value mismatch status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated extended key usage value mismatch: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedKeyUsageBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.KeyUsage = x509.KeyUsageDigitalSignature
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced key usage status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced key usage: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedKeyUsageValueMismatchBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 15}, Value: mustMarshalCertificateKeyUsage(t, x509.KeyUsageDigitalSignature)}},
		KeyUsage:   x509.KeyUsageDigitalSignature,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.KeyUsage = x509.KeyUsageCertSign
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced key usage value mismatch status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced key usage value mismatch: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedCertificateNameAndPolicyMetadataBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	policy, err := x509.OIDFromInts([]uint64{2, 5, 29, 32, 0})
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		Raw:               []byte{0x01, 0x02, 0x03},
		Issuer:            pkix.Name{Organization: []string{"trusted issuer"}},
		Subject:           pkix.Name{CommonName: "trusted.invalid"},
		Policies:          []x509.OID{policy},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{2, 5, 29, 32, 0}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Subject.CommonName = "attacker.invalid"
			certificate.PolicyIdentifiers[0][4] = 1
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate name/policy status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate name/policy: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedCertificateUsageAndConstraintsBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                   []byte{0x01, 0x02, 0x03},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		Version:               3,
		SerialNumber:          big.NewInt(7),
		NotBefore:             time.Unix(10, 0),
		NotAfter:              time.Unix(20, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            3,
		PermittedDNSDomains:   []string{"trusted.invalid"},
		PermittedIPRanges:     []*net.IPNet{{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}},
		EmailAddresses:        []string{"owner@trusted.invalid"},
		OCSPServer:            []string{"https://ocsp.trusted.invalid"},
		CRLDistributionPoints: []string{"https://crl.trusted.invalid"},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.NotAfter = time.Unix(30, 0)
			certificate.SignatureAlgorithm = x509.SignatureAlgorithm(255)
			certificate.MaxPathLen = 4
			certificate.SerialNumber = big.NewInt(-1)
			certificate.ExtKeyUsage[0] = x509.ExtKeyUsageClientAuth
			certificate.PermittedDNSDomains[0] = "attacker.invalid"
			certificate.PermittedIPRanges[0].Mask[1] = 0x01
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate usage/constraints status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate usage/constraints: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedKnownUnknownExtendedKeyUsageBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                []byte{0x01, 0x02, 0x03},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.UnknownExtKeyUsage[0] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced known unknown-EKU status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced known unknown-EKU: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedCertificateValidityBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:       []byte{0x01, 0x02, 0x03},
		NotBefore: time.Unix(10, 0),
		NotAfter:  time.Unix(20, 0),
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.NotAfter = time.Time{}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate validity status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate validity: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedCertificateNameConstraintCriticalityBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                         []byte{0x01, 0x02, 0x03},
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"trusted.invalid"},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.PermittedDNSDomainsCritical = true
			certificate.PermittedDNSDomains = nil
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate name-constraint criticality status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate name-constraint criticality: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedNameConstraintsRepresentationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                         []byte{0x01, 0x02, 0x03},
		Extensions:                  []pkix.Extension{{Id: []int{2, 5, 29, 30}, Critical: true, Value: mustMarshalCertificateNameConstraints(t, []string{"trusted.invalid"}, nil, nil, nil, nil, nil, nil, nil)}},
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"trusted.invalid"},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Critical = false
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated name constraints representation status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated name constraints representation: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedMarkerOnlyNameConstraintsSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	unsupportedGeneralName := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 2,
		Tag:   8,
		Bytes: []byte{0x2a, 0x03, 0x04},
	})
	generalSubtree := mustMarshalCertificateValue(t, asn1.RawValue{
		Class:      0,
		Tag:        16,
		IsCompound: true,
		Bytes:      unsupportedGeneralName,
	})
	generalSubtrees := mustMarshalCertificateValue(t, asn1.RawValue{
		Class:      0,
		Tag:        16,
		IsCompound: true,
		Bytes:      generalSubtree,
	})
	permittedSubtrees := mustMarshalCertificateValue(t, asn1.RawValue{
		Class:      2,
		Tag:        0,
		IsCompound: true,
		Bytes:      generalSubtrees,
	})
	parserCompatibleSource := mustMarshalCertificateValue(t, asn1.RawValue{
		Class:      0,
		Tag:        16,
		IsCompound: true,
		Bytes:      permittedSubtrees,
	})

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                         []byte{0x01, 0x02, 0x03},
		Extensions:                  []pkix.Extension{{Id: []int{2, 5, 29, 30}, Critical: true, Value: parserCompatibleSource}},
		PermittedDNSDomainsCritical: true,
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{2, 5, 29, 30}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x30, 0x00}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated marker-only name constraints source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated marker-only name constraints source: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedNameConstraintValuesBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                     []byte{0x01, 0x02, 0x03},
		Extensions:              []pkix.Extension{{Id: []int{2, 5, 29, 30}, Value: mustMarshalCertificateNameConstraints(t, []string{"trusted.invalid"}, nil, nil, nil, []string{"owner@trusted.invalid"}, nil, nil, nil)}},
		PermittedDNSDomains:     []string{"trusted.invalid"},
		PermittedEmailAddresses: []string{"owner@trusted.invalid"},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = mustMarshalCertificateNameConstraints(t, []string{"trusted.invalid"}, nil, nil, nil, []string{"owner..name@trusted.invalid"}, nil, nil, nil)
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated name-constraint values status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated name-constraint values: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedAsymmetricEmptyNameConstraintsSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw: []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 30},
			Value: mustMarshalCertificateNameConstraintsWithEmptySide(t, 0, 1, "blocked.invalid"),
		}},
		ExcludedDNSDomains: []string{"blocked.invalid"},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = mustMarshalCertificateNameConstraints(t, nil, nil, nil, nil, nil, nil, nil, nil)
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated asymmetric empty Name Constraints source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated asymmetric empty Name Constraints source: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedNameConstraintsOuterTrailingFieldBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw: []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 30},
			Value: mustMarshalCertificateNameConstraintsWithTrailingOuterField(t, []string{"trusted.invalid"}, mustMarshalCertificateValue(t, int64(7))),
		}},
		PermittedDNSDomains: []string{"trusted.invalid"},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = mustMarshalCertificateNameConstraints(t, []string{"trusted.invalid"}, nil, nil, nil, nil, nil, nil, nil)
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated outer Name Constraints trailing field status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated outer Name Constraints trailing field: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedCertificateSignatureAlgorithmBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                []byte{0x01, 0x02, 0x03},
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.PublicKeyAlgorithm = x509.Ed25519
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate signature algorithm status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate signature algorithm: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedCertificatePolicyMetadataBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	policy, err := x509.OIDFromInts([]uint64{2, 5, 29, 32, 0})
	if err != nil {
		t.Fatal(err)
	}
	mappedPolicy, err := x509.OIDFromInts([]uint64{2, 5, 29, 37, 0})
	if err != nil {
		t.Fatal(err)
	}
	mappingIssuerPolicy, err := x509.OIDFromInts([]uint64{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                         []byte{0x01, 0x02, 0x03},
		ExtraExtensions:             []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: []byte{1, 2, 3}}},
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{2, 5, 29, 37}},
		Policies:                    []x509.OID{policy},
		PolicyIdentifiers:           []asn1.ObjectIdentifier{{2, 5, 29, 32, 0}},
		InhibitAnyPolicy:            2,
		InhibitPolicyMapping:        3,
		RequireExplicitPolicy:       4,
		PolicyMappings: []x509.PolicyMapping{{
			IssuerDomainPolicy:  mappingIssuerPolicy,
			SubjectDomainPolicy: mappedPolicy,
		}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.ExtraExtensions[0].Value[0] = 0xff
			certificate.UnhandledCriticalExtensions[0][3] = 38
			certificate.Policies = append(certificate.Policies, certificate.Policies[0])
			certificate.InhibitAnyPolicy = 5
			certificate.InhibitPolicyMappingZero = true
			certificate.PolicyMappings[0].IssuerDomainPolicy = mappedPolicy
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate policy metadata status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate policy metadata: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedEmptyCertificatePolicySourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 32}, Value: []byte{0x30, 0x00}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x30, 0x01, 0x06}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated empty certificate-policy source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated empty certificate-policy source: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedConstructedCertificatePolicyOIDBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	policy := mustCertificateOID(t, "1.2.3.4")
	constructedOID := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 6, IsCompound: true, Bytes: []byte{0x2a, 0x03, 0x04},
	})
	policyInformation := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 16, IsCompound: true, Bytes: constructedOID,
	})
	constructedPolicyExtension := mustMarshalCertificateValue(t, asn1.RawValue{
		Class: 0, Tag: 16, IsCompound: true, Bytes: policyInformation,
	})
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw: []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 32},
			Value: mustMarshalCertificatePolicies(t, []x509.OID{policy}),
		}},
		Policies:          []x509.OID{policy},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = constructedPolicyExtension
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced constructed certificate-policy OID status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced constructed certificate-policy OID: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedDuplicateCertificateExtensionBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: []byte{1}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions = append(certificate.Extensions, certificate.Extensions[0])
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced duplicate extension status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced duplicate extension: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedBasicConstraintsRepresentationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                   []byte{0x01, 0x02, 0x03},
		Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 19}, Value: []byte{0x30, 0x00}}},
		BasicConstraintsValid: true,
		MaxPathLen:            -1,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.BasicConstraintsValid = false
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated basic constraints representation status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated basic constraints representation: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedConstructedSANBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	dnsName := "relay.invalid"
	certificate := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: mustMarshalCertificateSubjectAltNames(t, []string{dnsName}, nil, nil, nil)}},
		DNSNames:   []string{dnsName},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = mustMarshalCertificateValue(t, []asn1.RawValue{{Class: 2, Tag: 2, IsCompound: true, Bytes: []byte(dnsName)}})
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced constructed SAN status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced constructed SAN: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedBasicConstraintsValuesBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                   []byte{0x01, 0x02, 0x03},
		Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 19}, Value: mustMarshalCertificateBasicConstraints(t, true, -1)}},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.MaxPathLen = 0
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated basic constraints value status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated basic constraints value: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedPolicyConstraintsRepresentationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:              []byte{0x01, 0x02, 0x03},
		Extensions:       []pkix.Extension{{Id: []int{2, 5, 29, 54}, Value: []byte{0x02, 0x01, 0x01}}},
		InhibitAnyPolicy: 1,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.InhibitAnyPolicy = 0
			certificate.InhibitAnyPolicyZero = false
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated policy constraints representation status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated policy constraints representation: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedEmptyPolicyConstraintsSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 36}, Value: []byte{0x30, 0x00}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x30, 0x01, 0xa0}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated empty policy constraints source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated empty policy constraints source: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedPolicyConstraintValuesBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                   []byte{0x01, 0x02, 0x03},
		Extensions:            []pkix.Extension{{Id: []int{2, 5, 29, 36}, Value: mustMarshalCertificatePolicyConstraints(t, ptrToInt64(4), ptrToInt64(3))}},
		RequireExplicitPolicy: 4,
		InhibitPolicyMapping:  3,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.InhibitPolicyMapping = 5
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated policy constraint value status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated policy constraint value: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedPolicyMappingsRepresentationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw: []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: mustMarshalCertificatePolicyMappings(t, []x509.PolicyMapping{{
			IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
			SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
		}})}},
		PolicyMappings: []x509.PolicyMapping{{
			IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
			SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
		}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Id = []int{2, 5, 29, 17}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated policy-mapping representation status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated policy-mapping representation: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedPolicyMappingValuesBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	mappings := []x509.PolicyMapping{{
		IssuerDomainPolicy:  mustCertificateOID(t, "1.2.3.4"),
		SubjectDomainPolicy: mustCertificateOID(t, "1.2.3.5"),
	}}
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:            []byte{0x01, 0x02, 0x03},
		Extensions:     []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: mustMarshalCertificatePolicyMappings(t, mappings)}},
		PolicyMappings: mappings,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.PolicyMappings[0].SubjectDomainPolicy = mustCertificateOID(t, "1.2.3.6")
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated policy-mapping value status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated policy-mapping value: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedEmptyPolicyMappingSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 33}, Value: mustMarshalCertificatePolicyMappings(t, nil)}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x30, 0x01, 0x30}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated empty policy-mapping source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated empty policy-mapping source: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedCRLDistributionPointValueMismatchBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw: []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 31},
			Value: mustMarshalCertificateCRLDistributionPoints(t, "https://crl.relay.invalid/root.crl"),
		}},
		CRLDistributionPoints: []string{"https://crl.relay.invalid/root.crl"},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.CRLDistributionPoints[0] = "https://crl.relay.invalid/other.crl"
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated CRL distribution-point value status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated CRL distribution-point value: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedEmptyCRLDistributionPointSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 31}, Value: []byte{0x30, 0x00}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x30, 0x01, 0x30}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated empty CRL distribution-point source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated empty CRL distribution-point source: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedCRLDistributionPointOuterTrailingFieldBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	uris := []string{"https://crl.relay.invalid/root.crl"}
	certificate := &x509.Certificate{
		Raw: []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 31},
			Value: mustMarshalCertificateCRLDistributionPoints(t, uris...),
		}},
		CRLDistributionPoints: append([]string(nil), uris...),
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = mustMarshalCertificateCRLDistributionPointsWithTrailingOuterField(t, uris, mustMarshalCertificateValue(t, int64(7)))
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated outer CRL distribution-point trailing field status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated outer CRL distribution-point trailing field: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedUnmatchedUnhandledCriticalExtensionBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                         []byte{0x01, 0x02, 0x03},
		Extensions:                  []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true}},
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.UnhandledCriticalExtensions[0][3] = 5
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced unmatched unhandled-critical extension status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced unmatched unhandled-critical extension: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsDuplicateUnhandledCriticalExtensionBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                         []byte{0x01, 0x02, 0x03},
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{1, 2, 3, 4}, {1, 2, 3, 4}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = io.NopCloser(bytes.NewReader(payload))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate unhandled-critical extension status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks called for duplicate unhandled-critical extension: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedDuplicateUnhandledCriticalExtensionBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                         []byte{0x01, 0x02, 0x03},
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.UnhandledCriticalExtensions = append(certificate.UnhandledCriticalExtensions, certificate.UnhandledCriticalExtensions[0])
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced duplicate unhandled-critical extension status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced duplicate unhandled-critical extension: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedMissingUnhandledCriticalExtensionBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Raw:                         []byte{0x01, 0x02, 0x03},
		Extensions:                  []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true}},
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.UnhandledCriticalExtensions = nil
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced missing unhandled-critical extension status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced missing unhandled-critical extension: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsOversizedTLSStateBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{OCSPResponse: bytes.Repeat([]byte{0x01}, maxMCPTLSHandshakeBytes+1)}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized TLS state status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks called for oversized TLS state: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsMalformedTLSStringMetadataBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		state tls.ConnectionState
	}{
		{name: "negotiated protocol control byte", state: tls.ConnectionState{NegotiatedProtocol: "h2\x00"}},
		{name: "server name control byte", state: tls.ConnectionState{ServerName: "relay.invalid\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header.Set("Content-Type", "application/json")
			request.TLS = &tc.state
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("malformed TLS string metadata status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 0 || resolverCalls != 0 {
				t.Fatalf("security callbacks called for malformed TLS string metadata: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsOversizedCertificateMetadataBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Raw: []byte{0x01}, RawSubject: bytes.Repeat([]byte{0x02}, maxMCPTLSCertificateBytes+1)}},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized certificate metadata status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks called for oversized certificate metadata: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsUnsupportedCertificatePublicKeyBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: struct{}{}}}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unsupported certificate public key status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks called for unsupported certificate public key: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsInvalidCertificateVersionBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, version := range []int{-1, 4, 99} {
		request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		request.Header.Set("Content-Type", "application/json")
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Version: version}}}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid certificate version %d status = %d, want %d", version, response.Code, http.StatusBadRequest)
		}
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks called for invalid certificate version: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedCertificatePublicKeyBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	key := &rsa.PublicKey{N: big.NewInt(3233), E: 17}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKeyAlgorithm: x509.RSA, PublicKey: key}}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			key.N.SetInt64(65537)
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate public key status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate public key: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedCertificatePublicKeyAlgorithmBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	key := ed25519.PublicKey(bytes.Repeat([]byte{1}, ed25519.PublicKeySize))
	certificate := &x509.Certificate{PublicKeyAlgorithm: x509.Ed25519, PublicKey: key}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.PublicKeyAlgorithm = x509.RSA
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate public-key algorithm status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate public-key algorithm: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRevalidatesBodyMutatedCertificateVersionBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{Version: 1}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Version = 4
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate version status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate version: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedCertificateVersionRepresentationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Version:    3,
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: []byte{1}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Version = 2
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate version representation status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate version representation: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedTLS12TLSUniqueBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	state := &tls.ConnectionState{
		Version:           tls.VersionTLS12,
		HandshakeComplete: true,
		CipherSuite:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLSUnique:         bytes.Repeat([]byte{1}, 12),
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = state
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			state.TLSUnique = nil
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated TLS 1.2 TLSUnique status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated TLS 1.2 TLSUnique: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyTLS12TLSUniqueBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	state := &tls.ConnectionState{
		Version:           tls.VersionTLS12,
		HandshakeComplete: true,
		DidResume:         true,
		CipherSuite:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = state
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			state.TLSUnique = []byte{}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced empty TLS 1.2 TLSUnique status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced empty TLS 1.2 TLSUnique: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyTLSCollectionsBeforeAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*tls.ConnectionState)
	}{
		{
			name: "peer certificates",
			mutate: func(state *tls.ConnectionState) {
				state.PeerCertificates = []*x509.Certificate{}
			},
		},
		{
			name: "verified chains",
			mutate: func(state *tls.ConnectionState) {
				state.VerifiedChains = [][]*x509.Certificate{}
			},
		},
		{
			name: "signed certificate timestamps",
			mutate: func(state *tls.ConnectionState) {
				state.SignedCertificateTimestamps = [][]byte{}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			state := &tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
				CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
			}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = state
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					tc.mutate(state)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-introduced empty TLS collection status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-introduced empty TLS collection: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestTLSCollectionSnapshotPreservesPresentEmptyCollections(t *testing.T) {
	state := &tls.ConnectionState{
		PeerCertificates:            []*x509.Certificate{},
		VerifiedChains:              [][]*x509.Certificate{{}},
		SignedCertificateTimestamps: [][]byte{},
	}
	clone := cloneTLSConnectionState(state)
	if clone.PeerCertificates == nil || clone.VerifiedChains == nil || clone.VerifiedChains[0] == nil || clone.SignedCertificateTimestamps == nil {
		t.Fatal("TLS clone collapsed a present empty collection")
	}
	if !equalTLSConnectionState(state, clone) {
		t.Fatal("TLS clone did not preserve present empty collection state")
	}
	snapshot := snapshotTLSCertificateMetadata(state)
	if !equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot did not preserve present empty collection state")
	}
}

func TestTLSCertificateCollectionSnapshotPreservesPresentEmptyCollections(t *testing.T) {
	certificate := &x509.Certificate{
		Extensions:            []pkix.Extension{},
		ExtraExtensions:       []pkix.Extension{},
		DNSNames:              []string{},
		EmailAddresses:        []string{},
		IPAddresses:           []net.IP{[]byte{}},
		URIs:                  []*url.URL{},
		OCSPServer:            []string{},
		IssuingCertificateURL: []string{},
		CRLDistributionPoints: []string{},
	}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	snapshot := snapshotTLSCertificateMetadata(state)
	if !equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot did not preserve present empty collections or IP element")
	}
}

func TestTLSCertificateURLSnapshotPreservesUserinfoStructure(t *testing.T) {
	certificate := &x509.Certificate{
		URIs: []*url.URL{{
			Scheme: "https",
			Host:   "relay.invalid",
			User:   url.UserPassword("alice", "secret"),
		}},
	}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	snapshot := snapshotTLSCertificateMetadata(state)
	if snapshot.peerCertificates[0].additionalURIs[0].User == certificate.URIs[0].User {
		t.Fatal("certificate URL snapshot retained the original userinfo pointer")
	}
	if !equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate URL snapshot rejected unchanged userinfo")
	}

	certificate.URIs[0].User = url.User("alice")
	if equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate URL snapshot accepted a body-time password-presence change")
	}
}

func TestTLSCertificateSnapshotDistinguishesNilAndPresentEmptyIPElement(t *testing.T) {
	presentEmpty := &x509.Certificate{IPAddresses: []net.IP{[]byte{}}}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{presentEmpty}}
	snapshot := snapshotTLSCertificateMetadata(state)
	if !equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot rejected unchanged present-empty IP element")
	}

	presentEmpty.IPAddresses[0] = nil
	if equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot accepted an omitted IP element after transport verification")
	}
}

func TestTLSCertificateNameConstraintSnapshotPreservesPresentEmptyCollections(t *testing.T) {
	certificate := &x509.Certificate{
		PermittedDNSDomains:     []string{},
		ExcludedDNSDomains:      []string{},
		PermittedIPRanges:       []*net.IPNet{},
		ExcludedIPRanges:        []*net.IPNet{},
		PermittedEmailAddresses: []string{},
		ExcludedEmailAddresses:  []string{},
		PermittedURIDomains:     []string{},
		ExcludedURIDomains:      []string{},
	}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	snapshot := snapshotTLSCertificateMetadata(state)
	if !equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot did not preserve present empty Name Constraints collections")
	}
}

func TestTLSCertificateNameConstraintSnapshotPreservesIPRangeElementPresence(t *testing.T) {
	certificate := &x509.Certificate{PermittedIPRanges: []*net.IPNet{nil}}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	snapshot := snapshotTLSCertificateMetadata(state)
	if !equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot rejected an unchanged nil IP range element")
	}

	certificate.PermittedIPRanges[0] = &net.IPNet{}
	if equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot accepted a present-empty IP range element after an omitted element")
	}

	certificate.PermittedIPRanges = []*net.IPNet{{}}
	snapshot = snapshotTLSCertificateMetadata(state)
	if !equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot rejected an unchanged present-empty IP range element")
	}
	certificate.PermittedIPRanges[0] = nil
	if equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot accepted an omitted IP range element after a present-empty element")
	}
}

func TestTLSCertificateNameSnapshotPreservesPresentEmptyCollections(t *testing.T) {
	certificate := &x509.Certificate{
		Issuer: pkix.Name{
			Country:      []string{},
			Organization: []string{},
			Names:        []pkix.AttributeTypeAndValue{{Type: []int{}, Value: ""}},
		},
		Subject: pkix.Name{
			OrganizationalUnit: []string{},
			Locality:           []string{},
			Province:           []string{},
			StreetAddress:      []string{},
			PostalCode:         []string{},
			ExtraNames:         []pkix.AttributeTypeAndValue{},
		},
	}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	snapshot := snapshotTLSCertificateMetadata(state)
	if !equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot did not preserve present empty issuer/subject collections")
	}
}

func TestTLSCertificatePolicyMappingSnapshotPreservesCollectionPresence(t *testing.T) {
	certificate := &x509.Certificate{}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	snapshot := snapshotTLSCertificateMetadata(state)
	certificate.PolicyMappings = []x509.PolicyMapping{}
	if equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot accepted a body-introduced present-empty policy-mapping collection")
	}
	if !equalTLSCertificateMetadata(snapshotTLSCertificateMetadata(state), state) {
		t.Fatal("certificate snapshot rejected an unchanged present-empty policy-mapping collection")
	}
}

func TestTLSCertificateSnapshotPreservesByteFieldPresence(t *testing.T) {
	fields := []struct {
		name string
		set  func(*x509.Certificate, []byte)
	}{
		{name: "raw", set: func(certificate *x509.Certificate, value []byte) { certificate.Raw = value }},
		{name: "raw TBS certificate", set: func(certificate *x509.Certificate, value []byte) {
			certificate.RawTBSCertificate = value
		}},
		{name: "raw subject public key info", set: func(certificate *x509.Certificate, value []byte) {
			certificate.RawSubjectPublicKeyInfo = value
		}},
		{name: "raw subject", set: func(certificate *x509.Certificate, value []byte) { certificate.RawSubject = value }},
		{name: "raw issuer", set: func(certificate *x509.Certificate, value []byte) { certificate.RawIssuer = value }},
		{name: "signature", set: func(certificate *x509.Certificate, value []byte) { certificate.Signature = value }},
		{name: "subject key identifier", set: func(certificate *x509.Certificate, value []byte) {
			certificate.SubjectKeyId = value
		}},
		{name: "authority key identifier", set: func(certificate *x509.Certificate, value []byte) {
			certificate.AuthorityKeyId = value
		}},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			certificate := &x509.Certificate{}
			state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			snapshot := snapshotTLSCertificateMetadata(state)
			if !equalTLSCertificateMetadata(snapshot, state) {
				t.Fatal("certificate snapshot rejected unchanged nil byte field")
			}

			field.set(certificate, []byte{})
			if equalTLSCertificateMetadata(snapshot, state) {
				t.Fatal("certificate snapshot accepted a body-introduced present-empty byte field")
			}

			presentEmpty := &x509.Certificate{}
			field.set(presentEmpty, []byte{})
			presentEmptyState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{presentEmpty}}
			if !equalTLSCertificateMetadata(snapshotTLSCertificateMetadata(presentEmptyState), presentEmptyState) {
				t.Fatal("certificate snapshot rejected unchanged present-empty byte field")
			}
		})
	}
}

func TestTLSCertificateExtensionSnapshotPreservesNestedFieldPresence(t *testing.T) {
	fields := []struct {
		name string
		set  func(*pkix.Extension)
	}{
		{name: "extension identifier", set: func(extension *pkix.Extension) { extension.Id = []int{} }},
		{name: "extension value", set: func(extension *pkix.Extension) { extension.Value = []byte{} }},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			certificate := &x509.Certificate{
				Extensions:      []pkix.Extension{{Id: []int{1, 2, 3}}},
				ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3}}},
			}
			state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			snapshot := snapshotTLSCertificateMetadata(state)
			if !equalTLSCertificateMetadata(snapshot, state) {
				t.Fatal("certificate snapshot rejected unchanged omitted extension field")
			}

			field.set(&certificate.Extensions[0])
			if equalTLSCertificateMetadata(snapshot, state) {
				t.Fatal("certificate snapshot accepted a body-introduced present-empty Extensions field")
			}

			certificate = &x509.Certificate{
				Extensions:      []pkix.Extension{{Id: []int{1, 2, 3}}},
				ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3}}},
			}
			state = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			snapshot = snapshotTLSCertificateMetadata(state)
			field.set(&certificate.ExtraExtensions[0])
			if equalTLSCertificateMetadata(snapshot, state) {
				t.Fatal("certificate snapshot accepted a body-introduced present-empty ExtraExtensions field")
			}

			presentEmpty := &x509.Certificate{
				Extensions:      []pkix.Extension{{Id: []int{}, Value: []byte{}}},
				ExtraExtensions: []pkix.Extension{{Id: []int{}, Value: []byte{}}},
			}
			presentEmptyState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{presentEmpty}}
			if !equalTLSCertificateMetadata(snapshotTLSCertificateMetadata(presentEmptyState), presentEmptyState) {
				t.Fatal("certificate snapshot rejected unchanged present-empty extension fields")
			}
		})
	}
}

func TestTLSCertificateOIDSnapshotPreservesNestedComponentPresence(t *testing.T) {
	fields := []struct {
		name string
		set  func(*x509.Certificate, []int)
	}{
		{name: "unhandled critical extension", set: func(certificate *x509.Certificate, oid []int) {
			certificate.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{oid}
		}},
		{name: "policy identifier", set: func(certificate *x509.Certificate, oid []int) {
			certificate.PolicyIdentifiers = []asn1.ObjectIdentifier{oid}
		}},
		{name: "unknown extended key usage", set: func(certificate *x509.Certificate, oid []int) {
			certificate.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oid}
		}},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			certificate := &x509.Certificate{}
			field.set(certificate, []int{})
			state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			snapshot := snapshotTLSCertificateMetadata(state)
			if !equalTLSCertificateMetadata(snapshot, state) {
				t.Fatal("certificate snapshot rejected unchanged present-empty OID component")
			}

			field.set(certificate, nil)
			if equalTLSCertificateMetadata(snapshot, state) {
				t.Fatal("certificate snapshot accepted a body-introduced omitted OID component")
			}
		})
	}
}

func TestTLSCertificateExtKeyUsageSnapshotPreservesCollectionPresence(t *testing.T) {
	certificate := &x509.Certificate{}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	snapshot := snapshotTLSCertificateMetadata(state)
	if !equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot rejected unchanged omitted extended-key-usage collection")
	}

	certificate.ExtKeyUsage = []x509.ExtKeyUsage{}
	if equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot accepted a body-introduced present-empty extended-key-usage collection")
	}

	presentEmpty := &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{}}
	presentEmptyState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{presentEmpty}}
	if !equalTLSCertificateMetadata(snapshotTLSCertificateMetadata(presentEmptyState), presentEmptyState) {
		t.Fatal("certificate snapshot rejected unchanged present-empty extended-key-usage collection")
	}
}

func TestTLSCertificatePoliciesSnapshotPreservesCollectionPresence(t *testing.T) {
	certificate := &x509.Certificate{}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	snapshot := snapshotTLSCertificateMetadata(state)
	if !equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot rejected unchanged omitted policy collection")
	}

	certificate.Policies = []x509.OID{}
	if equalTLSCertificateMetadata(snapshot, state) {
		t.Fatal("certificate snapshot accepted a body-introduced present-empty policy collection")
	}

	presentEmpty := &x509.Certificate{Policies: []x509.OID{}}
	presentEmptyState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{presentEmpty}}
	if !equalTLSCertificateMetadata(snapshotTLSCertificateMetadata(presentEmptyState), presentEmptyState) {
		t.Fatal("certificate snapshot rejected unchanged present-empty policy collection")
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedOIDComponentPresenceChangeBeforeAuthentication(t *testing.T) {
	fields := []struct {
		name string
		set  func(*x509.Certificate, []int)
	}{
		{name: "unhandled critical extension", set: func(certificate *x509.Certificate, oid []int) {
			certificate.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{oid}
		}},
		{name: "policy identifier", set: func(certificate *x509.Certificate, oid []int) {
			certificate.PolicyIdentifiers = []asn1.ObjectIdentifier{oid}
		}},
		{name: "unknown extended key usage", set: func(certificate *x509.Certificate, oid []int) {
			certificate.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oid}
		}},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			certificate := &x509.Certificate{}
			switch field.name {
			case "unhandled critical extension":
				certificate.Extensions = []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true}}
			case "policy identifier":
				// PolicyIdentifiers is accepted as an older partial representation
				// when no opaque Policies list is supplied.
			case "unknown extended key usage":
				// This private OID is not one of the standard known EKUs.
			}
			field.set(certificate, []int{1, 2, 3, 4})
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					field.set(certificate, nil)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-introduced OID component presence change status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-introduced OID component presence change: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyExtendedKeyUsageCollectionBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.ExtKeyUsage = []x509.ExtKeyUsage{}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced empty extended-key-usage collection status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced empty extended-key-usage collection: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyCertificatePoliciesBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Policies = []x509.OID{}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced empty policy collection status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced empty policy collection: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyTLSCertificateByteFieldsBeforeAuthentication(t *testing.T) {
	fields := []struct {
		name string
		set  func(*x509.Certificate, []byte)
	}{
		{name: "raw", set: func(certificate *x509.Certificate, value []byte) { certificate.Raw = value }},
		{name: "raw TBS certificate", set: func(certificate *x509.Certificate, value []byte) {
			certificate.RawTBSCertificate = value
		}},
		{name: "raw subject public key info", set: func(certificate *x509.Certificate, value []byte) {
			certificate.RawSubjectPublicKeyInfo = value
		}},
		{name: "raw subject", set: func(certificate *x509.Certificate, value []byte) { certificate.RawSubject = value }},
		{name: "raw issuer", set: func(certificate *x509.Certificate, value []byte) { certificate.RawIssuer = value }},
		{name: "signature", set: func(certificate *x509.Certificate, value []byte) { certificate.Signature = value }},
		{name: "subject key identifier", set: func(certificate *x509.Certificate, value []byte) {
			certificate.SubjectKeyId = value
		}},
		{name: "authority key identifier", set: func(certificate *x509.Certificate, value []byte) {
			certificate.AuthorityKeyId = value
		}},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			certificate := &x509.Certificate{}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					field.set(certificate, []byte{})
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-introduced empty certificate byte field status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-introduced empty certificate byte field: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyTLSCertificateExtensionFieldsBeforeAuthentication(t *testing.T) {
	fields := []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{name: "extension identifier", mutate: func(certificate *x509.Certificate) {
			certificate.Extensions[0].Id = []int{}
		}},
		{name: "extension value", mutate: func(certificate *x509.Certificate) {
			certificate.Extensions[0].Value = []byte{}
		}},
		{name: "extra extension identifier", mutate: func(certificate *x509.Certificate) {
			certificate.ExtraExtensions[0].Id = []int{}
		}},
		{name: "extra extension value", mutate: func(certificate *x509.Certificate) {
			certificate.ExtraExtensions[0].Value = []byte{}
		}},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			certificate := &x509.Certificate{
				Extensions:      []pkix.Extension{{Id: []int{1, 2, 3}}},
				ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3}}},
			}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					field.mutate(certificate)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-introduced empty certificate extension field status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-introduced empty certificate extension field: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyTLSCertificatePolicyMappingsBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.PolicyMappings = []x509.PolicyMapping{}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced empty policy-mapping collection status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced empty policy-mapping collection: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyTLSCertificateNameCollectionsBeforeAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{
			name: "issuer country",
			mutate: func(certificate *x509.Certificate) {
				certificate.Issuer.Country = []string{}
			},
		},
		{
			name: "subject organization",
			mutate: func(certificate *x509.Certificate) {
				certificate.Subject.Organization = []string{}
			},
		},
		{
			name: "issuer names",
			mutate: func(certificate *x509.Certificate) {
				certificate.Issuer.Names = []pkix.AttributeTypeAndValue{}
			},
		},
		{
			name: "subject extra names",
			mutate: func(certificate *x509.Certificate) {
				certificate.Subject.ExtraNames = []pkix.AttributeTypeAndValue{}
			},
		},
		{
			name: "issuer attribute OID",
			mutate: func(certificate *x509.Certificate) {
				certificate.Issuer.Names = []pkix.AttributeTypeAndValue{{Type: []int{}, Value: ""}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			certificate := &x509.Certificate{}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					tc.mutate(certificate)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-introduced empty certificate name collection status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-introduced empty certificate name collection: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyTLSCertificateCollectionsBeforeAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{
			name: "extensions",
			mutate: func(certificate *x509.Certificate) {
				certificate.Extensions = []pkix.Extension{}
			},
		},
		{
			name: "extra extensions",
			mutate: func(certificate *x509.Certificate) {
				certificate.ExtraExtensions = []pkix.Extension{}
			},
		},
		{
			name: "CRL distribution points",
			mutate: func(certificate *x509.Certificate) {
				certificate.CRLDistributionPoints = []string{}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			certificate := &x509.Certificate{}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					tc.mutate(certificate)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-introduced empty certificate collection status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-introduced empty certificate collection: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyTLSCertificateAIACollectionsBeforeAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{
			name: "OCSP servers",
			mutate: func(certificate *x509.Certificate) {
				certificate.OCSPServer = []string{}
			},
		},
		{
			name: "issuing certificate URLs",
			mutate: func(certificate *x509.Certificate) {
				certificate.IssuingCertificateURL = []string{}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			certificate := &x509.Certificate{}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					tc.mutate(certificate)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-introduced empty certificate AIA collection status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-introduced empty certificate AIA collection: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyTLSCertificateSANCollectionsBeforeAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{
			name: "DNS names",
			mutate: func(certificate *x509.Certificate) {
				certificate.DNSNames = []string{}
			},
		},
		{
			name: "email addresses",
			mutate: func(certificate *x509.Certificate) {
				certificate.EmailAddresses = []string{}
			},
		},
		{
			name: "IP addresses",
			mutate: func(certificate *x509.Certificate) {
				certificate.IPAddresses = []net.IP{}
			},
		},
		{
			name: "URIs",
			mutate: func(certificate *x509.Certificate) {
				certificate.URIs = []*url.URL{}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			certificate := &x509.Certificate{}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					tc.mutate(certificate)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-introduced empty certificate SAN collection status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-introduced empty certificate SAN collection: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedTLSCertificateURIUserinfoBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{URIs: []*url.URL{{
		Scheme: "https",
		Host:   "relay.invalid",
		User:   url.UserPassword("alice", "secret"),
	}}}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.URIs[0].User = url.User("alice")
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated certificate URI userinfo status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated certificate URI userinfo: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedEmptyTLSCertificateNameConstraintCollectionsBeforeAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{
			name: "permitted DNS domains",
			mutate: func(certificate *x509.Certificate) {
				certificate.PermittedDNSDomains = []string{}
			},
		},
		{
			name: "excluded DNS domains",
			mutate: func(certificate *x509.Certificate) {
				certificate.ExcludedDNSDomains = []string{}
			},
		},
		{
			name: "permitted IP ranges",
			mutate: func(certificate *x509.Certificate) {
				certificate.PermittedIPRanges = []*net.IPNet{}
			},
		},
		{
			name: "excluded IP ranges",
			mutate: func(certificate *x509.Certificate) {
				certificate.ExcludedIPRanges = []*net.IPNet{}
			},
		},
		{
			name: "permitted email addresses",
			mutate: func(certificate *x509.Certificate) {
				certificate.PermittedEmailAddresses = []string{}
			},
		},
		{
			name: "excluded email addresses",
			mutate: func(certificate *x509.Certificate) {
				certificate.ExcludedEmailAddresses = []string{}
			},
		},
		{
			name: "permitted URI domains",
			mutate: func(certificate *x509.Certificate) {
				certificate.PermittedURIDomains = []string{}
			},
		},
		{
			name: "excluded URI domains",
			mutate: func(certificate *x509.Certificate) {
				certificate.ExcludedURIDomains = []string{}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := Open(privateTempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			secureCalls := 0
			resolverCalls := 0
			handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
				resolverCalls++
				return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
			}, func(*http.Request) bool {
				secureCalls++
				return true
			})
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			certificate := &x509.Certificate{}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					tc.mutate(certificate)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-introduced empty Name Constraints collection status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-introduced empty Name Constraints collection: secure=%d resolver=%d, want one security callback and no resolver", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedCriticalKeyIdentifierBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 14}, Critical: false}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Critical = true
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced critical key-identifier status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced critical key identifier: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedCriticalAuthorityInfoAccessBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Critical: false}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Critical = true
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced critical authority-information-access status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced critical authority-information-access: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedCertificateKeyIdentifierRepresentationBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{name: "subject key identifier", mutate: func(certificate *x509.Certificate) {
			certificate.SubjectKeyId = []byte{1, 2, 3}
		}},
		{name: "authority key identifier", mutate: func(certificate *x509.Certificate) {
			certificate.AuthorityKeyId = []byte{4, 5, 6}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			certificate := &x509.Certificate{}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					tc.mutate(certificate)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-mutated certificate key-identifier representation status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-mutated certificate key-identifier representation: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedCertificateKeyIdentifierValueBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{name: "subject key identifier", mutate: func(certificate *x509.Certificate) {
			certificate.SubjectKeyId = []byte{8, 8, 8}
		}},
		{name: "authority key identifier", mutate: func(certificate *x509.Certificate) {
			certificate.AuthorityKeyId = []byte{7, 7, 7}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			subjectKeyID := []byte{1, 2, 3}
			authorityKeyID := []byte{4, 5, 6}
			certificate := &x509.Certificate{
				Extensions: []pkix.Extension{
					{Id: []int{2, 5, 29, 14}, Value: mustMarshalCertificateValue(t, subjectKeyID)},
					{Id: []int{2, 5, 29, 35}, Value: mustMarshalCertificateValue(t, struct {
						ID []byte `asn1:"optional,tag:0"`
					}{ID: authorityKeyID})},
				},
				SubjectKeyId:   subjectKeyID,
				AuthorityKeyId: authorityKeyID,
			}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					tc.mutate(certificate)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-mutated certificate key-identifier value status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-mutated certificate key-identifier value: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedEmptyCertificateKeyIdentifierSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		name  string
		index int
		value []byte
	}{
		{name: "subject key identifier", index: 0, value: []byte{0x04, 0x01}},
		{name: "authority key identifier", index: 1, value: []byte{0x30, 0x01, 0xa0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			certificate := &x509.Certificate{Extensions: []pkix.Extension{
				{Id: []int{2, 5, 29, 14}, Value: []byte{0x04, 0x00}},
				{Id: []int{2, 5, 29, 35}, Value: []byte{0x30, 0x00}},
			}}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					certificate.Extensions[tc.index].Value = append([]byte(nil), tc.value...)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-mutated empty certificate key-identifier source status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-mutated empty certificate key-identifier source: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedSubjectAltNameBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{name: "DNS name", mutate: func(certificate *x509.Certificate) {
			certificate.DNSNames = []string{"attacker.invalid"}
		}},
		{name: "email name", mutate: func(certificate *x509.Certificate) {
			certificate.EmailAddresses = []string{"attacker@invalid"}
		}},
		{name: "IP address", mutate: func(certificate *x509.Certificate) {
			certificate.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
		}},
		{name: "URI", mutate: func(certificate *x509.Certificate) {
			certificate.URIs = []*url.URL{{Scheme: "https", Host: "attacker.invalid"}}
		}},
		{name: "URI raw fragment delimiter", mutate: func(certificate *x509.Certificate) {
			certificate.URIs = []*url.URL{{Scheme: "https", Host: "relay.invalid", Path: "/cert#fragment", RawPath: "/cert#fragment"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secureCalls = 0
			resolverCalls = 0
			certificate := &x509.Certificate{
				Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
			}
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = int64(len(payload))
			request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
			request.Body = &mutatingRequestBody{
				request: request,
				reader:  bytes.NewReader(payload),
				mutate: func(*http.Request) {
					tc.mutate(certificate)
				},
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("body-introduced Subject Alternative Name status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if secureCalls != 1 || resolverCalls != 0 {
				t.Fatalf("security callbacks after body-introduced Subject Alternative Name: secure=%d resolver=%d", secureCalls, resolverCalls)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsBodyIntroducedLeadingDotSubjectAltNameURIHostBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	uri := &url.URL{Scheme: "https", Host: ".relay.invalid"}
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions = []pkix.Extension{{
				Id:    []int{2, 5, 29, 17},
				Value: mustMarshalCertificateSubjectAltNames(t, nil, nil, nil, []*url.URL{uri}),
			}}
			certificate.URIs = []*url.URL{uri}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced leading-dot Subject Alternative Name URI host status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-introduced leading-dot Subject Alternative Name URI host: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedSubjectAltNameValueBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	dnsNames := []string{"relay.invalid"}
	certificate := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: mustMarshalCertificateSubjectAltNames(t, dnsNames, nil, nil, nil)}},
		DNSNames:   dnsNames,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.DNSNames[0] = "attacker.invalid"
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated Subject Alternative Name value status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated Subject Alternative Name value: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedEmptySubjectAltNameSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: []byte{0x30, 0x00}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x30, 0x01, 0x82}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated empty Subject Alternative Name source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated empty Subject Alternative Name source: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedSubjectAltNameOuterTrailingFieldBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	dnsNames := []string{"relay.invalid"}
	certificate := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: mustMarshalCertificateSubjectAltNames(t, dnsNames, nil, nil, nil)}},
		DNSNames:   dnsNames,
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = mustMarshalCertificateSubjectAltNamesWithTrailingOuterField(t, dnsNames, mustMarshalCertificateValue(t, int64(7)))
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated outer Subject Alternative Name trailing field status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated outer Subject Alternative Name trailing field: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedExtendedKeyUsageOuterTrailingFieldBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	usages := []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}}
	certificate := &x509.Certificate{
		Raw: []byte{0x01, 0x02, 0x03},
		Extensions: []pkix.Extension{{
			Id:    []int{2, 5, 29, 37},
			Value: mustMarshalCertificateExtendedKeyUsages(t, usages),
		}},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = mustMarshalCertificateExtendedKeyUsagesWithTrailingOuterField(t, usages, mustMarshalCertificateValue(t, int64(7)))
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated outer Extended Key Usage trailing field status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated outer Extended Key Usage trailing field: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedEmptyExtendedKeyUsageSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 37}, Value: []byte{0x30, 0x00}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x30, 0x01, 0x06}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated empty Extended Key Usage source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated empty Extended Key Usage source: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedEmptyKeyUsageSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: []int{2, 5, 29, 15}, Value: []byte{0x03, 0x01, 0x00}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x03, 0x01, 0x07}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated empty Key Usage source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated empty Key Usage source: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedEmptyAuthorityInfoAccessSourceBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 1, 1}, Value: []byte{0x30, 0x00}}},
	}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(*http.Request) {
			certificate.Extensions[0].Value = []byte{0x30, 0x01, 0x30}
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated empty Authority Information Access source status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body-mutated empty Authority Information Access source: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsOversizedDirectHeaderNameBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0"}`))
	request.Header["Content-Type"] = []string{"application/json"}
	request.Header[strings.Repeat("x", maxMCPHeaderNameBytes+1)] = []string{"ignored"}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized direct header name status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalls != 0 {
		t.Fatal("oversized direct header name reached authentication")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsOversizedDirectHeaderValuesBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		header http.Header
	}{
		{name: "single oversized value", header: http.Header{
			"Content-Type": []string{"application/json"},
			"X-Direct":     []string{strings.Repeat("x", maxMCPHeaderValueBytes+1)},
		}},
		{name: "aggregate oversized values", header: http.Header{
			"Content-Type": []string{"application/json"},
			"X-First":      []string{strings.Repeat("x", maxMCPHeaderBytes/2)},
			"X-Second":     []string{strings.Repeat("y", maxMCPHeaderBytes/2+1)},
		}},
		{name: "too many entries", header: func() http.Header {
			values := make([]string, maxMCPHeaderEntries+1)
			return http.Header{
				"Content-Type": []string{"application/json"},
				"X-Direct":     values,
			}
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header = tc.header
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks called for oversized direct header values: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
}

func TestMCPHTTPHandlerRejectsMalformedDirectHeaderMetadataBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		header http.Header
	}{
		{name: "empty field name", header: http.Header{"": {"ignored"}}},
		{name: "space in field name", header: http.Header{"X Invalid": {"ignored"}}},
		{name: "control in field name", header: http.Header{"X-Invalid\n": {"ignored"}}},
		{name: "line feed in field value", header: http.Header{"X-Direct": {"bad\nvalue"}}},
		{name: "carriage return in field value", header: http.Header{"X-Direct": {"bad\rvalue"}}},
		{name: "delete in field value", header: http.Header{"X-Direct": {"bad\x7fvalue"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.Header = http.Header{
				"Content-Type": []string{"application/json"},
			}
			for key, values := range tc.header {
				request.Header[key] = values
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks called for malformed direct header metadata: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
}

func TestMCPHTTPHandlerBindsAuthenticatedPrincipal(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, err := NewMCPHTTPHandler(store, func(r *http.Request) (Principal, error) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			return Principal{}, errors.New("invalid test credential")
		}
		return Principal{ID: "controller-a", Scopes: []string{ScopeProjectWrite}}, nil
	}, RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}

	request := func(token string, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(body))
		req.TLS = &tlsStateForTest
		req.Header.Set("Authorization", token)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := request("Bearer wrong", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"P"}}}`); response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("unauthorized status/challenge = %d/%q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
	response := request("Bearer test-token", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"P"}}}`)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"isError":false`)) {
		t.Fatalf("authorized response = %d %s", response.Code, response.Body.String())
	}
	assertHTTPBoundaryHeaders(t, response)
	if _, err := store.Project("p"); err != nil {
		t.Fatalf("authenticated principal did not create project: %v", err)
	}
}

func TestMCPHTTPHandlerBoundsBodyAndSuppressesNotificationResponse(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "controller-a", Scopes: []string{ScopeProjectWrite}}, nil
	}, RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}

	oversized := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(strings.Repeat("x", maxMCPRequestBytes+1)))
	oversized.TLS = &tlsStateForTest
	oversized.Header.Set("Content-Type", "application/json")
	oversized.ContentLength = maxMCPRequestBytes + 1
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, oversized)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", response.Code)
	}
	assertHTTPBoundaryHeaders(t, response)

	notification := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"p","name":"P"}}}`))
	notification.TLS = &tlsStateForTest
	notification.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, notification)
	if response.Code != http.StatusAccepted || response.Body.Len() != 0 {
		t.Fatalf("notification response = %d %q", response.Code, response.Body.String())
	}
	assertHTTPBoundaryHeaders(t, response)
	if _, err := store.Project("p"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("notification mutated lifecycle state: %v", err)
	}

	withoutBody := &http.Request{
		Method: http.MethodPost,
		URL:    httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil).URL,
		TLS:    &tlsStateForTest,
		Header: http.Header{"Content-Type": []string{"application/json"}},
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, withoutBody)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("nil body status = %d", response.Code)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsInvalidBodyReadCountBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		body io.ReadCloser
	}{
		{name: "negative count", body: invalidCountBody{count: -1}},
		{name: "count beyond buffer", body: invalidCountBody{count: maxMCPRequestBytes + 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
			request.Body = tc.body
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
	if resolverCalls != 0 {
		t.Fatalf("resolver calls = %d, want 0", resolverCalls)
	}
}

func TestMCPHTTPHandlerRejectsUncomparableRequestBodyBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	var closes atomic.Int32
	request.Body = countingUncomparableReadCloser{data: []byte("body"), closes: &closes}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("uncomparable body status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("security callbacks for uncomparable body: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("uncomparable entry body close count = %d, want 1", got)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyIntroducedUncomparableRequestBody(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.Body = uncomparableReadCloser("replacement")
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-introduced uncomparable body status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body replacement: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerClosesBodyReplacementAfterBodyMutation(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	replacement := &trackingBody{ReadCloser: io.NopCloser(strings.NewReader("replacement"))}
	original := &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.Body = replacement
		},
	}
	request.Body = original
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("body replacement status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("security callbacks after body replacement: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	if !replacement.closed {
		t.Fatal("body replacement was not closed")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerClosesIntermediateBodyReplacements(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	first := &trackingBody{ReadCloser: io.NopCloser(strings.NewReader("first"))}
	second := &trackingBody{ReadCloser: io.NopCloser(strings.NewReader("second"))}
	original := &rotatingRequestBody{
		request:      request,
		reader:       bytes.NewReader(payload),
		replacements: []*trackingBody{first, second},
	}
	request.Body = original
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("rotating body status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if !original.closed {
		t.Fatal("original body was not closed")
	}
	if !first.closed || !second.closed {
		t.Fatalf("intermediate body cleanup = first:%t second:%t, want both closed", first.closed, second.closed)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerBoundsBodyMutationTracking(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	var closes atomic.Int32
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	body := &mutationBudgetBody{request: request, closes: &closes}
	request.Body = body
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("body mutation overflow status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("callbacks after body mutation overflow: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	if body.reads != maxMCPBodyMutationReplacements+1 {
		t.Fatalf("body reads before mutation overflow = %d, want %d", body.reads, maxMCPBodyMutationReplacements+1)
	}
	if got := closes.Load(); got != maxMCPBodyCleanupCandidates {
		t.Fatalf("body close count after mutation overflow = %d, want %d", got, maxMCPBodyCleanupCandidates)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestCloseRequestBodiesDoesNotMergeDistinctFunctionClosures(t *testing.T) {
	firstClosed := 0
	secondClosed := 0
	first := newFunctionReadCloser(&firstClosed)
	second := newFunctionReadCloser(&secondClosed)

	if sameRequestBodyForCleanup(first, second) {
		t.Fatal("distinct function closures were treated as one request body")
	}
	request := &http.Request{Body: second}
	closeRequestBodies(request, first, nil, false)
	if firstClosed != 1 || secondClosed != 1 {
		t.Fatalf("function body cleanup = first:%d second:%d, want one close each", firstClosed, secondClosed)
	}
}

var sliceReadCloserCloseCounts [3]atomic.Int32

type sliceReadCloser []byte

func (sliceReadCloser) Read([]byte) (int, error) { return 0, io.EOF }

func (body sliceReadCloser) Close() error {
	sliceReadCloserCloseCounts[len(body)].Add(1)
	return nil
}

func TestCloseRequestBodiesDoesNotMergeDistinctSliceViews(t *testing.T) {
	for index := range sliceReadCloserCloseCounts {
		sliceReadCloserCloseCounts[index].Store(0)
	}
	backing := []byte{1, 2}
	first := sliceReadCloser(backing[:1])
	second := sliceReadCloser(backing[:2])

	if sameRequestBodyForCleanup(first, second) {
		t.Fatal("distinct slice-backed bodies were treated as one request body")
	}
	request := &http.Request{Body: second}
	closeRequestBodies(request, first, nil, false)
	if got := sliceReadCloserCloseCounts[1].Load(); got != 1 {
		t.Fatalf("first slice body close count = %d, want 1", got)
	}
	if got := sliceReadCloserCloseCounts[2].Load(); got != 1 {
		t.Fatalf("second slice body close count = %d, want 1", got)
	}
}

func TestMCPHTTPHandlerRejectsBodyMutatedPathValueBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle/item", nil)
	request.Pattern = "/lifecycle/{item}"
	request.SetPathValue("item", "item")
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.SetPathValue("item", "after")
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated path value status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("callbacks after body path-value replacement: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsBodyMutatedMethodBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	request.Body = &mutatingRequestBody{
		request: request,
		reader:  bytes.NewReader(payload),
		mutate: func(request *http.Request) {
			request.Method = strings.Repeat("M", maxMCPMethodBytes+1)
		},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("body-mutated method status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if secureCalls != 1 || resolverCalls != 0 {
		t.Fatalf("callbacks after body method replacement: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

type invalidCountBody struct {
	count int
}

type uncomparableReadCloser []byte

func (uncomparableReadCloser) Read([]byte) (int, error) { return 0, io.EOF }

func (uncomparableReadCloser) Close() error { return nil }

type countingUncomparableReadCloser struct {
	data   []byte
	closes *atomic.Int32
}

func (countingUncomparableReadCloser) Read([]byte) (int, error) { return 0, io.EOF }

func (body countingUncomparableReadCloser) Close() error {
	body.closes.Add(1)
	return nil
}

type functionReadCloser func([]byte) (int, error)

func (f functionReadCloser) Read(p []byte) (int, error) { return f(p) }

func (f functionReadCloser) Close() error {
	_, err := f(nil)
	return err
}

func newFunctionReadCloser(closed *int) functionReadCloser {
	return func(p []byte) (int, error) {
		if p == nil {
			(*closed)++
			return 0, nil
		}
		return 0, io.EOF
	}
}

type mutatingRequestBody struct {
	request *http.Request
	reader  *bytes.Reader
	mutate  func(*http.Request)
	done    bool
}

func (body *mutatingRequestBody) Read(p []byte) (int, error) {
	if !body.done {
		body.done = true
		body.mutate(body.request)
	}
	return body.reader.Read(p)
}

func (*mutatingRequestBody) Close() error { return nil }

type rotatingRequestBody struct {
	request      *http.Request
	reader       *bytes.Reader
	replacements []*trackingBody
	index        int
	closed       bool
}

func (body *rotatingRequestBody) Read(p []byte) (int, error) {
	if body.index < len(body.replacements) {
		body.request.Body = body.replacements[body.index]
		body.index++
	}
	return body.reader.Read(p)
}

func (body *rotatingRequestBody) Close() error {
	body.closed = true
	return nil
}

type mutationBudgetBody struct {
	request *http.Request
	closes  *atomic.Int32
	reads   int
}

func (body *mutationBudgetBody) Read(p []byte) (int, error) {
	body.reads++
	body.request.Body = &countedReplacementBody{closes: body.closes}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, nil
}

func (body *mutationBudgetBody) Close() error {
	body.closes.Add(1)
	return nil
}

type countedReplacementBody struct {
	closes *atomic.Int32
}

func (*countedReplacementBody) Read([]byte) (int, error) { return 0, io.EOF }

func (body *countedReplacementBody) Close() error {
	body.closes.Add(1)
	return nil
}

func (invalidCountBody) Close() error { return nil }

func (b invalidCountBody) Read(p []byte) (int, error) { return b.count, nil }

func TestMCPHTTPHandlerRejectsMalformedContentLength(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolverCalled := false
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalled = true
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.TLS = &tlsStateForTest
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = -2
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed Content-Length status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalled {
		t.Fatal("principal resolver called for malformed request framing")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsMismatchedContentLength(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolverCalled := false
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalled = true
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}

	const body = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	for _, tc := range []struct {
		name          string
		contentLength int64
	}{
		{name: "declared shorter", contentLength: int64(len(body) - 1)},
		{name: "declared longer", contentLength: int64(len(body) + 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolverCalled = false
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(body))
			request.TLS = &tlsStateForTest
			request.Header.Set("Content-Type", "application/json")
			request.ContentLength = tc.contentLength
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if resolverCalled {
				t.Fatal("principal resolver called for mismatched request framing")
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerValidatesTransferEncodingBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolverCalled := false
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalled = true
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name             string
		transferEncoding []string
		contentLength    int64
		want             int
	}{
		{name: "unsupported coding", transferEncoding: []string{"gzip"}, contentLength: -1, want: http.StatusBadRequest},
		{name: "duplicate chunked coding", transferEncoding: []string{"chunked", "chunked"}, contentLength: -1, want: http.StatusBadRequest},
		{name: "chunked with content length", transferEncoding: []string{"chunked"}, contentLength: 2, want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolverCalled = false
			req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.TransferEncoding = tc.transferEncoding
			req.ContentLength = tc.contentLength
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, req)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
			if resolverCalled {
				t.Fatal("principal resolver called for invalid transfer framing")
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}

	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.TransferEncoding = []string{"CHUNKED"}
	req.ContentLength = -1
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("valid chunked status = %d, want %d", response.Code, http.StatusOK)
	}
	if !resolverCalled {
		t.Fatal("principal resolver was not called for valid chunked framing")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsRawFramingHeaderAmbiguity(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	const body = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	for _, tc := range []struct {
		name             string
		transferHeaders  []string
		contentHeaders   []string
		transferEncoding []string
		contentLength    int64
		emptyTransfer    bool
		emptyContent     bool
		want             int
	}{
		{name: "raw unsupported transfer coding", transferHeaders: []string{"gzip"}, contentLength: int64(len(body)), want: http.StatusBadRequest},
		{name: "raw transfer coding without parsed field", transferHeaders: []string{"chunked"}, contentLength: int64(len(body)), want: http.StatusBadRequest},
		{name: "empty raw transfer coding", emptyTransfer: true, contentLength: int64(len(body)), want: http.StatusBadRequest},
		{name: "empty differently cased transfer coding", transferHeaders: []string{"chunked"}, emptyTransfer: true, transferEncoding: []string{"chunked"}, contentLength: -1, want: http.StatusBadRequest},
		{name: "duplicate raw transfer coding", transferHeaders: []string{"chunked", "chunked"}, transferEncoding: []string{"chunked"}, contentLength: -1, want: http.StatusBadRequest},
		{name: "malformed raw content length", contentHeaders: []string{"not-a-length"}, contentLength: int64(len(body)), want: http.StatusBadRequest},
		{name: "empty raw content length", emptyContent: true, contentLength: int64(len(body)), want: http.StatusBadRequest},
		{name: "empty differently cased content length", contentHeaders: []string{strconv.Itoa(len(body))}, emptyContent: true, contentLength: int64(len(body)), want: http.StatusBadRequest},
		{name: "negative raw content length", contentHeaders: []string{"-1"}, contentLength: -1, want: http.StatusBadRequest},
		{name: "signed raw content length", contentHeaders: []string{"+" + strconv.Itoa(len(body))}, contentLength: int64(len(body)), want: http.StatusBadRequest},
		{name: "conflicting raw content length", contentHeaders: []string{"1"}, contentLength: int64(len(body)), want: http.StatusBadRequest},
		{name: "oversized raw content length", contentHeaders: []string{strings.Repeat("1", maxMCPFramingValueBytes+1)}, contentLength: int64(len(body)), want: http.StatusBadRequest},
		{name: "oversized raw transfer coding", transferHeaders: []string{strings.Repeat("x", maxMCPFramingValueBytes+1)}, contentLength: int64(len(body)), want: http.StatusBadRequest},
		{name: "oversized parsed transfer coding", transferEncoding: []string{strings.Repeat("x", maxMCPFramingValueBytes+1)}, contentLength: -1, want: http.StatusBadRequest},
		{name: "matching raw content length", contentHeaders: []string{strconv.Itoa(len(body))}, contentLength: int64(len(body)), want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := resolverCalls
			req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			for _, value := range tc.transferHeaders {
				req.Header.Add("Transfer-Encoding", value)
			}
			for _, value := range tc.contentHeaders {
				req.Header.Add("Content-Length", value)
			}
			if tc.emptyTransfer {
				req.Header["transfer-encoding"] = nil
			}
			if tc.emptyContent {
				req.Header["content-length"] = nil
			}
			req.TransferEncoding = tc.transferEncoding
			req.ContentLength = tc.contentLength
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, req)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
			if tc.want != http.StatusOK && resolverCalls != before {
				t.Fatal("principal resolver called for ambiguous raw framing metadata")
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
}

func TestMCPHTTPHandlerRejectsAmbiguousOrOversizedContentTypeBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolverCalled := false
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalled = true
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, RequireDirectTLS)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		values []string
		want   int
	}{
		{name: "duplicate", values: []string{"application/json", "application/json"}, want: http.StatusBadRequest},
		{name: "oversized", values: []string{strings.Repeat("a", maxMCPContentTypeBytes+1)}, want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolverCalled = false
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			request.TLS = &tlsStateForTest
			for _, value := range tc.values {
				request.Header.Add("Content-Type", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
			if resolverCalled {
				t.Fatal("principal resolver called for ambiguous or oversized media type")
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.TLS = &tlsStateForTest
	request.Header = http.Header{
		"Content-Type": []string{"application/json"},
		"content-type": []string{"application/json"},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("differently cased duplicate status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalled {
		t.Fatal("principal resolver called for differently cased duplicate media type")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsNilBodyBeforeAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolverCalled := false
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalled = true
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	request := &http.Request{
		Method:        http.MethodPost,
		TLS:           &tlsStateForTest,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		ContentLength: 0,
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("nil body status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalled {
		t.Fatal("principal resolver called for malformed nil-body request")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsDoneRequestContextBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolveCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolveCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		ctx  func() context.Context
	}{
		{name: "canceled", ctx: func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
		{name: "deadline exceeded", ctx: func() context.Context {
			ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
			cancel()
			return ctx
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)).WithContext(tc.ctx())
			request.TLS = &tlsStateForTest
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusRequestTimeout {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestTimeout)
			}
			assertHTTPBoundaryHeaders(t, response)
		})
	}
	if secureCalls != 0 || resolveCalls != 0 {
		t.Fatalf("security callbacks called for done contexts: secure=%d resolve=%d", secureCalls, resolveCalls)
	}
}

func TestMCPHTTPHandlerRejectsTypedNilRequestContextBeforeSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	secureCalls := 0
	resolveCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolveCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectWrite}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	var typedNil *typedNilMCPContext
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"typed-nil","name":"Typed nil"}}}`,
	)).WithContext(typedNil)
	request.TLS = &tlsStateForTest
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestTimeout)
	}
	if secureCalls != 0 || resolveCalls != 0 {
		t.Fatalf("security callbacks called for typed-nil context: secure=%d resolve=%d", secureCalls, resolveCalls)
	}
	if _, err := store.Project("typed-nil"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("typed-nil request mutated lifecycle state: %v", err)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsCancellationAfterAuthentication(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	resolverCalls := 0
	secureCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		cancel()
		return Principal{
			ID:     "owner",
			Scopes: []string{ScopeProjectWrite},
		}, nil
	}, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"cancelled-project","name":"should-not-exist"}}}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestTimeout)
	}
	if resolverCalls != 1 || secureCalls != 1 {
		t.Fatalf("callback counts = secure %d, resolve %d, want 1 each", secureCalls, resolverCalls)
	}
	if _, err := store.Project("cancelled-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("canceled request mutated lifecycle state: project lookup error = %v", err)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerMapsAdapterContextCancellationToTimeout(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	requestContext := &cancelAfterResolverContext{}
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		requestContext.afterResolver.Store(true)
		return Principal{ID: "owner", Scopes: []string{ScopeProjectWrite}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"adapter-cancelled-project","name":"should-not-exist"}}}`)).WithContext(requestContext)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestTimeout)
	}
	if resolverCalls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolverCalls)
	}
	if _, err := store.Project("adapter-cancelled-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("adapter-boundary cancellation mutated lifecycle state: %v", err)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsCancellationAfterTransportVerification(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	resolverCalls := 0
	secureCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectWrite}}, nil
	}, func(*http.Request) bool {
		secureCalls++
		cancel()
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lifecycle.project.create","arguments":{"id":"transport-cancelled-project","name":"should-not-exist"}}}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestTimeout)
	}
	if resolverCalls != 0 || secureCalls != 1 {
		t.Fatalf("callback counts = secure %d, resolve %d, want 1 and 0", secureCalls, resolverCalls)
	}
	if _, err := store.Project("transport-cancelled-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("canceled request mutated lifecycle state: project lookup error = %v", err)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerRejectsCancellationDuringBodyRead(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectWrite}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Body = &cancelOnReadBody{cancel: cancel}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestTimeout)
	}
	if resolverCalls != 0 {
		t.Fatal("principal resolver called after body-read cancellation")
	}
	if _, err := store.Project("body-cancelled-project"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("canceled request mutated lifecycle state: project lookup error = %v", err)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerClosesRequestBodyOnEarlyAndSuccessfulPaths(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "controller", Scopes: []string{ScopeProjectRead, ScopeProjectWrite, ScopeTaskRead, ScopeTaskWrite, ScopeTaskLease}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "early method rejection", method: http.MethodGet, body: "ignored", want: http.StatusMethodNotAllowed},
		{name: "successful request", method: http.MethodPost, body: `{"jsonrpc":"2.0","id":1,"method":"ping"}`, want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "https://relay.invalid/lifecycle", strings.NewReader(tc.body))
			body := &trackingBody{ReadCloser: req.Body}
			req.Body = body
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, req)

			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
			if !body.closed {
				t.Fatal("request body was not closed")
			}
		})
	}
}

func TestMCPHTTPHandlerClosesBodyWhenReceiverIsUninitialized(t *testing.T) {
	for name, handler := range map[string]*MCPHTTPHandler{
		"zero value":   {},
		"nil receiver": nil,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader("{}"))
			body := &trackingBody{ReadCloser: req.Body}
			req.Body = body
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, req)

			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
			}
			if !body.closed {
				t.Fatal("request body was not closed for uninitialized handler")
			}
		})
	}
}

func TestMCPHTTPHandlerClosesBodyInstalledDuringClose(t *testing.T) {
	replacement := &trackingBody{ReadCloser: io.NopCloser(strings.NewReader("replacement"))}
	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	original := &closeReplacingBody{replacement: replacement}
	original.request = request
	request.Body = original
	response := httptest.NewRecorder()

	(&MCPHTTPHandler{}).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if original.closed != 1 {
		t.Fatalf("original body close count = %d, want 1", original.closed)
	}
	if !replacement.closed {
		t.Fatal("body installed during Close was not closed")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerClosesUncomparableEntryBodyOnceBeforeTracking(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	initialized, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		handler *MCPHTTPHandler
		method  string
		want    int
	}{
		{name: "uninitialized handler", handler: &MCPHTTPHandler{}, method: http.MethodPost, want: http.StatusServiceUnavailable},
		{name: "early method rejection", handler: initialized, method: http.MethodGet, want: http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var closes atomic.Int32
			request := httptest.NewRequest(tc.method, "https://relay.invalid/lifecycle", nil)
			request.Body = countingUncomparableReadCloser{data: []byte("body"), closes: &closes}
			response := httptest.NewRecorder()

			tc.handler.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
			if got := closes.Load(); got != 1 {
				t.Fatalf("uncomparable entry body close count = %d, want 1", got)
			}
		})
	}
}

func TestMCPHTTPHandlerContainsRequestBodyClosePanic(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Body = panicCloseBody{ReadCloser: req.Body}
	response := httptest.NewRecorder()

	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("ServeHTTP propagated request-body close panic: %v", recovered)
			}
		}()
		handler.ServeHTTP(response, req)
	}()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestMCPHTTPHandlerContainsResponseWriterPanicsAndClosesBody(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return false })
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		writer http.ResponseWriter
	}{
		{name: "header", writer: panicHeaderWriter{}},
		{name: "write", writer: panicWriteWriter{header: make(http.Header)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			body := &trackingBody{ReadCloser: req.Body}
			req.Body = body

			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				handler.ServeHTTP(tc.writer, req)
			}()
			if panicked {
				t.Fatal("ServeHTTP propagated response-writer panic")
			}
			if !body.closed {
				t.Fatal("request body was not closed after response-writer panic")
			}
		})
	}
}

func TestMCPHTTPHandlerContainsRequestBodyReadPanic(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolverCalled := false
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalled = true
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	body := &panicReadBody{ReadCloser: req.Body}
	req.Body = body
	response := httptest.NewRecorder()

	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("ServeHTTP propagated request-body read panic: %v", recovered)
			}
		}()
		handler.ServeHTTP(response, req)
	}()
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalled {
		t.Fatal("principal resolver called after request-body read panic")
	}
	if !body.closed {
		t.Fatal("request body was not closed after read panic")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerBoundsRequestBodyNoProgress(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolverCalled := false
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalled = true
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", nil)
	req.Header.Set("Content-Type", "application/json")
	body := &noProgressBody{}
	req.Body = body
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, req)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("no-progress body status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if resolverCalled {
		t.Fatal("principal resolver called after no-progress request body")
	}
	if body.closed != 1 {
		t.Fatalf("request body close count = %d, want 1", body.closed)
	}
	if body.reads != maxRequestBodyEmptyReads {
		t.Fatalf("no-progress reads = %d, want %d", body.reads, maxRequestBodyEmptyReads)
	}
	assertHTTPBoundaryHeaders(t, response)
}

type trackingBody struct {
	io.ReadCloser
	closed bool
}

type closeReplacingBody struct {
	request     *http.Request
	replacement io.ReadCloser
	closed      int
}

func (*closeReplacingBody) Read([]byte) (int, error) { return 0, io.EOF }

func (body *closeReplacingBody) Close() error {
	body.closed++
	body.request.Body = body.replacement
	return nil
}

type countingCloseBody struct {
	io.ReadCloser
	closeCount int
}

func (b *countingCloseBody) Close() error {
	b.closeCount++
	return b.ReadCloser.Close()
}

type cancelOnReadBody struct {
	cancel context.CancelFunc
	closed bool
}

func (b *cancelOnReadBody) Read([]byte) (int, error) {
	b.cancel()
	return 0, io.EOF
}

func (b *cancelOnReadBody) Close() error {
	b.closed = true
	return nil
}

func (b *trackingBody) Close() error {
	b.closed = true
	return b.ReadCloser.Close()
}

type panicCloseBody struct {
	io.ReadCloser
}

func (panicCloseBody) Close() error {
	panic("test request-body close panic")
}

type panicCountingCloseBody struct {
	io.ReadCloser
	closeCount int
}

func (b *panicCountingCloseBody) Close() error {
	b.closeCount++
	panic("test transport-verifier body close panic")
}

type panicHeaderWriter struct{}

func (panicHeaderWriter) Header() http.Header { panic("test response-writer header panic") }
func (panicHeaderWriter) Write([]byte) (int, error) {
	panic("test response-writer write panic")
}
func (panicHeaderWriter) WriteHeader(int) {}

type panicWriteWriter struct {
	header http.Header
}

func (w panicWriteWriter) Header() http.Header { return w.header }
func (panicWriteWriter) Write([]byte) (int, error) {
	panic("test response-writer write panic")
}
func (panicWriteWriter) WriteHeader(int) {}

type panicReadBody struct {
	io.ReadCloser
	closed bool
}

type noProgressBody struct {
	reads  int
	closed int
}

type cancelAfterResolverContext struct {
	afterResolver      atomic.Bool
	postResolverChecks atomic.Int32
}

func (*cancelAfterResolverContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*cancelAfterResolverContext) Done() <-chan struct{}       { return nil }
func (c *cancelAfterResolverContext) Err() error {
	if !c.afterResolver.Load() {
		return nil
	}
	if c.postResolverChecks.Add(1) >= 2 {
		return context.Canceled
	}
	return nil
}
func (*cancelAfterResolverContext) Value(any) any { return nil }

func (b *noProgressBody) Read([]byte) (int, error) {
	b.reads++
	return 0, nil
}

func (b *noProgressBody) Close() error {
	b.closed++
	return nil
}

func (b *panicReadBody) Read([]byte) (int, error) {
	panic("test request-body read panic")
}

func (b *panicReadBody) Close() error {
	b.closed = true
	return b.ReadCloser.Close()
}

func assertHTTPBoundaryHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := response.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := response.Header().Get("MCP-Protocol-Version"); got != MCPProtocolVersion {
		t.Fatalf("MCP-Protocol-Version = %q, want %s", got, MCPProtocolVersion)
	}
	if got := response.Header().Get("Vary"); got != "Authorization, Accept, MCP-Protocol-Version" {
		t.Fatalf("Vary = %q, want Authorization, Accept, MCP-Protocol-Version", got)
	}
}

func TestNewMCPHTTPHandlerRequiresSecurityCallbacks(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolver := PrincipalResolver(func(*http.Request) (Principal, error) { return Principal{}, nil })
	secure := SecureTransportVerifier(func(*http.Request) bool { return true })
	for name, tc := range map[string]struct {
		resolve PrincipalResolver
		verify  SecureTransportVerifier
	}{
		"missing resolver": {nil, secure},
		"missing verifier": {resolver, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewMCPHTTPHandler(store, tc.resolve, tc.verify); err == nil {
				t.Fatal("accepted incomplete security boundary")
			}
		})
	}
}

func TestNewMCPHTTPHandlerRejectsUninitializedOrClosedStore(t *testing.T) {
	resolver := PrincipalResolver(func(*http.Request) (Principal, error) {
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	})
	secure := SecureTransportVerifier(func(*http.Request) bool { return true })
	var zero Store
	if _, err := NewMCPHTTPHandler(&zero, resolver, secure); !errors.Is(err, ErrClosed) {
		t.Fatalf("zero-value store = %v, want ErrClosed", err)
	}

	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMCPHTTPHandler(store, resolver, secure); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed store = %v, want ErrClosed", err)
	}
}

func TestMCPHTTPHandlerReportsStoreCloseAsUnavailable(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	resolverCalls := 0
	secureCalls := 0
	resolver := PrincipalResolver(func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	})
	handler, err := NewMCPHTTPHandler(store, resolver, func(*http.Request) bool {
		secureCalls++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed-store status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if secureCalls != 0 || resolverCalls != 0 {
		t.Fatalf("closed store reached security callbacks: secure=%d resolver=%d", secureCalls, resolverCalls)
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerStopsBeforeAuthenticationWhenStoreClosesDuringTransport(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	resolverCalls := 0
	handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
		resolverCalls++
		return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
	}, func(*http.Request) bool {
		if err := store.Close(); err != nil {
			t.Fatalf("close store from transport verifier: %v", err)
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("store-close-during-transport status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if resolverCalls != 0 {
		t.Fatal("principal resolver called after store closed during transport verification")
	}
	assertHTTPBoundaryHeaders(t, response)
}

func TestMCPHTTPHandlerContainsSecurityCallbackPanics(t *testing.T) {
	store, err := Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	t.Run("transport verifier", func(t *testing.T) {
		resolverCalled := false
		handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
			resolverCalled = true
			return Principal{ID: "owner", Scopes: []string{ScopeProjectRead}}, nil
		}, func(*http.Request) bool {
			panic("test transport integration panic")
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusForbidden {
			t.Fatalf("panic verifier status = %d, want %d", response.Code, http.StatusForbidden)
		}
		if resolverCalled {
			t.Fatal("resolver ran after transport verifier panic")
		}
		assertHTTPBoundaryHeaders(t, response)
	})

	t.Run("principal resolver", func(t *testing.T) {
		handler, err := NewMCPHTTPHandler(store, func(*http.Request) (Principal, error) {
			panic("test principal integration panic")
		}, func(*http.Request) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "https://relay.invalid/lifecycle", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("panic resolver status/challenge = %d/%q", response.Code, response.Header().Get("WWW-Authenticate"))
		}
		assertHTTPBoundaryHeaders(t, response)
	})
}

func TestInvokeMCPHandlerContainsAdapterPanic(t *testing.T) {
	response, err := invokeMCPHandler(func() ([]byte, error) {
		panic("unexpected adapter failure")
	})
	if !errors.Is(err, errMCPHandlerPanic) {
		t.Fatalf("panic error = %v, want contained handler failure", err)
	}
	if response != nil {
		t.Fatalf("panic response = %q, want nil", response)
	}
}

// A completed TLS state is sufficient for the direct-TLS verifier; no network
// connection or certificate material is needed for this boundary test.
var tlsStateForTest = tls.ConnectionState{
	Version:                    tls.VersionTLS13,
	HandshakeComplete:          true,
	CipherSuite:                tls.TLS_AES_128_GCM_SHA256,
	NegotiatedProtocolIsMutual: true,
}
