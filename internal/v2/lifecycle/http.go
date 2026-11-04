package lifecycle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var errMCPHandlerPanic = errors.New("lifecycle MCP handler failed")
var errRequestBodyPanic = errors.New("lifecycle HTTP request body failed")
var errRequestBodyClosePanic = errors.New("lifecycle HTTP request body close failed")
var errRequestBodyNoProgress = errors.New("lifecycle HTTP request body made no progress")
var errRequestBodyContextDone = errors.New("lifecycle HTTP request context ended")
var errRequestBodyInvalidRead = errors.New("lifecycle HTTP request body returned an invalid read count")
var errRequestBodyMutationOverflow = errors.New("lifecycle HTTP request body changed too often")

// ErrDirectHTTPSServePanic reports that the reviewed direct-HTTPS serving
// goroutine panicked and the panic was contained at the serving boundary. The
// sentinel intentionally carries no panic detail; callers can classify this
// fail-closed result without depending on error text.
var ErrDirectHTTPSServePanic = errors.New("lifecycle direct HTTPS serve failed")

// Keep the package-local name for existing in-package boundary code and
// regression tests. It aliases the exported sentinel so both callers observe
// one stable classification.
var errDirectHTTPSServePanic = ErrDirectHTTPSServePanic

// ErrDirectHTTPSServeShutdownPanic reports that a reviewed direct-HTTPS
// shutdown or forced-close operation panicked. The panic value is intentionally
// not exposed across the serving boundary.
var ErrDirectHTTPSServeShutdownPanic = errors.New("lifecycle direct HTTPS shutdown failed")

// ErrDirectHTTPSListenerInvalid reports that a reviewed direct-HTTPS listener
// failed its opaque construction, provenance, address, or accepted-connection
// contract. The sentinel intentionally carries no delegate detail; callers can
// match the fail-closed classification without depending on error text.
var ErrDirectHTTPSListenerInvalid = errors.New("lifecycle direct HTTPS listener is invalid")

// Keep the package-local name for the existing in-package boundary code and
// regression tests. It aliases the exported sentinel so both callers observe
// one stable classification.
var errDirectHTTPSListenerInvalid = ErrDirectHTTPSListenerInvalid

// ErrDirectHTTPSServeContextInvalid reports that ServeDirectHTTPSServer
// received a nil, typed-nil, or malformed context. The serving binding is
// rejected before ownership is claimed, so callers can safely correct the
// context and retry the reviewed handoff.
var ErrDirectHTTPSServeContextInvalid = errors.New("lifecycle direct HTTPS context is invalid")

// ErrDirectHTTPSServeShutdownTimeout reports that context cancellation reached
// the bounded graceful-drain deadline and the serving server had to be force-
// closed. It is additive observability for callers; the wrapped deadline and
// any close/serve error remain available through errors.Is/errors.As.
var ErrDirectHTTPSServeShutdownTimeout = errors.New("lifecycle direct HTTPS shutdown timed out")

// ErrDirectTLSConfigInvalid reports that a direct-HTTPS TLS configuration
// failed the bounded, server-only preflight. The sentinel intentionally
// carries no configuration detail; callers can classify the construction
// failure with errors.Is without depending on error text.
var ErrDirectTLSConfigInvalid = errors.New("lifecycle direct HTTPS TLS configuration is invalid")

// ErrDirectHTTPSListenerCleanup reports that the reviewed direct-HTTPS
// listener's construction-approved delegate returned an error or panicked
// during cleanup. It is additive observability: callers still receive the
// original listener/replacement error, while errors.Is can distinguish a
// cleanup failure that may require supervisor review.
var ErrDirectHTTPSListenerCleanup = errors.New("lifecycle direct HTTPS listener cleanup failed")

const (
	maxRequestBodyEmptyReads = 100
	maxMCPAcceptBytes        = 1024
	// Framing tokens are short by definition. Bound direct-call header and
	// parsed-token inspection before trimming or comparing attacker-controlled
	// strings; normal net/http serving applies its own wire header limits.
	maxMCPFramingValueBytes = 256
	// HTTP methods are callback-visible request metadata. Keep direct callers
	// on the same bounded token surface as ordinary request framing.
	maxMCPMethodBytes = 256
	// The version header is an optional handshake-era transport signal. Keep
	// direct callers from supplying an unbounded value before the request is
	// handed to either deployment-owned security callback.
	maxMCPProtocolVersionBytes = 64
	// Browser Origin values are short serialized HTTPS origins. Keep direct
	// origin parsing bounded independently from the larger general header limit.
	maxMCPOriginBytes = 256
	// Direct library callers can construct an arbitrarily large Header map.
	// Bound field-name inspection before the case-insensitive collectors scan
	// it; normal net/http serving already applies its own wire header limits.
	maxMCPHeaderFields     = 256
	maxMCPHeaderEntries    = 1024
	maxMCPHeaderNameBytes  = 256
	maxMCPHeaderValueBytes = 16 << 10
	maxMCPHeaderBytes      = 64 << 10
	// The server-binding helper supplies conservative HTTP resource limits for
	// callers that want one reviewed direct-HTTPS handoff. These are transport
	// bounds, not certificate or application authorization policy.
	directHTTPSReadHeaderTimeout = 10 * time.Second
	directHTTPSReadTimeout       = 45 * time.Second
	directHTTPSWriteTimeout      = 45 * time.Second
	directHTTPSIdleTimeout       = 60 * time.Second
	directHTTPSMaxHeaderBytes    = maxMCPHeaderBytes
	directHTTPSShutdownTimeout   = 5 * time.Second
	// Consumers reject headers once their semantic bounds are exceeded. Keep
	// the case-insensitive collection bounded too, including for direct callers
	// that construct an arbitrarily large http.Header map.
	maxMCPHeaderValues = maxMCPAcceptBytes + 1
	// A malformed body can replace Request.Body from inside Close. Observe a
	// bounded number of such post-close candidates so cleanup cannot become an
	// unbounded loop when a hostile in-process body keeps manufacturing values.
	maxMCPBodyCleanupCandidates = 4096
	// Keep mutation tracking below the cleanup candidate cap so the tracker,
	// every retained replacement, and the final request field can all be closed
	// when a direct body exhausts its replacement budget.
	maxMCPBodyMutationReplacements = maxMCPBodyCleanupCandidates - 2
	// Request targets and URL components are inspected by the transport
	// boundary before authentication. Bound their direct-call representation so
	// a malformed in-process caller cannot hand a security verifier an
	// arbitrarily large request target.
	maxMCPRequestTargetBytes = 8 << 10
	// ServeMux patterns are callback-visible route metadata. Keep direct callers
	// from handing a security verifier an unbounded or visually deceptive value.
	maxMCPPatternBytes = maxMCPRequestTargetBytes
	// A bounded pattern can still contain many tiny wildcard segments. Keep
	// route-value snapshots and the private ServeMux probe proportional to the
	// supported direct-call shape instead of letting a caller spend the whole
	// pattern budget on thousands of map entries.
	maxMCPPatternWildcards = 256
	// Protocol and remote-address strings are callback-visible transport
	// metadata. Bound direct callers before a deployment-owned verifier sees
	// them; normal net/http serving supplies short values from the connection.
	maxMCPProtocolBytes   = 64
	maxMCPRemoteAddrBytes = 256
	// TLS connection state is callback-visible transport metadata. Bound the
	// direct-call certificate and handshake slices before a deployment-owned
	// verifier receives them or the body-boundary snapshot copies them.
	maxMCPTLSCertificates        = 64
	maxMCPTLSVerifiedChains      = 64
	maxMCPTLSChainCertificates   = 64
	maxMCPTLSCertificateBytes    = 1 << 20
	maxMCPTLSHandshakeBytes      = 1 << 20
	maxMCPTLSHandshakeStringSize = 1024
	// Standard private-key snapshots are serialized through PKCS#8. Keep
	// malformed in-process RSA/ECDSA values from forcing unbounded work at the
	// reviewed TLS handoff; Ed25519 has its own fixed key size.
	maxDirectTLSPrivateKeyBits = 16384
	// TLS 1.2's tls-unique binding is the fixed-width Finished verify_data
	// value exposed by crypto/tls. Keep this direct-server invariant separate
	// from the broader bounded handshake budget above.
	tls12UniqueLength = 12
	// Signed certificate timestamps are carried as a nested TLS vector: each
	// entry and the complete vector use a two-byte length. Keep the wire
	// prefixes in the accounting instead of allowing the broader metadata
	// budget to admit a value that crypto/tls cannot serialize as one SCT
	// vector.
	maxDirectTLSSCTBytes = (1 << 16) - 1
	tlsVectorLengthBytes = 2
	// Parsed certificate fields are callback-visible too. Bound their list and
	// aggregate sizes before a direct caller reaches a deployment verifier.
	maxMCPTLSCertificateValues      = 256
	maxMCPTLSCertificateStringBytes = 16 << 10
	// Keep the deployment bind-policy input bounded before parsing. The
	// accepted form is host:port, not an arbitrary URL or service name.
	maxMCPListenAddressBytes = 256
	// ALPN protocol names are encoded as a one-byte length plus a non-empty
	// value of at most 255 bytes. Bound the number of configured names before
	// summing their wire representation so a direct config preflight remains
	// resource-bounded even when supplied an unusually large slice.
	maxDirectTLSALPNProtocols     = 1024
	maxDirectTLSALPNProtocolBytes = 255
	maxDirectTLSALPNBytes         = (1 << 16) - 1
	// Cipher-suite and supported-group vectors encode two-byte entries behind
	// a 16-bit length. Keep direct configuration preflight work within the
	// largest representable vector before iterating either slice.
	maxDirectTLSVectorEntries = ((1 << 16) - 1) / 2
	// Static certificate selection remains deployment-owned, but bound the
	// metadata a future direct listener may inspect before serving a request.
	maxDirectTLSCertificateChains       = 64
	maxDirectTLSCertificateChainEntries = 64
	maxDirectTLSCertificateBytes        = 1 << 20
	maxDirectTLSNameMappings            = 256
	// SNI names are DNS host names on the wire; keep each static map key within
	// the protocol's maximum DNS name representation before map lookup work.
	maxDirectTLSNameBytes = 255
	// An explicit client-CA pool is deployment-owned trust material, but its
	// exported subject vector is still callback/listener-visible configuration.
	// Bound the metadata that a future direct listener may inspect without
	// parsing or replacing the pool.
	maxDirectTLSClientCASubjects     = 256
	maxDirectTLSClientCASubjectBytes = 16 << 10
	maxDirectTLSClientCABytes        = 1 << 20
)

// PrincipalResolver authenticates one request and returns the stable identity
// and already-authorized lifecycle scopes for it. The resolver owns token
// verification, expiry, audience/resource binding, and controller ownership;
// this package never parses credentials.
type PrincipalResolver func(*http.Request) (Principal, error)

// SecureTransportVerifier proves that the request arrived through the
// deployment's authenticated HTTPS boundary. Direct-TLS deployments can use
// RequireDirectTLS. A reverse proxy must provide a verifier that checks its
// trusted, authenticated transport metadata rather than trusting an arbitrary
// request header.
type SecureTransportVerifier func(*http.Request) bool

// MCPHTTPHandler is an additive HTTP boundary around MCPAdapter. It does not
// listen, terminate TLS, authenticate tokens, or modify the legacy 1.x
// gateway. Both security callbacks are mandatory so an integration cannot
// accidentally ship an unauthenticated or plaintext lifecycle route.
type MCPHTTPHandler struct {
	store   *Store
	resolve PrincipalResolver
	secure  SecureTransportVerifier
	// direct marks the handler as having passed the direct-HTTPS construction
	// policy. ServeDirectHTTPSServer uses this private provenance alongside
	// reviewedDirectHTTPSListener so a caller cannot replace the reviewed
	// handler with the default mux or a reverse-proxy handler before serving.
	direct bool
	// directServer and directListener are populated only by
	// BindDirectHTTPSServer. ServeDirectHTTPSServer requires the exact paired
	// objects so a caller cannot combine separately reviewed handoffs and lose
	// the construction-time ownership relationship.
	directServer    *http.Server
	directListener  *reviewedDirectHTTPSListener
	directTLSConfig *tls.Config
	// directListenHost/Port bind the reviewed direct handler to the literal
	// loopback authority that was approved at construction. RequireDirectTLS
	// intentionally remains a generic standalone verifier; this additional
	// handler-owned allowlist closes the DNS-rebinding gap for the direct
	// listener path without changing reverse-proxy integrations.
	directListenHost string
	directListenPort string
	// directServeMu makes the server/listener handoff single-use. A reviewed
	// binding cannot safely be served concurrently or reused after its serving
	// lifecycle has ended.
	directServeMu sync.Mutex
	directServing bool
	directServed  bool
}

// reviewedDirectHTTPSListener is the private provenance marker carried by
// ListenDirectHTTPS. A net.Listener alone does not prove that accepted
// connections are TLS-wrapped, so the bounded serving helper requires this
// marker before it starts an HTTPS server.
type reviewedDirectHTTPSListener struct {
	listener          net.Listener
	expectedListener  net.Listener
	config            *tls.Config
	expectedHost      string
	expectedPort      string
	cleanupMu         sync.Mutex
	reviewedClosed    bool
	reviewedCloseErr  error
	reviewedCloseDone chan struct{}
}

func (listener *reviewedDirectHTTPSListener) Accept() (connection net.Conn, err error) {
	if listener == nil {
		return nil, errDirectHTTPSListenerInvalid
	}
	// Constructors retain the exact TLS delegate they reviewed. A package
	// integration that replaces the mutable interface field must not be able to
	// swap in another loopback listener or TLS configuration after validation.
	// Hand-built test values leave expectedListener nil and still exercise the
	// lower-level type/address checks below.
	if listener.expectedListener != nil && !sameReviewedDirectHTTPSListener(listener.listener, listener.expectedListener) {
		cleanupErr := closeReviewedDirectHTTPSDelegate(listener)
		if cleanupErr != nil {
			return nil, errors.Join(errDirectHTTPSListenerInvalid, cleanupErr)
		}
		return nil, errDirectHTTPSListenerInvalid
	}
	// A malformed in-process seam can point the delegate back at this wrapper.
	// Reject it before invoking Accept so the wrapper cannot recurse until the
	// process exhausts its stack. If an approved delegate is retained, the
	// cleanup helper still closes only that delegate.
	if sameReviewedDirectHTTPSListener(listener, listener.listener) {
		return nil, errors.Join(errDirectHTTPSListenerInvalid, closeReviewedDirectHTTPSDelegate(listener))
	}
	if listener.listener == nil {
		return nil, errDirectHTTPSListenerInvalid
	}
	if address, addressErr := reviewedDirectHTTPSAddress(listener.listener); addressErr != nil || !listener.matchesExpectedAddress(address) {
		return nil, errors.Join(errDirectHTTPSListenerInvalid,
			closeReviewedDirectHTTPSAfterAddressFailure(listener, directHTTPSBoundAddressError(addressErr)))
	}
	defer func() {
		if recover() != nil {
			connection = nil
			err = errors.Join(errDirectHTTPSListenerInvalid, closeReviewedDirectHTTPSDelegate(listener))
		}
	}()
	connection, err = listener.listener.Accept()
	if err != nil {
		if connection != nil {
			connectionCloseErr := closeDirectHTTPSConnection(connection)
			connection = nil
			// net.Listener implementations must not return a live connection
			// alongside an error. Treat that malformed result as a provenance
			// failure instead of allowing http.Server to retry a delegate that
			// has already violated the reviewed handoff contract. Preserve a
			// connection-close failure as cleanup evidence without exposing the
			// delegate's malformed Accept error.
			return nil, errors.Join(errDirectHTTPSListenerInvalid,
				addDirectHTTPSListenerCleanupError(connectionCloseErr),
				closeReviewedDirectHTTPSDelegate(listener))
		}
		return connection, err
	}
	if connection == nil {
		// net.Listener implementations must return a connection whenever the
		// error is nil. Reject a malformed successful result before the type
		// assertion below, and release the construction-approved delegate so a
		// broken in-process handoff cannot leave it live.
		return nil, errors.Join(errDirectHTTPSListenerInvalid, closeReviewedDirectHTTPSDelegate(listener))
	}
	// The provenance marker is only useful if the delegate still returns the
	// TLS-wrapped connection installed by ListenDirectHTTPS. An in-package
	// replacement can otherwise retain a loopback address while silently
	// turning the serving handoff into plaintext.
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok || !listener.validAcceptedTLSConnection(tlsConnection) {
		connectionCloseErr := closeDirectHTTPSConnection(connection)
		return nil, errors.Join(errDirectHTTPSListenerInvalid,
			addDirectHTTPSListenerCleanupError(connectionCloseErr),
			closeReviewedDirectHTTPSDelegate(listener))
	}
	return tlsConnection, nil
}

func validReviewedTLSConnection(connection *tls.Conn) (valid bool) {
	valid = false
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if connection == nil {
		return false
	}
	underlying := connection.NetConn()
	if underlying == nil {
		return false
	}
	value := reflect.ValueOf(underlying)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return false
		}
	}
	localAddress := underlying.LocalAddr()
	if localAddress == nil {
		return false
	}
	value = reflect.ValueOf(localAddress)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return false
		}
	}
	return ValidateLoopbackListenAddress(localAddress.String()) == nil
}

func (listener *reviewedDirectHTTPSListener) validAcceptedTLSConnection(connection *tls.Conn) (valid bool) {
	valid = false
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if !validReviewedTLSConnection(connection) || connection == nil {
		return false
	}
	underlying := connection.NetConn()
	if underlying == nil {
		return false
	}
	return listener.matchesExpectedAddress(underlying.LocalAddr())
}

func closeDirectHTTPSConnection(connection net.Conn) (err error) {
	if connection == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			// A malformed in-process connection can panic during cleanup. Keep
			// the failure opaque and let the caller attach the cleanup sentinel.
			err = errDirectHTTPSListenerInvalid
		}
	}()
	return connection.Close()
}

func sameReviewedDirectHTTPSListener(left, right net.Listener) (same bool) {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftType, rightType := reflect.TypeOf(left), reflect.TypeOf(right)
	if leftType != rightType || !leftType.Comparable() {
		return false
	}
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return left == right
}

func closeReviewedDirectHTTPSDelegate(listener *reviewedDirectHTTPSListener) error {
	if listener == nil || listener.expectedListener == nil {
		return nil
	}
	expected := listener.expectedListener
	// A malformed in-package value can point expectedListener back at the
	// wrapper itself. Do not recurse through Close in that case. The normal
	// constructor path stores the TLS delegate, while this guard keeps the
	// cleanup boundary total for malformed test/integration values.
	if sameReviewedDirectHTTPSListener(listener, expected) {
		return nil
	}
	return addDirectHTTPSListenerCleanupError(closeReviewedDirectHTTPSDelegateOnce(listener, expected))
}

func closeReviewedDirectHTTPSDelegateOnce(listener *reviewedDirectHTTPSListener, delegate net.Listener) (err error) {
	if listener == nil || delegate == nil {
		return errDirectHTTPSListenerInvalid
	}
	listener.cleanupMu.Lock()
	if listener.reviewedClosed {
		done := listener.reviewedCloseDone
		listener.cleanupMu.Unlock()
		if done != nil {
			<-done
		}
		listener.cleanupMu.Lock()
		err = listener.reviewedCloseErr
		listener.cleanupMu.Unlock()
		return err
	}
	done := make(chan struct{})
	listener.reviewedClosed = true
	listener.reviewedCloseDone = done
	listener.cleanupMu.Unlock()
	defer func() {
		if recover() != nil {
			err = errDirectHTTPSListenerInvalid
		}
		listener.cleanupMu.Lock()
		listener.reviewedCloseErr = err
		close(done)
		listener.cleanupMu.Unlock()
	}()
	return delegate.Close()
}

func (listener *reviewedDirectHTTPSListener) Close() (err error) {
	if listener == nil {
		return errDirectHTTPSListenerInvalid
	}
	if listener.expectedListener != nil && !sameReviewedDirectHTTPSListener(listener.listener, listener.expectedListener) {
		cleanupErr := closeReviewedDirectHTTPSDelegate(listener)
		if cleanupErr != nil {
			return errors.Join(errDirectHTTPSListenerInvalid, cleanupErr)
		}
		return errDirectHTTPSListenerInvalid
	}
	if listener.listener == nil {
		return errDirectHTTPSListenerInvalid
	}
	if sameReviewedDirectHTTPSListener(listener, listener.listener) {
		return errDirectHTTPSListenerInvalid
	}
	return addDirectHTTPSListenerCleanupError(closeReviewedDirectHTTPSDelegateOnce(listener, listener.listener))
}

func addDirectHTTPSListenerCleanupError(err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(ErrDirectHTTPSListenerCleanup, err)
}

func (listener *reviewedDirectHTTPSListener) Addr() (address net.Addr) {
	if listener == nil {
		return nil
	}
	if listener.expectedListener != nil && !sameReviewedDirectHTTPSListener(listener.listener, listener.expectedListener) {
		// Addr cannot return an error, but a replaced delegate must not leave
		// the construction-approved listener live after provenance fails closed.
		// The cleanup result remains available through a later Close or serving
		// boundary, and the one-shot helper prevents duplicate closes.
		_ = closeReviewedDirectHTTPSDelegate(listener)
		return nil
	}
	// Addr cannot report an error, but it must still reject a self-referential
	// delegate before calling through the net.Listener interface. Otherwise a
	// malformed in-process value would recurse indefinitely.
	if sameReviewedDirectHTTPSListener(listener, listener.listener) {
		_ = closeReviewedDirectHTTPSDelegate(listener)
		return nil
	}
	if listener.listener == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			address = nil
			// Addr cannot return an error, but a panicking construction-approved
			// delegate is no longer safe to keep live. Record the same one-shot
			// cleanup result used by Accept and Close; a later Close can expose
			// the cleanup classification to the caller.
			_ = closeReviewedDirectHTTPSDelegate(listener)
		}
	}()
	address, addressErr := reviewedDirectHTTPSAddress(listener.listener)
	if addressErr != nil {
		// Addr cannot return an error, but an invalid live address must not be
		// handed to a caller that may publish or dial it. Treat the same
		// malformed-address evidence as the serving boundary and close the
		// construction-approved delegate once.
		_ = closeReviewedDirectHTTPSDelegate(listener)
		return nil
	}
	if !listener.matchesExpectedAddress(address) {
		_ = closeReviewedDirectHTTPSDelegate(listener)
		return nil
	}
	return address
}

func reviewedDirectHTTPSAddress(delegate net.Listener) (address net.Addr, err error) {
	err = errors.New("lifecycle direct HTTPS loopback listener address is required")
	if delegate == nil {
		return nil, err
	}
	defer func() {
		if recover() != nil {
			address = nil
			err = errors.New("lifecycle direct HTTPS loopback listener address is invalid")
		}
	}()
	address = delegate.Addr()
	if address == nil {
		return nil, err
	}
	value := reflect.ValueOf(address)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, err
		}
	}
	if !validReviewedDirectHTTPSAddress(address) {
		return nil, errors.New("lifecycle direct HTTPS loopback listener address is invalid")
	}
	return address, nil
}

func validReviewedDirectHTTPSAddress(address net.Addr) (valid bool) {
	valid = false
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if address == nil {
		return false
	}
	value := reflect.ValueOf(address)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return false
		}
	}
	return ValidateLoopbackListenAddress(address.String()) == nil
}

func (listener *reviewedDirectHTTPSListener) matchesExpectedAddress(address net.Addr) (valid bool) {
	valid = false
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	if listener == nil || address == nil {
		return false
	}
	// Hand-built test seams without a construction snapshot retain the lower-
	// level loopback-only contract. Production listeners always carry both
	// values from the OS-selected address, including when the request used :0.
	if listener.expectedHost == "" && listener.expectedPort == "" {
		return true
	}
	if listener.expectedHost == "" || listener.expectedPort == "" {
		return false
	}
	host, port, err := directListenAuthorityFromAddr(address)
	return err == nil && host == listener.expectedHost && port == listener.expectedPort
}

func directHTTPSBoundAddressError(addressErr error) error {
	if addressErr != nil {
		return addressErr
	}
	return errors.New("lifecycle direct HTTPS loopback listener bound address changed")
}

// NewMCPHTTPHandler creates a fail-closed HTTP adapter for the v2 lifecycle
// MCP surface. The caller must provide both authenticated-principal and secure
// transport verification callbacks.
func NewMCPHTTPHandler(store *Store, resolve PrincipalResolver, secure SecureTransportVerifier) (*MCPHTTPHandler, error) {
	if store == nil {
		return nil, errors.New("lifecycle HTTP store is required")
	}
	if err := store.ensureAdapterReady(); err != nil {
		return nil, err
	}
	if resolve == nil {
		return nil, errors.New("lifecycle HTTP principal resolver is required")
	}
	if secure == nil {
		return nil, errors.New("lifecycle HTTP secure transport verifier is required")
	}
	return &MCPHTTPHandler{store: store, resolve: resolve, secure: secure}, nil
}

// NewDirectHTTPSHandler composes the direct-HTTPS transport policy with the
// authenticated lifecycle handler. It performs no listener creation or
// network I/O; the caller must use the same address and TLS configuration when
// it later serves the returned handler. The configuration is validated here so
// a direct handler cannot be constructed while its deployment policy is known
// to be invalid.
func NewDirectHTTPSHandler(store *Store, resolve PrincipalResolver, address string, config *tls.Config) (*MCPHTTPHandler, error) {
	return newDirectHTTPSHandler(store, resolve, address, config, false)
}

// newDirectHTTPSHandler is the shared constructor for the public unbound
// handler and BindDirectHTTPS. Only the paired binder may defer the port
// decision to the OS, because it records the actual bound port before the
// handler is returned. The public unbound constructor must retain a concrete
// authority or its direct Host check would accept any loopback port.
func newDirectHTTPSHandler(store *Store, resolve PrincipalResolver, address string, config *tls.Config, allowPortZero bool) (*MCPHTTPHandler, error) {
	if err := ValidateDirectHTTPSListenPolicy(address, config); err != nil {
		return nil, err
	}
	host, port, err := directListenAuthority(address)
	if err != nil {
		return nil, err
	}
	if port == "0" && !allowPortZero {
		return nil, errors.New("lifecycle direct HTTPS handler requires a bound non-zero port")
	}
	handler, err := NewMCPHTTPHandler(store, resolve, RequireDirectTLS)
	if err != nil {
		return nil, err
	}
	handler.direct = true
	handler.directListenHost = host
	handler.directListenPort = port
	return handler, nil
}

func directListenAuthority(address string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(address)
	if err != nil {
		return "", "", errors.New("lifecycle direct HTTPS listen authority is invalid")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", "", errors.New("lifecycle direct HTTPS listen authority is not literal IP")
	}
	return ip.String(), port, nil
}

func directListenAuthorityFromAddr(address net.Addr) (host, port string, err error) {
	defer func() {
		if recover() != nil {
			host = ""
			port = ""
			err = errors.New("lifecycle direct HTTPS listener authority is invalid")
		}
	}()
	if address == nil {
		return "", "", errors.New("lifecycle direct HTTPS listener authority is invalid")
	}
	return directListenAuthority(address.String())
}

// RequireDirectTLS is suitable when the handler is attached directly to an
// HTTPS server. Reverse-proxy deployments must use a verifier that authenticates
// the proxy boundary instead of forwarding an untrusted TLS header. TLS 1.2 is
// the minimum supported direct-connection version, and the handshake must be
// complete before the request is accepted; the server's tls.Config should
// enforce the same floor before requests reach this handler.
func RequireDirectTLS(r *http.Request) bool {
	return requireDirectTLSWithPanicBoundary(r, validDirectTLSState)
}

func requireDirectTLSWithPanicBoundary(r *http.Request, validateTLSState func(*tls.ConnectionState) bool) (secure bool) {
	// This verifier is also an exported standalone callback for direct
	// integrations. Its request and certificate metadata are caller-owned, so a
	// future standard-library or validation-path panic must fail closed rather
	// than escape into the serving process.
	defer func() {
		if recover() != nil {
			secure = false
		}
	}()
	return requireDirectTLS(r, validateTLSState)
}

// requireDirectTLS contains the policy body behind RequireDirectTLS. Keeping
// the state-validation seam explicit makes the exported panic boundary
// regression-testable without changing the production callback contract.
func requireDirectTLS(r *http.Request, validateTLSState func(*tls.ConnectionState) bool) bool {
	if r == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version < tls.VersionTLS12 {
		return false
	}
	// A normal server request always carries a URL. Reject a missing URL for
	// direct callers rather than treating incomplete request metadata as an
	// authenticated HTTPS request.
	if r.URL == nil {
		return false
	}
	// RequireDirectTLS is also a public standalone verifier. Apply the direct
	// header-map bound before validDirectRequestMetadata inspects the separate
	// Request.Host field for a duplicate Host representation; the handler's
	// earlier preflight cannot protect callers that invoke this verifier alone.
	if !validDirectHeaderMap(r.Header) {
		return false
	}
	if !validDirectOriginHeader(r) {
		return false
	}
	if !validDirectTrailerMap(r.Trailer) {
		return false
	}
	if !validDirectServerRequestShape(r) {
		return false
	}
	// RequireDirectTLS is also a public verifier that may be called without
	// the HTTP handler's preceding metadata check. Apply the same bounded
	// request-target and URL-component policy before parsing caller-supplied
	// strings, so a standalone transport check cannot become an unbounded
	// inspection path.
	if !validDirectRequestMetadata(r) {
		return false
	}
	// The v2 direct-HTTPS contract is intentionally explicit: TLS 1.2 and
	// TLS 1.3 are supported, while an unknown future or synthetic version must
	// not pass a numeric minimum check merely because it is above TLS 1.2.
	if r.TLS.Version != tls.VersionTLS12 && r.TLS.Version != tls.VersionTLS13 {
		return false
	}
	if !validateTLSState(r.TLS) {
		return false
	}
	if !validDirectTLSServerState(r.TLS) {
		return false
	}
	if !validDirectTLSCipherSuite(r.TLS) {
		return false
	}
	// Server-side requests normally leave URL.Scheme empty. If a direct
	// library caller supplies an explicit scheme, reject a contradictory
	// plaintext or authority-less URL instead of allowing synthetic TLS metadata
	// to override an incomplete HTTPS request shape.
	if r.URL.Scheme != "" && !strings.EqualFold(r.URL.Scheme, "https") {
		return false
	}
	// Opaque URLs are not an HTTP request-target representation. Reject them
	// even when a malformed direct caller leaves Scheme empty; otherwise the
	// verifier would accept URL metadata that net/http would not route as an
	// HTTP request.
	if r.URL.Opaque != "" {
		return false
	}
	if r.URL.Scheme != "" && r.URL.Host == "" {
		return false
	}
	// A parsed URL stores userinfo separately from Host. Reject that normal
	// representation as well as the malformed raw Host form checked below;
	// direct callers must not turn credentials embedded in a request target
	// into transport identity metadata.
	if r.URL.User != nil {
		return false
	}
	// Fragments are never part of an HTTP request target. Reject them, along
	// with an inconsistent escaped path, so a direct caller cannot authenticate
	// URL metadata that the transport would discard or reinterpret.
	if r.URL.Fragment != "" || r.URL.RawFragment != "" {
		return false
	}
	// A direct caller can place a raw fragment delimiter in the escaped path
	// or query while leaving URL.Fragment empty. Those fields are later joined
	// into a request target by net/http, where the delimiter would change the
	// transport-visible boundary. Require callers to percent-encode it just as
	// they would on the wire.
	if strings.Contains(r.URL.RawPath, "#") || strings.Contains(r.URL.RawQuery, "#") {
		return false
	}
	if r.URL.RawPath != "" {
		path, err := url.PathUnescape(r.URL.RawPath)
		if err != nil || path != r.URL.Path {
			return false
		}
	}
	if r.URL.Host != "" && !validDirectTLSAuthority(r.URL.Host) {
		return false
	}
	return directTLSRequestTargetIsConsistent(r)
}

// validDirectTLSAuthority validates an authority supplied by a direct
// library caller. A server-created URL has already passed net/http parsing,
// but a caller can populate URL.Host with arbitrary text. Reparse the
// authority as a network-path reference and require the parser to preserve it
// exactly; this rejects control characters, invalid ports, embedded userinfo,
// and path delimiters before synthetic TLS metadata is trusted.
func validDirectTLSAuthority(authority string) bool {
	if authority == "" || len(authority) > maxMCPRequestTargetBytes || strings.TrimSpace(authority) != authority ||
		containsUnicodeControlOrFormat(authority) {
		return false
	}
	parsed, err := url.Parse("//" + authority)
	if err != nil || parsed.User != nil || parsed.Host != authority || parsed.Hostname() == "" {
		return false
	}
	if port := parsed.Port(); port != "" {
		// Keep callback-visible authorities on one canonical spelling. The
		// numeric port is semantically unchanged by leading zeroes, but an
		// alternate spelling can make transport, logs, and policy records
		// disagree about the same authority. The bind preflight applies the
		// same rule to listener addresses.
		if len(port) > 1 && port[0] == '0' {
			return false
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return false
		}
	}
	return !strings.HasSuffix(authority, ":")
}

// directTLSRequestTargetIsConsistent rejects a request-target that contradicts
// the parsed URL or the URL scheme accepted above. Origin-form targets are the
// normal server representation and remain compatible with an empty URL scheme;
// an omitted RequestURI is also valid for direct library callers. Malformed
// targets fail closed before a transport verifier can treat synthetic TLS
// metadata as authenticated.
func directTLSRequestTargetIsConsistent(r *http.Request) bool {
	if !directRequestTargetIsConsistent(r) {
		return false
	}
	if r == nil || r.RequestURI == "" {
		return true
	}
	// Absolute-form request targets require a valid, userinfo-free authority.
	// Parsing alone also accepts scheme-only and opaque forms such as
	// "https:/path" or "https:opaque", and it permits embedded userinfo. None
	// of those forms is valid transport identity metadata and must not be
	// treated as evidence that the request URL was HTTPS.
	target, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		return false
	}
	if !target.IsAbs() {
		return true
	}
	if target.Host == "" || target.User != nil || !validDirectTLSAuthority(target.Host) {
		return false
	}
	// Absolute-form targets carry the authority that an intermediary would
	// route. When the direct caller also supplied URL authority, require the
	// two views to agree; otherwise synthetic TLS metadata could authenticate
	// one host while the request target names another. A server request with an
	// absolute-form target normally populates URL.Host, while origin-form
	// requests remain covered by the compatibility path above.
	if r.URL.Host == "" || !strings.EqualFold(r.URL.Host, target.Host) {
		return false
	}
	return strings.EqualFold(target.Scheme, "https") &&
		(r.URL.Scheme == "" || strings.EqualFold(r.URL.Scheme, target.Scheme))
}

// directRequestTargetIsConsistent compares the raw request target with the
// parsed URL without making a transport-authentication decision. Both views
// are callback-visible to deployment integrations, so a direct caller must
// not be able to authenticate one while routing or logging the other.
func directRequestTargetIsConsistent(r *http.Request) bool {
	if r == nil || r.URL == nil || r.RequestURI == "" {
		return true
	}
	// ParseRequestURI assumes callers have already removed fragments and can
	// otherwise treat a raw '#' as path data. A request target never carries a
	// fragment delimiter; reject it before the parser can reinterpret it.
	if strings.Contains(r.RequestURI, "#") {
		return false
	}
	target, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		return false
	}
	// Compare escaped path text and the force-query bit so semantically similar
	// but wire-different targets do not pass.
	if target.EscapedPath() != r.URL.EscapedPath() ||
		target.RawQuery != r.URL.RawQuery ||
		target.ForceQuery != r.URL.ForceQuery {
		return false
	}
	if !target.IsAbs() {
		return target.Scheme == "" && target.Host == "" && target.User == nil && target.Opaque == ""
	}
	if target.Scheme == "" || !validURLScheme(target.Scheme) || target.Host == "" ||
		target.User != nil || !validDirectTLSAuthority(target.Host) {
		return false
	}
	if r.URL.Host != "" && !strings.EqualFold(r.URL.Host, target.Host) {
		return false
	}
	return r.URL.Scheme == "" || strings.EqualFold(r.URL.Scheme, target.Scheme)
}

// ValidateDirectTLSConfig checks the minimum server policy required by
// RequireDirectTLS. It requires an explicit TLS 1.2 or TLS 1.3 maximum so a
// future standard-library protocol cannot be enabled accidentally. It does
// not create a listener, load certificates, or mutate the supplied
// configuration; the deployment remains responsible for certificate
// provisioning and authenticated distribution.
func ValidateDirectTLSConfig(config *tls.Config) error {
	return validateDirectTLSConfigWith(config, validateDirectTLSCertificates)
}

// validateDirectTLSConfigWith keeps the public direct-TLS preflight total even
// when malformed in-process configuration or certificate metadata reaches a
// nested standard-library helper. The callback is an in-package seam for
// deterministic boundary tests; production callers always use the concrete
// certificate validator above.
func validateDirectTLSConfigWith(config *tls.Config, validateCertificates func(*tls.Config) error) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("%w: lifecycle TLS config validation failed", ErrDirectTLSConfigInvalid)
			return
		}
		if err != nil && !errors.Is(err, ErrDirectTLSConfigInvalid) {
			err = fmt.Errorf("%w: %w", ErrDirectTLSConfigInvalid, err)
		}
	}()
	if config == nil {
		return errors.New("lifecycle TLS config is required")
	}
	if validateCertificates == nil {
		return errors.New("lifecycle TLS certificate validator is required")
	}
	if config.Renegotiation != tls.RenegotiateNever {
		return errors.New("lifecycle TLS config must disable renegotiation")
	}
	if config.MinVersion != tls.VersionTLS12 && config.MinVersion != tls.VersionTLS13 {
		return errors.New("lifecycle TLS config requires TLS 1.2 or newer")
	}
	if config.MaxVersion != tls.VersionTLS12 && config.MaxVersion != tls.VersionTLS13 {
		return errors.New("lifecycle TLS config requires an explicit TLS 1.2 or TLS 1.3 maximum")
	}
	if config.MaxVersion < config.MinVersion {
		return errors.New("lifecycle TLS config has an invalid version range")
	}
	if err := validateDirectTLSClientAuth(config); err != nil {
		return err
	}
	// These fields configure the client side of crypto/tls and are ignored by
	// servers. Reject them rather than allowing a mixed-role configuration to
	// pass review with misleading trust, hostname, or ECH settings. A direct
	// HTTPS deployment must construct a server-only configuration; client
	// behavior belongs to a separately reviewed outbound transport.
	if config.GetClientCertificate != nil ||
		config.RootCAs != nil ||
		config.ServerName != "" ||
		config.InsecureSkipVerify ||
		config.ClientSessionCache != nil ||
		len(config.EncryptedClientHelloConfigList) > 0 ||
		config.EncryptedClientHelloRejectionVerify != nil {
		return errors.New("lifecycle TLS config contains client-only settings")
	}
	// PreferServerCipherSuites is a deprecated no-op in the standard library.
	// Reject it rather than allowing a direct deployment to appear to select a
	// server cipher-order policy that crypto/tls will ignore.
	if config.PreferServerCipherSuites {
		return errors.New("lifecycle TLS config cannot request legacy server cipher preference")
	}
	if config.GetConfigForClient != nil {
		return errors.New("lifecycle TLS config cannot select per-client configurations")
	}
	// GetCertificate runs during the handshake and can replace the certificate
	// selected by the statically preflighted configuration. Keep direct HTTPS
	// certificate selection on the reviewed Certificates/NameToCertificate
	// data rather than allowing an unreviewed callback to vary identity after
	// this static check.
	if config.GetCertificate != nil {
		return errors.New("lifecycle TLS config cannot select certificates dynamically")
	}
	if err := validateCertificates(config); err != nil {
		return err
	}
	// Certificate-verification callbacks execute at handshake time and are not
	// invoked consistently across resumed and full connections. Keep direct
	// HTTPS on the standard server certificate/client-auth policy so a future
	// deployment cannot add an unreviewed authentication decision after this
	// static preflight. Deployments that need custom certificate policy must
	// terminate TLS outside this direct v2 boundary.
	if config.VerifyPeerCertificate != nil || config.VerifyConnection != nil {
		return errors.New("lifecycle TLS config cannot customize certificate verification")
	}
	// Custom session-ticket callbacks run during handshake and resumption. They
	// can replace the standard ticket state and introduce an unreviewed
	// cross-process/session-identity boundary after this static preflight. Keep
	// direct HTTPS on the standard library's managed ticket implementation;
	// integrations that need custom ticket storage must terminate TLS outside
	// this direct v2 boundary.
	if config.WrapSession != nil || config.UnwrapSession != nil {
		return errors.New("lifecycle TLS config cannot customize session tickets")
	}
	// A non-zero SessionTicketKey disables crypto/tls's automatic ticket-key
	// rotation. Keep direct HTTPS on the standard rotating ticket state rather
	// than accepting a long-lived operator-supplied secret whose rotation and
	// cross-process sharing are outside this preflight boundary.
	if config.SessionTicketKey != [32]byte{} {
		return errors.New("lifecycle TLS config cannot set a static session-ticket key")
	}
	// Keep direct HTTPS on the standard managed session-ticket lifecycle. A
	// deployment that disables tickets changes resumption semantics and the
	// controller's connection behavior; that transport policy needs a separate
	// review rather than being silently accepted by this static preflight.
	if config.SessionTicketsDisabled {
		return errors.New("lifecycle TLS config cannot disable session tickets")
	}
	// Keep direct HTTPS on crypto/tls's adaptive record sizing. Disabling it
	// forces the largest records and changes the reviewed latency/resource
	// behavior after this static preflight; deployments that require a fixed
	// record policy must terminate TLS outside this direct v2 boundary.
	if config.DynamicRecordSizingDisabled {
		return errors.New("lifecycle TLS config cannot disable dynamic record sizing")
	}
	// EncryptedClientHelloKeys change the server handshake and can cause ECH
	// retry configuration, while carrying private key material that needs a
	// separate distribution and rotation review. Keep ECH server termination
	// outside this direct boundary until that protocol and key-management
	// contract is explicit. The client-only ECH fields are ignored by servers
	// and therefore do not affect this server preflight.
	if len(config.EncryptedClientHelloKeys) > 0 {
		return errors.New("lifecycle TLS config cannot enable server Encrypted Client Hello keys")
	}
	// Rand and Time are handshake-time hooks. Allowing a direct HTTPS
	// deployment to replace either default would let the configuration change
	// cryptographic randomness or certificate/ticket time semantics after this
	// static policy check. Keep the direct boundary on crypto/rand and the
	// standard clock; custom reverse-proxy integrations retain their own
	// transport contract outside this helper.
	if config.Rand != nil {
		return errors.New("lifecycle TLS config cannot replace the randomness source")
	}
	if config.Time != nil {
		return errors.New("lifecycle TLS config cannot replace the handshake clock")
	}
	// KeyLogWriter receives TLS session secrets in the NSS key-log format. A
	// direct HTTPS listener must never enable that diagnostic sink through its
	// deployment configuration, because doing so would disclose connection
	// secrets to an arbitrary writer before the authenticated route runs.
	if config.KeyLogWriter != nil {
		return errors.New("lifecycle TLS config cannot export session secrets")
	}
	if err := validateDirectTLSCipherSuites(config); err != nil {
		return err
	}
	if err := validateDirectTLSCurvePreferences(config); err != nil {
		return err
	}
	if err := validateDirectTLSNextProtos(config); err != nil {
		return err
	}
	return nil
}

// validateDirectTLSCertificates bounds the static certificate metadata that a
// future direct listener may inspect. It deliberately does not parse or
// provision certificates: deployments still own certificate identity,
// private-key handling, and trust review. Empty certificate configuration is
// therefore valid here because the deployment may complete that step later.
func validateDirectTLSCertificates(config *tls.Config) error {
	if len(config.Certificates) > maxDirectTLSCertificateChains {
		return errors.New("lifecycle TLS config contains too many certificate chains")
	}
	if len(config.NameToCertificate) > maxDirectTLSNameMappings {
		return errors.New("lifecycle TLS config contains too many certificate name mappings")
	}

	totalBytes := 0
	leafMetadataBytes := 0
	knownCertificates := make(map[*tls.Certificate]struct{}, len(config.Certificates))
	seenCertificateChains := make(map[string]struct{}, len(config.Certificates))
	seenStaticTimestamps := make(map[string]struct{})
	for index := range config.Certificates {
		certificate := &config.Certificates[index]
		knownCertificates[certificate] = struct{}{}
		if !validDirectTLSPrivateKey(certificate.PrivateKey) {
			return errors.New("lifecycle TLS config contains an invalid certificate private key")
		}
		if certificate.PrivateKey != nil && !snapshotableDirectTLSPrivateKey(certificate.PrivateKey) {
			return errors.New("lifecycle TLS config contains a non-snapshotable certificate private key")
		}
		if len(certificate.Certificate) > maxDirectTLSCertificateChainEntries {
			return errors.New("lifecycle TLS config contains too many certificates in a chain")
		}
		if err := validateDirectTLSSignatureAlgorithms(certificate.SupportedSignatureAlgorithms); err != nil {
			return err
		}
		if len(certificate.SignedCertificateTimestamps) > maxDirectTLSCertificateChainEntries {
			return errors.New("lifecycle TLS config contains too many certificate timestamps")
		}
		seenTimestamps := make(map[string]struct{}, len(certificate.SignedCertificateTimestamps))
		sctBytes := 0
		seenChainEntries := make(map[string]struct{}, len(certificate.Certificate))
		for _, der := range certificate.Certificate {
			if len(der) == 0 {
				return errors.New("lifecycle TLS config contains an empty certificate chain entry")
			}
			if len(der) > maxDirectTLSCertificateBytes-totalBytes {
				return errors.New("lifecycle TLS config contains oversized certificate metadata")
			}
			derKey := string(der)
			if _, ok := seenChainEntries[derKey]; ok {
				return errors.New("lifecycle TLS config contains duplicate certificate chain entries")
			}
			seenChainEntries[derKey] = struct{}{}
			totalBytes += len(der)
		}
		if len(certificate.Certificate) > 0 {
			// Length-prefix each DER element so arbitrary certificate bytes cannot
			// create an ambiguous key. Empty chains remain valid placeholders for
			// deployment-owned certificate provisioning.
			var chainKey strings.Builder
			for _, der := range certificate.Certificate {
				chainKey.WriteString(strconv.Itoa(len(der)))
				chainKey.WriteByte(':')
				_, _ = chainKey.Write(der)
			}
			key := chainKey.String()
			if _, ok := seenCertificateChains[key]; ok {
				return errors.New("lifecycle TLS config contains duplicate certificate chains")
			}
			seenCertificateChains[key] = struct{}{}
		}
		if len(certificate.OCSPStaple) > maxDirectTLSCertificateBytes-totalBytes {
			return errors.New("lifecycle TLS config contains oversized certificate metadata")
		}
		if certificate.OCSPStaple != nil && len(certificate.OCSPStaple) == 0 {
			return errors.New("lifecycle TLS config contains an empty OCSP response")
		}
		totalBytes += len(certificate.OCSPStaple)
		for _, timestamp := range certificate.SignedCertificateTimestamps {
			if len(timestamp) == 0 {
				return errors.New("lifecycle TLS config contains an empty certificate timestamp")
			}
			if !addBoundedDirectTLSSCT(&sctBytes, timestamp) {
				return errors.New("lifecycle TLS config contains oversized certificate timestamp vector")
			}
			timestampKey := string(timestamp)
			if _, ok := seenTimestamps[timestampKey]; ok {
				return errors.New("lifecycle TLS config contains duplicate certificate timestamps")
			}
			if _, ok := seenStaticTimestamps[timestampKey]; ok {
				return errors.New("lifecycle TLS config contains duplicate certificate timestamps across chains")
			}
			seenTimestamps[timestampKey] = struct{}{}
			seenStaticTimestamps[timestampKey] = struct{}{}
			if len(timestamp) > maxDirectTLSCertificateBytes-totalBytes {
				return errors.New("lifecycle TLS config contains oversized certificate metadata")
			}
			totalBytes += len(timestamp)
		}
		leaf := certificate.Leaf
		if certificate.PrivateKey != nil && len(certificate.Certificate) > 0 {
			// tls.Certificate.Leaf is optional. When a signer and a static chain
			// are both supplied, parse every entry even when the caller also
			// supplied a Leaf. Otherwise an internally coherent leaf could defer
			// malformed intermediate DER failure until handshake time.
			// Empty/partial provisioning placeholders remain valid when either
			// side is absent.
			for chainIndex, der := range certificate.Certificate {
				parsed, err := x509.ParseCertificate(der)
				if err != nil {
					if chainIndex == 0 {
						return errors.New("lifecycle TLS config contains an invalid certificate leaf")
					}
					return errors.New("lifecycle TLS config contains an invalid certificate chain entry")
				}
				if chainIndex == 0 && leaf == nil {
					leaf = parsed
				}
			}
		}
		if leaf != nil {
			if len(certificate.Certificate) == 0 ||
				!bytes.Equal(leaf.Raw, certificate.Certificate[0]) {
				return errors.New("lifecycle TLS config contains a mismatched certificate leaf")
			}
			if !validDirectTLSCertificate(leaf, &leafMetadataBytes) {
				return errors.New("lifecycle TLS config contains invalid certificate leaf metadata")
			}
			if certificate.PrivateKey != nil &&
				!validDirectTLSCertificateKeyPair(leaf, certificate.PrivateKey) {
				return errors.New("lifecycle TLS config contains a certificate leaf/private-key mismatch")
			}
		}
	}
	for name, certificate := range config.NameToCertificate {
		if !validDirectTLSNameMapping(name) {
			return errors.New("lifecycle TLS config contains an invalid certificate name mapping")
		}
		if certificate == nil {
			return errors.New("lifecycle TLS config contains a nil certificate name mapping")
		}
		if _, ok := knownCertificates[certificate]; !ok {
			return errors.New("lifecycle TLS config maps a name to an unlisted certificate")
		}
	}
	return nil
}

// validateDirectTLSSignatureAlgorithms keeps an explicit certificate policy on
// the set of schemes understood by the reviewed crypto/tls version. The
// standard library otherwise ignores unknown entries, which can turn a
// non-empty operator policy into an empty one and makes future numeric scheme
// assignments change the meaning of an already-reviewed configuration. Keep
// all currently defined schemes, including the legacy TLS 1.2 SHA-1 values;
// the TLS handshake still decides whether a scheme is usable for the selected
// key and protocol version.
func validateDirectTLSSignatureAlgorithms(algorithms []tls.SignatureScheme) error {
	if len(algorithms) > maxDirectTLSVectorEntries {
		return errors.New("lifecycle TLS config contains too many certificate signature algorithms")
	}
	seen := make(map[tls.SignatureScheme]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		if _, ok := seen[algorithm]; ok {
			return errors.New("lifecycle TLS config contains duplicate certificate signature algorithms")
		}
		seen[algorithm] = struct{}{}
		switch algorithm {
		case tls.PKCS1WithSHA256,
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
			tls.ECDSAWithSHA1:
			// The configured certificate key and negotiated TLS version apply
			// the narrower compatibility checks during certificate selection.
		default:
			return errors.New("lifecycle TLS config contains an unknown certificate signature algorithm")
		}
	}
	return nil
}

// validDirectTLSPrivateKey mirrors the server-side crypto/tls requirement for
// static certificates without invoking arbitrary signer methods or inspecting
// private-key material. A nil key remains valid for the deployment-owned
// provisioning contract; when a key is supplied, it must implement the
// signer interface used by the reviewed TLS 1.2/1.3 server cipher policy and
// must not be a typed-nil value that would fail during handshake.
func validDirectTLSPrivateKey(key crypto.PrivateKey) bool {
	if key == nil {
		return true
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return false
	}
	value := reflect.ValueOf(signer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

// snapshotableDirectTLSPrivateKey identifies the standard private-key types
// that can be copied into the reviewed listener without retaining a mutable
// caller-owned signer object. Custom crypto.Signer implementations may carry
// external state or private handles that cannot be snapshotted safely; direct
// HTTPS rejects those at preflight rather than allowing post-bind mutation to
// change the certificate identity or signing behavior.
func snapshotableDirectTLSPrivateKey(key crypto.PrivateKey) (valid bool) {
	// Standard-library key helpers may panic on malformed in-process values.
	// Keep public preflight fail-closed before listener construction and the
	// independent snapshot handoff.
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	switch value := key.(type) {
	case *rsa.PrivateKey:
		if value == nil || value.N == nil || value.N.Sign() <= 0 || value.N.BitLen() > maxDirectTLSPrivateKeyBits {
			return false
		}
		// rsa.PrivateKey.Validate may populate Precomputed. Validate a shallow
		// copy with that cache cleared so preflight does not mutate caller-owned
		// key state before the independent snapshot is built.
		candidate := *value
		candidate.Precomputed = rsa.PrecomputedValues{}
		return candidate.Validate() == nil
	case *ecdsa.PrivateKey:
		if value == nil || value.Curve == nil || value.D == nil || value.X == nil || value.Y == nil ||
			value.D.Sign() <= 0 || value.D.BitLen() > maxDirectTLSPrivateKeyBits {
			return false
		}
		params := value.Curve.Params()
		if params == nil || params.N == nil || value.D.Cmp(params.N) >= 0 || !value.Curve.IsOnCurve(value.X, value.Y) {
			return false
		}
		x, y := value.Curve.ScalarBaseMult(value.D.Bytes())
		return x != nil && y != nil && x.Cmp(value.X) == 0 && y.Cmp(value.Y) == 0
	case ed25519.PrivateKey:
		return len(value) == ed25519.PrivateKeySize
	default:
		return false
	}
}

// validDirectTLSCertificateKeyPair checks the public key exposed by an
// already-parsed static leaf against its standard private signer. Empty
// certificate provisioning placeholders remain valid, and a missing leaf or
// key leaves certificate provisioning to the deployment. When both are
// supplied, accepting a mismatch would defer a malformed in-process handoff
// until TLS use, after the reviewed configuration boundary.
func validDirectTLSCertificateKeyPair(leaf *x509.Certificate, key crypto.PrivateKey) (valid bool) {
	if leaf == nil || key == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	signer, ok := key.(crypto.Signer)
	if !ok || leaf.PublicKey == nil {
		return false
	}
	privatePublicKey, ok := marshalCertificatePublicKey(signer.Public())
	if !ok {
		return false
	}
	leafPublicKey, ok := marshalCertificatePublicKey(leaf.PublicKey)
	return ok && bytes.Equal(privatePublicKey, leafPublicKey)
}

// validDirectTLSNameMapping bounds the operator-supplied keys used by the
// standard library's static SNI lookup. crypto/tls lowercases the client SNI
// before looking up NameToCertificate, so require the map key to already use
// that canonical spelling; otherwise a mixed-case entry would be accepted by
// preflight but remain unreachable during the handshake. Keep wildcard and
// otherwise opaque non-control bytes compatible with crypto/tls, but reject
// bytes and Unicode characters that cannot be a trustworthy callback-visible
// SNI name.
func validDirectTLSNameMapping(name string) bool {
	return len(name) > 0 && len(name) <= maxDirectTLSNameBytes &&
		name == strings.ToLower(name) &&
		validDirectTLSSNIName(name) &&
		!containsURLControlByte(name) && !containsUnicodeControlOrFormat(name)
}

// validDirectTLSSNIName mirrors the server-side ClientHello parser's
// rejection of absolute FQDN spellings. A trailing dot is not accepted by
// crypto/tls for SNI, so a static map entry or synthetic completed state that
// carries one would be unreachable or impossible on the direct server path.
func validDirectTLSSNIName(name string) bool {
	return name == "" || !strings.HasSuffix(name, ".")
}

// validateDirectTLSClientAuth accepts only the ClientAuth modes defined by
// crypto/tls. The v2 HTTP boundary leaves the choice of client-certificate
// authentication to the deployment, but an unknown numeric mode must not be
// allowed to silently acquire whatever semantics a future library version
// assigns to it.
func validateDirectTLSClientAuth(config *tls.Config) error {
	switch config.ClientAuth {
	case tls.NoClientCert:
		// ClientCAs is ignored when the server does not request a client
		// certificate. Reject an unused pool rather than allowing a direct
		// configuration to carry trust material that appears reviewed but has
		// no effect on the handshake.
		if config.ClientCAs != nil {
			return errors.New("lifecycle TLS config cannot set client CAs when client certificates are disabled")
		}
		return nil
	case tls.RequestClientCert, tls.RequireAnyClientCert:
		return validateDirectTLSClientCASubjects(config.ClientCAs)
	case tls.VerifyClientCertIfGiven, tls.RequireAndVerifyClientCert:
		// A nil ClientCAs makes x509.Verify use the host system roots. Keep
		// the direct boundary on an explicit deployment-owned trust set so
		// the accepted client identity cannot change with host configuration.
		if config.ClientCAs == nil {
			return errors.New("lifecycle TLS config requires explicit client CAs for certificate verification")
		}
		return validateDirectTLSClientCASubjects(config.ClientCAs)
	default:
		return errors.New("lifecycle TLS config contains an unsupported client-auth mode")
	}
}

// validateDirectTLSClientCASubjects bounds the subject names that crypto/tls
// may copy into a client-certificate request. RequestClientCert and
// RequireAnyClientCert do not verify the certificate, but they still expose
// ClientCAs.Subjects() during the handshake; leaving those modes unbounded
// would make the direct preflight's resource limit depend on the auth mode.
func validateDirectTLSClientCASubjects(pool *x509.CertPool) error {
	if pool == nil {
		return nil
	}
	subjects := pool.Subjects()
	if len(subjects) > maxDirectTLSClientCASubjects {
		return errors.New("lifecycle TLS config contains too many client CA subjects")
	}
	totalBytes := 0
	for _, subject := range subjects {
		if len(subject) > maxDirectTLSClientCASubjectBytes ||
			!addBoundedBytes(&totalBytes, len(subject), maxDirectTLSClientCABytes) {
			return errors.New("lifecycle TLS config contains oversized client CA subjects")
		}
	}
	return nil
}

// validateDirectTLSCipherSuites keeps an explicit legacy-version cipher list
// from weakening the standard library's secure defaults. TLS 1.3 suites are
// not configurable through tls.Config.CipherSuites, but remain valid in an
// otherwise bounded TLS 1.3 configuration. Any configuration whose minimum is
// TLS 1.2 must name at least one current secure TLS 1.2 suite or it cannot
// serve a client at its permitted floor; omitting the field is rejected rather
// than silently selecting a future standard-library default. TLS 1.3 suites
// remain valid alongside that lower-version entry, but cannot substitute for
// it because crypto/tls ignores them for TLS 1.2.
func validateDirectTLSCipherSuites(config *tls.Config) error {
	if len(config.CipherSuites) > maxDirectTLSVectorEntries {
		return errors.New("lifecycle TLS config contains too many cipher suites")
	}
	if len(config.CipherSuites) == 0 {
		if config.MinVersion == tls.VersionTLS12 {
			return errors.New("lifecycle TLS config requires an explicit TLS 1.2 cipher suite")
		}
		return nil
	}
	// crypto/tls ignores Config.CipherSuites for TLS 1.3. Reject a non-empty
	// list on a TLS 1.3-only server rather than accepting a configuration whose
	// explicit cipher policy has no effect. A TLS 1.2-to-1.3 range remains
	// compatible with an explicit TLS 1.2 list because those entries still
	// govern the lower end of the configured range.
	if config.MinVersion == tls.VersionTLS13 {
		return errors.New("lifecycle TLS 1.3-only config cannot set explicit cipher suites")
	}
	secure := make(map[uint16]*tls.CipherSuite, len(tls.CipherSuites()))
	for _, suite := range tls.CipherSuites() {
		secure[suite.ID] = suite
	}
	knownInsecure := make(map[uint16]struct{}, len(tls.InsecureCipherSuites()))
	for _, suite := range tls.InsecureCipherSuites() {
		knownInsecure[suite.ID] = struct{}{}
	}
	hasTLS12 := false
	seen := make(map[uint16]struct{}, len(config.CipherSuites))
	for _, id := range config.CipherSuites {
		if _, ok := seen[id]; ok {
			return errors.New("lifecycle TLS config contains duplicate cipher suites")
		}
		seen[id] = struct{}{}
		suite, ok := secure[id]
		if !ok {
			if _, insecure := knownInsecure[id]; insecure {
				return errors.New("lifecycle TLS config enables an insecure cipher suite")
			}
			return errors.New("lifecycle TLS config contains an unknown cipher suite")
		}
		for _, version := range suite.SupportedVersions {
			if version == tls.VersionTLS12 {
				hasTLS12 = true
			}
		}
	}
	if config.MinVersion == tls.VersionTLS12 && !hasTLS12 {
		return errors.New("lifecycle TLS config has no secure TLS 1.2 cipher suite")
	}
	return nil
}

// validateDirectTLSCurvePreferences rejects explicit groups that crypto/tls
// cannot use and prevents a TLS 1.2-capable version range from being paired
// with TLS 1.3-only post-quantum groups. A nil slice keeps the standard
// library defaults, while an explicit slice is treated as the complete
// operator-selected allowlist.
func validateDirectTLSCurvePreferences(config *tls.Config) error {
	if len(config.CurvePreferences) > maxDirectTLSVectorEntries {
		return errors.New("lifecycle TLS config contains too many supported groups")
	}
	if len(config.CurvePreferences) == 0 {
		return nil
	}
	hasTLS12Group := false
	seen := make(map[tls.CurveID]struct{}, len(config.CurvePreferences))
	for _, curve := range config.CurvePreferences {
		if _, ok := seen[curve]; ok {
			return errors.New("lifecycle TLS config contains duplicate supported groups")
		}
		seen[curve] = struct{}{}
		switch curve {
		case tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521:
			hasTLS12Group = true
		case tls.X25519MLKEM768:
			// This hybrid group is TLS 1.3-only.
		default:
			return errors.New("lifecycle TLS config contains an unsupported curve")
		}
	}
	if config.MinVersion == tls.VersionTLS12 && !hasTLS12Group {
		return errors.New("lifecycle TLS config has no TLS 1.2-compatible curve")
	}
	return nil
}

// validateDirectTLSNextProtos mirrors crypto/tls's ALPN wire bounds before a
// deployment attempts to construct a listener. TLS accepts opaque protocol
// names, so this check deliberately preserves arbitrary non-empty bytes while
// rejecting only impossible names, an oversized list, or an oversized protocol
// vector. The preflight does not choose an application protocol or claim that
// an authenticated controller will negotiate one.
func validateDirectTLSNextProtos(config *tls.Config) error {
	if len(config.NextProtos) > maxDirectTLSALPNProtocols {
		return errors.New("lifecycle TLS config contains too many ALPN protocols")
	}
	seen := make(map[string]struct{}, len(config.NextProtos))
	total := 0
	for _, protocol := range config.NextProtos {
		if len(protocol) == 0 || len(protocol) > maxDirectTLSALPNProtocolBytes {
			return errors.New("lifecycle TLS config contains an invalid ALPN protocol")
		}
		if _, ok := seen[protocol]; ok {
			return errors.New("lifecycle TLS config contains duplicate ALPN protocols")
		}
		seen[protocol] = struct{}{}
		if total > maxDirectTLSALPNBytes-1-len(protocol) {
			return errors.New("lifecycle TLS config contains oversized ALPN protocols")
		}
		total += 1 + len(protocol)
	}
	return nil
}

// ValidateDirectHTTPSListenPolicy composes the required preflight for a
// future direct-HTTPS v2 listener. It requires a loopback-only host:port and
// an explicit TLS 1.2-or-newer configuration, in that order. It performs no
// name resolution, listener creation, certificate loading, or network I/O;
// deployment code remains responsible for the actual bound socket and
// authenticated distribution review.
func ValidateDirectHTTPSListenPolicy(address string, config *tls.Config) error {
	if err := ValidateLoopbackListenAddress(address); err != nil {
		return err
	}
	return ValidateDirectTLSConfig(config)
}

// ListenDirectHTTPS creates a loopback-only TLS listener after the direct
// HTTPS policy has passed. It does not serve requests or load certificates;
// the caller owns the returned listener and must attach the handler produced
// by NewDirectHTTPSHandler to an http.Server. The TLS configuration is cloned
// before it is handed to crypto/tls so later top-level caller changes cannot
// alter the listener's reviewed policy.
func ListenDirectHTTPS(address string, config *tls.Config) (net.Listener, error) {
	// Validate and hand crypto/tls the same private snapshot. A caller may
	// retain the configuration pointer and mutate it after this function
	// returns; validating the caller-owned value and cloning only afterward
	// would leave a time-of-check/use gap between the reviewed policy and the
	// listener's actual handshake configuration.
	reviewedConfig, err := cloneDirectTLSConfig(config)
	if err != nil {
		return nil, err
	}
	return listenDirectHTTPSWithReviewedConfig(address, reviewedConfig)
}

func listenDirectHTTPSWithReviewedConfig(address string, reviewedConfig *tls.Config) (net.Listener, error) {
	if err := ValidateDirectHTTPSListenPolicy(address, reviewedConfig); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("lifecycle direct HTTPS listener: %w", err)
	}
	tlsListener := tls.NewListener(listener, reviewedConfig)
	boundAddress, err := reviewedDirectHTTPSAddress(tlsListener)
	if err != nil {
		_ = tlsListener.Close()
		return nil, err
	}
	boundHost, boundPort, err := directListenAuthorityFromAddr(boundAddress)
	if err != nil {
		_ = tlsListener.Close()
		return nil, err
	}
	return &reviewedDirectHTTPSListener{
		listener:         tlsListener,
		expectedListener: tlsListener,
		config:           reviewedConfig,
		expectedHost:     boundHost,
		expectedPort:     boundPort,
	}, nil
}

// BindDirectHTTPS constructs the reviewed direct handler and its loopback-only
// TLS listener from one address/configuration pair. It does not serve the
// listener or register a route; the caller owns the listener and must pass the
// returned handler to an http.Server. If either construction step fails, no
// listener is returned to the caller.
func BindDirectHTTPS(store *Store, resolve PrincipalResolver, address string, config *tls.Config) (*MCPHTTPHandler, net.Listener, error) {
	// Take one private snapshot before either construction step so the handler
	// preflight and listener policy cannot observe different caller-owned
	// configurations if the input is changed between them.
	reviewedConfig, err := cloneDirectTLSConfig(config)
	if err != nil {
		return nil, nil, err
	}
	handler, err := newDirectHTTPSHandler(store, resolve, address, reviewedConfig, true)
	if err != nil {
		return nil, nil, err
	}
	listener, err := listenDirectHTTPSWithReviewedConfig(address, reviewedConfig)
	if err != nil {
		return nil, nil, err
	}
	reviewedListener, ok := listener.(*reviewedDirectHTTPSListener)
	if !ok || reviewedListener == nil || reviewedListener.config != reviewedConfig {
		_ = listener.Close()
		return nil, nil, errors.New("lifecycle direct HTTPS TLS snapshot provenance is invalid")
	}
	boundAddress, err := reviewedDirectHTTPSAddress(reviewedListener.listener)
	if err != nil {
		_ = listener.Close()
		return nil, nil, err
	}
	boundHost, boundPort, err := directListenAuthorityFromAddr(boundAddress)
	if err != nil {
		_ = listener.Close()
		return nil, nil, err
	}
	handler.directListenHost = boundHost
	handler.directListenPort = boundPort
	handler.directTLSConfig = reviewedConfig
	return handler, listener, nil
}

// cloneDirectTLSConfig establishes the nil boundary before invoking the
// tls.Config method. Direct callers must receive the same fail-closed error as
// the pure validator rather than turning malformed transport setup into a
// process panic.
func cloneDirectTLSConfig(config *tls.Config) (*tls.Config, error) {
	return cloneDirectTLSConfigWith(config, func(value *tls.Config) *tls.Config {
		return value.Clone()
	})
}

// cloneDirectTLSConfigWith keeps the snapshot boundary total even if a
// malformed or concurrently-mutated in-process tls.Config makes the standard
// library clone path panic. The direct binding must return an ordinary
// construction error and no partial listener/handler rather than allowing a
// caller-owned configuration to crash the serving process.
func cloneDirectTLSConfigWith(config *tls.Config, clone func(*tls.Config) *tls.Config) (reviewed *tls.Config, err error) {
	defer func() {
		if recover() != nil {
			reviewed = nil
			err = fmt.Errorf("%w: lifecycle TLS config snapshot failed", ErrDirectTLSConfigInvalid)
			return
		}
		if err != nil && !errors.Is(err, ErrDirectTLSConfigInvalid) {
			err = fmt.Errorf("%w: %w", ErrDirectTLSConfigInvalid, err)
		}
	}()
	if config == nil {
		return nil, errors.New("lifecycle TLS config is required")
	}
	if clone == nil {
		return nil, errors.New("lifecycle TLS config clone function is required")
	}
	// Validate the caller-owned shape before Clone or any collection snapshot
	// can allocate from it. The direct policy validator rejects oversized
	// vectors and aggregate metadata without copying them; the cloned snapshot
	// is validated again by the binding path after the copy, so a caller
	// mutation between these two operations cannot weaken the reviewed policy.
	if err := ValidateDirectTLSConfig(config); err != nil {
		return nil, err
	}
	// Clone once through crypto/tls so the exported fields are read under its
	// synchronization boundary. Do not use that clone as the handoff itself:
	// tls.Config.Clone also carries unexported session-ticket state, including
	// keys installed through SetSessionTicketKeys while SessionTicketKey is
	// still zero. Rebuild only the reviewed server-policy fields below so a
	// caller's hidden ticket history or static ticket policy cannot cross this
	// ownership boundary.
	source := clone(config)
	if source == nil {
		return nil, errors.New("lifecycle TLS config snapshot is nil")
	}
	if err := ValidateDirectTLSConfig(source); err != nil {
		return nil, err
	}
	reviewed = &tls.Config{
		ClientAuth:    source.ClientAuth,
		MinVersion:    source.MinVersion,
		MaxVersion:    source.MaxVersion,
		Renegotiation: source.Renegotiation,
	}

	// tls.Config.Clone deliberately preserves several caller-owned slices,
	// maps, certificates, and trust pools. The direct listener must instead
	// retain the exact collections that passed preflight, so a later mutation
	// of the input cannot change the handshake policy after this boundary.
	reviewed.Certificates, err = cloneDirectTLSCertificates(source.Certificates)
	if err != nil {
		return nil, err
	}
	if source.NameToCertificate != nil {
		reviewed.NameToCertificate = make(map[string]*tls.Certificate, len(source.NameToCertificate))
		certificateIndexes := make(map[*tls.Certificate]int, len(source.Certificates))
		for index := range source.Certificates {
			certificateIndexes[&source.Certificates[index]] = index
		}
		for name, certificate := range source.NameToCertificate {
			if index, ok := certificateIndexes[certificate]; ok {
				reviewed.NameToCertificate[name] = &reviewed.Certificates[index]
				continue
			}
			// Validation rejects detached mappings before the reviewed
			// configuration reaches crypto/tls. Keep the malformed value
			// isolated here so this snapshot helper remains total.
			reviewed.NameToCertificate[name] = certificate
		}
	}
	reviewed.NextProtos = cloneDirectTLSStrings(source.NextProtos)
	reviewed.CipherSuites = cloneDirectTLSUint16s(source.CipherSuites)
	reviewed.CurvePreferences = cloneDirectTLSCurveIDs(source.CurvePreferences)
	if source.ClientCAs != nil {
		reviewed.ClientCAs = source.ClientCAs.Clone()
	}
	return reviewed, nil
}

func cloneDirectTLSCertificates(certificates []tls.Certificate) ([]tls.Certificate, error) {
	if certificates == nil {
		return nil, nil
	}
	cloned := make([]tls.Certificate, len(certificates))
	for index, certificate := range certificates {
		cloned[index] = certificate
		privateKey, err := cloneDirectTLSPrivateKey(certificate.PrivateKey)
		if err != nil {
			return nil, err
		}
		cloned[index].PrivateKey = privateKey
		cloned[index].Certificate = cloneDirectTLSByteMatrix(certificate.Certificate)
		cloned[index].OCSPStaple = cloneDirectTLSBytes(certificate.OCSPStaple)
		cloned[index].SignedCertificateTimestamps = cloneDirectTLSByteMatrix(certificate.SignedCertificateTimestamps)
		cloned[index].SupportedSignatureAlgorithms = cloneDirectTLSSignatureSchemes(certificate.SupportedSignatureAlgorithms)
		// crypto/tls reparses Leaf from the snapshotted DER when needed. Do
		// not retain a caller-owned parsed certificate pointer in the
		// listener configuration.
		cloned[index].Leaf = nil
	}
	return cloned, nil
}

// cloneDirectTLSPrivateKey copies standard signer implementations through a
// serialized PKCS#8 representation. The returned signer has independent key
// material, while the original remains owned by the caller. Ed25519 keys are
// copied directly because their private representation is already a bounded
// byte slice. Unknown signer implementations are rejected by preflight and
// this helper remains fail-closed if called with one through an in-package
// seam.
func cloneDirectTLSPrivateKey(key crypto.PrivateKey) (crypto.PrivateKey, error) {
	if key == nil {
		return nil, nil
	}
	if !snapshotableDirectTLSPrivateKey(key) {
		return nil, errors.New("lifecycle TLS config contains a non-snapshotable certificate private key")
	}
	if ed25519Key, ok := key.(ed25519.PrivateKey); ok {
		return append(ed25519.PrivateKey(nil), ed25519Key...), nil
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.New("lifecycle TLS config certificate private key cannot be snapshotted")
	}
	cloned, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil || !snapshotableDirectTLSPrivateKey(cloned) {
		return nil, errors.New("lifecycle TLS config certificate private key snapshot is invalid")
	}
	return cloned, nil
}

func cloneDirectTLSBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}

func cloneDirectTLSByteMatrix(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	cloned := make([][]byte, len(values))
	for index, value := range values {
		cloned[index] = cloneDirectTLSBytes(value)
	}
	return cloned
}

func cloneDirectTLSStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func cloneDirectTLSUint16s(values []uint16) []uint16 {
	if values == nil {
		return nil
	}
	cloned := make([]uint16, len(values))
	copy(cloned, values)
	return cloned
}

func cloneDirectTLSCurveIDs(values []tls.CurveID) []tls.CurveID {
	if values == nil {
		return nil
	}
	cloned := make([]tls.CurveID, len(values))
	copy(cloned, values)
	return cloned
}

func cloneDirectTLSSignatureSchemes(values []tls.SignatureScheme) []tls.SignatureScheme {
	if values == nil {
		return nil
	}
	cloned := make([]tls.SignatureScheme, len(values))
	copy(cloned, values)
	return cloned
}

// BindDirectHTTPSServer constructs a reviewed direct-HTTPS handler, TLS
// listener, and http.Server as one additive handoff. It does not call Serve,
// start a goroutine, register a route, load certificates, or publish a
// listener. The returned server has bounded HTTP resource defaults; callers
// own both the server and listener and may deliberately shut them down or
// pass the server to their separately reviewed serving lifecycle.
func BindDirectHTTPSServer(store *Store, resolve PrincipalResolver, address string, config *tls.Config) (*http.Server, net.Listener, error) {
	handler, listener, err := BindDirectHTTPS(store, resolve, address, config)
	if err != nil {
		return nil, nil, err
	}
	reviewedListener, ok := listener.(*reviewedDirectHTTPSListener)
	if !ok || reviewedListener == nil {
		_ = listener.Close()
		return nil, nil, errors.New("lifecycle direct HTTPS listener provenance is invalid")
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: directHTTPSReadHeaderTimeout,
		ReadTimeout:       directHTTPSReadTimeout,
		WriteTimeout:      directHTTPSWriteTimeout,
		IdleTimeout:       directHTTPSIdleTimeout,
		MaxHeaderBytes:    directHTTPSMaxHeaderBytes,
	}
	handler.directServer = server
	handler.directListener = reviewedListener
	return server, listener, nil
}

// validateDirectHTTPSServer keeps the bounded defaults and execution policy
// installed by BindDirectHTTPSServer in force at the serving boundary. The
// returned *http.Server is intentionally public so callers can close it or
// hand it to other code, but changing a timeout, hook, context factory,
// protocol setting, or listener address before calling the reviewed serving
// helper must fail closed rather than silently changing the direct HTTPS
// serving contract.
func (handler *MCPHTTPHandler) validateDirectHTTPSServer(server *http.Server) error {
	if server.ReadHeaderTimeout != directHTTPSReadHeaderTimeout ||
		server.ReadTimeout != directHTTPSReadTimeout ||
		server.WriteTimeout != directHTTPSWriteTimeout ||
		server.IdleTimeout != directHTTPSIdleTimeout ||
		server.MaxHeaderBytes != directHTTPSMaxHeaderBytes {
		return errors.New("lifecycle direct HTTPS server resource limits were changed")
	}
	if server.Addr != "" ||
		server.DisableGeneralOptionsHandler ||
		server.TLSConfig != nil ||
		server.ConnState != nil ||
		server.ErrorLog != nil ||
		server.BaseContext != nil ||
		server.ConnContext != nil ||
		server.HTTP2 != nil ||
		server.Protocols != nil {
		return errors.New("lifecycle direct HTTPS server execution policy was changed")
	}
	// net/http may populate TLSNextProto during the first Serve call when it
	// enables automatic HTTP/2 for a TLS listener. Before that call, however,
	// a non-nil map is caller-owned protocol takeover configuration and must be
	// rejected. A later reuse attempt is rejected by claimDirectHTTPSServer
	// before this check, so the standard library's internal map is harmless.
	handler.directServeMu.Lock()
	served := handler.directServed
	handler.directServeMu.Unlock()
	if !served && server.TLSNextProto != nil {
		return errors.New("lifecycle direct HTTPS server execution policy was changed")
	}
	return nil
}

func (handler *MCPHTTPHandler) claimDirectHTTPSServer() error {
	handler.directServeMu.Lock()
	defer handler.directServeMu.Unlock()
	if handler.directServing || handler.directServed {
		return errors.New("lifecycle direct HTTPS server binding is already in use")
	}
	handler.directServing = true
	return nil
}

func (handler *MCPHTTPHandler) unclaimDirectHTTPSServer() {
	handler.directServeMu.Lock()
	handler.directServing = false
	handler.directServeMu.Unlock()
}

func (handler *MCPHTTPHandler) releaseDirectHTTPSServer() {
	handler.directServeMu.Lock()
	handler.directServing = false
	handler.directServed = true
	handler.directServeMu.Unlock()
}

// awaitDirectHTTPSServerOperation waits only until the reviewed shutdown
// deadline. A net.Listener is an interface owned by the integration, so a
// malformed Close or Accept implementation cannot be allowed to hold this
// serving boundary forever. The operation goroutine has a buffered result
// channel and may finish later; the binding remains permanently served after
// ServeDirectHTTPSServer returns, so it cannot be retried.
func awaitDirectHTTPSServerOperation(result <-chan error, deadline time.Time) (err error, timedOut bool) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		select {
		case err = <-result:
			return err, false
		default:
			return nil, true
		}
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case err = <-result:
		return err, false
	case <-timer.C:
		return nil, true
	}
}

func shutdownDirectHTTPSServerUntil(server *http.Server, deadline time.Time) (error, bool) {
	shutdownContext, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- invokeDirectHTTPSServerShutdown(server, shutdownContext) }()
	return awaitDirectHTTPSServerOperation(result, deadline)
}

func closeDirectHTTPSServerUntil(server *http.Server, deadline time.Time) (error, bool) {
	result := make(chan error, 1)
	go func() { result <- invokeDirectHTTPSServerClose(server) }()
	return awaitDirectHTTPSServerOperation(result, deadline)
}

// invokeDirectHTTPSServerShutdown contains an unexpected panic from the
// standard-library shutdown path. A malformed in-process connection or
// listener can be reached while net/http drains its internal state; that
// integration panic must become an opaque operation result rather than
// terminating the serving process.
func invokeDirectHTTPSServerShutdown(server *http.Server, ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrDirectHTTPSServeShutdownPanic
		}
	}()
	return server.Shutdown(ctx)
}

// invokeDirectHTTPSServerClose contains an unexpected panic from the forced
// close path for the same reason as invokeDirectHTTPSServerShutdown. The
// caller still applies the shared deadline to the operation and final Serve
// result.
func invokeDirectHTTPSServerClose(server *http.Server) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrDirectHTTPSServeShutdownPanic
		}
	}()
	return server.Close()
}

// validateReviewedDirectHTTPSListener checks the live address at the serving
// boundary. Construction validates the requested address, but the private
// listener marker is still an in-process object and malformed integrations
// must not be able to replace its delegate with a non-loopback, nil, or
// panicking address before ownership is claimed.
func validateReviewedDirectHTTPSListener(listener *reviewedDirectHTTPSListener) (err error) {
	err = errors.New("lifecycle direct HTTPS loopback listener address is required")
	defer func() {
		if recover() != nil {
			err = closeReviewedDirectHTTPSAfterAddressFailure(listener, errors.New("lifecycle direct HTTPS loopback listener address is invalid"))
		}
	}()
	if listener == nil {
		return err
	}
	if listener.expectedListener != nil && !sameReviewedDirectHTTPSListener(listener.listener, listener.expectedListener) {
		replacementErr := errors.New("lifecycle direct HTTPS loopback listener delegate was replaced")
		cleanupErr := closeReviewedDirectHTTPSDelegate(listener)
		if cleanupErr != nil {
			return errors.Join(replacementErr, cleanupErr)
		}
		return replacementErr
	}
	if sameReviewedDirectHTTPSListener(listener, listener.listener) {
		return closeReviewedDirectHTTPSAfterAddressFailure(listener, errors.New("lifecycle direct HTTPS loopback listener is invalid"))
	}
	if listener.listener == nil {
		return err
	}
	address, addressErr := reviewedDirectHTTPSAddress(listener.listener)
	if addressErr != nil {
		return closeReviewedDirectHTTPSAfterAddressFailure(listener, addressErr)
	}
	if !listener.matchesExpectedAddress(address) {
		return closeReviewedDirectHTTPSAfterAddressFailure(listener, directHTTPSBoundAddressError(nil))
	}
	return nil
}

// closeReviewedDirectHTTPSAfterAddressFailure closes the construction-approved
// delegate when the serving-boundary address no longer proves the reviewed
// loopback scope. Addr cannot report cleanup failures itself, but the serving
// boundary can preserve that classification while preventing a malformed
// listener from remaining live after validation fails.
func closeReviewedDirectHTTPSAfterAddressFailure(listener *reviewedDirectHTTPSListener, validationErr error) error {
	cleanupErr := closeReviewedDirectHTTPSDelegate(listener)
	if cleanupErr == nil {
		return validationErr
	}
	return errors.Join(validationErr, cleanupErr)
}

// directHTTPSServeContextState validates a serving context once and returns
// the channel captured from that validation. Context is an interface, so a
// typed-nil or malformed implementation must not be allowed to panic before
// the reviewed server binding is claimed. A closed Done channel is
// authoritative even when a malformed context reports a nil Err.
func directHTTPSServeContextState(ctx context.Context) (done <-chan struct{}, stateErr error) {
	stateErr = ErrDirectHTTPSServeContextInvalid
	defer func() {
		if recover() != nil {
			done = nil
			stateErr = ErrDirectHTTPSServeContextInvalid
		}
	}()
	if ctx == nil {
		return nil, ErrDirectHTTPSServeContextInvalid
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, ErrDirectHTTPSServeContextInvalid
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, canonicalDirectHTTPSServeContextError(err)
	}
	done = ctx.Done()
	// Context implementations must return the same Done channel on every
	// call. Verify that contract before the serving binding is claimed so a
	// malformed implementation cannot leave the server waiting on a channel
	// that later context inspections no longer expose.
	if repeatedDone := ctx.Done(); repeatedDone != done {
		return nil, ErrDirectHTTPSServeContextInvalid
	}
	// Recheck Err after the Done contract has been observed. A context may be
	// canceled during the probes while still exposing a nil Done channel; do
	// not claim the serving binding when that cancellation is visible here.
	if err := ctx.Err(); err != nil {
		return done, canonicalDirectHTTPSServeContextError(err)
	}
	if done == nil {
		return done, nil
	}
	select {
	case <-done:
		if err := ctx.Err(); err != nil {
			return done, canonicalDirectHTTPSServeContextError(err)
		}
		return done, context.Canceled
	default:
		return done, nil
	}
}

// canonicalDirectHTTPSServeContextError keeps arbitrary caller-owned context
// errors from crossing the serving boundary. The context contract defines only
// these two cancellation causes; every other value is malformed and must not
// be returned with its implementation-defined detail.
func canonicalDirectHTTPSServeContextError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrDirectHTTPSServeContextInvalid
}

// directHTTPSServeShutdownResult preserves shutdown/close/serve failures while
// adding the timeout classification only when one of the bounded operations
// actually reached its deadline. In particular, a contained panic from
// Shutdown or Close is an operation failure, not evidence that the drain
// deadline elapsed.
func directHTTPSServeShutdownResult(shutdownErr error, shutdownTimedOut bool, closeErr error, closeTimedOut bool, serveErr error, serveTimedOut bool) error {
	if shutdownTimedOut {
		// The bounded operation normally returns no error alongside its timeout,
		// but retain any error a malformed integration reports with that result.
		// Timeout classification is additive; it must not erase cleanup or
		// operation evidence that callers may need to review.
		if shutdownErr == nil || shutdownErr == http.ErrServerClosed {
			shutdownErr = context.DeadlineExceeded
		} else if !errors.Is(shutdownErr, context.DeadlineExceeded) {
			shutdownErr = errors.Join(shutdownErr, context.DeadlineExceeded)
		}
	}
	causes := make([]error, 0, 3)
	for _, cause := range []error{shutdownErr, closeErr, serveErr} {
		// Ignore only the standalone normal Serve termination. A joined or
		// wrapped error may also carry a meaningful cleanup/operation cause.
		if cause == nil || cause == http.ErrServerClosed {
			continue
		}
		causes = append(causes, cause)
	}
	timedOut := shutdownTimedOut || closeTimedOut || serveTimedOut
	for _, cause := range causes {
		if errors.Is(cause, context.DeadlineExceeded) {
			timedOut = true
			break
		}
	}
	if timedOut {
		// Preserve the standard deadline cause for every bounded operation
		// timeout, including a forced-close or final Serve wait that timed out
		// after graceful Shutdown returned without an error. Callers can then
		// distinguish the additive timeout classification without losing the
		// ordinary context cancellation cause.
		deadlineCause := false
		for _, cause := range causes {
			if errors.Is(cause, context.DeadlineExceeded) {
				deadlineCause = true
				break
			}
		}
		if !deadlineCause {
			causes = append(causes, context.DeadlineExceeded)
		}
		return fmt.Errorf("%w: %w", ErrDirectHTTPSServeShutdownTimeout, errors.Join(causes...))
	}
	switch len(causes) {
	case 0:
		return nil
	case 1:
		return causes[0]
	default:
		return errors.Join(causes...)
	}
}

// ServeDirectHTTPSServer runs a previously reviewed direct-HTTPS server until
// its context ends or Serve returns. Context cancellation triggers graceful
// shutdown with a bounded five-second drain; connections that do not finish in
// that window are force-closed so a malformed or stalled client cannot retain
// the serving goroutine indefinitely. The caller still owns the server and
// listener and must not reuse either after this function returns.
func ServeDirectHTTPSServer(ctx context.Context, server *http.Server, listener net.Listener) error {
	done, contextErr := directHTTPSServeContextState(ctx)
	if contextErr != nil {
		return contextErr
	}
	if server == nil {
		return errors.New("lifecycle direct HTTPS server is required")
	}
	if listener == nil {
		return errors.New("lifecycle direct HTTPS listener is required")
	}
	reviewedListener, ok := listener.(*reviewedDirectHTTPSListener)
	if !ok || reviewedListener == nil {
		return errors.New("lifecycle direct HTTPS reviewed TLS listener is required")
	}
	handler, ok := server.Handler.(*MCPHTTPHandler)
	if !ok || handler == nil || !handler.direct {
		return errors.New("lifecycle direct HTTPS handler is required")
	}
	if handler.directServer != server || handler.directListener != reviewedListener {
		return errors.New("lifecycle direct HTTPS server binding is required")
	}
	if handler.directTLSConfig == nil || reviewedListener.config != handler.directTLSConfig {
		return errors.New("lifecycle direct HTTPS TLS snapshot binding is required")
	}
	if err := validateReviewedDirectHTTPSListener(reviewedListener); err != nil {
		return err
	}
	if err := handler.claimDirectHTTPSServer(); err != nil {
		return err
	}
	if err := handler.validateDirectHTTPSServer(server); err != nil {
		handler.unclaimDirectHTTPSServer()
		return err
	}
	recheckedDone, err := directHTTPSServeContextState(ctx)
	if err != nil {
		handler.unclaimDirectHTTPSServer()
		return err
	}
	// The first probe captured the channel used by the serving wait. A
	// malformed context can otherwise return one stable channel during each
	// individual probe while switching channels between probes, leaving the
	// serving goroutine detached from the cancellation that was revalidated
	// immediately before ownership was handed to net/http.
	if recheckedDone != done {
		handler.unclaimDirectHTTPSServer()
		return ErrDirectHTTPSServeContextInvalid
	}
	// Revalidate the mutable public handoff objects after the final context
	// probe and immediately before starting net/http. An in-process integration
	// can otherwise change the reviewed listener address or server policy in
	// the small interval between the initial validation and this goroutine
	// launch, allowing serving to begin on an unreviewed binding.
	if err := validateReviewedDirectHTTPSListener(reviewedListener); err != nil {
		handler.unclaimDirectHTTPSServer()
		return err
	}
	if err := handler.validateDirectHTTPSServer(server); err != nil {
		handler.unclaimDirectHTTPSServer()
		return err
	}
	defer handler.releaseDirectHTTPSServer()

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- invokeDirectHTTPSServe(server, listener)
	}()

	select {
	case err := <-serveResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("lifecycle direct HTTPS serve: %w", err)
	case <-done:
		shutdownDeadline := time.Now().Add(directHTTPSShutdownTimeout)
		shutdownErr, shutdownTimedOut := shutdownDirectHTTPSServerUntil(server, shutdownDeadline)
		if shutdownTimedOut {
			shutdownErr = context.DeadlineExceeded
		}
		if shutdownErr != nil {
			// Shutdown leaves active connections in place when its context
			// expires. Close them before waiting for Serve so the bounded
			// handoff cannot retain caller-visible serving ownership. Both
			// operations are deadline-bounded because a malformed listener may
			// block in Close or fail to unblock Accept.
			closeErr, closeTimedOut := closeDirectHTTPSServerUntil(server, shutdownDeadline)
			serveErr, serveTimedOut := awaitDirectHTTPSServerOperation(serveResult, shutdownDeadline)
			return directHTTPSServeShutdownResult(shutdownErr, shutdownTimedOut, closeErr, closeTimedOut, serveErr, serveTimedOut)
		}
		serveErr, serveTimedOut := awaitDirectHTTPSServerOperation(serveResult, shutdownDeadline)
		if serveTimedOut {
			closeErr, closeTimedOut := closeDirectHTTPSServerUntil(server, shutdownDeadline)
			return directHTTPSServeShutdownResult(nil, false, closeErr, closeTimedOut, nil, true)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("lifecycle direct HTTPS serve after shutdown: %w", serveErr)
		}
		_, contextErr = directHTTPSServeContextState(ctx)
		if contextErr == nil {
			contextErr = context.Canceled
		}
		return contextErr
	}
}

// invokeDirectHTTPSServe contains an unexpected panic from the serving
// goroutine. The reviewed listener normally comes from ListenDirectHTTPS, but
// keeping the goroutine's result channel total prevents a malformed in-process
// listener or future net/http change from leaving ServeDirectHTTPSServer
// waiting forever. The panic value is deliberately not exposed.
func invokeDirectHTTPSServe(server *http.Server, listener net.Listener) (err error) {
	defer func() {
		if recover() != nil {
			err = errDirectHTTPSServePanic
		}
	}()
	return server.Serve(listener)
}

// ValidateLoopbackListenAddress checks the bind address a deployment intends
// to use for the additive v2 route. It performs no name resolution and never
// opens a listener; only literal IP loopback addresses are accepted, while
// hostnames (including localhost), wildcard, public, service-name, and
// malformed endpoints fail closed. Using literal addresses keeps the
// loopback-only claim independent of hosts-file or DNS overrides.
// Port zero remains valid for test harnesses that let the OS choose a port.
func ValidateLoopbackListenAddress(address string) error {
	if address == "" || len(address) > maxMCPListenAddressBytes || strings.TrimSpace(address) != address {
		return errors.New("lifecycle listen address is invalid")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return errors.New("lifecycle listen address must be host:port")
	}
	// Keep the preflight's accepted endpoint spelling aligned with the
	// deployment-facing host:port contract. strconv.Atoi accepts a leading
	// sign and leading zeroes, but neither is canonical network endpoint
	// metadata; alternate spellings could make the same bind identity appear
	// different to logs, policy records, or supervisor review.
	for index := 0; index < len(port); index++ {
		if port[index] < '0' || port[index] > '9' {
			return errors.New("lifecycle listen port is invalid")
		}
	}
	if len(port) > 1 && port[0] == '0' {
		return errors.New("lifecycle listen port is not canonical")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return errors.New("lifecycle listen port is invalid")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("lifecycle listen address must be loopback")
	}
	return nil
}

// verifySecureTransport contains integration failures at the HTTP boundary.
// A verifier is supplied by the deployment, so a panic in malformed or
// partially initialized integration code must fail closed instead of escaping
// the handler or reaching the authenticated resolver.
func verifySecureTransport(verify SecureTransportVerifier, r *http.Request) (secure bool) {
	defer func() {
		if recover() != nil {
			secure = false
		}
	}()
	return verify(r)
}

// resolvePrincipal contains integration failures at the HTTP boundary. The
// returned error is intentionally generic; resolver details never cross the
// authentication response boundary.
func resolvePrincipal(resolve PrincipalResolver, r *http.Request) (principal Principal, err error) {
	defer func() {
		if recover() != nil {
			principal = Principal{}
			err = errors.New("lifecycle HTTP principal resolution failed")
		}
	}()
	return resolve(r)
}

// invokeMCPHandler contains an unexpected adapter panic at the HTTP boundary.
// The adapter is an internal library, but malformed persisted state or a future
// integration change must not let one authenticated request crash its serving
// process. The caller maps this sentinel to a generic 500 response and never
// exposes the panic value.
func invokeMCPHandler(handle func() ([]byte, error)) (response []byte, err error) {
	defer func() {
		if recover() != nil {
			response = nil
			err = errMCPHandlerPanic
		}
	}()
	return handle()
}

// ServeHTTP enforces the transport boundary before constructing an
// owner-bound MCP adapter. Authentication failures are intentionally generic so
// resolver errors cannot disclose token or account details.
func (h *MCPHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer containHTTPResponsePanic(w)
	// Install cleanup before touching the response writer. A direct library
	// caller can provide a malformed writer whose Header method panics; that
	// must not skip cleanup of the caller-owned request body.
	var bodyTracker *requestBodyMutationTracker
	// Until the transport verifier is entered, no callback or body tracker can
	// replace Request.Body. Keep that fact explicit because an uncomparable
	// entry body cannot be deduplicated by interface identity during cleanup.
	entryBodyUnchangedBeforeTracking := true
	if r != nil && r.Body != nil {
		originalBody := r.Body
		defer func() {
			closeRequestBodies(r, originalBody, bodyTracker, entryBodyUnchangedBeforeTracking)
		}()
	}
	setHTTPBoundaryHeaders(w)
	// Keep the library boundary responsible for caller-owned resources even
	// when a zero-value or nil handler is invoked directly. A net/http server
	// normally owns this cleanup, but direct use must not leak a body merely
	// because handler construction was bypassed.
	if h == nil || h.store == nil || h.resolve == nil || h.secure == nil {
		writeHTTPError(w, http.StatusServiceUnavailable)
		return
	}
	if r == nil {
		writeHTTPError(w, http.StatusMethodNotAllowed)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeHTTPError(w, http.StatusMethodNotAllowed)
		return
	}
	if requestContextDone(r) {
		writeHTTPError(w, http.StatusRequestTimeout)
		return
	}
	// The store may have been closed after this handler was constructed. Check
	// the live lifecycle boundary before invoking either deployment-owned
	// security callback; a closed route must not spend authentication work or
	// expose request metadata to an integration that cannot serve it.
	if err := h.store.ensureAdapterReady(); err != nil {
		writeHTTPError(w, http.StatusServiceUnavailable)
		return
	}
	// Bound direct-library header inspection before invoking either deployment-
	// owned security callback. Normal net/http serving has wire-level header
	// limits, but a direct caller can otherwise hand a verifier an arbitrarily
	// large map before this boundary rejects it.
	if !validDirectHeaderMap(r.Header) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if !validMCPProtocolVersionHeader(r.Header) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if !validMCPAuthorizationHeader(r.Header) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	// Trailers are another callback-visible HTTP header map. Normal net/http
	// serving keeps them within its wire limits, but a direct caller can set an
	// arbitrarily large map before the body is read. Apply the same structural
	// bound before deployment-owned security callbacks inspect the request.
	if !validDirectTrailerMap(r.Trailer) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if !validDirectRequestMetadata(r) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if h.direct && !h.validDirectListenAuthority(r) {
		// A direct listener is loopback-only, but Host remains caller-controlled
		// request metadata. Do not let a matching attacker Origin/Host pair turn
		// DNS rebinding into an authenticated direct transport.
		writeHTTPError(w, http.StatusForbidden)
		return
	}
	if !validDirectServerRequestShape(r) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if !validDirectRequestBody(r) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if !validDirectTLSState(r.TLS) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	// Validate direct-call framing before either deployment-owned security
	// callback. Normal net/http serving has already normalized these fields,
	// but a library caller can construct contradictory framing metadata that a
	// transport verifier might otherwise inspect or trust.
	if !validRequestFraming(r) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if r.ContentLength < -1 {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if r.ContentLength > maxMCPRequestBytes {
		writeHTTPError(w, http.StatusRequestEntityTooLarge)
		return
	}
	// The deployment-owned transport verifier is observational: it proves the
	// request crossed the authenticated HTTPS boundary but must not rewrite the
	// metadata or consume the body that the principal resolver will later
	// authenticate. Guard the body while invoking it so a buggy or compromised
	// verifier cannot silently establish a different request identity or leave
	// the resolver with a truncated request.
	entryBodyUnchangedBeforeTracking = false
	var verifierBody *transportVerifierBody
	if r.Body != nil {
		verifierBody = &transportVerifierBody{ReadCloser: r.Body}
		r.Body = verifierBody
	}
	transportSnapshot := snapshotRequestBodyMetadata(r)
	if !verifySecureTransport(h.secure, r) {
		writeHTTPError(w, http.StatusForbidden)
		return
	}
	// The deployment-owned verifier is allowed to inspect the request but not
	// to expand the direct-call metadata that the snapshot comparison examines.
	// Reapply all bounded structural checks before comparing the callback-visible
	// values; otherwise a verifier that replaces a header map, URL, or TLS state
	// could make the comparison path inspect an unbounded direct value first.
	if !validDirectHeaderMap(r.Header) ||
		!validMCPProtocolVersionHeader(r.Header) ||
		!validMCPAuthorizationHeader(r.Header) ||
		!validDirectTrailerMap(r.Trailer) ||
		!validDirectRequestMetadata(r) ||
		!validDirectServerRequestShape(r) ||
		!validDirectRequestBody(r) ||
		!validDirectTLSState(r.TLS) ||
		!validRequestFraming(r) ||
		r.ContentLength < -1 ||
		r.ContentLength > maxMCPRequestBytes {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if !transportSnapshot.matches(r) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if verifierBody != nil && (verifierBody.read || verifierBody.closed) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if verifierBody != nil {
		r.Body = verifierBody.ReadCloser
	}
	// The deployment-owned transport verifier may perform non-trivial work.
	// Re-check cancellation before inspecting request framing or invoking the
	// principal resolver so a request withdrawn during transport verification
	// cannot continue into authentication or lifecycle mutation.
	if requestContextDone(r) {
		writeHTTPError(w, http.StatusRequestTimeout)
		return
	}
	// Transport verification can race an explicit store close. Recheck before
	// parsing media/authentication metadata so a route that became unavailable
	// during deployment-owned transport work does not continue into auth.
	if err := h.store.ensureAdapterReady(); err != nil {
		writeHTTPError(w, http.StatusServiceUnavailable)
		return
	}
	contentTypeValues := headerValuesCaseInsensitive(r.Header, "Content-Type")
	if len(contentTypeValues) == 0 {
		writeHTTPError(w, http.StatusUnsupportedMediaType)
		return
	}
	// Header.Get selects one value when a direct caller supplied duplicate
	// Content-Type fields. Reject ambiguity before parsing so an intermediary
	// and this boundary cannot disagree about the request media type.
	if len(contentTypeValues) != 1 || len(contentTypeValues[0]) > maxMCPContentTypeBytes {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(contentTypeValues[0])
	if err != nil || mediaType != "application/json" {
		writeHTTPError(w, http.StatusUnsupportedMediaType)
		return
	}
	acceptsJSON, validAccept := acceptsJSONResponse(r.Header)
	if !validAccept {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if !acceptsJSON {
		writeHTTPError(w, http.StatusNotAcceptable)
		return
	}
	// A nil body is malformed direct-library input. Reject it before invoking
	// authentication or constructing an owner-bound adapter; net/http normally
	// supplies a non-nil body, but this boundary must fail closed for callers
	// that invoke ServeHTTP directly.
	if r.Body == nil {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	// Keep observing the request field while the original body is read. A
	// malformed direct reader can replace Request.Body between reads; retaining
	// every replacement lets the deferred cleanup close intermediate resources,
	// not only the final value visible after collection.
	bodyTracker = &requestBodyMutationTracker{request: r, body: r.Body}
	r.Body = bodyTracker
	metadataSnapshot := snapshotRequestBodyMetadata(r)
	body, err := readBoundedRequestBody(r.Context(), bodyTracker)
	if errors.Is(err, errRequestBodyContextDone) || requestContextDone(r) {
		writeHTTPError(w, http.StatusRequestTimeout)
		return
	}
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if len(body) > maxMCPRequestBytes {
		writeHTTPError(w, http.StatusRequestEntityTooLarge)
		return
	}
	// A direct body reader can mutate the request object while it is being
	// consumed. Revalidate all callback-visible HTTP metadata before the
	// principal resolver sees the request, and reject changes to the metadata
	// already authenticated by the transport verifier. Normal net/http bodies
	// do not mutate these fields; trailers are intentionally validated here
	// without requiring them to equal their pre-read declaration map.
	if r.Method != http.MethodPost ||
		!validDirectHeaderMap(r.Header) ||
		!validMCPProtocolVersionHeader(r.Header) ||
		!validMCPAuthorizationHeader(r.Header) ||
		!validDirectTrailerMap(r.Trailer) ||
		!validDirectRequestMetadata(r) ||
		!validDirectServerRequestShape(r) ||
		!validDirectTLSState(r.TLS) ||
		!validRequestFraming(r) ||
		!metadataSnapshot.matchesAfterBody(r) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	// A known content length must describe exactly the bytes delivered to this
	// library boundary. net/http validates framing for normal server requests,
	// but direct integrations can construct inconsistent requests. Rejecting
	// both short and long bodies prevents an intermediary and this handler from
	// authenticating or parsing different request boundaries.
	if r.ContentLength >= 0 && int64(len(body)) != r.ContentLength {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	if requestContextDone(r) {
		writeHTTPError(w, http.StatusRequestTimeout)
		return
	}
	// Body collection is bounded but may still outlive a concurrent store
	// shutdown. Keep authentication behind one final live-store check; adapter
	// construction performs its own check as a last race-safe guard.
	if err := h.store.ensureAdapterReady(); err != nil {
		writeHTTPError(w, http.StatusServiceUnavailable)
		return
	}
	// The principal resolver is deployment-owned authentication code, but it
	// still receives the same request whose transport metadata was checked and
	// whose body was collected. Give it a bounded replay rather than the
	// already-consumed transport body. Keep that callback observational as well:
	// a resolver that reads, closes, replaces the body, or changes other
	// callback-visible metadata must not make the adapter continue with a
	// different request after auth.
	resolverBody := &principalResolverBody{reader: bytes.NewReader(body)}
	r.Body = resolverBody
	principalSnapshot := snapshotRequestBodyMetadata(r)
	// Authenticate only after bounded request framing is coherent. This keeps
	// malformed direct-library requests from invoking deployment-owned
	// authentication callbacks while the body remains capped before MCP
	// parsing or lifecycle mutation.
	principal, err := resolvePrincipal(h.resolve, r)
	if err != nil {
		writeHTTPAuthenticationError(w)
		return
	}
	if resolverBody.read || resolverBody.closed || !principalSnapshot.matches(r) {
		writeHTTPError(w, http.StatusBadRequest)
		return
	}
	// Authentication may be a deployment-owned callback with non-trivial
	// latency. Re-check the caller's context before binding the principal to a
	// controller so cancellation during authentication cannot reach a mutating
	// MCP operation.
	if requestContextDone(r) {
		writeHTTPError(w, http.StatusRequestTimeout)
		return
	}
	adapter, err := NewMCPAdapter(h.store, principal)
	if err != nil {
		if errors.Is(err, ErrClosed) {
			writeHTTPError(w, http.StatusServiceUnavailable)
			return
		}
		writeHTTPError(w, http.StatusForbidden)
		return
	}
	response, err := invokeMCPHandler(func() ([]byte, error) { return adapter.HandleContext(r.Context(), body) })
	if err != nil {
		switch {
		case errors.Is(err, ErrMCPRequestCanceled):
			writeHTTPError(w, http.StatusRequestTimeout)
		case errors.Is(err, ErrMCPRequestTooLarge):
			writeHTTPError(w, http.StatusRequestEntityTooLarge)
		case errors.Is(err, ErrMCPResponseTooLarge):
			writeHTTPError(w, http.StatusInternalServerError)
		case errors.Is(err, ErrClosed):
			writeHTTPError(w, http.StatusServiceUnavailable)
		case errors.Is(err, errMCPHandlerPanic):
			writeHTTPError(w, http.StatusInternalServerError)
		default:
			writeHTTPError(w, http.StatusBadRequest)
		}
		return
	}
	if response == nil {
		// Streamable HTTP acknowledges JSON-RPC notifications without a body.
		// Keep the in-process adapter's nil response contract, but use the
		// transport-level 202 status required for notification POSTs instead of
		// making clients infer notification handling from a 204 response.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

// validDirectListenAuthority applies the literal host and bound-port policy
// owned by NewDirectHTTPSHandler/BindDirectHTTPS. The standalone
// RequireDirectTLS verifier intentionally cannot make this decision because it
// has no configured listener authority; reviewed direct handlers can.
func (h *MCPHTTPHandler) validDirectListenAuthority(r *http.Request) bool {
	if h == nil || !h.direct || r == nil || h.directListenHost == "" || h.directListenPort == "" {
		return false
	}
	authority := r.Host
	if authority == "" && r.URL != nil {
		authority = r.URL.Host
	}
	if authority == "" || !validDirectTLSAuthority(authority) {
		return false
	}
	parsed, err := url.Parse("//" + authority)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	actualIP := net.ParseIP(parsed.Hostname())
	expectedIP := net.ParseIP(h.directListenHost)
	if actualIP == nil || expectedIP == nil || !actualIP.Equal(expectedIP) {
		return false
	}
	// A :0 construction is the only intentionally unspecified port. BindDirectHTTPS
	// replaces it with the actual OS-selected port before returning the handler.
	// HTTPS authority syntax also permits the default port to be omitted. Treat
	// an omitted port as 443 only for the reviewed HTTPS default; every other
	// bound port must remain explicit so an authority cannot silently drift to a
	// different listener.
	actualPort := parsed.Port()
	if actualPort == "" {
		actualPort = "443"
	}
	return h.directListenPort == "0" || actualPort == h.directListenPort
}

// requestContextDone rejects work after a direct caller's request has already
// been canceled or exceeded its deadline. Normal net/http servers generally
// stop delivering such requests themselves, but this library boundary must
// not invoke deployment-owned security callbacks or mutate lifecycle state
// after a caller has withdrawn the request.
func requestContextDone(r *http.Request) bool {
	return r == nil || mcpContextDone(r.Context())
}

type requestBodyMetadataSnapshot struct {
	method           string
	host             string
	requestURI       string
	pattern          string
	url              *url.URL
	body             io.ReadCloser
	header           http.Header
	proto            string
	protoMajor       int
	protoMinor       int
	close            bool
	remoteAddr       string
	requestContext   context.Context
	pathValues       map[string]string
	tlsPointer       *tls.ConnectionState
	tls              *tls.ConnectionState
	tlsCertificates  tlsCertificateMetadataSnapshot
	contentLength    int64
	transferEncoding []string
	trailer          http.Header
	trailerNames     map[string]int
}

// transportVerifierBody makes the transport verifier's observational body
// contract enforceable for direct integrations. Reading or closing the body
// before the handler's bounded collection would otherwise change the bytes
// later authenticated and parsed by the lifecycle adapter.
type transportVerifierBody struct {
	io.ReadCloser
	read      bool
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

func (b *transportVerifierBody) Read(p []byte) (int, error) {
	b.read = true
	return b.ReadCloser.Read(p)
}

func (b *transportVerifierBody) Close() error {
	b.closeOnce.Do(func() {
		b.closed = true
		defer func() {
			if recover() != nil {
				// Do not let a malformed body turn verifier cleanup into a
				// serving-process panic. The Once remains consumed so deferred
				// handler cleanup cannot invoke a caller-owned Close twice.
				b.closeErr = errRequestBodyClosePanic
			}
		}()
		b.closeErr = b.ReadCloser.Close()
	})
	return b.closeErr
}

// principalResolverBody gives authentication a bounded replay of the body
// already collected by the HTTP boundary. A resolver may inspect that replay,
// but reading or closing it is still a mutation of the callback-visible
// request: the resolver must not consume or invalidate the body while the
// boundary is authenticating the captured request. The handler rejects either
// action before constructing the owner-bound adapter.
type principalResolverBody struct {
	reader *bytes.Reader
	read   bool
	closed bool
}

func (b *principalResolverBody) Read(p []byte) (int, error) {
	if b == nil || b.reader == nil {
		return 0, io.EOF
	}
	b.read = true
	return b.reader.Read(p)
}

func (b *principalResolverBody) Close() error {
	if b != nil {
		b.closed = true
	}
	return nil
}

func snapshotRequestBodyMetadata(r *http.Request) requestBodyMetadataSnapshot {
	var requestURL *url.URL
	if r.URL != nil {
		urlCopy := *r.URL
		requestURL = &urlCopy
	}
	return requestBodyMetadataSnapshot{
		method:           r.Method,
		host:             r.Host,
		requestURI:       r.RequestURI,
		pattern:          r.Pattern,
		url:              requestURL,
		body:             r.Body,
		header:           cloneHTTPHeader(r.Header),
		proto:            r.Proto,
		protoMajor:       r.ProtoMajor,
		protoMinor:       r.ProtoMinor,
		close:            r.Close,
		remoteAddr:       r.RemoteAddr,
		requestContext:   r.Context(),
		pathValues:       snapshotRequestPathValues(r),
		tlsPointer:       r.TLS,
		tls:              cloneTLSConnectionState(r.TLS),
		tlsCertificates:  snapshotTLSCertificateMetadata(r.TLS),
		contentLength:    r.ContentLength,
		transferEncoding: cloneCertificateStrings(r.TransferEncoding),
		trailer:          cloneHTTPHeader(r.Trailer),
		trailerNames:     snapshotHeaderNames(r.Trailer),
	}
}

func (snapshot requestBodyMetadataSnapshot) matches(r *http.Request) bool {
	return snapshot.matchesWithTrailer(r, false)
}

// matchesAfterBody preserves the server-side trailer contract: declared
// trailer fields may transition from nil values to their wire-populated values
// while the body is consumed, but no field may be added, removed, or rewrite a
// value that was already visible to the transport verifier.
func (snapshot requestBodyMetadataSnapshot) matchesAfterBody(r *http.Request) bool {
	return snapshot.matchesWithTrailer(r, true)
}

func (snapshot requestBodyMetadataSnapshot) matchesWithTrailer(r *http.Request, allowTrailerPopulation bool) bool {
	if r == nil {
		return false
	}
	return snapshot.method == r.Method &&
		snapshot.host == r.Host &&
		snapshot.requestURI == r.RequestURI &&
		snapshot.pattern == r.Pattern &&
		equalRequestBody(snapshot.body, r.Body) &&
		snapshot.proto == r.Proto &&
		snapshot.protoMajor == r.ProtoMajor &&
		snapshot.protoMinor == r.ProtoMinor &&
		snapshot.close == r.Close &&
		snapshot.remoteAddr == r.RemoteAddr &&
		equalRequestContext(snapshot.requestContext, r.Context()) &&
		equalRequestPathValues(snapshot.pathValues, r) &&
		snapshot.tlsPointer == r.TLS &&
		equalTLSConnectionState(snapshot.tls, r.TLS) &&
		equalTLSCertificateMetadata(snapshot.tlsCertificates, r.TLS) &&
		snapshot.contentLength == r.ContentLength &&
		equalURLMetadata(snapshot.url, r.URL) &&
		equalHTTPHeader(snapshot.header, r.Header) &&
		equalOptionalStringSlice(snapshot.transferEncoding, r.TransferEncoding) &&
		((allowTrailerPopulation && equalTrailerAfterBody(snapshot.trailer, snapshot.trailerNames, r.Trailer)) ||
			(!allowTrailerPopulation && equalHTTPHeader(snapshot.trailer, r.Trailer)))
}

func equalTrailerAfterBody(snapshot http.Header, snapshotNames map[string]int, current http.Header) bool {
	if (snapshot == nil) != (current == nil) {
		return false
	}
	if !equalHeaderNames(snapshotNames, current) {
		return false
	}
	for name, before := range snapshot {
		after := headerValuesCaseInsensitive(current, name)
		// A declared trailer starts with a nil value and may become populated
		// after the body is consumed. Preserve the distinct nil-versus-present-
		// empty state until that legitimate non-empty wire population occurs;
		// otherwise a body reader could rewrite callback-visible trailer shape
		// without changing the declared field names.
		if len(before) == 0 && len(after) == 0 {
			if (before == nil) != (after == nil) {
				return false
			}
			continue
		}
		if len(before) == 0 && len(after) > 0 {
			continue
		}
		if !equalStringSlice(before, after) {
			return false
		}
	}
	return true
}

func snapshotHeaderNames(header http.Header) map[string]int {
	if len(header) == 0 {
		return nil
	}
	names := make(map[string]int, len(header))
	for name := range header {
		names[strings.ToLower(name)]++
	}
	return names
}

func equalHeaderNames(snapshot map[string]int, header http.Header) bool {
	current := snapshotHeaderNames(header)
	if len(snapshot) != len(current) {
		return false
	}
	for name, count := range snapshot {
		if current[name] != count {
			return false
		}
	}
	return true
}

func cloneTLSConnectionState(state *tls.ConnectionState) *tls.ConnectionState {
	if state == nil {
		return nil
	}
	clone := *state
	clone.PeerCertificates = cloneCertificatePointers(state.PeerCertificates)
	clone.VerifiedChains = cloneCertificateChains(state.VerifiedChains)
	clone.SignedCertificateTimestamps = cloneByteSlices(state.SignedCertificateTimestamps)
	clone.OCSPResponse = cloneOptionalBytes(state.OCSPResponse)
	clone.TLSUnique = cloneOptionalBytes(state.TLSUnique)
	return &clone
}

func cloneCertificatePointers(values []*x509.Certificate) []*x509.Certificate {
	if values == nil {
		return nil
	}
	clone := make([]*x509.Certificate, len(values))
	copy(clone, values)
	return clone
}

func cloneCertificateChains(values [][]*x509.Certificate) [][]*x509.Certificate {
	if values == nil {
		return nil
	}
	clone := make([][]*x509.Certificate, len(values))
	for index, chain := range values {
		clone[index] = cloneCertificatePointers(chain)
	}
	return clone
}

type tlsCertificateMetadata struct {
	pointer                   *x509.Certificate
	raw                       []byte
	rawTBSCertificate         []byte
	rawSubjectPublicKeyInfo   []byte
	rawSubject                []byte
	rawIssuer                 []byte
	signature                 []byte
	subjectKeyID              []byte
	authorityKeyID            []byte
	dnsNames                  []string
	ipAddresses               [][]byte
	additionalURIs            []*url.URL
	extensions                []tlsExtensionMetadata
	extraExtensions           []tlsExtensionMetadata
	unhandledCritical         [][]int
	issuer                    tlsCertificateNameMetadata
	subject                   tlsCertificateNameMetadata
	policyIdentifiers         [][]int
	policies                  []tlsCertificateOIDMetadata
	inhibitAnyPolicy          int
	inhibitAnyPolicyZero      bool
	inhibitPolicyMapping      int
	inhibitPolicyMappingZero  bool
	requireExplicitPolicy     int
	requireExplicitPolicyZero bool
	policyMappings            []tlsCertificatePolicyMappingMetadata
	signatureAlgorithm        x509.SignatureAlgorithm
	publicKeyAlgorithm        x509.PublicKeyAlgorithm
	version                   int
	serialNumber              *big.Int
	notBefore                 time.Time
	notAfter                  time.Time
	keyUsage                  x509.KeyUsage
	extKeyUsage               []x509.ExtKeyUsage
	unknownExtKeyUsage        [][]int
	basicConstraintsValid     bool
	isCA                      bool
	maxPathLen                int
	maxPathLenZero            bool
	ocspServers               []string
	issuingCertificateURLs    []string
	emailAddresses            []string
	permittedDNSCritical      bool
	permittedDNSDomains       []string
	excludedDNSDomains        []string
	permittedIPRanges         []tlsCertificateIPNetMetadata
	excludedIPRanges          []tlsCertificateIPNetMetadata
	permittedEmailAddresses   []string
	excludedEmailAddresses    []string
	permittedURIDomains       []string
	excludedURIDomains        []string
	crlDistributionPoints     []string
	publicKey                 tlsCertificatePublicKeyMetadata
}

type tlsCertificatePublicKeyKind uint8

const (
	tlsCertificatePublicKeyNone tlsCertificatePublicKeyKind = iota
	tlsCertificatePublicKeyRSA
	tlsCertificatePublicKeyECDSA
	tlsCertificatePublicKeyEd25519
	tlsCertificatePublicKeyECDH
	tlsCertificatePublicKeyDSA
)

// tlsCertificatePublicKeyMetadata stores a bounded, immutable representation
// of the standard public-key types x509 can expose. Certificate.PublicKey is an
// any field and may otherwise point at an arbitrary mutable object graph; the
// callback boundary deliberately rejects unsupported types instead of trying
// to clone them.
type tlsCertificatePublicKeyMetadata struct {
	kind tlsCertificatePublicKeyKind
	der  []byte
	dsaP *big.Int
	dsaQ *big.Int
	dsaG *big.Int
	dsaY *big.Int
}

type tlsCertificateNameMetadata struct {
	country            []string
	organization       []string
	organizationalUnit []string
	locality           []string
	province           []string
	streetAddress      []string
	postalCode         []string
	serialNumber       string
	commonName         string
	names              []tlsCertificateAttributeMetadata
	extraNames         []tlsCertificateAttributeMetadata
}

type tlsCertificateAttributeMetadata struct {
	id    []int
	value string
}

type tlsCertificateIPNetMetadata struct {
	present bool
	ip      []byte
	mask    []byte
}

type tlsExtensionMetadata struct {
	id       []int
	critical bool
	value    []byte
}

type tlsCertificateOIDMetadata struct {
	der   []byte
	valid bool
}

type tlsCertificatePolicyMappingMetadata struct {
	issuer  tlsCertificateOIDMetadata
	subject tlsCertificateOIDMetadata
}

type tlsCertificateMetadataSnapshot struct {
	peerCertificates []tlsCertificateMetadata
	verifiedChains   [][]tlsCertificateMetadata
}

func snapshotTLSCertificateMetadata(state *tls.ConnectionState) tlsCertificateMetadataSnapshot {
	if state == nil {
		return tlsCertificateMetadataSnapshot{}
	}
	snapshot := tlsCertificateMetadataSnapshot{}
	if state.PeerCertificates != nil {
		snapshot.peerCertificates = make([]tlsCertificateMetadata, len(state.PeerCertificates))
		for index, certificate := range state.PeerCertificates {
			snapshot.peerCertificates[index] = snapshotTLSCertificate(certificate)
		}
	}
	if state.VerifiedChains != nil {
		snapshot.verifiedChains = make([][]tlsCertificateMetadata, len(state.VerifiedChains))
		for chainIndex, chain := range state.VerifiedChains {
			if chain != nil {
				snapshot.verifiedChains[chainIndex] = make([]tlsCertificateMetadata, len(chain))
				for certificateIndex, certificate := range chain {
					snapshot.verifiedChains[chainIndex][certificateIndex] = snapshotTLSCertificate(certificate)
				}
			}
		}
	}
	return snapshot
}

func snapshotTLSCertificate(certificate *x509.Certificate) tlsCertificateMetadata {
	if certificate == nil {
		return tlsCertificateMetadata{}
	}
	publicKey, _ := snapshotTLSCertificatePublicKey(certificate.PublicKey)
	return tlsCertificateMetadata{
		pointer:                   certificate,
		raw:                       cloneOptionalBytes(certificate.Raw),
		rawTBSCertificate:         cloneOptionalBytes(certificate.RawTBSCertificate),
		rawSubjectPublicKeyInfo:   cloneOptionalBytes(certificate.RawSubjectPublicKeyInfo),
		rawSubject:                cloneOptionalBytes(certificate.RawSubject),
		rawIssuer:                 cloneOptionalBytes(certificate.RawIssuer),
		signature:                 cloneOptionalBytes(certificate.Signature),
		subjectKeyID:              cloneOptionalBytes(certificate.SubjectKeyId),
		authorityKeyID:            cloneOptionalBytes(certificate.AuthorityKeyId),
		dnsNames:                  cloneCertificateStrings(certificate.DNSNames),
		ipAddresses:               cloneCertificateIPAddresses(certificate.IPAddresses),
		additionalURIs:            cloneCertificateURLs(certificate.URIs),
		extensions:                cloneTLSCertificateExtensions(certificate.Extensions),
		extraExtensions:           cloneTLSCertificateExtensions(certificate.ExtraExtensions),
		unhandledCritical:         cloneCertificateOIDs(certificate.UnhandledCriticalExtensions),
		issuer:                    snapshotTLSCertificateName(certificate.Issuer),
		subject:                   snapshotTLSCertificateName(certificate.Subject),
		policyIdentifiers:         cloneCertificateOIDs(certificate.PolicyIdentifiers),
		policies:                  cloneCertificateOpaqueOIDs(certificate.Policies),
		inhibitAnyPolicy:          certificate.InhibitAnyPolicy,
		inhibitAnyPolicyZero:      certificate.InhibitAnyPolicyZero,
		inhibitPolicyMapping:      certificate.InhibitPolicyMapping,
		inhibitPolicyMappingZero:  certificate.InhibitPolicyMappingZero,
		requireExplicitPolicy:     certificate.RequireExplicitPolicy,
		requireExplicitPolicyZero: certificate.RequireExplicitPolicyZero,
		policyMappings:            cloneCertificatePolicyMappings(certificate.PolicyMappings),
		signatureAlgorithm:        certificate.SignatureAlgorithm,
		publicKeyAlgorithm:        certificate.PublicKeyAlgorithm,
		version:                   certificate.Version,
		serialNumber:              cloneCertificateBigInt(certificate.SerialNumber),
		notBefore:                 certificate.NotBefore,
		notAfter:                  certificate.NotAfter,
		keyUsage:                  certificate.KeyUsage,
		extKeyUsage:               cloneCertificateExtKeyUsages(certificate.ExtKeyUsage),
		unknownExtKeyUsage:        cloneCertificateOIDs(certificate.UnknownExtKeyUsage),
		basicConstraintsValid:     certificate.BasicConstraintsValid,
		isCA:                      certificate.IsCA,
		maxPathLen:                certificate.MaxPathLen,
		maxPathLenZero:            certificate.MaxPathLenZero,
		ocspServers:               cloneCertificateStrings(certificate.OCSPServer),
		issuingCertificateURLs:    cloneCertificateStrings(certificate.IssuingCertificateURL),
		emailAddresses:            cloneCertificateStrings(certificate.EmailAddresses),
		permittedDNSCritical:      certificate.PermittedDNSDomainsCritical,
		permittedDNSDomains:       cloneCertificateStrings(certificate.PermittedDNSDomains),
		excludedDNSDomains:        cloneCertificateStrings(certificate.ExcludedDNSDomains),
		permittedIPRanges:         cloneCertificateIPNets(certificate.PermittedIPRanges),
		excludedIPRanges:          cloneCertificateIPNets(certificate.ExcludedIPRanges),
		permittedEmailAddresses:   cloneCertificateStrings(certificate.PermittedEmailAddresses),
		excludedEmailAddresses:    cloneCertificateStrings(certificate.ExcludedEmailAddresses),
		permittedURIDomains:       cloneCertificateStrings(certificate.PermittedURIDomains),
		excludedURIDomains:        cloneCertificateStrings(certificate.ExcludedURIDomains),
		crlDistributionPoints:     cloneCertificateStrings(certificate.CRLDistributionPoints),
		publicKey:                 publicKey,
	}
}

func snapshotTLSCertificatePublicKey(key any) (tlsCertificatePublicKeyMetadata, bool) {
	switch key := key.(type) {
	case nil:
		return tlsCertificatePublicKeyMetadata{}, true
	case *rsa.PublicKey:
		if key == nil || !validCertificatePublicKeyBigInt(key.N) || key.E <= 0 {
			return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyInvalid}, false
		}
		der, ok := marshalCertificatePublicKey(key)
		if !ok || !validCertificatePublicKeyDER(der) {
			return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyInvalid}, false
		}
		return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyRSA, der: append([]byte(nil), der...)}, true
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || !validCertificatePublicKeyBigInt(key.X) || !validCertificatePublicKeyBigInt(key.Y) {
			return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyInvalid}, false
		}
		der, ok := marshalCertificatePublicKey(key)
		if !ok || !validCertificatePublicKeyDER(der) {
			return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyInvalid}, false
		}
		return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyECDSA, der: append([]byte(nil), der...)}, true
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyInvalid}, false
		}
		der, ok := marshalCertificatePublicKey(key)
		if !ok || !validCertificatePublicKeyDER(der) {
			return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyInvalid}, false
		}
		return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyEd25519, der: append([]byte(nil), der...)}, true
	case *ecdh.PublicKey:
		if key == nil {
			return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyInvalid}, false
		}
		der, ok := marshalCertificatePublicKey(key)
		if !ok || !validCertificatePublicKeyDER(der) {
			return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyInvalid}, false
		}
		return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyECDH, der: append([]byte(nil), der...)}, true
	case *dsa.PublicKey:
		if key == nil || !validCertificatePublicKeyBigInt(key.P) || !validCertificatePublicKeyBigInt(key.Q) ||
			!validCertificatePublicKeyBigInt(key.G) || !validCertificatePublicKeyBigInt(key.Y) {
			return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyInvalid}, false
		}
		return tlsCertificatePublicKeyMetadata{
			kind: tlsCertificatePublicKeyDSA,
			dsaP: cloneCertificateBigInt(key.P),
			dsaQ: cloneCertificateBigInt(key.Q),
			dsaG: cloneCertificateBigInt(key.G),
			dsaY: cloneCertificateBigInt(key.Y),
		}, true
	default:
		return tlsCertificatePublicKeyMetadata{kind: tlsCertificatePublicKeyInvalid}, false
	}
}

const tlsCertificatePublicKeyInvalid tlsCertificatePublicKeyKind = 255

func marshalCertificatePublicKey(key any) (der []byte, ok bool) {
	defer func() {
		if recover() != nil {
			der = nil
			ok = false
		}
	}()
	der, err := x509.MarshalPKIXPublicKey(key)
	return der, err == nil
}

func validCertificatePublicKeyBigInt(value *big.Int) bool {
	return value != nil && value.Sign() > 0 && value.BitLen() <= maxMCPTLSCertificateBytes*8
}

func validCertificatePublicKeyDER(value []byte) bool {
	return len(value) > 0 && len(value) <= maxMCPTLSCertificateBytes
}

func certificatePublicKeyMetadataSize(value tlsCertificatePublicKeyMetadata) int {
	if value.kind != tlsCertificatePublicKeyDSA {
		return len(value.der)
	}
	return certificatePublicKeyBigIntBytes(value.dsaP) + certificatePublicKeyBigIntBytes(value.dsaQ) +
		certificatePublicKeyBigIntBytes(value.dsaG) + certificatePublicKeyBigIntBytes(value.dsaY)
}

func certificatePublicKeyBigIntBytes(value *big.Int) int {
	if value == nil {
		return 0
	}
	return (value.BitLen() + 7) / 8
}

func equalTLSCertificatePublicKey(snapshot tlsCertificatePublicKeyMetadata, key any) bool {
	current, ok := snapshotTLSCertificatePublicKey(key)
	if !ok || snapshot.kind != current.kind {
		return false
	}
	if snapshot.kind != tlsCertificatePublicKeyDSA {
		return bytes.Equal(snapshot.der, current.der)
	}
	return equalCertificateBigInt(snapshot.dsaP, current.dsaP) &&
		equalCertificateBigInt(snapshot.dsaQ, current.dsaQ) &&
		equalCertificateBigInt(snapshot.dsaG, current.dsaG) &&
		equalCertificateBigInt(snapshot.dsaY, current.dsaY)
}

func equalTLSCertificateMetadata(snapshot tlsCertificateMetadataSnapshot, state *tls.ConnectionState) bool {
	if state == nil {
		return len(snapshot.peerCertificates) == 0 && len(snapshot.verifiedChains) == 0
	}
	if (snapshot.peerCertificates == nil) != (state.PeerCertificates == nil) ||
		(snapshot.verifiedChains == nil) != (state.VerifiedChains == nil) ||
		!equalTLSCertificateSlice(snapshot.peerCertificates, state.PeerCertificates) ||
		len(snapshot.verifiedChains) != len(state.VerifiedChains) {
		return false
	}
	for chainIndex, chain := range state.VerifiedChains {
		if (snapshot.verifiedChains[chainIndex] == nil) != (chain == nil) {
			return false
		}
		if !equalTLSCertificateSlice(snapshot.verifiedChains[chainIndex], chain) {
			return false
		}
	}
	return true
}

func equalTLSCertificateSlice(snapshot []tlsCertificateMetadata, certificates []*x509.Certificate) bool {
	if (snapshot == nil) != (certificates == nil) || len(snapshot) != len(certificates) {
		return false
	}
	for index, certificate := range certificates {
		if !equalTLSCertificateMetadataEntry(snapshot[index], certificate, true) {
			return false
		}
	}
	return true
}

func equalTLSCertificateMetadataEntry(snapshot tlsCertificateMetadata, certificate *x509.Certificate, requirePointer bool) bool {
	if certificate == nil || (requirePointer && snapshot.pointer != certificate) ||
		!equalOptionalBytes(snapshot.raw, certificate.Raw) ||
		!equalOptionalBytes(snapshot.rawTBSCertificate, certificate.RawTBSCertificate) ||
		!equalOptionalBytes(snapshot.rawSubjectPublicKeyInfo, certificate.RawSubjectPublicKeyInfo) ||
		!equalOptionalBytes(snapshot.rawSubject, certificate.RawSubject) ||
		!equalOptionalBytes(snapshot.rawIssuer, certificate.RawIssuer) ||
		!equalOptionalBytes(snapshot.signature, certificate.Signature) ||
		!equalOptionalBytes(snapshot.subjectKeyID, certificate.SubjectKeyId) ||
		!equalOptionalBytes(snapshot.authorityKeyID, certificate.AuthorityKeyId) {
		return false
	}
	return equalCertificateStrings(snapshot.dnsNames, certificate.DNSNames) &&
		equalSnapshotCertificateIPAddresses(snapshot.ipAddresses, certificate.IPAddresses) &&
		equalSnapshotCertificateURLs(snapshot.additionalURIs, certificate.URIs) &&
		equalTLSCertificateExtensions(snapshot.extensions, certificate.Extensions) &&
		equalTLSCertificateExtensions(snapshot.extraExtensions, certificate.ExtraExtensions) &&
		equalSnapshotCertificateOIDs(snapshot.unhandledCritical, certificate.UnhandledCriticalExtensions) &&
		equalTLSCertificateName(snapshot.issuer, certificate.Issuer) &&
		equalTLSCertificateName(snapshot.subject, certificate.Subject) &&
		equalSnapshotCertificateOIDs(snapshot.policyIdentifiers, certificate.PolicyIdentifiers) &&
		equalTLSCertificatePublicKey(snapshot.publicKey, certificate.PublicKey) &&
		equalTLSCertificateSemantics(snapshot, certificate)
}

func cloneCertificateBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func cloneCertificateIPNets(values []*net.IPNet) []tlsCertificateIPNetMetadata {
	if values == nil {
		return nil
	}
	clone := make([]tlsCertificateIPNetMetadata, len(values))
	for index, value := range values {
		if value != nil {
			clone[index] = tlsCertificateIPNetMetadata{
				present: true,
				ip:      cloneOptionalBytes(value.IP),
				mask:    cloneOptionalBytes(value.Mask),
			}
		}
	}
	return clone
}

func equalTLSCertificateSemantics(snapshot tlsCertificateMetadata, certificate *x509.Certificate) bool {
	return snapshot.signatureAlgorithm == certificate.SignatureAlgorithm &&
		snapshot.publicKeyAlgorithm == certificate.PublicKeyAlgorithm &&
		snapshot.version == certificate.Version &&
		equalCertificateBigInt(snapshot.serialNumber, certificate.SerialNumber) &&
		snapshot.notBefore.Equal(certificate.NotBefore) &&
		snapshot.notAfter.Equal(certificate.NotAfter) &&
		snapshot.keyUsage == certificate.KeyUsage &&
		equalSnapshotCertificateExtKeyUsage(snapshot.extKeyUsage, certificate.ExtKeyUsage) &&
		equalSnapshotCertificateOIDs(snapshot.unknownExtKeyUsage, certificate.UnknownExtKeyUsage) &&
		equalSnapshotCertificateOpaqueOIDs(snapshot.policies, certificate.Policies) &&
		snapshot.basicConstraintsValid == certificate.BasicConstraintsValid &&
		snapshot.isCA == certificate.IsCA &&
		snapshot.maxPathLen == certificate.MaxPathLen &&
		snapshot.maxPathLenZero == certificate.MaxPathLenZero &&
		snapshot.inhibitAnyPolicy == certificate.InhibitAnyPolicy &&
		snapshot.inhibitAnyPolicyZero == certificate.InhibitAnyPolicyZero &&
		snapshot.inhibitPolicyMapping == certificate.InhibitPolicyMapping &&
		snapshot.inhibitPolicyMappingZero == certificate.InhibitPolicyMappingZero &&
		snapshot.requireExplicitPolicy == certificate.RequireExplicitPolicy &&
		snapshot.requireExplicitPolicyZero == certificate.RequireExplicitPolicyZero &&
		equalCertificateStrings(snapshot.ocspServers, certificate.OCSPServer) &&
		equalCertificateStrings(snapshot.issuingCertificateURLs, certificate.IssuingCertificateURL) &&
		equalCertificateStrings(snapshot.emailAddresses, certificate.EmailAddresses) &&
		snapshot.permittedDNSCritical == certificate.PermittedDNSDomainsCritical &&
		equalCertificateStrings(snapshot.permittedDNSDomains, certificate.PermittedDNSDomains) &&
		equalCertificateStrings(snapshot.excludedDNSDomains, certificate.ExcludedDNSDomains) &&
		equalSnapshotCertificateIPNets(snapshot.permittedIPRanges, certificate.PermittedIPRanges) &&
		equalSnapshotCertificateIPNets(snapshot.excludedIPRanges, certificate.ExcludedIPRanges) &&
		equalCertificateStrings(snapshot.permittedEmailAddresses, certificate.PermittedEmailAddresses) &&
		equalCertificateStrings(snapshot.excludedEmailAddresses, certificate.ExcludedEmailAddresses) &&
		equalCertificateStrings(snapshot.permittedURIDomains, certificate.PermittedURIDomains) &&
		equalCertificateStrings(snapshot.excludedURIDomains, certificate.ExcludedURIDomains) &&
		equalCertificateStrings(snapshot.crlDistributionPoints, certificate.CRLDistributionPoints) &&
		equalSnapshotCertificatePolicyMappings(snapshot.policyMappings, certificate.PolicyMappings)
}

func equalCertificateStrings(left, right []string) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalCertificateBigInt(left, right *big.Int) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Cmp(right) == 0
}

func equalExtKeyUsage(left []x509.ExtKeyUsage, right []x509.ExtKeyUsage) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneCertificateExtKeyUsages(values []x509.ExtKeyUsage) []x509.ExtKeyUsage {
	if values == nil {
		return nil
	}
	clone := make([]x509.ExtKeyUsage, len(values))
	copy(clone, values)
	return clone
}

func equalSnapshotCertificateExtKeyUsage(left, right []x509.ExtKeyUsage) bool {
	if (left == nil) != (right == nil) {
		return false
	}
	return equalExtKeyUsage(left, right)
}

func equalCertificateIPNets(left []tlsCertificateIPNetMetadata, right []*net.IPNet) bool {
	if len(left) != len(right) {
		return false
	}
	for index, value := range right {
		if value == nil {
			if left[index].ip != nil || left[index].mask != nil {
				return false
			}
			continue
		}
		if !bytes.Equal(left[index].ip, value.IP) || !bytes.Equal(left[index].mask, value.Mask) {
			return false
		}
	}
	return true
}

func equalSnapshotCertificateIPNets(left []tlsCertificateIPNetMetadata, right []*net.IPNet) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index, value := range right {
		if value == nil {
			if left[index].present || left[index].ip != nil || left[index].mask != nil {
				return false
			}
			continue
		}
		if !left[index].present || !equalOptionalBytes(left[index].ip, value.IP) || !equalOptionalBytes(left[index].mask, value.Mask) {
			return false
		}
	}
	return true
}

func cloneCertificateIPAddresses(addresses []net.IP) [][]byte {
	if addresses == nil {
		return nil
	}
	clone := make([][]byte, len(addresses))
	for index, address := range addresses {
		// Preserve nil-versus-present-empty state for each callback-visible IP
		// element. The body-boundary comparator intentionally distinguishes the
		// two, and append-to-nil would erase that distinction for an unchanged
		// direct or reverse-proxy request.
		clone[index] = cloneOptionalBytes(address)
	}
	return clone
}

func snapshotTLSCertificateName(name pkix.Name) tlsCertificateNameMetadata {
	return tlsCertificateNameMetadata{
		country:            cloneCertificateStrings(name.Country),
		organization:       cloneCertificateStrings(name.Organization),
		organizationalUnit: cloneCertificateStrings(name.OrganizationalUnit),
		locality:           cloneCertificateStrings(name.Locality),
		province:           cloneCertificateStrings(name.Province),
		streetAddress:      cloneCertificateStrings(name.StreetAddress),
		postalCode:         cloneCertificateStrings(name.PostalCode),
		serialNumber:       name.SerialNumber,
		commonName:         name.CommonName,
		names:              cloneTLSCertificateAttributes(name.Names),
		extraNames:         cloneTLSCertificateAttributes(name.ExtraNames),
	}
}

func cloneTLSCertificateAttributes(values []pkix.AttributeTypeAndValue) []tlsCertificateAttributeMetadata {
	if values == nil {
		return nil
	}
	clone := make([]tlsCertificateAttributeMetadata, len(values))
	for index, value := range values {
		stringValue, _ := value.Value.(string)
		clone[index] = tlsCertificateAttributeMetadata{
			id:    cloneCertificateIntSlice(value.Type),
			value: stringValue,
		}
	}
	return clone
}

func cloneCertificateIntSlice(value []int) []int {
	if value == nil {
		return nil
	}
	clone := make([]int, len(value))
	copy(clone, value)
	return clone
}

func cloneCertificateOIDs(values []asn1.ObjectIdentifier) [][]int {
	if values == nil {
		return nil
	}
	clone := make([][]int, len(values))
	for index, value := range values {
		clone[index] = cloneCertificateIntSlice(value)
	}
	return clone
}

func cloneCertificateOpaqueOID(value x509.OID) tlsCertificateOIDMetadata {
	der, err := value.MarshalBinary()
	return tlsCertificateOIDMetadata{der: append([]byte(nil), der...), valid: err == nil && len(der) > 0}
}

func cloneCertificateOpaqueOIDs(values []x509.OID) []tlsCertificateOIDMetadata {
	if values == nil {
		return nil
	}
	clone := make([]tlsCertificateOIDMetadata, len(values))
	for index, value := range values {
		clone[index] = cloneCertificateOpaqueOID(value)
	}
	return clone
}

func cloneCertificatePolicyMappings(values []x509.PolicyMapping) []tlsCertificatePolicyMappingMetadata {
	if values == nil {
		return nil
	}
	clone := make([]tlsCertificatePolicyMappingMetadata, len(values))
	for index, value := range values {
		clone[index] = tlsCertificatePolicyMappingMetadata{
			issuer:  cloneCertificateOpaqueOID(value.IssuerDomainPolicy),
			subject: cloneCertificateOpaqueOID(value.SubjectDomainPolicy),
		}
	}
	return clone
}

func equalTLSCertificateName(left tlsCertificateNameMetadata, right pkix.Name) bool {
	return equalCertificateStrings(left.country, right.Country) &&
		equalCertificateStrings(left.organization, right.Organization) &&
		equalCertificateStrings(left.organizationalUnit, right.OrganizationalUnit) &&
		equalCertificateStrings(left.locality, right.Locality) &&
		equalCertificateStrings(left.province, right.Province) &&
		equalCertificateStrings(left.streetAddress, right.StreetAddress) &&
		equalCertificateStrings(left.postalCode, right.PostalCode) &&
		left.serialNumber == right.SerialNumber &&
		left.commonName == right.CommonName &&
		equalTLSCertificateAttributes(left.names, right.Names) &&
		equalTLSCertificateAttributes(left.extraNames, right.ExtraNames)
}

func equalTLSCertificateAttributes(left []tlsCertificateAttributeMetadata, right []pkix.AttributeTypeAndValue) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index, value := range right {
		stringValue, ok := value.Value.(string)
		if !ok || !equalCertificateIntSlice(left[index].id, value.Type) || left[index].value != stringValue {
			return false
		}
	}
	return true
}

func equalCertificateIntSlice(left, right []int) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalCertificateOIDs(left [][]int, right []asn1.ObjectIdentifier) bool {
	if len(left) != len(right) {
		return false
	}
	for index, value := range right {
		if !equalIntSlice(left[index], value) {
			return false
		}
	}
	return true
}

func equalSnapshotCertificateOIDs(left [][]int, right []asn1.ObjectIdentifier) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index, value := range right {
		if !equalCertificateIntSlice(left[index], value) {
			return false
		}
	}
	return true
}

func equalCertificateOpaqueOID(left tlsCertificateOIDMetadata, right x509.OID) bool {
	rightSnapshot := cloneCertificateOpaqueOID(right)
	return left.valid == rightSnapshot.valid && bytes.Equal(left.der, rightSnapshot.der)
}

func equalCertificateOpaqueOIDs(left []tlsCertificateOIDMetadata, right []x509.OID) bool {
	if len(left) != len(right) {
		return false
	}
	for index, value := range right {
		if !equalCertificateOpaqueOID(left[index], value) {
			return false
		}
	}
	return true
}

func equalSnapshotCertificateOpaqueOIDs(left []tlsCertificateOIDMetadata, right []x509.OID) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	return equalCertificateOpaqueOIDs(left, right)
}

func equalCertificateOpaqueOIDValues(left, right []x509.OID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range right {
		if !left[index].Equal(right[index]) {
			return false
		}
	}
	return true
}

func equalCertificatePolicyMappings(left []tlsCertificatePolicyMappingMetadata, right []x509.PolicyMapping) bool {
	if len(left) != len(right) {
		return false
	}
	for index, value := range right {
		if !equalCertificateOpaqueOID(left[index].issuer, value.IssuerDomainPolicy) ||
			!equalCertificateOpaqueOID(left[index].subject, value.SubjectDomainPolicy) {
			return false
		}
	}
	return true
}

func equalSnapshotCertificatePolicyMappings(left []tlsCertificatePolicyMappingMetadata, right []x509.PolicyMapping) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	return equalCertificatePolicyMappings(left, right)
}

func equalCertificateIPAddresses(left [][]byte, right []net.IP) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func equalSnapshotCertificateIPAddresses(left [][]byte, right []net.IP) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index := range left {
		if !equalOptionalBytes(left[index], right[index]) {
			return false
		}
	}
	return true
}

func cloneCertificateStrings(values []string) []string {
	if values == nil {
		return nil
	}
	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}

func cloneCertificateURLs(values []*url.URL) []*url.URL {
	if values == nil {
		return nil
	}
	clone := make([]*url.URL, len(values))
	for index, value := range values {
		if value != nil {
			copy := *value
			copy.User = cloneCertificateURLUserinfo(value.User)
			clone[index] = &copy
		}
	}
	return clone
}

func cloneCertificateURLUserinfo(value *url.Userinfo) *url.Userinfo {
	if value == nil {
		return nil
	}
	password, passwordSet := value.Password()
	if passwordSet {
		return url.UserPassword(value.Username(), password)
	}
	return url.User(value.Username())
}

func equalCertificateURLs(left, right []*url.URL) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] == nil || right[index] == nil {
			if left[index] != right[index] {
				return false
			}
			continue
		}
		if !equalCertificateURLMetadata(left[index], right[index]) {
			return false
		}
	}
	return true
}

func equalSnapshotCertificateURLs(left, right []*url.URL) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] == nil || right[index] == nil {
			if left[index] != right[index] {
				return false
			}
			continue
		}
		if !equalCertificateURLMetadata(left[index], right[index]) {
			return false
		}
	}
	return true
}

func equalCertificateURLMetadata(left, right *url.URL) bool {
	if left == nil || right == nil {
		return left == right
	}
	if left.Scheme != right.Scheme || left.Opaque != right.Opaque || left.Host != right.Host ||
		left.Path != right.Path || left.RawPath != right.RawPath || left.ForceQuery != right.ForceQuery ||
		left.RawQuery != right.RawQuery || left.Fragment != right.Fragment || left.RawFragment != right.RawFragment ||
		left.OmitHost != right.OmitHost {
		return false
	}
	if left.User == nil || right.User == nil {
		return left.User == right.User
	}
	leftPassword, leftPasswordSet := left.User.Password()
	rightPassword, rightPasswordSet := right.User.Password()
	return left.User.Username() == right.User.Username() &&
		leftPasswordSet == rightPasswordSet &&
		(!leftPasswordSet || leftPassword == rightPassword)
}

func cloneTLSCertificateExtensions(values []pkix.Extension) []tlsExtensionMetadata {
	if values == nil {
		return nil
	}
	clone := make([]tlsExtensionMetadata, len(values))
	for index, value := range values {
		clone[index] = tlsExtensionMetadata{
			id:       cloneCertificateIntSlice(value.Id),
			critical: value.Critical,
			value:    cloneOptionalBytes(value.Value),
		}
	}
	return clone
}

func equalTLSCertificateExtensions(left []tlsExtensionMetadata, right []pkix.Extension) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index := range left {
		if !equalCertificateIntSlice(left[index].id, right[index].Id) ||
			left[index].critical != right[index].Critical ||
			!equalOptionalBytes(left[index].value, right[index].Value) {
			return false
		}
	}
	return true
}

func equalIntSlice(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	clone := make([][]byte, len(values))
	for index, value := range values {
		clone[index] = cloneOptionalBytes(value)
	}
	return clone
}

func cloneOptionalBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	clone := make([]byte, len(value))
	copy(clone, value)
	return clone
}

func equalTLSConnectionState(left, right *tls.ConnectionState) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Version == right.Version &&
		left.HandshakeComplete == right.HandshakeComplete &&
		left.DidResume == right.DidResume &&
		left.CipherSuite == right.CipherSuite &&
		left.NegotiatedProtocol == right.NegotiatedProtocol &&
		left.NegotiatedProtocolIsMutual == right.NegotiatedProtocolIsMutual &&
		left.ServerName == right.ServerName &&
		left.ECHAccepted == right.ECHAccepted &&
		equalCertificatePointers(left.PeerCertificates, right.PeerCertificates) &&
		equalCertificateChains(left.VerifiedChains, right.VerifiedChains) &&
		equalByteSlices(left.SignedCertificateTimestamps, right.SignedCertificateTimestamps) &&
		equalOptionalBytes(left.OCSPResponse, right.OCSPResponse) &&
		equalOptionalBytes(left.TLSUnique, right.TLSUnique)
}

func equalCertificatePointers(left, right []*x509.Certificate) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalCertificateChains(left, right [][]*x509.Certificate) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index := range left {
		if !equalCertificatePointers(left[index], right[index]) {
			return false
		}
	}
	return true
}

func equalByteSlices(left, right [][]byte) bool {
	if (left == nil) != (right == nil) || len(left) != len(right) {
		return false
	}
	for index := range left {
		if !equalOptionalBytes(left[index], right[index]) {
			return false
		}
	}
	return true
}

func equalOptionalBytes(left, right []byte) bool {
	if (left == nil) != (right == nil) {
		return false
	}
	return bytes.Equal(left, right)
}

func equalURLMetadata(left, right *url.URL) bool {
	if left == nil || right == nil {
		return left == right
	}
	if left.Scheme != right.Scheme || left.Opaque != right.Opaque || left.User != nil || right.User != nil ||
		left.Host != right.Host || left.Path != right.Path || left.RawPath != right.RawPath ||
		left.ForceQuery != right.ForceQuery || left.RawQuery != right.RawQuery ||
		left.Fragment != right.Fragment || left.RawFragment != right.RawFragment {
		return false
	}
	return left.OmitHost == right.OmitHost
}

func equalHTTPHeader(left, right http.Header) bool {
	if (left == nil) != (right == nil) {
		return false
	}
	if len(left) != len(right) {
		return false
	}
	for key, leftValues := range left {
		rightValues, ok := right[key]
		if !ok || !equalHTTPHeaderValues(leftValues, rightValues) {
			return false
		}
	}
	return true
}

func equalHTTPHeaderValues(left, right []string) bool {
	if (left == nil) != (right == nil) {
		return false
	}
	return equalStringSlice(left, right)
}

func equalStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalOptionalStringSlice(left, right []string) bool {
	if (left == nil) != (right == nil) {
		return false
	}
	return equalStringSlice(left, right)
}

// equalRequestContext compares the request context by identity. Context
// values are callback-visible through the principal resolver, but context
// interfaces do not provide a semantic equality operation. The direct HTTP
// boundary therefore accepts only comparable context implementations and
// rejects an altered identity rather than guessing from values or deadlines.
func equalRequestContext(left, right context.Context) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftType, rightType := reflect.TypeOf(left), reflect.TypeOf(right)
	if leftType != rightType || !leftType.Comparable() {
		return false
	}
	return left == right
}

// snapshotRequestPathValues copies the route-declared wildcard values exposed
// by http.Request.PathValue. The standard server fills these values from the
// matched ServeMux pattern; a direct caller or body reader can otherwise
// replace them after transport verification without changing Pattern.
func snapshotRequestPathValues(r *http.Request) map[string]string {
	names, ok := requestPathValueNames(r.Pattern)
	if !ok || len(names) == 0 {
		return nil
	}
	values := make(map[string]string, len(names))
	for _, name := range names {
		values[name] = r.PathValue(name)
	}
	return values
}

// validDirectRequestPathValues rejects values installed through
// Request.SetPathValue that are not declared by Request.Pattern. The public
// API deliberately has no enumeration method for these direct-only values;
// Go 1.24 stores them in Request's private otherValues map, so inspect that
// bounded representation and fail closed if the runtime shape is different.
// This keeps an undeclared value from being visible to a transport verifier or
// resolver without being covered by the matched route snapshot.
func validDirectRequestPathValues(r *http.Request) (valid bool) {
	if r == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	names, ok := requestPathValueNames(r.Pattern)
	if !ok {
		return false
	}
	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		allowed[name] = struct{}{}
	}
	values := reflect.ValueOf(r).Elem().FieldByName("otherValues")
	if !values.IsValid() || values.Kind() != reflect.Map || values.Type().Key().Kind() != reflect.String || values.Type().Elem().Kind() != reflect.String {
		return false
	}
	if values.IsNil() {
		return true
	}
	if values.Len() > len(allowed) {
		return false
	}
	iterator := values.MapRange()
	for iterator.Next() {
		name := iterator.Key().String()
		value := iterator.Value().String()
		if _, ok := allowed[name]; !ok || len(value) > maxMCPRequestTargetBytes || containsUnicodeControlOrFormat(value) {
			return false
		}
	}
	return true
}

func equalRequestPathValues(snapshot map[string]string, r *http.Request) bool {
	if r == nil {
		return false
	}
	names, ok := requestPathValueNames(r.Pattern)
	if !ok || len(snapshot) != len(names) {
		return false
	}
	for _, name := range names {
		value, exists := snapshot[name]
		if !exists || value != r.PathValue(name) {
			return false
		}
	}
	return true
}

// requestPathValueNames extracts the Go 1.22+ ServeMux wildcard names from a
// bounded pattern. It intentionally covers only path wildcards: {$} is the
// end-of-path marker, while a host wildcard is not returned by PathValue.
func requestPathValueNames(pattern string) ([]string, bool) {
	if pattern == "" {
		return nil, true
	}
	pathPattern, ok := serveMuxPatternPath(pattern)
	if !ok {
		return nil, false
	}
	var names []string
	for segmentStart := 0; segmentStart < len(pathPattern); {
		if pathPattern[segmentStart] != '/' {
			return nil, false
		}
		segmentEnd := strings.IndexByte(pathPattern[segmentStart+1:], '/')
		if segmentEnd < 0 {
			segmentEnd = len(pathPattern)
		} else {
			segmentEnd += segmentStart + 1
		}
		segment := pathPattern[segmentStart+1 : segmentEnd]
		// ServeMux treats a segment without an opening brace as a literal,
		// including a literal closing brace. Only an opening brace starts the
		// wildcard grammar; rejecting a lone '}' here would reject patterns
		// that the standard parser accepts.
		if strings.ContainsRune(segment, '{') {
			// ServeMux wildcards are complete path segments. Rejecting an
			// embedded brace or a partial wildcard here keeps the callback
			// boundary aligned with the pattern syntax that produces PathValue.
			if len(segment) < 3 || segment[0] != '{' || segment[len(segment)-1] != '}' {
				return nil, false
			}
			name := segment[1 : len(segment)-1]
			multi := strings.HasSuffix(name, "...")
			if multi {
				name = strings.TrimSuffix(name, "...")
				// A remainder wildcard must be the final path segment; a
				// trailing slash or later segment would not be a ServeMux
				// pattern that can populate the same PathValue.
				if segmentEnd != len(pathPattern) {
					return nil, false
				}
			}
			if name == "$" {
				if multi || segmentEnd != len(pathPattern) {
					return nil, false
				}
			} else {
				if !validRequestPathValueName(name) {
					return nil, false
				}
				for _, existing := range names {
					if existing == name {
						return nil, false
					}
				}
				names = append(names, name)
				if len(names) > maxMCPPatternWildcards {
					return nil, false
				}
			}
		}
		if segmentEnd == len(pathPattern) {
			break
		}
		segmentStart = segmentEnd
	}
	return names, true
}

// serveMuxPatternPath validates the method/host/path envelope used by the
// standard library's ServeMux patterns and returns the path portion. The
// lifecycle boundary only needs wildcard values from the path, but accepting
// a value without a path would let a direct caller present an impossible route
// label to a deployment-owned security callback. Empty patterns remain valid
// for direct callers because net/http leaves Request.Pattern empty when no
// ServeMux route metadata is attached.
func serveMuxPatternPath(pattern string) (string, bool) {
	_, pathPart, ok := serveMuxPatternParts(pattern)
	return pathPart, ok
}

func serveMuxPatternParts(pattern string) (host, pathPart string, ok bool) {
	if pattern == "" {
		return "", "", true
	}
	method, rest := pattern, ""
	if separator := strings.IndexAny(pattern, " \t"); separator >= 0 {
		method = pattern[:separator]
		rest = strings.TrimLeft(pattern[separator+1:], " \t")
		if method != "" && !validHTTPHeaderFieldName(method) {
			return "", "", false
		}
	} else {
		rest = pattern
	}
	pathStart := strings.IndexByte(rest, '/')
	if pathStart < 0 || strings.Contains(rest[:pathStart], "{") {
		return "", "", false
	}
	host = rest[:pathStart]
	pathPart = rest[pathStart:]
	// Match net/http's ServeMux parser: a method-qualified pattern must use
	// the canonical path form unless the method is CONNECT. Otherwise a direct
	// caller could present an impossible route label to the transport verifier.
	if method != "" && method != http.MethodConnect && pathPart != cleanServeMuxPatternPath(pathPart) {
		return "", "", false
	}
	return host, pathPart, true
}

// directRequestPatternHost mirrors the primary ServeMux host view for the
// methods that reach this server-side boundary. Ordinary requests ignore a
// valid host port when matching a host-qualified pattern; CONNECT first uses
// its URL.Host without port stripping and may fall back to Request.Host.
func directRequestPatternHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := r.Host
	if r.Method == http.MethodConnect && r.URL != nil && r.URL.Host != "" {
		host = r.URL.Host
	}
	if r.Method != http.MethodConnect {
		if stripped, _, err := net.SplitHostPort(host); err == nil {
			return stripped
		}
	}
	return host
}

// directRequestPatternHostMatches mirrors ServeMux's CONNECT lookup. The
// standard mux first tries URL.Host and, when that host has no matching route,
// retries with Request.Host. A direct caller must be allowed to present the
// same route metadata that the mux would have produced, without broadening
// ordinary request matching beyond its single normalized host view.
func directRequestPatternHostMatches(r *http.Request, patternHost string) bool {
	if r == nil {
		return false
	}
	if r.Method == http.MethodConnect && r.URL != nil && r.URL.Host != "" {
		return patternHost == r.URL.Host || patternHost == r.Host
	}
	return patternHost == directRequestPatternHost(r)
}

func cleanServeMuxPatternPath(patternPath string) string {
	cleaned := path.Clean(patternPath)
	if strings.HasSuffix(patternPath, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

func validRequestPathValueName(name string) bool {
	if name == "" {
		return false
	}
	for index, char := range name {
		if index == 0 {
			if char != '_' && !unicode.IsLetter(char) {
				return false
			}
			continue
		}
		if char != '_' && !unicode.IsLetter(char) && !unicode.IsDigit(char) {
			return false
		}
	}
	return true
}

// equalRequestBody compares body identity without allowing an uncomparable
// direct-call implementation to panic the HTTP boundary. Normal net/http
// bodies are pointer-backed; direct integrations must preserve that identity
// while the bounded body is collected.
func equalRequestBody(left, right io.ReadCloser) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftType, rightType := reflect.TypeOf(left), reflect.TypeOf(right)
	if leftType != rightType || !leftType.Comparable() {
		return false
	}
	return left == right
}

// sameRequestBodyForCleanup extends identity checks to uncomparable
// reference-backed body implementations. Function and slice values are
// deliberately not included: reflect.Value.Pointer reports a function's code
// pointer rather than its closure identity, and a slice pointer identifies
// shared backing storage rather than the complete slice value. Either shortcut
// could treat distinct caller-owned bodies as one resource and leak cleanup.
func sameRequestBodyForCleanup(left, right io.ReadCloser) bool {
	if equalRequestBody(left, right) {
		return true
	}
	if left == nil || right == nil {
		return false
	}
	leftType, rightType := reflect.TypeOf(left), reflect.TypeOf(right)
	if leftType != rightType {
		return false
	}
	leftValue, rightValue := reflect.ValueOf(left), reflect.ValueOf(right)
	switch leftValue.Kind() {
	case reflect.Chan, reflect.Pointer, reflect.UnsafePointer:
		leftPointer, rightPointer := leftValue.Pointer(), rightValue.Pointer()
		return leftPointer != 0 && leftPointer == rightPointer
	default:
		return false
	}
}

// requestBodyChangedDuringClose reports whether a body replacement observed
// after Close is distinguishable from the value that was present immediately
// before Close. Uncomparable same-typed values cannot be identified without
// unsafe, alias-prone shortcuts, so an unchanged-looking value is left alone
// rather than risking a duplicate Close on the original resource.
func requestBodyChangedDuringClose(before, after io.ReadCloser) bool {
	if before == nil || after == nil {
		return before != after
	}
	if sameRequestBodyForCleanup(before, after) {
		return false
	}
	if reflect.TypeOf(before) != reflect.TypeOf(after) {
		return true
	}
	return reflect.TypeOf(before).Comparable()
}

// requestBodyMutationTracker reads one stable underlying body while recording
// any distinct Request.Body replacement that becomes callback-visible during
// a read. Replacements are closed by the handler's final cleanup boundary.
type requestBodyMutationTracker struct {
	request      *http.Request
	body         io.ReadCloser
	replacements []io.ReadCloser
	overflow     bool
}

func (b *requestBodyMutationTracker) Read(p []byte) (n int, err error) {
	b.observe()
	if b.overflow {
		return 0, errRequestBodyMutationOverflow
	}
	defer b.observe()
	n, err = b.body.Read(p)
	if b.overflow {
		return n, errRequestBodyMutationOverflow
	}
	return n, err
}

func (b *requestBodyMutationTracker) Close() error {
	return b.body.Close()
}

func (b *requestBodyMutationTracker) observe() {
	if b == nil || b.request == nil || b.request.Body == nil || sameRequestBodyForCleanup(b.request.Body, b) {
		return
	}
	for _, replacement := range b.replacements {
		if sameRequestBodyForCleanup(replacement, b.request.Body) {
			return
		}
	}
	if len(b.replacements) >= maxMCPBodyMutationReplacements {
		b.overflow = true
		return
	}
	b.replacements = append(b.replacements, b.request.Body)
}

func cloneHTTPHeader(header http.Header) http.Header {
	if header == nil {
		return nil
	}
	clone := make(http.Header, len(header))
	for key, values := range header {
		if values == nil {
			clone[key] = nil
			continue
		}
		clone[key] = make([]string, len(values))
		copy(clone[key], values)
	}
	return clone
}

// validDirectTLSState bounds callback-visible TLS metadata before a deployment
// verifier receives a direct library request. Normal net/http serving produces
// bounded handshake state, but an in-process caller can otherwise supply
// arbitrarily large certificate and handshake slices. Certificate identity and
// Raw bytes are also checked by the body-boundary snapshot so a body reader
// cannot replace or mutate the certificate material after transport approval.
func validDirectTLSState(state *tls.ConnectionState) bool {
	if state == nil {
		return true
	}
	if len(state.NegotiatedProtocol) > maxMCPTLSHandshakeStringSize ||
		len(state.ServerName) > maxMCPTLSHandshakeStringSize ||
		containsURLControlByte(state.NegotiatedProtocol) ||
		containsURLControlByte(state.ServerName) ||
		containsUnicodeControlOrFormat(state.NegotiatedProtocol) ||
		containsUnicodeControlOrFormat(state.ServerName) ||
		len(state.PeerCertificates) > maxMCPTLSCertificates ||
		len(state.VerifiedChains) > maxMCPTLSVerifiedChains ||
		len(state.SignedCertificateTimestamps) > maxMCPTLSCertificates {
		return false
	}
	certificateBytes := 0
	for _, certificate := range state.PeerCertificates {
		if !validDirectTLSCertificate(certificate, &certificateBytes) {
			return false
		}
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) > maxMCPTLSChainCertificates {
			return false
		}
		for _, certificate := range chain {
			if !validDirectTLSCertificate(certificate, &certificateBytes) {
				return false
			}
		}
	}
	handshakeBytes := 0
	sctBytes := 0
	seenTimestamps := make(map[string]struct{}, len(state.SignedCertificateTimestamps))
	for _, timestamp := range state.SignedCertificateTimestamps {
		if len(timestamp) == 0 {
			return false
		}
		if !addBoundedDirectTLSSCT(&sctBytes, timestamp) {
			return false
		}
		if !addBoundedBytes(&handshakeBytes, len(timestamp), maxMCPTLSHandshakeBytes) {
			return false
		}
		timestampKey := string(timestamp)
		if _, ok := seenTimestamps[timestampKey]; ok {
			return false
		}
		seenTimestamps[timestampKey] = struct{}{}
	}
	if !addBoundedBytes(&handshakeBytes, len(state.OCSPResponse), maxMCPTLSHandshakeBytes) ||
		!addBoundedBytes(&handshakeBytes, len(state.TLSUnique), maxMCPTLSHandshakeBytes) {
		return false
	}
	return true
}

// validDirectTLSCipherSuite requires a completed direct handshake to expose a
// known secure cipher suite that is valid for the negotiated TLS version. A
// real net/http server populates CipherSuite after the handshake, but a direct
// caller can otherwise synthesize a completed state with zero or an
// incompatible suite. Custom reverse-proxy verifiers intentionally retain the
// broader partial-state compatibility of validDirectTLSState and are not
// routed through this stricter direct-HTTPS rule.
func validDirectTLSCipherSuite(state *tls.ConnectionState) bool {
	if state == nil {
		return false
	}
	for _, suite := range tls.CipherSuites() {
		if suite.ID != state.CipherSuite {
			continue
		}
		for _, version := range suite.SupportedVersions {
			if version == state.Version {
				return true
			}
		}
		return false
	}
	return false
}

// validDirectTLSServerState rejects connection-state combinations that the
// standard library cannot produce for a direct server request. Reverse-proxy
// verifiers intentionally retain the broader partial-state compatibility of
// validDirectTLSState because they own their transport metadata contract.
func validDirectTLSServerState(state *tls.ConnectionState) bool {
	if state == nil {
		return false
	}
	// crypto/tls rejects a trailing-dot SNI name while parsing ClientHello.
	// Keep the standalone direct verifier aligned with that server state
	// contract; an empty name remains valid when the client omitted SNI.
	if !validDirectTLSSNIName(state.ServerName) {
		return false
	}
	// ConnectionState.VerifiedChains is documented as a list of one or more
	// verified chains. A direct server can expose no chains when client
	// authentication is disabled or no optional certificate was supplied, but
	// the standard library represents that absence as nil, not a present empty
	// outer slice. Reject the synthetic presence marker while retaining the
	// broader reverse-proxy metadata contract in validDirectTLSState.
	if state.VerifiedChains != nil && len(state.VerifiedChains) == 0 {
		return false
	}
	// The server-side ConnectionState contract represents an absent optional
	// client-certificate collection as nil. Reject a present empty slice so a
	// direct caller cannot manufacture a second absence representation that a
	// transport verifier or audit path might interpret differently.
	if state.PeerCertificates != nil && len(state.PeerCertificates) == 0 {
		return false
	}
	// The server-side certificate parser exposes a stapled OCSP response only
	// when the response contains bytes. A missing response is represented by
	// nil; reject a present-but-empty synthetic value while retaining the
	// broader reverse-proxy metadata contract in validDirectTLSState.
	if state.OCSPResponse != nil && len(state.OCSPResponse) == 0 {
		return false
	}
	// A direct server handshake cannot produce the same peer certificate
	// identity twice in one received chain. Reject repeated parsed objects and
	// repeated non-empty DER identities before accepting the state as evidence
	// of an authenticated peer. The shared state preflight remains broader for
	// reverse-proxy integrations, which own their transport metadata contract.
	if !validDirectTLSCertificateSequence(state.PeerCertificates) {
		return false
	}
	for _, chain := range state.VerifiedChains {
		if !validDirectTLSCertificateSequence(chain) {
			return false
		}
	}
	// A negotiated ALPN protocol is one length-prefixed name from the server
	// configuration. The shared callback boundary deliberately permits a
	// broader bounded string for trusted reverse-proxy metadata, but a direct
	// server state must fit the one-byte protocol-name field before it is
	// treated as evidence of a completed crypto/tls handshake.
	if len(state.NegotiatedProtocol) > maxDirectTLSALPNProtocolBytes {
		return false
	}
	// Go's ConnectionState documents NegotiatedProtocolIsMutual as always true
	// in current releases. Preserve the historical server-side compatibility
	// case for an omitted protocol, but reject a non-empty selected protocol
	// paired with the contradictory synthetic false value.
	if state.NegotiatedProtocol != "" && !state.NegotiatedProtocolIsMutual {
		return false
	}
	// On a direct server connection, every verified client-certificate chain
	// starts with the leaf in PeerCertificates[0]. Reject an empty chain, a
	// chain without a peer leaf, or a different leaf before transport metadata
	// can be treated as authenticated. Reverse-proxy verifiers retain their
	// broader partial-state compatibility because they own that contract.
	if len(state.VerifiedChains) > 0 {
		if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
			return false
		}
		for _, chain := range state.VerifiedChains {
			if len(chain) == 0 || chain[0] != state.PeerCertificates[0] {
				return false
			}
		}
	}
	// ECH is currently client-side-only in crypto/tls. A direct server request
	// must not treat synthetic client-side state as evidence of an HTTPS server
	// handshake.
	if state.ECHAccepted {
		return false
	}
	// TLS 1.3 does not define the tls-unique channel binding. The standard
	// library therefore leaves TLSUnique nil for every TLS 1.3 connection;
	// reject an empty-but-present synthetic value as well as non-empty data.
	if state.Version == tls.VersionTLS13 {
		return state.TLSUnique == nil
	}
	// For a full TLS 1.2 handshake, crypto/tls always exposes the Finished
	// message as TLSUnique. A resumed TLS 1.2 connection may legitimately leave
	// it nil when Extended Master Secret was not negotiated, so retain that
	// documented compatibility case while rejecting any present value whose
	// length is not the fixed Finished verify_data width. An empty-but-present
	// slice is not emitted by the standard library in either case.
	if state.TLSUnique == nil {
		return state.DidResume
	}
	return len(state.TLSUnique) == tls12UniqueLength
}

// validDirectTLSCertificateSequence rejects exact repeated certificate
// identities inside one direct-server certificate sequence. Parsed
// certificates with Raw bytes use those bytes as their identity; synthetic
// metadata without Raw bytes can still be detected when the same object is
// repeated. Cross-collection repetition of the peer leaf is expected because
// VerifiedChains[0] must refer to PeerCertificates[0].
func validDirectTLSCertificateSequence(certificates []*x509.Certificate) bool {
	seenPointers := make(map[*x509.Certificate]struct{}, len(certificates))
	seenRaw := make(map[string]struct{}, len(certificates))
	for _, certificate := range certificates {
		if certificate == nil {
			return false
		}
		if _, ok := seenPointers[certificate]; ok {
			return false
		}
		seenPointers[certificate] = struct{}{}
		if len(certificate.Raw) == 0 {
			continue
		}
		key := string(certificate.Raw)
		if _, ok := seenRaw[key]; ok {
			return false
		}
		seenRaw[key] = struct{}{}
	}
	return true
}

func validDirectTLSCertificate(certificate *x509.Certificate, total *int) bool {
	if certificate == nil {
		return false
	}
	if !validCertificateAlgorithms(certificate) ||
		!validCertificateSignatureAlgorithm(certificate.SignatureAlgorithm, certificate.PublicKeyAlgorithm) ||
		!validCertificateUsage(certificate) ||
		!validCertificateKeyUsageRepresentation(certificate) || !validCertificateBasicConstraints(certificate) ||
		!validCertificateBasicConstraintsRepresentation(certificate) ||
		!validCertificateBasicConstraintsValues(certificate) ||
		!validCertificateNameConstraints(certificate) ||
		!validCertificateNameConstraintsRepresentation(certificate) ||
		!validCertificateNameConstraintValues(certificate) ||
		!validCertificatePolicyConstraintsRepresentation(certificate) ||
		!validCertificatePolicyConstraintValues(certificate) ||
		!validCertificateVersion(certificate.Version) ||
		!validCertificateVersionRepresentation(certificate) ||
		!validCertificateTBSSourceValue(certificate) ||
		!validCertificateRawSourceValues(certificate) ||
		!validCertificateKeyIdentifierCriticality(certificate) ||
		!validCertificateKeyIdentifierRepresentation(certificate) ||
		!validCertificateKeyIdentifierValues(certificate) ||
		!validCertificatePublicKeySourceValue(certificate) ||
		!validCertificateNameSourceValues(certificate) ||
		!validCertificateSubjectAltNameRepresentation(certificate) ||
		!validCertificateSubjectAltNameValues(certificate) ||
		!validCertificateExtendedKeyUsageRepresentation(certificate) ||
		!validCertificateExtendedKeyUsageValues(certificate) ||
		!validCertificateKeyUsageValues(certificate) ||
		!validCertificateAuthorityInfoAccessRepresentation(certificate) ||
		!validCertificateAuthorityInfoAccessValues(certificate) ||
		!validCertificateCRLDistributionPointRepresentation(certificate) ||
		!validCertificateCRLDistributionPointValues(certificate) ||
		!validCertificatePolicyMappingValues(certificate) ||
		!validCertificateAuthorityInfoAccessCriticality(certificate) {
		return false
	}
	publicKey, publicKeyValid := snapshotTLSCertificatePublicKey(certificate.PublicKey)
	if !publicKeyValid || !validCertificatePublicKeyAlgorithm(certificate.PublicKeyAlgorithm, publicKey) ||
		!addBoundedBytes(total, certificatePublicKeyMetadataSize(publicKey), maxMCPTLSCertificateBytes) {
		return false
	}
	for _, value := range [][]byte{
		certificate.Raw,
		certificate.RawTBSCertificate,
		certificate.RawSubjectPublicKeyInfo,
		certificate.RawSubject,
		certificate.RawIssuer,
		certificate.Signature,
		certificate.SubjectKeyId,
		certificate.AuthorityKeyId,
	} {
		if len(value) > maxMCPTLSCertificateBytes ||
			!addBoundedBytes(total, len(value), maxMCPTLSCertificateBytes) {
			return false
		}
	}
	if len(certificate.DNSNames) > maxMCPTLSCertificateValues ||
		!validBoundedCertificateStrings(certificate.DNSNames, total) ||
		len(certificate.EmailAddresses) > maxMCPTLSCertificateValues ||
		!validBoundedCertificateStrings(certificate.EmailAddresses, total) ||
		len(certificate.IPAddresses) > maxMCPTLSCertificateValues ||
		!validBoundedCertificateIPs(certificate.IPAddresses, total) ||
		len(certificate.URIs) > maxMCPTLSCertificateValues ||
		!validBoundedCertificateURLs(certificate.URIs, total) ||
		len(certificate.OCSPServer) > maxMCPTLSCertificateValues ||
		!validBoundedCertificateStrings(certificate.OCSPServer, total) ||
		len(certificate.IssuingCertificateURL) > maxMCPTLSCertificateValues ||
		!validBoundedCertificateStrings(certificate.IssuingCertificateURL, total) ||
		len(certificate.CRLDistributionPoints) > maxMCPTLSCertificateValues ||
		!validBoundedCertificateStrings(certificate.CRLDistributionPoints, total) ||
		len(certificate.Extensions) > maxMCPTLSCertificateValues ||
		!validCertificateExtensionOIDs(certificate.Extensions) ||
		!validBoundedCertificateExtensions(certificate.Extensions, total) ||
		len(certificate.ExtraExtensions) > maxMCPTLSCertificateValues ||
		!validCertificateExtensionOIDs(certificate.ExtraExtensions) ||
		!validBoundedCertificateExtensions(certificate.ExtraExtensions, total) ||
		!validBoundedCertificateOIDs(certificate.UnhandledCriticalExtensions, total) ||
		!validCertificateUnhandledCriticalExtensions(certificate) ||
		!validCertificatePolicies(certificate.Policies) ||
		!validBoundedCertificateOpaqueOIDs(certificate.Policies, total) ||
		!validBoundedCertificatePolicyMappings(certificate.PolicyMappings, total) ||
		!validCertificatePolicyRepresentation(certificate) ||
		!validCertificatePolicyValues(certificate) ||
		!validCertificatePolicyIdentifierValues(certificate) ||
		!validCertificatePolicyMappingsRepresentation(certificate) ||
		len(certificate.ExtKeyUsage) > maxMCPTLSCertificateValues ||
		len(certificate.UnknownExtKeyUsage) > maxMCPTLSCertificateValues ||
		!validCertificateUnknownExtKeyUsages(certificate.UnknownExtKeyUsage) ||
		!validBoundedCertificateOIDs(certificate.UnknownExtKeyUsage, total) ||
		!validBoundedCertificateName(certificate.Issuer, total) ||
		!validBoundedCertificateName(certificate.Subject, total) ||
		!validBoundedCertificateOIDs(certificate.PolicyIdentifiers, total) ||
		!validCertificatePolicyIdentifiers(certificate.Policies, certificate.PolicyIdentifiers) ||
		!validBoundedCertificateStrings(certificate.PermittedDNSDomains, total) ||
		!validBoundedCertificateStrings(certificate.ExcludedDNSDomains, total) ||
		!validBoundedCertificateStrings(certificate.PermittedEmailAddresses, total) ||
		!validBoundedCertificateStrings(certificate.ExcludedEmailAddresses, total) ||
		!validBoundedCertificateStrings(certificate.PermittedURIDomains, total) ||
		!validBoundedCertificateStrings(certificate.ExcludedURIDomains, total) ||
		!validBoundedCertificateIPNets(certificate.PermittedIPRanges, total) ||
		!validBoundedCertificateIPNets(certificate.ExcludedIPRanges, total) ||
		!validCertificatePolicyConstraint(certificate.InhibitAnyPolicy, certificate.InhibitAnyPolicyZero) ||
		!validCertificatePolicyConstraint(certificate.InhibitPolicyMapping, certificate.InhibitPolicyMappingZero) ||
		!validCertificatePolicyConstraint(certificate.RequireExplicitPolicy, certificate.RequireExplicitPolicyZero) ||
		!validCertificateSerialNumber(certificate.SerialNumber, total) {
		return false
	}
	return true
}

// validCertificateAlgorithms rejects enum values that the standard library
// cannot expose for a parsed certificate. Unknown zero values remain accepted
// for partial reverse-proxy metadata, but a supplied algorithm must be one of
// the current x509 enum values before a direct transport verifier sees it.
func validCertificateAlgorithms(certificate *x509.Certificate) bool {
	return certificate.SignatureAlgorithm >= x509.UnknownSignatureAlgorithm &&
		certificate.SignatureAlgorithm <= x509.PureEd25519 &&
		certificate.PublicKeyAlgorithm >= x509.UnknownPublicKeyAlgorithm &&
		certificate.PublicKeyAlgorithm <= x509.Ed25519
}

// validCertificateSignatureAlgorithm mirrors crypto/x509's signature-algorithm
// table for the key-family relationship exposed on parsed certificates.
// Unknown values remain compatible with partial reverse-proxy metadata, but
// known signature and public-key algorithms must not contradict each other.
func validCertificateSignatureAlgorithm(signature x509.SignatureAlgorithm, publicKey x509.PublicKeyAlgorithm) bool {
	if signature == x509.UnknownSignatureAlgorithm || publicKey == x509.UnknownPublicKeyAlgorithm {
		return true
	}
	switch signature {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA,
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return publicKey == x509.RSA
	case x509.DSAWithSHA1, x509.DSAWithSHA256:
		return publicKey == x509.DSA
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return publicKey == x509.ECDSA
	case x509.PureEd25519:
		return publicKey == x509.Ed25519
	default:
		return false
	}
}

// validCertificatePublicKeyAlgorithm keeps a declared, non-zero x509 public-key
// algorithm coherent with a supplied bounded concrete key snapshot. Unknown
// and nil-key partial reverse-proxy metadata remain accepted, while a parsed
// certificate's known algorithm must match the concrete key type exposed by the
// standard library. ECDH keys are intentionally covered by the unknown partial
// case: crypto/x509 currently exposes no ECDH PublicKeyAlgorithm enum.
func validCertificatePublicKeyAlgorithm(algorithm x509.PublicKeyAlgorithm, key tlsCertificatePublicKeyMetadata) bool {
	if key.kind == tlsCertificatePublicKeyNone {
		return true
	}
	switch algorithm {
	case x509.UnknownPublicKeyAlgorithm:
		return true
	case x509.RSA:
		return key.kind == tlsCertificatePublicKeyRSA
	case x509.DSA:
		return key.kind == tlsCertificatePublicKeyDSA
	case x509.ECDSA:
		return key.kind == tlsCertificatePublicKeyECDSA
	case x509.Ed25519:
		return key.kind == tlsCertificatePublicKeyEd25519
	default:
		return false
	}
}

// validCertificateVersion mirrors the one-indexed version exposed by the
// standard-library parser: v1, v2, and v3 are represented as 1, 2, and 3.
// Zero remains accepted for partial reverse-proxy metadata that does not
// provide a parsed certificate version, but any supplied value must be one of
// the versions an x509.Certificate can actually contain.
func validCertificateVersion(version int) bool {
	return version == 0 || (version >= 1 && version <= 3)
}

// validCertificateVersionRepresentation preserves the parser-derived
// relationship between a certificate version and its full Extensions list.
// Parsed certificates with extensions are v3; zero remains compatible with
// partial reverse-proxy metadata that does not provide a parsed version.
func validCertificateVersionRepresentation(certificate *x509.Certificate) bool {
	return len(certificate.Extensions) == 0 || certificate.Version == 0 || certificate.Version == 3
}

// validCertificateRawSourceValues preserves the parser-derived relationship
// between a complete DER certificate and the fields exposed alongside it. A
// parsed certificate carries Raw as the complete certificate envelope;
// callers must not provide a different parsed view next to that source. The
// non-DER form remains compatible with trusted reverse-proxy integrations
// that carry only opaque or partial certificate bytes.
func validCertificateRawSourceValues(certificate *x509.Certificate) bool {
	raw := certificate.Raw
	if len(raw) == 0 || raw[0] != 0x30 {
		return true
	}
	if len(raw) > maxMCPTLSCertificateBytes {
		return false
	}
	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		return false
	}
	return equalTLSCertificateMetadataEntry(snapshotTLSCertificate(parsed), certificate, false)
}

// validCertificateTBSSourceValue preserves crypto/x509's relationship between
// a DER-shaped RawTBSCertificate and the complete Raw certificate envelope.
// Parsed certificates always expose the TBS bytes as a slice of Raw; a direct
// caller must not provide a standalone DER TBS value that the parser could not
// have produced. Opaque non-DER partial metadata remains compatible with
// trusted reverse-proxy integrations.
func validCertificateTBSSourceValue(certificate *x509.Certificate) bool {
	rawTBS := certificate.RawTBSCertificate
	if len(rawTBS) == 0 || rawTBS[0] != 0x30 {
		return true
	}
	raw := certificate.Raw
	if len(raw) == 0 || raw[0] != 0x30 || len(rawTBS) > maxMCPTLSCertificateBytes || len(raw) > maxMCPTLSCertificateBytes {
		return false
	}
	parsed, err := x509.ParseCertificate(raw)
	return err == nil && bytes.Equal(parsed.RawTBSCertificate, rawTBS)
}

// validCertificateNameSourceValues preserves the parser-derived relationship
// between the DER Name fields and their parsed pkix.Name values. A parsed
// certificate carries RawSubject and RawIssuer as DER SEQUENCE values; a
// direct caller must not provide different parsed names alongside those source
// bytes. Opaque non-DER partial metadata remains compatible for trusted
// reverse-proxy integrations that only populate bounded byte fields.
func validCertificateNameSourceValues(certificate *x509.Certificate) bool {
	return validCertificateNameSourceValue(certificate.RawSubject, certificate.Subject) &&
		validCertificateNameSourceValue(certificate.RawIssuer, certificate.Issuer)
}

func validCertificateNameSourceValue(raw []byte, want pkix.Name) bool {
	if len(raw) == 0 || raw[0] != 0x30 {
		return true
	}
	var sequence pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &sequence); err != nil {
		return false
	}
	var got pkix.Name
	got.FillFromRDNSequence(&sequence)
	return equalTLSCertificateName(snapshotTLSCertificateName(got), want)
}

// validCertificatePublicKeySourceValue preserves the parser-derived
// relationship between RawSubjectPublicKeyInfo and PublicKey. A parsed
// certificate carries the SubjectPublicKeyInfo as DER and exposes the
// corresponding concrete key; a direct caller must not provide a different
// key alongside that source. Opaque non-DER partial metadata remains
// compatible for trusted reverse-proxy integrations.
func validCertificatePublicKeySourceValue(certificate *x509.Certificate) bool {
	raw := certificate.RawSubjectPublicKeyInfo
	if len(raw) == 0 || raw[0] != 0x30 {
		return true
	}
	if len(raw) > maxMCPTLSCertificateBytes {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return false
	}
	want, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return false
	}
	got, err := x509.MarshalPKIXPublicKey(parsed)
	return err == nil && bytes.Equal(got, want)
}

// validCertificateKeyIdentifierCriticality preserves crypto/x509's parser
// contract for the Subject Key Identifier (2.5.29.14) and Authority Key
// Identifier (2.5.29.35) extensions. Both extensions must be non-critical;
// marker-only partial reverse-proxy metadata remains compatible when the full
// Extensions list is omitted.
func validCertificateKeyIdentifierCriticality(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if extension.Critical &&
			(equalIntSlice(extension.Id, []int{2, 5, 29, 14}) ||
				equalIntSlice(extension.Id, []int{2, 5, 29, 35})) {
			return false
		}
	}
	return true
}

// validCertificateKeyIdentifierRepresentation preserves the parser-derived
// source relationship for non-empty SubjectKeyId and AuthorityKeyId fields.
// The parser only populates those fields from their corresponding Extensions
// entries; an omitted Extensions list remains compatible with partial
// reverse-proxy metadata, and an empty parsed key identifier carries no
// source-presence information that this bounded representation can enforce.
func validCertificateKeyIdentifierRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	subjectKeyIdentifierPresent := false
	authorityKeyIdentifierPresent := false
	for _, extension := range certificate.Extensions {
		switch {
		case equalIntSlice(extension.Id, []int{2, 5, 29, 14}):
			subjectKeyIdentifierPresent = true
		case equalIntSlice(extension.Id, []int{2, 5, 29, 35}):
			authorityKeyIdentifierPresent = true
		}
	}
	return (len(certificate.SubjectKeyId) == 0 || subjectKeyIdentifierPresent) &&
		(len(certificate.AuthorityKeyId) == 0 || authorityKeyIdentifierPresent)
}

// validCertificateKeyIdentifierValues preserves the parser-derived values for
// SubjectKeyId and AuthorityKeyId. The standard library reads the Subject Key
// Identifier from the first OCTET STRING in its extension and the Authority
// Key Identifier from the first context-specific [0] value in its sequence;
// trailing extension data is intentionally ignored to match that parser
// behavior. Empty fields remain compatible with bounded partial metadata when
// the source is omitted or opaque, while a DER-shaped source must still parse
// (including the parser-compatible empty OCTET STRING/SEQUENCE forms).
func validCertificateKeyIdentifierValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if equalIntSlice(extension.Id, []int{2, 5, 29, 14}) {
			if len(certificate.SubjectKeyId) == 0 &&
				(len(extension.Value) == 0 || extension.Value[0] != 0x04) {
				// Preserve opaque marker-only metadata used by trusted reverse
				// proxies. A DER-shaped source is still parsed below, including
				// an empty OCTET STRING that produces no identifier bytes.
				return true
			}
			value, ok := parseCertificateSubjectKeyIdentifier(extension.Value)
			if !ok || !bytes.Equal(value, certificate.SubjectKeyId) {
				return false
			}
		}
		if equalIntSlice(extension.Id, []int{2, 5, 29, 35}) {
			if len(certificate.AuthorityKeyId) == 0 &&
				(len(extension.Value) == 0 || extension.Value[0] != 0x30) {
				// Preserve opaque marker-only metadata used by trusted reverse
				// proxies. A DER-shaped source is still parsed below, including
				// an empty SEQUENCE that produces no identifier bytes.
				return true
			}
			value, ok := parseCertificateAuthorityKeyIdentifier(extension.Value)
			if !ok || !bytes.Equal(value, certificate.AuthorityKeyId) {
				return false
			}
		}
	}
	return true
}

// validCertificateSubjectAltNameRepresentation preserves the parser-derived
// source relationship for non-empty Subject Alternative Name fields. The
// standard library populates DNSNames, EmailAddresses, IPAddresses, and URIs
// only from the 2.5.29.17 Extensions entry; an omitted Extensions list remains
// compatible with partial reverse-proxy metadata.
func validCertificateSubjectAltNameRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 ||
		(len(certificate.DNSNames) == 0 && len(certificate.EmailAddresses) == 0 &&
			len(certificate.IPAddresses) == 0 && len(certificate.URIs) == 0) {
		return true
	}
	for _, extension := range certificate.Extensions {
		if equalIntSlice(extension.Id, []int{2, 5, 29, 17}) {
			return true
		}
	}
	return false
}

// validCertificateSubjectAltNameValues preserves the parser-visible values of
// the Subject Alternative Name extension. Go's parser keeps DNS, email, IP,
// and URI GeneralNames in separate slices while preserving order within each
// slice; unknown GeneralName tags are ignored. An omitted Extensions list and
// opaque marker-only values remain compatible with partial metadata. A
// DER-shaped source with no derived values is parsed too, so malformed source
// bytes cannot hide behind an empty SAN field set.
func validCertificateSubjectAltNameValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	hasDerivedValues := len(certificate.DNSNames) > 0 || len(certificate.EmailAddresses) > 0 ||
		len(certificate.IPAddresses) > 0 || len(certificate.URIs) > 0
	for _, extension := range certificate.Extensions {
		if !equalIntSlice(extension.Id, []int{2, 5, 29, 17}) {
			continue
		}
		if !hasDerivedValues && (len(extension.Value) == 0 || extension.Value[0] != 0x30) {
			return true
		}
		dnsNames, emailAddresses, ipAddresses, uris, ok := parseCertificateSubjectAltName(extension.Value)
		return ok && equalStringSlice(dnsNames, certificate.DNSNames) &&
			equalStringSlice(emailAddresses, certificate.EmailAddresses) &&
			equalCertificateIPAddresses(cloneCertificateIPAddresses(ipAddresses), certificate.IPAddresses) &&
			equalCertificateURLs(uris, certificate.URIs)
	}
	return true
}

func parseCertificateSubjectAltName(value []byte) (dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL, ok bool) {
	sequence, _, err := unmarshalCertificateRawValue(value)
	if err != nil || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return nil, nil, nil, nil, false
	}
	for remaining := sequence.Bytes; len(remaining) > 0; {
		generalName, next, err := unmarshalCertificateRawValue(remaining)
		if err != nil {
			return nil, nil, nil, nil, false
		}
		remaining = next
		if generalName.Class != 2 || generalName.IsCompound {
			continue
		}
		switch generalName.Tag {
		case 1: // rfc822Name
			if !validCertificateIA5String(generalName.Bytes) {
				return nil, nil, nil, nil, false
			}
			emailAddresses = append(emailAddresses, string(generalName.Bytes))
		case 2: // dNSName
			if !validCertificateIA5String(generalName.Bytes) {
				return nil, nil, nil, nil, false
			}
			dnsNames = append(dnsNames, string(generalName.Bytes))
		case 6: // uniformResourceIdentifier
			if !validCertificateIA5String(generalName.Bytes) {
				return nil, nil, nil, nil, false
			}
			uri, err := url.Parse(string(generalName.Bytes))
			if err != nil || (uri.Host != "" && !validCertificateURIHost(uri.Host)) {
				return nil, nil, nil, nil, false
			}
			uris = append(uris, uri)
		case 7: // iPAddress
			if len(generalName.Bytes) != net.IPv4len && len(generalName.Bytes) != net.IPv6len {
				return nil, nil, nil, nil, false
			}
			ipAddresses = append(ipAddresses, append(net.IP(nil), generalName.Bytes...))
		}
	}
	return dnsNames, emailAddresses, ipAddresses, uris, true
}

func validCertificateIA5String(value []byte) bool {
	for _, character := range value {
		if character > 0x7f {
			return false
		}
	}
	return true
}

func validCertificateURIHost(host string) bool {
	// crypto/x509 validates URI hosts with domainNameValid(..., false), so a
	// leading dot is not a valid first label. Domain-only name constraints use
	// a separate parser-compatible leading-dot rule.
	if host == "" || host[0] == '.' {
		return host == ""
	}
	for len(host) > 0 {
		index := strings.LastIndexByte(host, '.')
		label := host
		if index == -1 {
			host = ""
		} else {
			label = host[index+1:]
			host = host[:index]
		}
		if label == "" {
			return false
		}
		for _, character := range label {
			if character < 33 || character > 126 {
				return false
			}
		}
	}
	return true
}

// validCertificateExtendedKeyUsageRepresentation preserves the parser-derived
// source relationship for non-empty ExtKeyUsage and UnknownExtKeyUsage fields.
// The standard library populates both fields only from the Extended Key Usage
// extension (2.5.29.37); an omitted Extensions list remains compatible with
// partial reverse-proxy metadata.
func validCertificateExtendedKeyUsageRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 ||
		(len(certificate.ExtKeyUsage) == 0 && len(certificate.UnknownExtKeyUsage) == 0) {
		return true
	}
	for _, extension := range certificate.Extensions {
		if equalIntSlice(extension.Id, []int{2, 5, 29, 37}) {
			return true
		}
	}
	return false
}

// validCertificateExtendedKeyUsageValues preserves the parser-visible value
// split and order for the Extended Key Usage extension (2.5.29.37). Go's
// parser emits recognized OIDs in ExtKeyUsage and genuinely unknown OIDs in
// UnknownExtKeyUsage; an omitted Extensions list and an empty parsed value set
// remain compatible with partial metadata. A DER-shaped source with no derived
// values is parsed too, so malformed source bytes cannot hide behind an empty
// EKU field set.
func validCertificateExtendedKeyUsageValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	hasDerivedValues := len(certificate.ExtKeyUsage) > 0 || len(certificate.UnknownExtKeyUsage) > 0
	found := false
	for _, extension := range certificate.Extensions {
		if !equalIntSlice(extension.Id, []int{2, 5, 29, 37}) {
			continue
		}
		found = true
		extKeyUsages, unknownExtKeyUsages, ok := parseCertificateExtendedKeyUsages(extension.Value)
		if !hasDerivedValues && (len(extension.Value) == 0 || extension.Value[0] != 0x30) {
			// Preserve opaque marker-only metadata used by trusted reverse
			// proxies. A DER-shaped source is still parsed below, including an
			// empty SEQUENCE that produces no derived usage values.
			return true
		}
		return ok && equalExtKeyUsage(extKeyUsages, certificate.ExtKeyUsage) &&
			equalCertificateOIDs(cloneCertificateOIDs(unknownExtKeyUsages), certificate.UnknownExtKeyUsage)
	}
	return !found
}

func parseCertificateExtendedKeyUsages(value []byte) ([]x509.ExtKeyUsage, []asn1.ObjectIdentifier, bool) {
	var oids []asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(value, &oids)
	if err != nil {
		return nil, nil, false
	}
	extKeyUsages := make([]x509.ExtKeyUsage, 0, len(oids))
	unknownExtKeyUsages := make([]asn1.ObjectIdentifier, 0, len(oids))
	for _, oid := range oids {
		if usage, ok := certificateExtKeyUsageFromOID(oid); ok {
			extKeyUsages = append(extKeyUsages, usage)
		} else {
			unknownExtKeyUsages = append(unknownExtKeyUsages, oid)
		}
	}
	return extKeyUsages, unknownExtKeyUsages, true
}

func certificateExtKeyUsageFromOID(oid asn1.ObjectIdentifier) (x509.ExtKeyUsage, bool) {
	known := []struct {
		usage x509.ExtKeyUsage
		oid   asn1.ObjectIdentifier
	}{
		{x509.ExtKeyUsageAny, asn1.ObjectIdentifier{2, 5, 29, 37, 0}},
		{x509.ExtKeyUsageServerAuth, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}},
		{x509.ExtKeyUsageClientAuth, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}},
		{x509.ExtKeyUsageCodeSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}},
		{x509.ExtKeyUsageEmailProtection, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}},
		{x509.ExtKeyUsageIPSECEndSystem, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}},
		{x509.ExtKeyUsageIPSECTunnel, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}},
		{x509.ExtKeyUsageIPSECUser, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}},
		{x509.ExtKeyUsageTimeStamping, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}},
		{x509.ExtKeyUsageOCSPSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}},
		{x509.ExtKeyUsageMicrosoftServerGatedCrypto, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}},
		{x509.ExtKeyUsageNetscapeServerGatedCrypto, asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}},
		{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}},
		{x509.ExtKeyUsageMicrosoftKernelCodeSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}},
	}
	for _, candidate := range known {
		if equalIntSlice(oid, candidate.oid) {
			return candidate.usage, true
		}
	}
	return 0, false
}

// validCertificateAuthorityInfoAccessRepresentation preserves the parser
// source relationship for non-empty OCSPServer and IssuingCertificateURL
// fields. The standard library populates both fields only from the Authority
// Information Access extension (1.3.6.1.5.5.7.1.1); an omitted Extensions
// list remains compatible with partial reverse-proxy metadata.
func validCertificateAuthorityInfoAccessRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 ||
		(len(certificate.OCSPServer) == 0 && len(certificate.IssuingCertificateURL) == 0) {
		return true
	}
	for _, extension := range certificate.Extensions {
		if equalIntSlice(extension.Id, []int{1, 3, 6, 1, 5, 5, 7, 1, 1}) {
			return true
		}
	}
	return false
}

// validCertificateAuthorityInfoAccessValues preserves the parser-visible
// values for the Authority Information Access extension (1.3.6.1.5.5.7.1.1).
// Go's parser keeps URI access locations for the OCSP and caIssuers methods in
// separate ordered slices and ignores other access methods. An omitted
// Extensions list and opaque marker-only values remain compatible with partial
// reverse-proxy metadata. A DER-shaped source with no recognized access
// locations is still parsed so malformed bytes cannot hide behind an empty
// derived field set.
func validCertificateAuthorityInfoAccessValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	hasDerivedValues := len(certificate.OCSPServer) > 0 || len(certificate.IssuingCertificateURL) > 0
	found := false
	for _, extension := range certificate.Extensions {
		if !equalIntSlice(extension.Id, []int{1, 3, 6, 1, 5, 5, 7, 1, 1}) {
			continue
		}
		found = true
		if !hasDerivedValues && (len(extension.Value) == 0 || extension.Value[0] != 0x30) {
			// Preserve opaque marker-only metadata used by trusted reverse
			// proxies. A DER-shaped source is still parsed below, including an
			// empty SEQUENCE that produces no derived access locations.
			return true
		}
		ocspServers, issuingCertificateURLs, ok := parseCertificateAuthorityInfoAccess(extension.Value)
		return ok && equalStringSlice(ocspServers, certificate.OCSPServer) &&
			equalStringSlice(issuingCertificateURLs, certificate.IssuingCertificateURL)
	}
	return !found
}

func parseCertificateAuthorityInfoAccess(value []byte) ([]string, []string, bool) {
	sequence, _, err := unmarshalCertificateRawValue(value)
	if err != nil || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return nil, nil, false
	}
	var ocspServers, issuingCertificateURLs []string
	for remaining := sequence.Bytes; len(remaining) > 0; {
		accessDescription, next, err := unmarshalCertificateRawValue(remaining)
		if err != nil || accessDescription.Class != 0 || accessDescription.Tag != 16 || !accessDescription.IsCompound {
			return nil, nil, false
		}
		remaining = next

		var methodOID asn1.ObjectIdentifier
		accessLocation, err := asn1.Unmarshal(accessDescription.Bytes, &methodOID)
		if err != nil {
			return nil, nil, false
		}
		if len(accessLocation) == 0 {
			continue
		}
		// crypto/x509 checks the access-location tag before decoding it. A
		// non-URI GeneralName is ignored, even when its bytes are not a
		// decodable value; only the primitive URI form can contribute to the
		// callback-visible OCSP/caIssuers slices below. Keep that parser
		// compatibility without weakening malformed URI handling.
		if accessLocation[0] != 0x86 {
			continue
		}
		location, _, err := unmarshalCertificateRawValue(accessLocation)
		if err != nil {
			return nil, nil, false
		}
		if location.Class != 2 || location.Tag != 6 || location.IsCompound {
			continue
		}
		switch {
		case equalIntSlice(methodOID, []int{1, 3, 6, 1, 5, 5, 7, 48, 1}):
			ocspServers = append(ocspServers, string(location.Bytes))
		case equalIntSlice(methodOID, []int{1, 3, 6, 1, 5, 5, 7, 48, 2}):
			issuingCertificateURLs = append(issuingCertificateURLs, string(location.Bytes))
		}
	}
	return ocspServers, issuingCertificateURLs, true
}

// validCertificateCRLDistributionPointRepresentation preserves the parser
// source relationship for non-empty CRLDistributionPoints. The standard
// library populates the field only from the CRL Distribution Points extension
// (2.5.29.31); an omitted Extensions list remains compatible with partial
// reverse-proxy metadata.
func validCertificateCRLDistributionPointRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 || len(certificate.CRLDistributionPoints) == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if equalIntSlice(extension.Id, []int{2, 5, 29, 31}) {
			return true
		}
	}
	return false
}

// validCertificateCRLDistributionPointValues preserves the parser-visible URI
// values for CRLDistributionPoints. Go 1.24 walks each distribution point's
// fullName URI entries and ignores other distribution-point names; compare the
// resulting ordered strings when a direct caller supplies them. An empty
// derived list remains compatible with omitted or opaque partial metadata, but
// a DER-shaped source must still parse so malformed bytes cannot hide behind
// an empty field.
func validCertificateCRLDistributionPointValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if !equalIntSlice(extension.Id, []int{2, 5, 29, 31}) {
			continue
		}
		values, ok := parseCertificateCRLDistributionPoints(extension.Value)
		if len(certificate.CRLDistributionPoints) == 0 &&
			(len(extension.Value) == 0 || extension.Value[0] != 0x30) {
			// Preserve opaque marker-only metadata used by trusted reverse
			// proxies. A DER-shaped source is parsed below, including an
			// empty SEQUENCE that produces no derived distribution points.
			return true
		}
		return ok && equalStringSlice(values, certificate.CRLDistributionPoints)
	}
	return len(certificate.CRLDistributionPoints) == 0
}

func parseCertificateSubjectKeyIdentifier(value []byte) ([]byte, bool) {
	var identifier asn1.RawValue
	if _, err := asn1.Unmarshal(value, &identifier); err != nil ||
		identifier.Class != 0 || identifier.Tag != 4 || identifier.IsCompound {
		return nil, false
	}
	return identifier.Bytes, true
}

func parseCertificateAuthorityKeyIdentifier(value []byte) ([]byte, bool) {
	var sequence asn1.RawValue
	if _, err := asn1.Unmarshal(value, &sequence); err != nil ||
		sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return nil, false
	}
	if len(sequence.Bytes) == 0 {
		return nil, true
	}
	var identifier asn1.RawValue
	if _, err := asn1.Unmarshal(sequence.Bytes, &identifier); err != nil {
		return nil, false
	}
	if identifier.Class != 2 || identifier.Tag != 0 || identifier.IsCompound {
		return nil, true
	}
	return identifier.Bytes, true
}

func parseCertificateCRLDistributionPoints(value []byte) ([]string, bool) {
	// crypto/x509 reads the outer SEQUENCE and intentionally ignores bytes
	// after it. Keep that parser-compatible read-and-discard behavior while
	// retaining strict validation of each distribution point and URI that can
	// populate CRLDistributionPoints.
	sequence, _, err := unmarshalCertificateRawValue(value)
	if err != nil || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return nil, false
	}
	var distributionPoints []string
	for remaining := sequence.Bytes; len(remaining) > 0; {
		distributionPoint, next, err := unmarshalCertificateRawValue(remaining)
		if err != nil || distributionPoint.Class != 0 || distributionPoint.Tag != 16 || !distributionPoint.IsCompound {
			return nil, false
		}
		remaining = next

		if len(distributionPoint.Bytes) == 0 || distributionPoint.Bytes[0] != 0xa0 {
			// The standard parser ignores distribution points without the
			// optional distributionPoint [0] field.
			continue
		}
		name, _, err := unmarshalCertificateRawValue(distributionPoint.Bytes)
		if err != nil || name.Class != 2 || name.Tag != 0 || !name.IsCompound {
			return nil, false
		}

		fullName, _, err := unmarshalCertificateRawValue(name.Bytes)
		if err != nil || fullName.Class != 2 || fullName.Tag != 0 || !fullName.IsCompound {
			return nil, false
		}
		for names := fullName.Bytes; len(names) > 0; {
			// crypto/x509 checks the GeneralName tag before decoding it. A
			// non-URI name is ignored, even when its bytes are truncated; only
			// the primitive URI form can populate CRLDistributionPoints and
			// therefore needs strict length/value parsing here.
			if names[0] != 0x86 { // context-specific primitive tag 6
				break
			}
			generalName, next, err := unmarshalCertificateRawValue(names)
			if err != nil {
				return nil, false
			}
			if generalName.Class != 2 || generalName.Tag != 6 || generalName.IsCompound {
				break
			}
			distributionPoints = append(distributionPoints, string(generalName.Bytes))
			names = next
		}
	}
	return distributionPoints, true
}

func unmarshalCertificateRawValue(value []byte) (asn1.RawValue, []byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(value, &raw)
	return raw, rest, err
}

// validCertificateAuthorityInfoAccessCriticality preserves crypto/x509's
// parser contract for Authority Information Access (1.3.6.1.5.5.7.1.1).
// Conforming certificates must mark this extension non-critical; marker-only
// partial reverse-proxy metadata remains compatible when Extensions is absent.
func validCertificateAuthorityInfoAccessCriticality(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if extension.Critical && equalIntSlice(extension.Id, []int{1, 3, 6, 1, 5, 5, 7, 1, 1}) {
			return false
		}
	}
	return true
}

// validCertificateUsage rejects semantic certificate values that the standard
// parser cannot expose for a valid certificate. Zero values remain accepted so
// direct callers can provide partial metadata for a reverse-proxy integration;
// any supplied usage bit, extended-usage enum, or pair of validity bounds must
// still be internally valid before a direct transport verifier sees it.
func validCertificateUsage(certificate *x509.Certificate) bool {
	const knownKeyUsage = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign |
		x509.KeyUsageEncipherOnly |
		x509.KeyUsageDecipherOnly
	if certificate.KeyUsage&^knownKeyUsage != 0 {
		return false
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage < x509.ExtKeyUsageAny || usage > x509.ExtKeyUsageMicrosoftKernelCodeSigning {
			return false
		}
	}
	return validCertificateValidity(certificate.NotBefore, certificate.NotAfter)
}

// validCertificateKeyUsageRepresentation preserves the parser-derived source
// relationship for non-zero KeyUsage values. The standard library populates
// KeyUsage only from the Key Usage extension (2.5.29.15); an omitted
// Extensions list remains compatible with partial reverse-proxy metadata, and
// a zero parsed value carries no source-presence information to enforce.
func validCertificateKeyUsageRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 || certificate.KeyUsage == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if equalIntSlice(extension.Id, []int{2, 5, 29, 15}) {
			return true
		}
	}
	return false
}

// validCertificateKeyUsageValues preserves the parser-visible bit values for
// Key Usage extension (2.5.29.15). Go's parser reads the first nine bits and
// permits a zero-bit BIT STRING, which produces a zero KeyUsage value. An
// omitted Extensions list and an opaque non-DER partial value remain
// compatible with reverse-proxy metadata, while a DER-shaped source is
// parsed even when it produces no derived bits.
func validCertificateKeyUsageValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	found := false
	for _, extension := range certificate.Extensions {
		if !equalIntSlice(extension.Id, []int{2, 5, 29, 15}) {
			continue
		}
		found = true
		if certificate.KeyUsage == 0 && (len(extension.Value) == 0 || extension.Value[0] != 0x03) {
			// Preserve the existing marker-only reverse-proxy form. A
			// DER-shaped BIT STRING is still parsed below, including a
			// valid zero-bit value that produces no KeyUsage flags.
			return true
		}
		value, ok := parseCertificateKeyUsage(extension.Value)
		return ok && value == certificate.KeyUsage
	}
	return !found
}

func parseCertificateKeyUsage(value []byte) (x509.KeyUsage, bool) {
	var usageBits asn1.BitString
	if _, err := asn1.Unmarshal(value, &usageBits); err != nil {
		return 0, false
	}
	var usage x509.KeyUsage
	for bit := 0; bit < 9; bit++ {
		if usageBits.At(bit) != 0 {
			usage |= 1 << uint(bit)
		}
	}
	return usage, true
}

// validCertificateUnknownExtKeyUsages preserves crypto/x509's split between
// recognized ExtKeyUsage enum values and UnknownExtKeyUsage OIDs. A direct
// caller can otherwise place a known EKU OID in the unknown slice, creating a
// certificate representation that the parser cannot produce.
func validCertificateUnknownExtKeyUsages(values []asn1.ObjectIdentifier) bool {
	known := []asn1.ObjectIdentifier{
		{2, 5, 29, 37, 0},
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
		{1, 3, 6, 1, 5, 5, 7, 3, 3},
		{1, 3, 6, 1, 5, 5, 7, 3, 4},
		{1, 3, 6, 1, 5, 5, 7, 3, 5},
		{1, 3, 6, 1, 5, 5, 7, 3, 6},
		{1, 3, 6, 1, 5, 5, 7, 3, 7},
		{1, 3, 6, 1, 5, 5, 7, 3, 8},
		{1, 3, 6, 1, 5, 5, 7, 3, 9},
		{1, 3, 6, 1, 4, 1, 311, 10, 3, 3},
		{2, 16, 840, 1, 113730, 4, 1},
		{1, 3, 6, 1, 4, 1, 311, 2, 1, 22},
		{1, 3, 6, 1, 4, 1, 311, 61, 1, 1},
	}
	for _, value := range values {
		for _, knownOID := range known {
			if equalIntSlice(value, knownOID) {
				return false
			}
		}
	}
	return true
}

// validCertificateValidity preserves the parser's all-or-nothing validity
// representation. A partial reverse-proxy certificate may omit both bounds,
// while a parsed certificate supplies two non-zero bounds in chronological
// order; a one-sided interval cannot come from crypto/x509.
func validCertificateValidity(notBefore, notAfter time.Time) bool {
	if notBefore.IsZero() || notAfter.IsZero() {
		return notBefore.IsZero() && notAfter.IsZero()
	}
	return !notAfter.Before(notBefore)
}

// validCertificateBasicConstraints rejects path-length combinations that the
// x509 parser and certificate generator cannot expose coherently. The zero
// certificate remains valid for reverse-proxy callers that provide only the
// metadata they need; once a basic-constraints field is supplied, its
// presence and sentinel values must agree.
func validCertificateBasicConstraints(certificate *x509.Certificate) bool {
	if certificate.MaxPathLen < -1 ||
		(certificate.MaxPathLenZero && certificate.MaxPathLen != 0) {
		return false
	}
	if !certificate.BasicConstraintsValid {
		return !certificate.IsCA && certificate.MaxPathLen == 0 && !certificate.MaxPathLenZero
	}
	if !certificate.IsCA && certificate.MaxPathLen > 0 {
		return false
	}
	return true
}

// validCertificateBasicConstraintsRepresentation preserves the parser-derived
// relationship between BasicConstraintsValid and the full Extensions list.
// A parsed certificate sets BasicConstraintsValid only while processing the
// basic-constraints extension. Marker-only partial reverse-proxy metadata
// remains compatible when Extensions is omitted.
func validCertificateBasicConstraintsRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	found := false
	for _, extension := range certificate.Extensions {
		if equalIntSlice(extension.Id, []int{2, 5, 29, 19}) {
			found = true
			break
		}
	}
	return found == certificate.BasicConstraintsValid
}

// validCertificateBasicConstraintsValues preserves the parser-visible values
// from the Basic Constraints extension (2.5.29.19). Go's parser defaults the
// optional CA BOOLEAN to false and pathLenConstraint INTEGER to -1, then
// ignores trailing fields in the sequence. An omitted Extensions list remains
// compatible with partial reverse-proxy metadata.
func validCertificateBasicConstraintsValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 || !certificate.BasicConstraintsValid {
		return true
	}
	for _, extension := range certificate.Extensions {
		if !equalIntSlice(extension.Id, []int{2, 5, 29, 19}) {
			continue
		}
		isCA, maxPathLen, ok := parseCertificateBasicConstraints(extension.Value)
		return ok && isCA == certificate.IsCA && maxPathLen == certificate.MaxPathLen &&
			(maxPathLen == 0) == certificate.MaxPathLenZero
	}
	return false
}

func parseCertificateBasicConstraints(value []byte) (isCA bool, maxPathLen int, ok bool) {
	sequence, _, err := unmarshalCertificateRawValue(value)
	if err != nil || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return false, 0, false
	}
	maxPathLen = -1
	remaining := sequence.Bytes
	if len(remaining) > 0 {
		field, rest, err := unmarshalCertificateRawValue(remaining)
		if err != nil {
			return false, 0, false
		}
		if field.Class == 0 && field.Tag == 1 && !field.IsCompound {
			if len(field.Bytes) != 1 {
				return false, 0, false
			}
			switch field.Bytes[0] {
			case 0:
				isCA = false
			case 0xff:
				isCA = true
			default:
				return false, 0, false
			}
			remaining = rest
		}
	}
	if len(remaining) > 0 {
		field, _, err := unmarshalCertificateRawValue(remaining)
		if err != nil {
			return false, 0, false
		}
		if field.Class == 0 && field.Tag == 2 && !field.IsCompound {
			if _, err := asn1.Unmarshal(field.FullBytes, &maxPathLen); err != nil {
				return false, 0, false
			}
		}
	}
	return isCA, maxPathLen, true
}

// validCertificateNameConstraints preserves the parser's representation of
// critical name constraints. A parsed certificate either exposes at least one
// recognized subtree, or records the critical extension as unhandled when it
// contains only GeneralName forms this package does not decode. A synthetic
// critical marker with neither representation cannot come from x509 parsing;
// an all-zero partial certificate remains compatible because its marker is
// false.
func validCertificateNameConstraints(certificate *x509.Certificate) bool {
	if !certificate.PermittedDNSDomainsCritical {
		return true
	}
	if len(certificate.PermittedDNSDomains) > 0 || len(certificate.ExcludedDNSDomains) > 0 ||
		len(certificate.PermittedIPRanges) > 0 || len(certificate.ExcludedIPRanges) > 0 ||
		len(certificate.PermittedEmailAddresses) > 0 || len(certificate.ExcludedEmailAddresses) > 0 ||
		len(certificate.PermittedURIDomains) > 0 || len(certificate.ExcludedURIDomains) > 0 {
		return true
	}
	for _, oid := range certificate.UnhandledCriticalExtensions {
		if len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 29 && oid[3] == 30 {
			return true
		}
	}
	return false
}

// validCertificateNameConstraintsRepresentation preserves the parser-derived
// relationship between the name-constraints criticality marker and the full
// Extensions list. A parsed certificate sets PermittedDNSDomainsCritical from
// the Name Constraints extension's critical bit; marker-only partial
// reverse-proxy metadata remains compatible when Extensions is omitted.
func validCertificateNameConstraintsRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	found := false
	critical := false
	for _, extension := range certificate.Extensions {
		if equalIntSlice(extension.Id, []int{2, 5, 29, 30}) {
			found = true
			critical = extension.Critical
			break
		}
	}
	return certificate.PermittedDNSDomainsCritical == (found && critical)
}

// validCertificateNameConstraintValues preserves the parser-visible values of
// the Name Constraints extension (2.5.29.30). Go's parser keeps recognized
// DNS, IP, e-mail, and URI constraints in separate permitted/excluded slices
// and ignores unsupported GeneralName forms and trailing GeneralSubtree
// fields. A full Extensions list must still agree with those values; the
// omitted-list form remains compatible with partial reverse-proxy metadata.
func validCertificateNameConstraintValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	var extension *pkix.Extension
	for index := range certificate.Extensions {
		if equalIntSlice(certificate.Extensions[index].Id, []int{2, 5, 29, 30}) {
			extension = &certificate.Extensions[index]
			break
		}
	}
	if extension == nil {
		return len(certificate.PermittedDNSDomains) == 0 &&
			len(certificate.ExcludedDNSDomains) == 0 &&
			len(certificate.PermittedIPRanges) == 0 &&
			len(certificate.ExcludedIPRanges) == 0 &&
			len(certificate.PermittedEmailAddresses) == 0 &&
			len(certificate.ExcludedEmailAddresses) == 0 &&
			len(certificate.PermittedURIDomains) == 0 &&
			len(certificate.ExcludedURIDomains) == 0
	}
	if extension.Critical && certificateHasUnhandledCriticalMarker(certificate, extension.Id) &&
		len(certificate.PermittedDNSDomains) == 0 && len(certificate.ExcludedDNSDomains) == 0 &&
		len(certificate.PermittedIPRanges) == 0 && len(certificate.ExcludedIPRanges) == 0 &&
		len(certificate.PermittedEmailAddresses) == 0 && len(certificate.ExcludedEmailAddresses) == 0 &&
		len(certificate.PermittedURIDomains) == 0 && len(certificate.ExcludedURIDomains) == 0 {
		// Preserve the existing opaque marker-only reverse-proxy representation,
		// but do not let a DER-shaped value bypass the parser-equivalent check.
		// A real x509 parser can produce this marker for a valid source that
		// contains only unsupported GeneralName forms; malformed or empty
		// NameConstraints values must still fail closed.
		if len(extension.Value) == 0 || extension.Value[0] != 0x30 {
			return true
		}
	}
	permittedDNS, excludedDNS, permittedIPs, excludedIPs, permittedEmails, excludedEmails,
		permittedURIs, excludedURIs, _, ok := parseCertificateNameConstraints(extension.Value)
	if !ok {
		return false
	}
	return equalStringSlice(permittedDNS, certificate.PermittedDNSDomains) &&
		equalStringSlice(excludedDNS, certificate.ExcludedDNSDomains) &&
		equalCertificateIPNets(cloneCertificateIPNets(permittedIPs), certificate.PermittedIPRanges) &&
		equalCertificateIPNets(cloneCertificateIPNets(excludedIPs), certificate.ExcludedIPRanges) &&
		equalStringSlice(permittedEmails, certificate.PermittedEmailAddresses) &&
		equalStringSlice(excludedEmails, certificate.ExcludedEmailAddresses) &&
		equalStringSlice(permittedURIs, certificate.PermittedURIDomains) &&
		equalStringSlice(excludedURIs, certificate.ExcludedURIDomains)
}

func parseCertificateNameConstraints(value []byte) (permittedDNS, excludedDNS []string,
	permittedIPs, excludedIPs []*net.IPNet, permittedEmails, excludedEmails,
	permittedURIs, excludedURIs []string, unhandled, ok bool) {
	// crypto/x509 reads the outer SEQUENCE and intentionally ignores bytes
	// after it. Keep that parser-compatible read-and-discard behavior while
	// retaining strict validation of the permitted/excluded subtree fields.
	sequence, _, err := unmarshalCertificateRawValue(value)
	if err != nil || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return nil, nil, nil, nil, nil, nil, nil, nil, false, false
	}
	remaining := sequence.Bytes
	var permitted, excluded []byte
	if len(remaining) == 0 {
		return nil, nil, nil, nil, nil, nil, nil, nil, false, false
	}
	field, next, err := unmarshalCertificateRawValue(remaining)
	if err != nil || field.Class != 2 || !field.IsCompound || (field.Tag != 0 && field.Tag != 1) {
		return nil, nil, nil, nil, nil, nil, nil, nil, false, false
	}
	if field.Tag == 0 {
		permitted = field.Bytes
		remaining = next
		if len(remaining) > 0 {
			field, next, err = unmarshalCertificateRawValue(remaining)
			if err != nil || field.Class != 2 || field.Tag != 1 || !field.IsCompound {
				return nil, nil, nil, nil, nil, nil, nil, nil, false, false
			}
			excluded = field.Bytes
			remaining = next
		}
	} else {
		excluded = field.Bytes
		remaining = next
	}
	if len(remaining) != 0 || (len(permitted) == 0 && len(excluded) == 0) {
		return nil, nil, nil, nil, nil, nil, nil, nil, false, false
	}
	parseSubtrees := func(encoded []byte) (dns []string, ips []*net.IPNet, emails, uris []string, unsupported, valid bool) {
		if len(encoded) == 0 {
			// Go 1.24 accepts a present empty permittedSubtrees or
			// excludedSubtrees sequence when the other side contains values;
			// it rejects only when both sides are empty. The outer check above
			// preserves that latter rejection while this branch keeps the
			// asymmetric representation parser-compatible.
			return nil, nil, nil, nil, false, true
		}
		for remaining := encoded; len(remaining) > 0; {
			subtree, next, err := unmarshalCertificateRawValue(remaining)
			if err != nil || subtree.Class != 0 || subtree.Tag != 16 || !subtree.IsCompound {
				return nil, nil, nil, nil, false, false
			}
			remaining = next
			base, _, err := unmarshalCertificateRawValue(subtree.Bytes)
			if err != nil {
				return nil, nil, nil, nil, false, false
			}
			if base.Class != 2 || base.IsCompound {
				unsupported = true
				continue
			}
			switch base.Tag {
			case 1: // rfc822Name
				if !validCertificateNameConstraintEmail(base.Bytes) {
					return nil, nil, nil, nil, false, false
				}
				emails = append(emails, string(base.Bytes))
			case 2: // dNSName
				if !validCertificateNameConstraintDomain(base.Bytes) {
					return nil, nil, nil, nil, false, false
				}
				dns = append(dns, string(base.Bytes))
			case 6: // uniformResourceIdentifier
				if !validCertificateNameConstraintDomain(base.Bytes) || net.ParseIP(string(base.Bytes)) != nil {
					return nil, nil, nil, nil, false, false
				}
				uris = append(uris, string(base.Bytes))
			case 7: // iPAddress
				if len(base.Bytes) != 2*net.IPv4len && len(base.Bytes) != 2*net.IPv6len {
					return nil, nil, nil, nil, false, false
				}
				width := len(base.Bytes) / 2
				mask := net.IPMask(append([]byte(nil), base.Bytes[width:]...))
				if !validCertificateIPMask(mask) {
					return nil, nil, nil, nil, false, false
				}
				ips = append(ips, &net.IPNet{IP: net.IP(append([]byte(nil), base.Bytes[:width]...)), Mask: mask})
			default:
				unsupported = true
			}
		}
		return dns, ips, emails, uris, unsupported, true
	}
	permittedDNS, permittedIPs, permittedEmails, permittedURIs, permittedUnhandled, valid := parseSubtrees(permitted)
	if !valid {
		return nil, nil, nil, nil, nil, nil, nil, nil, false, false
	}
	excludedDNS, excludedIPs, excludedEmails, excludedURIs, excludedUnhandled, valid := parseSubtrees(excluded)
	if !valid {
		return nil, nil, nil, nil, nil, nil, nil, nil, false, false
	}
	return permittedDNS, excludedDNS, permittedIPs, excludedIPs, permittedEmails, excludedEmails,
		permittedURIs, excludedURIs, permittedUnhandled || excludedUnhandled, true
}

func validCertificateNameConstraintDomain(value []byte) bool {
	if !validCertificateIA5String(value) || (len(value) > 0 && value[len(value)-1] == '.') {
		return false
	}
	domain := string(value)
	if domain == "" {
		return true
	}
	if domain[0] == '.' {
		domain = domain[1:]
	}
	if domain == "" {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return false
		}
		for _, character := range label {
			if character < 33 || character > 126 {
				return false
			}
		}
	}
	return true
}

func validCertificateNameConstraintEmail(value []byte) bool {
	if !validCertificateIA5String(value) {
		return false
	}
	email := string(value)
	if !strings.Contains(email, "@") {
		return validCertificateNameConstraintDomain(value)
	}
	return validCertificateRFC2821Mailbox(email)
}

// validCertificateRFC2821Mailbox mirrors crypto/x509's RFC 2821 mailbox
// parser for exact rfc822Name constraints. The certificate parser accepts
// quoted strings and the documented escaped-pair forms, but rejects empty,
// dotted, or otherwise malformed atom local parts before validating the
// domain. The domain-only constraint path intentionally keeps its separate
// leading-dot compatibility rule.
func validCertificateRFC2821Mailbox(value string) bool {
	if len(value) == 0 {
		return false
	}

	localPart := make([]byte, 0, len(value)/2)
	if value[0] == '"' {
		value = value[1:]
		for {
			if len(value) == 0 {
				return false
			}
			character := value[0]
			value = value[1:]
			switch {
			case character == '"':
				goto quotedStringDone
			case character == '\\':
				if len(value) == 0 {
					return false
				}
				escaped := value[0]
				if escaped != 11 && escaped != 12 &&
					!(escaped >= 1 && escaped <= 9) &&
					!(escaped >= 14 && escaped <= 127) {
					return false
				}
				localPart = append(localPart, escaped)
				value = value[1:]
			case character == 11 || character == 12 || character == 32 || character == 33 ||
				character == 127 || (character >= 1 && character <= 8) ||
				(character >= 14 && character <= 31) || (character >= 35 && character <= 91) ||
				(character >= 93 && character <= 126):
				localPart = append(localPart, character)
			default:
				return false
			}
		}
	quotedStringDone:
	} else {
		for len(value) > 0 {
			character := value[0]
			switch {
			case character == '\\':
				value = value[1:]
				if len(value) == 0 {
					return false
				}
				localPart = append(localPart, value[0])
				value = value[1:]
			case (character >= '0' && character <= '9') ||
				(character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				character == '!' || character == '#' || character == '$' || character == '%' ||
				character == '&' || character == '\'' || character == '*' || character == '+' ||
				character == '-' || character == '/' || character == '=' || character == '?' ||
				character == '^' || character == '_' || character == '`' || character == '{' ||
				character == '|' || character == '}' || character == '~' || character == '.':
				localPart = append(localPart, character)
				value = value[1:]
			default:
				goto atomDone
			}
		}
	atomDone:
		if len(localPart) == 0 || localPart[0] == '.' || localPart[len(localPart)-1] == '.' ||
			bytes.Contains(localPart, []byte("..")) {
			return false
		}
	}

	if len(value) == 0 || value[0] != '@' {
		return false
	}
	value = value[1:]
	return len(value) > 0 && value[0] != '.' && validCertificateNameConstraintDomain([]byte(value))
}

// validCertificatePolicyConstraintsRepresentation preserves the parser-derived
// presence markers for policyConstraints (2.5.29.36) and inhibitAnyPolicy
// (2.5.29.54). A positive counter or an explicit zero can only be produced
// when its corresponding extension is present. Go's parser also accepts a
// policyConstraints sequence with neither optional field, so that extension
// may be present without a derived counter; the value validator still requires
// its source to be parser-compatible. The zero-value and -1 partial
// reverse-proxy forms remain compatible when Extensions is omitted.
func validCertificatePolicyConstraintsRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	foundPolicyConstraints := false
	foundInhibitAnyPolicy := false
	for _, extension := range certificate.Extensions {
		switch {
		case equalIntSlice(extension.Id, []int{2, 5, 29, 36}):
			foundPolicyConstraints = true
		case equalIntSlice(extension.Id, []int{2, 5, 29, 54}):
			foundInhibitAnyPolicy = true
		}
	}
	policyConstraintsPresent := certificate.RequireExplicitPolicy > 0 ||
		certificate.RequireExplicitPolicyZero ||
		certificate.InhibitPolicyMapping > 0 ||
		certificate.InhibitPolicyMappingZero
	inhibitAnyPolicyPresent := certificate.InhibitAnyPolicy > 0 || certificate.InhibitAnyPolicyZero
	if policyConstraintsPresent && !foundPolicyConstraints {
		return false
	}
	// Unlike policyConstraints, inhibitAnyPolicy always derives a value from a
	// valid source INTEGER, including its explicit-zero sentinel.
	return foundInhibitAnyPolicy == inhibitAnyPolicyPresent
}

// validCertificatePolicyConstraintValues preserves the parser-visible values
// from policyConstraints (2.5.29.36) and inhibitAnyPolicy (2.5.29.54). Go's
// parser reads the optional context-specific INTEGERs in order, records an
// explicit zero with a companion flag, and ignores trailing fields. An
// omitted Extensions list remains compatible with partial reverse-proxy
// metadata; the representation check above handles source presence.
func validCertificatePolicyConstraintValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		switch {
		case equalIntSlice(extension.Id, []int{2, 5, 29, 36}):
			requireExplicitPolicy, requireExplicitPolicyZero, inhibitPolicyMapping, inhibitPolicyMappingZero, ok :=
				parseCertificatePolicyConstraints(extension.Value)
			if !ok ||
				requireExplicitPolicy != int64(certificate.RequireExplicitPolicy) ||
				requireExplicitPolicyZero != certificate.RequireExplicitPolicyZero ||
				inhibitPolicyMapping != int64(certificate.InhibitPolicyMapping) ||
				inhibitPolicyMappingZero != certificate.InhibitPolicyMappingZero {
				return false
			}
		case equalIntSlice(extension.Id, []int{2, 5, 29, 54}):
			inhibitAnyPolicy, inhibitAnyPolicyZero, ok := parseCertificateInhibitAnyPolicy(extension.Value)
			if !ok || inhibitAnyPolicy != int64(certificate.InhibitAnyPolicy) ||
				inhibitAnyPolicyZero != certificate.InhibitAnyPolicyZero {
				return false
			}
		}
	}
	return true
}

func parseCertificatePolicyConstraints(value []byte) (requireExplicitPolicy int64, requireExplicitPolicyZero bool, inhibitPolicyMapping int64, inhibitPolicyMappingZero bool, ok bool) {
	sequence, _, err := unmarshalCertificateRawValue(value)
	if err != nil || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return 0, false, 0, false, false
	}
	remaining := sequence.Bytes
	if len(remaining) > 0 {
		field, rest, err := unmarshalCertificateRawValue(remaining)
		if err != nil {
			return 0, false, 0, false, false
		}
		if field.Class == 2 && field.Tag == 0 && !field.IsCompound {
			requireExplicitPolicy, ok = parseCertificateContextInteger(field.Bytes)
			if !ok {
				return 0, false, 0, false, false
			}
			requireExplicitPolicyZero = requireExplicitPolicy == 0
			remaining = rest
		}
	}
	if len(remaining) > 0 {
		field, _, err := unmarshalCertificateRawValue(remaining)
		if err != nil {
			return 0, false, 0, false, false
		}
		if field.Class == 2 && field.Tag == 1 && !field.IsCompound {
			inhibitPolicyMapping, ok = parseCertificateContextInteger(field.Bytes)
			if !ok {
				return 0, false, 0, false, false
			}
			inhibitPolicyMappingZero = inhibitPolicyMapping == 0
		}
	}
	return requireExplicitPolicy, requireExplicitPolicyZero, inhibitPolicyMapping, inhibitPolicyMappingZero, true
}

func parseCertificateContextInteger(value []byte) (int64, bool) {
	if len(value) == 0 {
		return 0, false
	}
	encoded, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 2, Bytes: value})
	if err != nil {
		return 0, false
	}
	var integer int64
	remaining, err := asn1.Unmarshal(encoded, &integer)
	return integer, err == nil && len(remaining) == 0
}

func parseCertificateInhibitAnyPolicy(value []byte) (inhibitAnyPolicy int64, inhibitAnyPolicyZero bool, ok bool) {
	var integer asn1.RawValue
	if _, err := asn1.Unmarshal(value, &integer); err != nil ||
		integer.Class != 0 || integer.Tag != 2 || integer.IsCompound {
		return 0, false, false
	}
	inhibitAnyPolicy, ok = parseCertificateContextInteger(integer.Bytes)
	if !ok || int64(int(inhibitAnyPolicy)) != inhibitAnyPolicy {
		return 0, false, false
	}
	return inhibitAnyPolicy, inhibitAnyPolicy == 0, true
}

// validCertificateUnhandledCriticalExtensions preserves the relationship
// crypto/x509 exposes between a parsed Extensions list and
// UnhandledCriticalExtensions. A full parsed certificate records exactly the
// critical extensions that processExtensions could not handle; a marker-only
// value remains valid for partial reverse-proxy metadata.
func validCertificateUnhandledCriticalExtensions(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return validUniqueCertificateOIDs(certificate.UnhandledCriticalExtensions)
	}
	if !validUniqueCertificateOIDs(certificate.UnhandledCriticalExtensions) {
		return false
	}
	expected := make([][]int, 0, len(certificate.Extensions))
	for _, extension := range certificate.Extensions {
		if !extension.Critical {
			continue
		}
		if certificateExtensionRequiresUnhandledCriticalMarker(certificate, extension) {
			expected = append(expected, extension.Id)
		}
	}
	if len(expected) != len(certificate.UnhandledCriticalExtensions) {
		return false
	}
	for index, unhandled := range certificate.UnhandledCriticalExtensions {
		if !equalIntSlice(unhandled, expected[index]) {
			return false
		}
	}
	return true
}

// certificateExtensionRequiresUnhandledCriticalMarker mirrors the cases where
// crypto/x509's processExtensions leaves a critical extension unhandled. Most
// recognized extensions are handled unconditionally; SAN and name constraints
// are marked unhandled when they contain no supported values. Unknown critical
// extensions always require the corresponding marker.
func certificateExtensionRequiresUnhandledCriticalMarker(certificate *x509.Certificate, extension pkix.Extension) bool {
	switch {
	case equalIntSlice(extension.Id, []int{2, 5, 29, 14}), // subjectKeyIdentifier
		equalIntSlice(extension.Id, []int{2, 5, 29, 15}),              // keyUsage
		equalIntSlice(extension.Id, []int{2, 5, 29, 19}),              // basicConstraints
		equalIntSlice(extension.Id, []int{2, 5, 29, 31}),              // cRLDistributionPoints
		equalIntSlice(extension.Id, []int{2, 5, 29, 32}),              // certificatePolicies
		equalIntSlice(extension.Id, []int{2, 5, 29, 33}),              // policyMappings
		equalIntSlice(extension.Id, []int{2, 5, 29, 35}),              // authorityKeyIdentifier
		equalIntSlice(extension.Id, []int{2, 5, 29, 36}),              // policyConstraints
		equalIntSlice(extension.Id, []int{2, 5, 29, 37}),              // extKeyUsage
		equalIntSlice(extension.Id, []int{2, 5, 29, 54}),              // inhibitAnyPolicy
		equalIntSlice(extension.Id, []int{1, 3, 6, 1, 5, 5, 7, 1, 1}): // authorityInfoAccess
		return false
	case equalIntSlice(extension.Id, []int{2, 5, 29, 17}): // subjectAltName
		return len(certificate.DNSNames) == 0 && len(certificate.EmailAddresses) == 0 &&
			len(certificate.IPAddresses) == 0 && len(certificate.URIs) == 0
	case equalIntSlice(extension.Id, []int{2, 5, 29, 30}): // nameConstraints
		return !certificateHasParsedNameConstraintData(certificate) ||
			certificateHasUnhandledCriticalMarker(certificate, extension.Id)
	default:
		return true
	}
}

func certificateHasUnhandledCriticalMarker(certificate *x509.Certificate, id []int) bool {
	for _, unhandled := range certificate.UnhandledCriticalExtensions {
		if equalIntSlice(unhandled, id) {
			return true
		}
	}
	return false
}

func certificateHasParsedNameConstraintData(certificate *x509.Certificate) bool {
	return len(certificate.PermittedDNSDomains) > 0 || len(certificate.ExcludedDNSDomains) > 0 ||
		len(certificate.PermittedIPRanges) > 0 || len(certificate.ExcludedIPRanges) > 0 ||
		len(certificate.PermittedEmailAddresses) > 0 || len(certificate.ExcludedEmailAddresses) > 0 ||
		len(certificate.PermittedURIDomains) > 0 || len(certificate.ExcludedURIDomains) > 0
}

// validUniqueCertificateOIDs mirrors the parser's one-entry-per-extension
// representation. UnhandledCriticalExtensions is derived from the parsed
// extension sequence, so a duplicate marker OID cannot occur on a parsed
// certificate. Keep the marker-only partial reverse-proxy form compatible
// when its entries are unique.
func validUniqueCertificateOIDs(values []asn1.ObjectIdentifier) bool {
	for index, value := range values {
		for _, previous := range values[:index] {
			if equalIntSlice(value, previous) {
				return false
			}
		}
	}
	return true
}

// validCertificateSerialNumber mirrors the positive INTEGER required by an
// X.509 certificate while retaining nil for synthetic metadata that does not
// provide a serial number. Direct callers must not hand the transport verifier
// a zero or negative serial value that could not come from a parsed certificate.
// Count the copied integer against the aggregate certificate budget as well as
// enforcing its per-value bound, so a peer chain cannot multiply snapshot
// memory by supplying many individually bounded serial numbers.
func validCertificateSerialNumber(value *big.Int, total *int) bool {
	if value == nil || value.Sign() <= 0 || value.BitLen() > maxMCPTLSCertificateBytes*8 {
		return value == nil
	}
	return addBoundedBytes(total, certificatePublicKeyBigIntBytes(value), maxMCPTLSCertificateBytes)
}

func validBoundedCertificateOpaqueOID(value x509.OID, total *int) bool {
	der, err := value.MarshalBinary()
	if err != nil || len(der) == 0 || len(der) > maxMCPTLSCertificateBytes {
		return false
	}
	return addBoundedBytes(total, len(der), maxMCPTLSCertificateBytes)
}

func validBoundedCertificateOpaqueOIDs(values []x509.OID, total *int) bool {
	if len(values) > maxMCPTLSCertificateValues {
		return false
	}
	for _, value := range values {
		if !validBoundedCertificateOpaqueOID(value, total) {
			return false
		}
	}
	return true
}

// validCertificatePolicies mirrors crypto/x509's certificate-policy parser,
// which rejects a policy OID repeated in the same extension. The opaque
// Policies field is the complete Go 1.24 representation, so duplicate values
// cannot come from a parsed certificate. PolicyIdentifiers remains a separate
// partial-compatible representation when callers do not provide Policies.
func validCertificatePolicies(values []x509.OID) bool {
	for index, value := range values {
		for _, previous := range values[:index] {
			if value.Equal(previous) {
				return false
			}
		}
	}
	return true
}

// validCertificatePolicyIdentifiers mirrors crypto/x509's derived policy
// representation. When Policies is present, the parser fills
// PolicyIdentifiers with every policy OID that fits the legacy int32-based
// asn1.ObjectIdentifier type and omits only opaque OIDs that do not. A caller
// may still provide the older partial PolicyIdentifiers-only representation,
// so the relationship is enforced only when Policies is non-empty.
func validCertificatePolicyIdentifiers(policies []x509.OID, identifiers []asn1.ObjectIdentifier) bool {
	if len(policies) == 0 {
		return true
	}
	expected := make([]asn1.ObjectIdentifier, 0, len(policies))
	for _, policy := range policies {
		if identifier, ok := certificateOIDAsASN1(policy); ok {
			expected = append(expected, identifier)
		}
	}
	if len(expected) != len(identifiers) {
		return false
	}
	for index, identifier := range identifiers {
		if !equalIntSlice(expected[index], identifier) {
			return false
		}
	}
	return true
}

// validCertificatePolicyRepresentation preserves the parser-derived source
// relationship for non-empty Policies. The standard library populates
// Policies only from the certificate policies extension (2.5.29.32); an
// omitted Extensions list remains compatible with partial reverse-proxy
// metadata.
func validCertificatePolicyRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 || len(certificate.Policies) == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if equalIntSlice(extension.Id, []int{2, 5, 29, 32}) {
			return true
		}
	}
	return false
}

// validCertificatePolicyValues preserves the parser-visible ordered OIDs for
// the certificate policies extension (2.5.29.32). Go 1.24 ignores bytes after
// the outer SEQUENCE and trailing policy qualifiers after each policy OID, so
// the bounded parser below does the same while retaining the required ASN.1
// sequence and primitive OID shapes. An omitted Extensions list and an opaque
// marker-only source remain compatible with partial metadata; a DER-shaped
// source is parsed even when it produces an empty Policies list.
func validCertificatePolicyValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if !equalIntSlice(extension.Id, []int{2, 5, 29, 32}) {
			continue
		}
		if len(certificate.Policies) == 0 &&
			(len(extension.Value) == 0 || extension.Value[0] != 0x30) {
			// Preserve opaque marker-only metadata used by trusted reverse
			// proxies. A DER-shaped source is parsed below, including the
			// parser-compatible empty SEQUENCE form.
			return true
		}
		values, ok := parseCertificatePolicies(extension.Value)
		return ok && equalCertificateOpaqueOIDValues(values, certificate.Policies)
	}
	return len(certificate.Policies) == 0
}

// validCertificatePolicyIdentifierValues preserves the parser-derived legacy
// PolicyIdentifiers slice when a full Extensions list is supplied. Go 1.24
// derives this slice from the same certificatePolicies source as Policies,
// omitting only opaque OIDs that cannot fit the legacy ASN.1-int form. An
// omitted Extensions list remains compatible with partial reverse-proxy
// metadata that supplies PolicyIdentifiers on its own.
func validCertificatePolicyIdentifierValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 || len(certificate.PolicyIdentifiers) == 0 || len(certificate.Policies) > 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if !equalIntSlice(extension.Id, []int{2, 5, 29, 32}) {
			continue
		}
		policies, ok := parseCertificatePolicies(extension.Value)
		if !ok {
			return false
		}
		identifiers := make([]asn1.ObjectIdentifier, 0, len(policies))
		for _, policy := range policies {
			if identifier, fits := certificateOIDAsASN1(policy); fits {
				identifiers = append(identifiers, identifier)
			}
		}
		if len(identifiers) != len(certificate.PolicyIdentifiers) {
			return false
		}
		for index, identifier := range identifiers {
			if !equalIntSlice(identifier, certificate.PolicyIdentifiers[index]) {
				return false
			}
		}
		return true
	}
	return len(certificate.PolicyIdentifiers) == 0
}

func parseCertificatePolicies(value []byte) ([]x509.OID, bool) {
	sequence, _, err := unmarshalCertificateRawValue(value)
	if err != nil || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return nil, false
	}
	var policies []x509.OID
	for remaining := sequence.Bytes; len(remaining) > 0; {
		policyInformation, next, err := unmarshalCertificateRawValue(remaining)
		if err != nil || policyInformation.Class != 0 || policyInformation.Tag != 16 || !policyInformation.IsCompound {
			return nil, false
		}
		remaining = next

		encoded, _, err := unmarshalCertificateRawValue(policyInformation.Bytes)
		if err != nil || encoded.Class != 0 || encoded.Tag != 6 || encoded.IsCompound {
			return nil, false
		}
		var policy x509.OID
		if err := policy.UnmarshalBinary(encoded.Bytes); err != nil {
			return nil, false
		}
		policies = append(policies, policy)
	}
	return policies, true
}

// certificateOIDAsASN1 decodes the canonical DER content held by x509.OID
// into the narrower legacy asn1.ObjectIdentifier representation. The standard
// library uses the same int32 component limit when deriving
// Certificate.PolicyIdentifiers from Certificate.Policies.
func certificateOIDAsASN1(value x509.OID) (asn1.ObjectIdentifier, bool) {
	der, err := value.MarshalBinary()
	if err != nil || len(der) == 0 {
		return nil, false
	}
	const maxASN1OIDComponent = int64(1<<31 - 1)
	readComponent := func(offset int) (int64, int, bool) {
		var component int64
		for count := 0; offset < len(der); count++ {
			if count == 5 || (count > 0 && der[offset] == 0x80) {
				return 0, offset, false
			}
			component = component<<7 | int64(der[offset]&0x7f)
			if component > maxASN1OIDComponent {
				return 0, offset, false
			}
			byteValue := der[offset]
			offset++
			if byteValue&0x80 == 0 {
				return component, offset, true
			}
		}
		return 0, offset, false
	}

	first, offset, ok := readComponent(0)
	if !ok {
		return nil, false
	}
	identifier := make(asn1.ObjectIdentifier, 0, 2)
	switch {
	case first < 40:
		identifier = append(identifier, 0, int(first))
	case first < 80:
		identifier = append(identifier, 1, int(first-40))
	default:
		identifier = append(identifier, 2, int(first-80))
	}
	for offset < len(der) {
		component, next, ok := readComponent(offset)
		if !ok {
			return nil, false
		}
		identifier = append(identifier, int(component))
		offset = next
	}
	return identifier, true
}

func validBoundedCertificatePolicyMappings(values []x509.PolicyMapping, total *int) bool {
	if len(values) > maxMCPTLSCertificateValues {
		return false
	}
	for _, value := range values {
		if !validBoundedCertificateOpaqueOID(value.IssuerDomainPolicy, total) ||
			!validBoundedCertificateOpaqueOID(value.SubjectDomainPolicy, total) ||
			isCertificateAnyPolicy(value.IssuerDomainPolicy) ||
			isCertificateAnyPolicy(value.SubjectDomainPolicy) {
			return false
		}
	}
	return true
}

// validCertificatePolicyMappingsRepresentation preserves the parser-derived
// relationship between a non-empty PolicyMappings list and the full
// Extensions representation. Marker-only partial reverse-proxy metadata
// remains compatible when Extensions is omitted.
func validCertificatePolicyMappingsRepresentation(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 || len(certificate.PolicyMappings) == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if equalIntSlice(extension.Id, []int{2, 5, 29, 33}) {
			return true
		}
	}
	return false
}

// validCertificatePolicyMappingValues preserves the parser-visible ordered OID
// pairs for the Policy Mappings extension (2.5.29.33). Go 1.24 stores these
// OIDs as opaque x509.OID values, so compare their canonical DER content
// rather than narrowing them to legacy ASN.1 integer arcs. An omitted
// Extensions list and an opaque marker-only source remain compatible with
// partial metadata, while a DER-shaped source is parsed even when it produces
// an empty mapping list.
func validCertificatePolicyMappingValues(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return true
	}
	for _, extension := range certificate.Extensions {
		if !equalIntSlice(extension.Id, []int{2, 5, 29, 33}) {
			continue
		}
		if len(certificate.PolicyMappings) == 0 &&
			(len(extension.Value) == 0 || extension.Value[0] != 0x30) {
			// Preserve opaque marker-only metadata used by trusted reverse
			// proxies. A DER-shaped source is still parsed below, including
			// the parser-compatible empty SEQUENCE form.
			return true
		}
		values, ok := parseCertificatePolicyMappings(extension.Value)
		return ok && equalCertificatePolicyMappings(cloneCertificatePolicyMappings(values), certificate.PolicyMappings)
	}
	return len(certificate.PolicyMappings) == 0
}

func parseCertificatePolicyMappings(value []byte) ([]x509.PolicyMapping, bool) {
	sequence, _, err := unmarshalCertificateRawValue(value)
	if err != nil || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return nil, false
	}
	var mappings []x509.PolicyMapping
	for remaining := sequence.Bytes; len(remaining) > 0; {
		mapping, next, err := unmarshalCertificateRawValue(remaining)
		if err != nil || mapping.Class != 0 || mapping.Tag != 16 || !mapping.IsCompound {
			return nil, false
		}
		remaining = next

		issuer, remainingMapping, ok := parseCertificatePolicyMappingOID(mapping.Bytes)
		if !ok {
			return nil, false
		}
		subject, _, ok := parseCertificatePolicyMappingOID(remainingMapping)
		if !ok {
			return nil, false
		}
		// crypto/x509 reads the two policy OIDs and intentionally ignores
		// trailing fields in the mapping SEQUENCE. Keep the source/value
		// comparison parser-compatible while still requiring both OIDs to be
		// valid primitive values.
		mappings = append(mappings, x509.PolicyMapping{
			IssuerDomainPolicy:  issuer,
			SubjectDomainPolicy: subject,
		})
	}
	return mappings, true
}

func parseCertificatePolicyMappingOID(value []byte) (x509.OID, []byte, bool) {
	encoded, rest, err := unmarshalCertificateRawValue(value)
	if err != nil || encoded.Class != 0 || encoded.Tag != 6 || encoded.IsCompound {
		return x509.OID{}, nil, false
	}
	var oid x509.OID
	if err := oid.UnmarshalBinary(encoded.Bytes); err != nil {
		return x509.OID{}, nil, false
	}
	return oid, rest, true
}

// isCertificateAnyPolicy identifies the special anyPolicy OID. RFC 5280
// prohibits anyPolicy in either side of a policyMappings entry; direct
// callers can construct PolicyMapping values without going through the
// certificate parser, so reject that representation before transport
// metadata is treated as authenticated.
func isCertificateAnyPolicy(value x509.OID) bool {
	anyPolicy, err := x509.OIDFromInts([]uint64{2, 5, 29, 32, 0})
	return err == nil && value.Equal(anyPolicy)
}

func validCertificatePolicyConstraint(value int, zero bool) bool {
	return value >= -1 && (!zero || value == 0)
}

func validBoundedCertificateName(name pkix.Name, total *int) bool {
	for _, values := range [][]string{
		name.Country,
		name.Organization,
		name.OrganizationalUnit,
		name.Locality,
		name.Province,
		name.StreetAddress,
		name.PostalCode,
	} {
		if len(values) > maxMCPTLSCertificateValues || !validBoundedCertificateStrings(values, total) {
			return false
		}
	}
	if !validBoundedCertificateString(name.SerialNumber, total) ||
		!validBoundedCertificateString(name.CommonName, total) ||
		!validBoundedCertificateAttributes(name.Names, total) ||
		!validBoundedCertificateAttributes(name.ExtraNames, total) {
		return false
	}
	return true
}

func validBoundedCertificateAttributes(values []pkix.AttributeTypeAndValue, total *int) bool {
	if len(values) > maxMCPTLSCertificateValues {
		return false
	}
	for _, value := range values {
		stringValue, ok := value.Value.(string)
		if !ok || !validBoundedCertificateOID(value.Type, total) || !validBoundedCertificateString(stringValue, total) {
			return false
		}
	}
	return true
}

func validBoundedCertificateOIDs(values []asn1.ObjectIdentifier, total *int) bool {
	if len(values) > maxMCPTLSCertificateValues {
		return false
	}
	for _, value := range values {
		if !validBoundedCertificateOID(value, total) {
			return false
		}
	}
	return true
}

func validBoundedCertificateOID(value []int, total *int) bool {
	if len(value) > maxMCPTLSCertificateValues || !validCertificateOID(value) {
		return false
	}
	return addBoundedBytes(total, len(value)*4, maxMCPTLSCertificateBytes)
}

func validBoundedCertificateStrings(values []string, total *int) bool {
	if len(values) > maxMCPTLSCertificateValues {
		return false
	}
	for _, value := range values {
		if !validBoundedCertificateString(value, total) {
			return false
		}
	}
	return true
}

func validBoundedCertificateString(value string, total *int) bool {
	return len(value) <= maxMCPTLSCertificateStringBytes &&
		validCertificateText(value) &&
		addBoundedBytes(total, len(value), maxMCPTLSCertificateBytes)
}

func validBoundedCertificateIPs(values []net.IP, total *int) bool {
	if len(values) > maxMCPTLSCertificateValues {
		return false
	}
	for _, value := range values {
		if len(value) != net.IPv4len && len(value) != net.IPv6len {
			return false
		}
		if !addBoundedBytes(total, len(value), maxMCPTLSCertificateBytes) {
			return false
		}
	}
	return true
}

func validBoundedCertificateIPNets(values []*net.IPNet, total *int) bool {
	if len(values) > maxMCPTLSCertificateValues {
		return false
	}
	for _, value := range values {
		if value == nil || (len(value.IP) != net.IPv4len && len(value.IP) != net.IPv6len) ||
			(len(value.Mask) != net.IPv4len && len(value.Mask) != net.IPv6len) ||
			len(value.IP) != len(value.Mask) || !validCertificateIPMask(value.Mask) {
			return false
		}
		if !addBoundedBytes(total, len(value.IP), maxMCPTLSCertificateBytes) ||
			!addBoundedBytes(total, len(value.Mask), maxMCPTLSCertificateBytes) {
			return false
		}
	}
	return true
}

// validCertificateIPMask mirrors crypto/x509's name-constraint parser: an IP
// range uses an equally sized IPv4 or IPv6 address and a contiguous mask of
// ones followed by zeroes. Direct callers can construct *net.IPNet values that
// bypass that parser, so reject impossible ranges before transport metadata is
// treated as authenticated.
func validCertificateIPMask(mask net.IPMask) bool {
	seenZero := false
	for _, value := range mask {
		if seenZero {
			if value != 0 {
				return false
			}
			continue
		}
		switch value {
		case 0xff:
		case 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe:
			seenZero = true
		default:
			return false
		}
	}
	return true
}

func validCertificateText(value string) bool {
	return !containsURLControlByte(value) && !containsUnicodeControlOrFormat(value)
}

func validBoundedCertificateURLs(values []*url.URL, total *int) bool {
	for _, value := range values {
		if value == nil || len(value.Scheme) > maxMCPTLSCertificateStringBytes ||
			len(value.Opaque) > maxMCPTLSCertificateStringBytes ||
			len(value.Host) > maxMCPTLSCertificateStringBytes ||
			len(value.Path) > maxMCPTLSCertificateStringBytes ||
			len(value.RawPath) > maxMCPTLSCertificateStringBytes ||
			len(value.RawQuery) > maxMCPTLSCertificateStringBytes ||
			len(value.Fragment) > maxMCPTLSCertificateStringBytes ||
			len(value.RawFragment) > maxMCPTLSCertificateStringBytes {
			return false
		}
		if !validCertificateURLStructure(value) {
			return false
		}
		if value.User != nil && len(value.User.String()) > maxMCPTLSCertificateStringBytes {
			return false
		}
		if value.User != nil {
			username := value.User.Username()
			password, passwordSet := value.User.Password()
			// Userinfo.String percent-escapes control and format characters.
			// Validate the raw components as well, otherwise a synthetic URI
			// could carry callback-visible identity that looks harmless only
			// after rendering.
			if !validCertificateText(username) || (passwordSet && !validCertificateText(password)) {
				return false
			}
		}
		for _, component := range []string{value.Scheme, value.Opaque, value.Host, value.Path, value.RawPath, value.RawQuery, value.Fragment, value.RawFragment} {
			if !validCertificateText(component) || !addBoundedBytes(total, len(component), maxMCPTLSCertificateBytes) {
				return false
			}
		}
		if value.User != nil && (!validCertificateText(value.User.String()) ||
			!addBoundedBytes(total, len(value.User.String()), maxMCPTLSCertificateBytes)) {
			return false
		}
	}
	return true
}

// validCertificateURLStructure rejects URL structs that could not have come
// from a successful net/url parse. x509.ParseCertificate supplies coherent
// URI values, but direct callers can construct a *url.URL with an invalid raw
// escape or contradictory opaque/path fields before the transport verifier
// sees the certificate metadata.
func validCertificateURLStructure(value *url.URL) bool {
	if value.Scheme != "" && !validURLScheme(value.Scheme) {
		return false
	}
	// Raw query and fragment delimiters terminate URI components in their wire
	// representation. Direct callers must percent-encode them when they are
	// data; otherwise opaque data or RawPath can serialize to a different
	// certificate URI than the parsed fields describe. RawQuery may contain '?'
	// as query data, but an opaque value cannot because '?' starts its query.
	if strings.Contains(value.Opaque, "?") || strings.Contains(value.RawPath, "?") ||
		strings.Contains(value.Opaque, "#") || strings.Contains(value.RawPath, "#") ||
		strings.Contains(value.RawQuery, "#") || strings.Contains(value.RawFragment, "#") {
		return false
	}
	if value.RawPath != "" {
		path, err := url.PathUnescape(value.RawPath)
		if err != nil || path != value.Path {
			return false
		}
	}
	if value.RawFragment != "" {
		fragment, err := url.PathUnescape(value.RawFragment)
		if err != nil || fragment != value.Fragment {
			return false
		}
	}
	if !validURLRawQuery(value.Opaque) || !validURLRawQuery(value.RawQuery) || !validURLRawQuery(value.RawFragment) {
		return false
	}
	if value.Opaque != "" && (value.Host != "" || value.Path != "" || value.RawPath != "" || value.ForceQuery) {
		return false
	}
	return value.User == nil || value.Host != ""
}

func validBoundedCertificateExtensions(values []pkix.Extension, total *int) bool {
	for _, value := range values {
		if !validCertificateOID(value.Id) || len(value.Id) > maxMCPTLSCertificateValues || len(value.Value) > maxMCPTLSCertificateBytes ||
			!addBoundedBytes(total, len(value.Value), maxMCPTLSCertificateBytes) {
			return false
		}
	}
	return true
}

// validCertificateExtensionOIDs mirrors crypto/x509's certificate parser,
// which rejects duplicate extension OIDs in one extensions sequence. The
// public Certificate type keeps Extensions and ExtraExtensions as separate
// representations for parsed and certificate-generation callers, so validate
// each list independently while preserving that partial-metadata compatibility.
func validCertificateExtensionOIDs(values []pkix.Extension) bool {
	for index, value := range values {
		for _, previous := range values[:index] {
			if equalIntSlice(value.Id, previous.Id) {
				return false
			}
		}
	}
	return true
}

func validCertificateOID(value []int) bool {
	if len(value) == 0 || value[0] < 0 || value[0] > 2 {
		return false
	}
	if len(value) > 1 && (value[1] < 0 || value[0] < 2 && value[1] > 39) {
		return false
	}
	for _, arc := range value[2:] {
		if arc < 0 {
			return false
		}
	}
	return true
}

func addBoundedBytes(total *int, amount int, limit int) bool {
	if amount < 0 || amount > limit-*total {
		return false
	}
	*total += amount
	return true
}

// addBoundedDirectTLSSCT accounts for the two-byte length on each SCT and the
// two-byte outer vector length. The caller's total tracks the encoded entries
// inside that outer vector; reserving its prefix keeps the complete serialized
// value within crypto/tls's uint16 wire bound.
func addBoundedDirectTLSSCT(total *int, timestamp []byte) bool {
	if len(timestamp) == 0 || len(timestamp) > maxDirectTLSSCTBytes-2*tlsVectorLengthBytes {
		return false
	}
	return addBoundedBytes(total, tlsVectorLengthBytes+len(timestamp), maxDirectTLSSCTBytes-tlsVectorLengthBytes)
}

// validDirectRequestMetadata bounds request-target and URL-component
// inspection before invoking deployment-owned security callbacks. Normal
// net/http serving has already parsed a bounded wire request, but direct
// library callers can construct arbitrary strings on http.Request and
// url.URL. The aggregate check covers both raw RequestURI and the parsed URL
// representation without serializing the URL or allocating another copy.
func validDirectRequestMetadata(r *http.Request) bool {
	if r == nil || r.URL == nil || len(r.RequestURI) > maxMCPRequestTargetBytes ||
		!validDirectRequestHost(r) || !validDirectTransportMetadata(r) || !validDirectRequestPattern(r) ||
		!validDirectRequestContext(r) {
		return false
	}
	// Fragments are never part of an HTTP request target. Reject them before
	// any deployment-owned transport verifier sees direct-call metadata; a
	// custom reverse-proxy verifier must not be the only component that notices
	// a request target net/http would discard or reinterpret. A raw fragment
	// delimiter in escaped path/query data is equally malformed, while an
	// percent-encoded hash remains ordinary request-target data.
	if strings.Contains(r.RequestURI, "#") || containsUnicodeControlOrFormat(r.RequestURI) ||
		containsUnicodeControlOrFormat(r.Host) {
		return false
	}
	total := 0
	for _, component := range []string{
		r.URL.Scheme,
		r.URL.Opaque,
		r.URL.Host,
		r.URL.Path,
		r.URL.RawPath,
		r.URL.RawQuery,
		r.URL.Fragment,
		r.URL.RawFragment,
	} {
		if containsURLControlByte(component) || containsUnicodeControlOrFormat(component) {
			return false
		}
		if len(component) > maxMCPRequestTargetBytes-total {
			return false
		}
		total += len(component)
	}
	if r.URL.User != nil {
		// Userinfo is not transport identity metadata for this boundary. A
		// direct caller can populate URL.User without going through URL
		// parsing, and a custom reverse-proxy verifier must not receive it as
		// callback-visible request metadata even if it would otherwise ignore
		// the field. RequireDirectTLS applies the same rule independently.
		return false
	}
	// Opaque and scheme-only URLs are not HTTP request-target metadata. A
	// direct caller can populate these fields without going through net/url;
	// reject them before a custom reverse-proxy verifier sees a shape that the
	// HTTP transport would not route as an ordinary request.
	if r.URL.Opaque != "" || (r.URL.Scheme != "" && r.URL.Host == "") {
		return false
	}
	if r.URL.Scheme != "" && !validURLScheme(r.URL.Scheme) {
		return false
	}
	if r.URL.Host != "" && !validDirectTLSAuthority(r.URL.Host) {
		return false
	}
	if r.URL.Fragment != "" || r.URL.RawFragment != "" ||
		strings.Contains(r.URL.RawPath, "#") || strings.Contains(r.URL.RawQuery, "#") {
		return false
	}
	if r.URL.RawPath != "" {
		path, err := url.PathUnescape(r.URL.RawPath)
		if err != nil || path != r.URL.Path {
			return false
		}
	}
	if !validURLRawQuery(r.URL.RawQuery) {
		return false
	}
	return directRequestTargetIsConsistent(r)
}

// validDirectRequestContext keeps the request context identity comparable so
// the body-boundary snapshot can prove that deployment-owned authentication
// sees the same context as transport verification. Standard net/http contexts
// are pointer- or value-comparable; an arbitrary uncomparable implementation
// is rejected before either security callback because it cannot be snapshotted
// safely without inventing a weaker equality rule.
func validDirectRequestContext(r *http.Request) bool {
	if r == nil {
		return false
	}
	contextValue := r.Context()
	return contextValue != nil && reflect.TypeOf(contextValue).Comparable()
}

// validDirectRequestBody rejects nil, typed-nil, and uncomparable bodies
// before a deployment-owned transport verifier sees malformed direct input.
// The post-read snapshot uses body identity, so accepting an uncomparable
// implementation would make a later interface comparison panic instead of
// failing closed.
func validDirectRequestBody(r *http.Request) bool {
	if r == nil || r.Body == nil {
		return false
	}
	bodyValue := reflect.ValueOf(r.Body)
	switch bodyValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if bodyValue.IsNil() {
			return false
		}
	}
	return bodyValue.Type().Comparable()
}

// validDirectRequestPattern bounds the matched ServeMux pattern exposed on a
// server request. Normal net/http routing supplies a configured pattern, but a
// direct library caller can populate it independently of the request target.
// Reject invalid UTF-8 and control/format characters before a deployment-owned
// verifier sees route metadata; ordinary non-ASCII patterns remain valid.
func validDirectRequestPattern(r *http.Request) bool {
	if r == nil || len(r.Pattern) > maxMCPPatternBytes || containsUnicodeControlOrFormat(r.Pattern) {
		return false
	}
	patternMethod, ok := serveMuxPatternMethod(r.Pattern)
	if !ok || patternMethod != "" && patternMethod != r.Method && !(patternMethod == http.MethodGet && r.Method == http.MethodHead) {
		return false
	}
	patternHost, _, ok := serveMuxPatternParts(r.Pattern)
	if !ok || patternHost != "" && !directRequestPatternHostMatches(r, patternHost) {
		return false
	}
	if r.Pattern != "" && (!serveMuxPatternMatchesRequest(r) || !serveMuxPatternPathValuesMatchRequest(r)) {
		return false
	}
	names, ok := requestPathValueNames(r.Pattern)
	if !ok {
		return false
	}
	if !validDirectRequestPathValues(r) {
		return false
	}
	for _, name := range names {
		value := r.PathValue(name)
		if len(value) > maxMCPRequestTargetBytes || containsUnicodeControlOrFormat(value) {
			return false
		}
	}
	return true
}

// serveMuxPatternMatchesRequest asks the standard library's current ServeMux
// matcher to confirm that a non-empty direct-call pattern is coherent with
// the request target. The boundary has already validated the pattern shape,
// method, host, and URL metadata; using a private one-pattern mux here keeps
// wildcard unescaping, CONNECT routing, and path canonicalization aligned with
// net/http instead of maintaining a second matcher with subtly different
// semantics. Invalid patterns or matcher panics fail closed.
func serveMuxPatternMatchesRequest(r *http.Request) (matched bool) {
	if r == nil || r.Pattern == "" || r.URL == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			matched = false
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc(r.Pattern, func(http.ResponseWriter, *http.Request) {})
	_, pattern := mux.Handler(r)
	return pattern == r.Pattern
}

// serveMuxPatternPathValuesMatchRequest routes a clone through the standard
// ServeMux so its unexported wildcard matches become the same public
// Request.PathValue values that a real server would expose. Handler only
// reports the pattern; it does not populate PathValue. Comparing the routed
// clone with the original request prevents a direct caller from presenting a
// matching pattern and URL while substituting a different route parameter.
func serveMuxPatternPathValuesMatchRequest(r *http.Request) (matched bool) {
	if r == nil || r.Pattern == "" || r.URL == nil {
		return false
	}
	names, ok := requestPathValueNames(r.Pattern)
	if !ok || len(names) == 0 {
		return true
	}
	values := make(map[string]string, len(names))
	routed := false
	mux := http.NewServeMux()
	mux.HandleFunc(r.Pattern, func(_ http.ResponseWriter, request *http.Request) {
		routed = true
		for _, name := range names {
			values[name] = request.PathValue(name)
		}
	})
	clone := r.Clone(r.Context())
	mux.ServeHTTP(&discardHTTPResponseWriter{}, clone)
	if !routed {
		return false
	}
	for _, name := range names {
		if values[name] != r.PathValue(name) {
			return false
		}
	}
	return true
}

// discardHTTPResponseWriter keeps the private ServeMux route probe from
// allocating or exposing a response. A valid one-pattern match invokes the
// no-op handler; redirect/not-found paths are discarded and fail closed via
// the routed flag above.
type discardHTTPResponseWriter struct {
	header http.Header
}

func (w *discardHTTPResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (*discardHTTPResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (*discardHTTPResponseWriter) WriteHeader(int) {}

// serveMuxPatternMethod extracts the method qualifier from a validated-shaped
// ServeMux pattern. A pattern without a method matches every method; GET also
// matches HEAD under net/http's standard method semantics. Keeping this check
// at the direct-call boundary prevents a caller from presenting a route label
// whose method disagrees with the request delivered to the callbacks.
func serveMuxPatternMethod(pattern string) (string, bool) {
	if pattern == "" {
		return "", true
	}
	separator := strings.IndexAny(pattern, " \t")
	if separator < 0 {
		return "", true
	}
	method := pattern[:separator]
	if method == "" || !validHTTPHeaderFieldName(method) {
		return "", false
	}
	return method, true
}

// validDirectTransportMetadata bounds scalar request metadata that is visible
// to deployment-owned security callbacks. Normal net/http requests obtain
// these values from a trusted connection, but direct library callers can set
// arbitrary strings on http.Request without going through the parser.
func validDirectTransportMetadata(r *http.Request) bool {
	if r == nil || len(r.Method) > maxMCPMethodBytes ||
		r.Method != "" && !validHTTPHeaderFieldName(r.Method) ||
		len(r.Proto) > maxMCPProtocolBytes || len(r.RemoteAddr) > maxMCPRemoteAddrBytes {
		return false
	}
	if r.Proto == "" {
		// Keep compatibility for synthetic reverse-proxy requests that omit
		// protocol metadata, but reject a half-populated version tuple.
		if r.ProtoMajor != 0 || r.ProtoMinor != 0 {
			return false
		}
	} else {
		major, minor, ok := http.ParseHTTPVersion(r.Proto)
		if !ok || major != r.ProtoMajor || minor != r.ProtoMinor {
			return false
		}
	}
	if !validDirectConnectionClose(r) {
		return false
	}
	return !containsURLControlByte(r.Proto) && !containsURLControlByte(r.RemoteAddr) &&
		!containsUnicodeControlOrFormat(r.Proto) && !containsUnicodeControlOrFormat(r.RemoteAddr)
}

// validDirectConnectionClose mirrors net/http's shouldClose derivation for
// HTTP/1.x requests. A direct caller can otherwise present a Connection header
// that disagrees with Request.Close, giving a deployment-owned callback two
// conflicting views of the same connection policy. An omitted protocol keeps
// compatibility with synthetic reverse-proxy requests; non-HTTP/1 protocols
// retain their deployment-owned metadata contract.
func validDirectConnectionClose(r *http.Request) bool {
	if r == nil || r.Proto == "" || r.ProtoMajor != 1 {
		return true
	}
	values := headerValuesCaseInsensitive(r.Header, "Connection")
	// Match net/http's HeaderValuesContainsToken behavior: spaces, tabs, and
	// commas are token boundaries. Do not replace it with strings.Split on
	// commas, because the standard library deliberately recognizes a token
	// before/after optional whitespace even when a direct caller supplies a
	// non-canonical neighboring value.
	hasClose := headerValuesContainToken(values, "close")
	hasKeepAlive := headerValuesContainToken(values, "keep-alive")
	wantClose := hasClose
	if r.ProtoMinor == 0 {
		wantClose = hasClose || !hasKeepAlive
	}
	return r.Close == wantClose
}

func headerValuesContainToken(values []string, token string) bool {
	if token == "" {
		return false
	}
	for _, value := range values {
		if len(token) > len(value) {
			continue
		}
		for start := 0; start <= len(value)-len(token); start++ {
			if start > 0 && !isHTTPTokenBoundary(value[start-1]) {
				continue
			}
			end := start + len(token)
			if end != len(value) && !isHTTPTokenBoundary(value[end]) {
				continue
			}
			if strings.EqualFold(value[start:end], token) {
				return true
			}
		}
	}
	return false
}

func isHTTPTokenBoundary(value byte) bool {
	return value == ' ' || value == '\t' || value == ','
}

// validDirectServerRequestShape rejects client-only Request fields at the
// additive server boundary. A normal net/http server request does not carry a
// replay body factory, parsed form state, a multipart form, a client cancel
// channel, or a redirect response. Direct callers can populate those fields
// independently of the wire request; keeping them empty prevents either
// deployment-owned security callback from observing metadata that was not
// established by the authenticated server transport. The same check runs
// after body collection so a body reader cannot inject those fields before
// principal resolution.
func validDirectServerRequestShape(r *http.Request) bool {
	return r != nil && !sameHTTPHeaderMap(r.Header, r.Trailer) &&
		!headerNamePresentCaseInsensitive(r.Header, "Trailer") &&
		r.GetBody == nil && r.Form == nil && r.PostForm == nil &&
		r.MultipartForm == nil && r.Cancel == nil && r.Response == nil
}

// sameHTTPHeaderMap rejects a direct caller that aliases the ordinary header
// and trailer maps. net/http always exposes separate collections; sharing one
// map would let a callback mutate one framing view through the other name and
// would make the normalized server-request shape ambiguous.
func sameHTTPHeaderMap(left, right http.Header) bool {
	if left == nil || right == nil {
		return false
	}
	return reflect.ValueOf(left).Pointer() == reflect.ValueOf(right).Pointer()
}

func validURLScheme(scheme string) bool {
	if scheme == "" || !isURLSchemeAlpha(scheme[0]) {
		return false
	}
	for index := 1; index < len(scheme); index++ {
		value := scheme[index]
		if !isURLSchemeAlpha(value) && (value < '0' || value > '9') && value != '+' && value != '-' && value != '.' {
			return false
		}
	}
	return true
}

func isURLSchemeAlpha(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func validURLRawQuery(query string) bool {
	for index := 0; index < len(query); index++ {
		if query[index] != '%' {
			continue
		}
		if index+2 >= len(query) || !isHexByte(query[index+1]) || !isHexByte(query[index+2]) {
			return false
		}
		index += 2
	}
	return true
}

func isHexByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

// validDirectRequestHost bounds the separate Host field exposed by
// net/http.Request. Normal serving has already parsed the authority, but a
// direct library caller can populate Host independently of URL.Host and hand
// the deployment-owned callbacks an unbounded or contradictory authority.
func validDirectRequestHost(r *http.Request) bool {
	if r == nil {
		return false
	}
	// net/http promotes the incoming Host field to Request.Host instead of
	// leaving it in Request.Header. A direct caller that supplies both views
	// would give a transport verifier two potentially different authorities;
	// reject the duplicate rather than inventing a precedence rule.
	if headerNamePresentCaseInsensitive(r.Header, "Host") {
		return false
	}
	if r.Host == "" {
		return r != nil
	}
	if !validDirectTLSAuthority(r.Host) {
		return false
	}
	return r.URL == nil || r.URL.Host == "" || strings.EqualFold(r.Host, r.URL.Host)
}

// validDirectOriginHeader applies the MCP direct-HTTPS DNS-rebinding boundary.
// Non-browser clients commonly omit Origin, but a present browser origin must
// be one exact secure origin for the request authority. Reverse-proxy
// verifiers own the equivalent trusted-origin policy for their deployment.
func validDirectOriginHeader(r *http.Request) bool {
	if r == nil {
		return false
	}
	values := headerValuesCaseInsensitive(r.Header, "Origin")
	if len(values) == 0 {
		return !headerHasEmptyValueCaseInsensitive(r.Header, "Origin")
	}
	if len(values) != 1 || len(values[0]) > maxMCPOriginBytes ||
		containsURLControlByte(values[0]) || containsUnicodeControlOrFormat(values[0]) ||
		strings.ContainsAny(values[0], "?#") {
		return false
	}
	parsed, err := url.Parse(values[0])
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawFragment != "" ||
		!validDirectTLSAuthority(parsed.Host) {
		return false
	}
	if r.URL == nil {
		return false
	}
	expectedAuthority := r.Host
	if r.URL.Host != "" {
		expectedAuthority = r.URL.Host
	}
	if !validDirectTLSAuthority(expectedAuthority) {
		return false
	}
	return sameDirectOriginAuthority(parsed.Host, expectedAuthority)
}

// sameDirectOriginAuthority compares authorities with the URL origin rules:
// host names are case-insensitive and an omitted HTTPS port is equivalent to
// the explicit default port. Both inputs have already passed strict
// direct-authority validation above.
func sameDirectOriginAuthority(left, right string) bool {
	leftURL, err := url.Parse("//" + left)
	if err != nil {
		return false
	}
	rightURL, err := url.Parse("//" + right)
	if err != nil {
		return false
	}
	leftPort := leftURL.Port()
	rightPort := rightURL.Port()
	if leftPort == "" {
		leftPort = "443"
	}
	if rightPort == "" {
		rightPort = "443"
	}
	return strings.EqualFold(leftURL.Hostname(), rightURL.Hostname()) && leftPort == rightPort
}

// containsURLControlByte rejects metadata that cannot appear in an HTTP
// request target. A direct caller can construct url.URL values without going
// through net/url parsing, so this check must cover the parsed components
// before a transport verifier treats them as authenticated HTTPS metadata.
func containsURLControlByte(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return true
		}
	}
	return false
}

// containsUnicodeControlOrFormat rejects Unicode controls, format characters,
// and line/paragraph separators from callback-visible transport metadata.
// Percent-encoded URI data remains ordinary ASCII request-target text; this
// only rejects decoded or directly supplied characters that can render or
// behave differently from the value the caller intended to authenticate.
func containsUnicodeControlOrFormat(value string) bool {
	if !utf8.ValidString(value) {
		return true
	}
	for _, char := range value {
		if unicode.IsControl(char) || unicode.In(char, unicode.Cf, unicode.Zl, unicode.Zp) {
			return true
		}
	}
	return false
}

func validRequestFraming(r *http.Request) bool {
	if r == nil {
		return false
	}
	// net/http normally consumes these fields from the wire and leaves the
	// parsed values on Request. Direct library callers can construct a Header
	// map independently, though; reject metadata that disagrees with the
	// parsed representation instead of allowing two request-boundary views.
	contentLengthHeaders := headerValuesCaseInsensitive(r.Header, "Content-Length")
	if headerHasEmptyValueCaseInsensitive(r.Header, "Content-Length") ||
		(headerNamePresentCaseInsensitive(r.Header, "Content-Length") && len(contentLengthHeaders) == 0) {
		return false
	}
	if len(contentLengthHeaders) > 1 {
		return false
	}
	if len(contentLengthHeaders) == 1 {
		if len(contentLengthHeaders[0]) > maxMCPFramingValueBytes {
			return false
		}
		rawLength := strings.TrimSpace(contentLengthHeaders[0])
		// HTTP Content-Length is 1*DIGIT. Do not let strconv's optional
		// sign syntax make a malformed raw header look like net/http's
		// internal -1 unknown-length sentinel.
		if rawLength == "" {
			return false
		}
		for index := 0; index < len(rawLength); index++ {
			if rawLength[index] < '0' || rawLength[index] > '9' {
				return false
			}
		}
		declared, err := strconv.ParseInt(rawLength, 10, 64)
		if err != nil || declared != r.ContentLength {
			return false
		}
	}
	transferEncodingHeaders := headerValuesCaseInsensitive(r.Header, "Transfer-Encoding")
	if headerHasEmptyValueCaseInsensitive(r.Header, "Transfer-Encoding") ||
		(headerNamePresentCaseInsensitive(r.Header, "Transfer-Encoding") && len(transferEncodingHeaders) == 0) {
		return false
	}
	if len(transferEncodingHeaders) > 0 {
		if len(transferEncodingHeaders[0]) > maxMCPFramingValueBytes {
			return false
		}
		// A valid request has at most one final chunked coding. If a direct
		// caller leaves the raw header in place, it must agree exactly with
		// Request.TransferEncoding and the unknown-length sentinel.
		if len(transferEncodingHeaders) != 1 || len(r.TransferEncoding) != 1 ||
			!strings.EqualFold(strings.TrimSpace(transferEncodingHeaders[0]), "chunked") {
			return false
		}
	}
	if len(r.TransferEncoding) == 0 {
		return true
	}
	if len(r.TransferEncoding[0]) > maxMCPFramingValueBytes {
		return false
	}
	// A valid chunked request has one final transfer-coding token and no
	// Content-Length. The standard library represents its length as -1.
	return len(r.TransferEncoding) == 1 &&
		strings.EqualFold(r.TransferEncoding[0], "chunked") &&
		r.ContentLength == -1
}

// containHTTPResponsePanic keeps a malformed direct caller's response writer
// from crashing the serving process. The best-effort generic error is useful
// only when the writer has not already failed; a second writer panic is
// contained and never exposes the original panic value.
func containHTTPResponsePanic(w http.ResponseWriter) {
	if recover() == nil {
		return
	}
	defer func() { _ = recover() }()
	writeHTTPError(w, http.StatusInternalServerError)
}

// readBoundedRequestBody contains a malformed direct caller's Read method and
// observes cancellation between bounded reads. An underlying Read that blocks
// forever cannot be interrupted by this library, so deployments must still
// provide request bodies whose Read honors request cancellation.
// Normal net/http request bodies are controlled by the server, but this
// library also supports direct integrations. A body panic must fail closed
// before authentication or lifecycle parsing rather than escape the handler.
func readBoundedRequestBody(ctx context.Context, body io.Reader) (data []byte, err error) {
	defer func() {
		if recover() != nil {
			data = nil
			err = errRequestBodyPanic
		}
	}()
	// io.ReadAll retries a (0, nil) read forever. Normal net/http request
	// bodies are well-behaved, but direct library callers can supply any
	// io.Reader, so bound empty-read retries before authentication or parsing.
	return io.ReadAll(io.LimitReader(&progressBoundedReader{Reader: &contextBoundedReader{ctx: ctx, Reader: &validatedRequestBodyReader{Reader: body}}}, maxMCPRequestBytes+1))
}

// validatedRequestBodyReader rejects an invalid io.Reader return count before
// it reaches io.LimitReader or io.ReadAll. A direct library caller can supply
// an arbitrary Reader; accepting n < 0 or n > len(p) would violate the Reader
// contract and could make the standard-library collector index or allocate
// from an attacker-controlled count instead of the bounded byte stream.
type validatedRequestBodyReader struct {
	io.Reader
}

func (r *validatedRequestBodyReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n < 0 || n > len(p) {
		return 0, errRequestBodyInvalidRead
	}
	return n, err
}

type contextBoundedReader struct {
	ctx context.Context
	io.Reader
}

func (r *contextBoundedReader) Read(p []byte) (int, error) {
	if mcpContextDone(r.ctx) {
		return 0, errRequestBodyContextDone
	}
	n, err := r.Reader.Read(p)
	if mcpContextDone(r.ctx) {
		return n, errRequestBodyContextDone
	}
	return n, err
}

type progressBoundedReader struct {
	io.Reader
	emptyReads int
}

func (r *progressBoundedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n == 0 && err == nil {
		r.emptyReads++
		if r.emptyReads >= maxRequestBodyEmptyReads {
			return 0, errRequestBodyNoProgress
		}
	} else if n > 0 {
		r.emptyReads = 0
	}
	return n, err
}

// headerValuesCaseInsensitive mirrors net/http's header-name semantics while
// also handling direct callers that construct a Header map without first
// canonicalizing its keys. A differently cased duplicate must remain visible
// to this boundary instead of being hidden by Header.Values' canonical lookup.
func headerValuesCaseInsensitive(header http.Header, name string) []string {
	var values []string
	found := false
	for key, entries := range header {
		if strings.EqualFold(key, name) {
			if !found {
				found = true
				if entries != nil {
					values = make([]string, 0, len(entries))
				}
			} else if values == nil && entries != nil {
				values = make([]string, 0, len(entries))
			}
			remaining := maxMCPHeaderValues - len(values)
			if remaining <= 0 {
				return values
			}
			if len(entries) > remaining {
				return append(values, entries[:remaining]...)
			}
			values = append(values, entries...)
		}
	}
	if !found {
		return nil
	}
	return values
}

// validDirectHeaderMap bounds field-name inspection for direct library
// callers. Normal net/http serving applies wire-level header-name limits, but
// an in-process caller can construct a map with a small number of enormous
// keys and otherwise force every case-insensitive lookup to scan them.
func validDirectHeaderMap(header http.Header) bool {
	if len(header) > maxMCPHeaderFields {
		return false
	}
	entries := 0
	valueBytes := 0
	for key := range header {
		if len(key) > maxMCPHeaderNameBytes || !validHTTPHeaderFieldName(key) {
			return false
		}
		values := header[key]
		if len(values) > maxMCPHeaderEntries-entries {
			return false
		}
		entries += len(values)
		for _, value := range values {
			if len(value) > maxMCPHeaderValueBytes ||
				valueBytes > maxMCPHeaderBytes-len(value) ||
				!validHTTPHeaderFieldValue(value) {
				return false
			}
			valueBytes += len(value)
		}
	}
	return true
}

// validMCPProtocolVersionHeader validates the optional handshake-era MCP
// transport version marker. A missing header remains compatible with legacy
// initialize callers; when present, exactly one case-insensitive value must
// name the revision implemented by this adapter. Rejecting duplicates and
// alternate spellings keeps a proxy and the lifecycle boundary on one
// negotiated protocol contract.
func validMCPProtocolVersionHeader(header http.Header) bool {
	values := headerValuesCaseInsensitive(header, "MCP-Protocol-Version")
	if len(values) == 0 {
		return !headerHasEmptyValueCaseInsensitive(header, "MCP-Protocol-Version")
	}
	return len(values) == 1 && len(values[0]) <= maxMCPProtocolVersionBytes && values[0] == MCPProtocolVersion
}

// validMCPAuthorizationHeader keeps the generic lifecycle boundary from
// handing ambiguous credentials to a deployment-owned resolver. A missing
// value remains valid for integrations that authenticate through another
// mechanism, such as a reviewed client certificate; when present, the field
// must contain exactly one non-empty value. The resolver still owns scheme,
// token, expiry, audience, and resource validation.
func validMCPAuthorizationHeader(header http.Header) bool {
	values := headerValuesCaseInsensitive(header, "Authorization")
	if len(values) == 0 {
		return !headerHasEmptyValueCaseInsensitive(header, "Authorization")
	}
	return len(values) == 1 && values[0] != ""
}

// validDirectTrailerMap applies the ordinary header bounds and rejects the
// framing fields that net/http never permits in a trailer section. A direct
// caller can populate Request.Trailer without going through HTTP parsing;
// exposing Content-Length, Transfer-Encoding, or Trailer there would give a
// deployment verifier an impossible second framing view after the body.
func validDirectTrailerMap(trailer http.Header) bool {
	if !validDirectHeaderMap(trailer) {
		return false
	}
	for name := range trailer {
		if strings.EqualFold(name, "Content-Length") ||
			strings.EqualFold(name, "Transfer-Encoding") ||
			strings.EqualFold(name, "Trailer") {
			return false
		}
	}
	return true
}

// validHTTPHeaderFieldName applies the RFC 9110 field-name token grammar to
// direct callers. A net/http server has already validated wire header names,
// but an in-process caller can otherwise place spaces or control bytes in a
// map key before a deployment-owned security callback inspects it.
func validHTTPHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		if !isHTTPTokenByte(name[index]) {
			return false
		}
	}
	return true
}

func isHTTPTokenByte(value byte) bool {
	switch {
	case value >= 'a' && value <= 'z':
		return true
	case value >= 'A' && value <= 'Z':
		return true
	case value >= '0' && value <= '9':
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))
}

// validHTTPHeaderFieldValue rejects the control bytes forbidden in an HTTP
// field value while retaining horizontal tab and visible/obs-text bytes. The
// latter are still bounded above; this check only prevents a direct caller
// from smuggling line breaks or other controls into callback-visible metadata.
func validHTTPHeaderFieldValue(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 && value[index] != '\t' || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func headerNamePresentCaseInsensitive(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func headerHasEmptyValueCaseInsensitive(header http.Header, name string) bool {
	for key, values := range header {
		if strings.EqualFold(key, name) && len(values) == 0 {
			return true
		}
	}
	return false
}

// acceptsJSONResponse negotiates the one response representation this
// stateless adapter emits. An absent Accept header is the HTTP default of
// accepting any representation. A client may advertise the usual MCP pair
// (application/json, text/event-stream), but a request that only accepts SSE
// cannot receive this adapter's JSON response.
func acceptsJSONResponse(header http.Header) (accepted, valid bool) {
	values := headerValuesCaseInsensitive(header, "Accept")
	// A direct caller can represent a present header with a nil or empty
	// value slice. Treat that malformed representation differently from an
	// absent header; otherwise it would silently opt into the JSON default.
	if headerHasEmptyValueCaseInsensitive(header, "Accept") {
		return false, false
	}
	if len(values) == 0 {
		return true, true
	}
	total := 0
	bestSpecificity := -1
	bestQuality := 0
	for _, value := range values {
		total += len(value)
		if total > maxMCPAcceptBytes {
			return false, false
		}
		for _, item := range splitAcceptItems(value) {
			item = strings.TrimSpace(item)
			if item == "" {
				return false, false
			}
			mediaType, params, err := mime.ParseMediaType(item)
			if err != nil {
				return false, false
			}
			quality := 1000
			if rawQuality, ok := params["q"]; ok {
				var valid bool
				quality, valid = parseHTTPQuality(rawQuality)
				if !valid {
					return false, false
				}
			}
			specificity := jsonAcceptSpecificity(mediaType)
			if specificity < 0 || specificity < bestSpecificity {
				continue
			}
			if specificity > bestSpecificity || quality > bestQuality {
				bestSpecificity = specificity
				bestQuality = quality
			}
		}
	}
	return bestSpecificity >= 0 && bestQuality > 0, true
}

// parseHTTPQuality enforces the HTTP qvalue grammar used by Accept and returns
// its value as integer thousandths. Floating-point parsing also accepts
// exponent notation and arbitrary precision, which are not wire qvalues and
// could make a direct caller's content-negotiation policy differ from a
// standards-compliant intermediary. Quoted parameter values have already been
// unquoted by mime.ParseMediaType before this check.
func parseHTTPQuality(value string) (int, bool) {
	if value == "0" || value == "1" {
		if value == "0" {
			return 0, true
		}
		return 1000, true
	}
	// The HTTP qvalue grammar permits the decimal point with zero through
	// three fractional digits, so both "0." and "1." are valid spellings.
	if len(value) < 2 || (value[0] != '0' && value[0] != '1') || value[1] != '.' || len(value) > 5 {
		return 0, false
	}
	quality := 0
	fractionDigits := len(value) - 2
	for index := 2; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
		quality = quality*10 + int(value[index]-'0')
	}
	if value[0] == '1' {
		for index := 2; index < len(value); index++ {
			if value[index] != '0' {
				return 0, false
			}
		}
	}
	for index := fractionDigits; index < 3; index++ {
		quality *= 10
	}
	if value[0] == '1' {
		quality += 1000
	}
	return quality, true
}
func jsonAcceptSpecificity(mediaType string) int {
	switch strings.ToLower(mediaType) {
	case "application/json":
		return 2
	case "application/*":
		return 1
	case "*/*":
		return 0
	default:
		return -1
	}
}

// splitAcceptItems separates comma-delimited media ranges while preserving
// commas inside quoted parameter values. Invalid quoting is left for
// mime.ParseMediaType to reject at the bounded negotiation boundary.
func splitAcceptItems(value string) []string {
	items := make([]string, 0, 2)
	start := 0
	inQuotes := false
	escaped := false
	for index, char := range value {
		switch {
		case escaped:
			escaped = false
		case char == '\\' && inQuotes:
			escaped = true
		case char == '"':
			inQuotes = !inQuotes
		case char == ',' && !inQuotes:
			items = append(items, value[start:index])
			start = index + 1
		}
	}
	items = append(items, value[start:])
	return items
}

// closeRequestBody contains a malformed direct caller's Close implementation.
// net/http supplies trusted bodies in normal serving, but this library also
// supports direct integrations. Cleanup must not turn an already-bounded
// request into a process panic after the response path ran.
func closeRequestBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	_ = body.Close()
}

// closeRequestBodies closes the body captured at handler entry and any distinct
// body that a malformed direct caller installs later. A transportVerifierBody
// wrapping the original is one logical body, so close only the wrapper in that
// case; otherwise a body replacement is caller-owned too and must not leak when
// the handler rejects the request before authentication. The
// entryBodyUnchangedBeforeTracking flag covers every return before transport
// verification, including malformed writers, early method rejection, and
// uninitialized handlers; its unchanged request field is not a second
// independently-owned resource even when the entry body is uncomparable.
func closeRequestBodies(r *http.Request, original io.ReadCloser, tracker *requestBodyMutationTracker, entryBodyUnchangedBeforeTracking bool) {
	var bodies []io.ReadCloser
	appendBody := func(body io.ReadCloser) {
		if body == nil || len(bodies) >= maxMCPBodyCleanupCandidates {
			return
		}
		for _, existing := range bodies {
			if sameRequestBodyForCleanup(existing, body) {
				return
			}
		}
		bodies = append(bodies, body)
	}

	// A tracker owns the original body through its stable reader. Prefer that
	// wrapper so the original is closed exactly once even when the request field
	// now points at a replacement.
	originalCovered := false
	if tracker != nil && sameRequestBodyForCleanup(tracker.body, original) {
		appendBody(tracker)
		originalCovered = true
	}

	current := (*http.Request)(nil)
	if r != nil {
		current = r
	}
	var currentBody io.ReadCloser
	if current != nil {
		currentBody = current.Body
	}
	if !originalCovered {
		if wrapper, ok := currentBody.(*transportVerifierBody); ok && sameRequestBodyForCleanup(wrapper.ReadCloser, original) {
			appendBody(currentBody)
			originalCovered = true
		} else {
			appendBody(original)
			originalCovered = true
		}
	}
	if tracker != nil {
		for _, replacement := range tracker.replacements {
			appendBody(replacement)
		}
		if !sameRequestBodyForCleanup(currentBody, tracker) {
			appendBody(currentBody)
		}
	} else if currentBody != nil {
		if wrapper, ok := currentBody.(*transportVerifierBody); !ok || !sameRequestBodyForCleanup(wrapper.ReadCloser, original) {
			// Before transport verification, the request field is still the
			// original caller-owned value; adding it again would invoke an
			// uncomparable body's Close twice. Replacements observed after
			// transport verification use the tracker branch above and remain
			// independently closed.
			if !entryBodyUnchangedBeforeTracking {
				appendBody(currentBody)
			}
		}
	}
	for index := 0; index < len(bodies); index++ {
		body := bodies[index]
		var before io.ReadCloser
		if r != nil {
			before = r.Body
		}
		closeRequestBody(body)
		if r != nil && requestBodyChangedDuringClose(before, r.Body) {
			// A malformed Close implementation may publish one more caller-owned
			// body. Add it to the same bounded cleanup queue before the next
			// candidate is closed; ordinary bodies leave the request field alone.
			appendBody(r.Body)
		}
	}
}

func setHTTPBoundaryHeaders(w http.ResponseWriter) {
	// Lifecycle results may contain task payloads. Never allow an intermediary
	// or browser cache to retain an authenticated response, and prevent a
	// browser from treating an error or JSON response as another MIME type.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Advertise the single version implemented by this additive adapter on
	// every response, including bounded errors and notification acknowledgments.
	// This is protocol metadata only; authentication and transport ownership
	// remain the separate resolver and verifier responsibilities.
	w.Header().Set("MCP-Protocol-Version", MCPProtocolVersion)
	// The response status and representation depend on the negotiated MCP
	// protocol marker as well as authentication and Accept. Keep intermediary
	// metadata coherent for integrations that inspect Vary even though the
	// response is otherwise explicitly non-cacheable.
	w.Header().Set("Vary", "Authorization, Accept, MCP-Protocol-Version")
}

func writeHTTPError(w http.ResponseWriter, status int) {
	// Keep authentication, parser, and internal failures opaque at the HTTP
	// boundary. Detailed bounded tool errors remain inside authenticated MCP.
	http.Error(w, http.StatusText(status), status)
}

func writeHTTPAuthenticationError(w http.ResponseWriter) {
	// A bearer challenge is required for OAuth/MCP clients to know that a
	// retry may authenticate the request. Keep the challenge generic: resolver
	// details, token state, and account identity must not cross this boundary.
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeHTTPError(w, http.StatusUnauthorized)
}
