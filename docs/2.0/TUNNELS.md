# P8 provider-neutral tunnel boundary

`internal/v2/tunnel` is a side-effect-free boundary for authenticated tunnel
distribution. It validates a provider name, HTTPS endpoint, audience, and
protected-resource URI, and it defines a narrow provider health seam. It does
not resolve DNS, open a socket, contact a tunnel provider, load credentials,
issue tokens, or publish a route.

Both endpoint and resource are HTTPS URLs without userinfo, query parameters,
or fragments. This keeps credentials and mutable provider state out of the
identity used for health correlation. Provider and audience metadata are
bounded UTF-8 text without control or Unicode format characters. A health
report must carry the exact configured provider, endpoint, audience, and
protected resource plus a check timestamp; `Healthy: false` is a valid negative
result. Correlating all four identity fields prevents a report for one resource
or audience from being reused for another endpoint configuration. The validator
proves shape and correlation only, not reachability, authentication, provider
health, or safe public distribution.

`Provider.Check` receives the caller's context and owns provider-specific
transport and authentication. `tunnel.Check` rejects nil, typed-nil, canceled,
or panicking boundaries, rechecks cancellation after the callback, and reduces
provider failures to a stable error class. It does not create a replacement
context or infer consent from availability.

`ProviderRegistry` is the bounded provider-ownership seam. It snapshots at most
16 supervisor-selected providers, requires unique bounded names, rejects
typed-nil or panicking name implementations, and performs exact-name lookup.
Every lookup and check revalidates the private snapshot, including its map
identity, size, key-to-provider name binding, and adapter availability, before
publishing or calling a provider. `ProviderRegistry.Check` delegates the
selected adapter to `tunnel.Check`; it does not discover providers, retry, fall
back, or silently replace a configured provider. The registry is immutable
after construction, but adapter internals remain owned by their caller and must
provide their own synchronization.

The additive `Authenticator`/`Authenticate` seam is the corresponding
distribution handoff. It accepts exactly one bounded Bearer value, delegates
token signature/issuer/key validation to the injected authenticator, then
requires the returned principal to match the configured audience and resource,
have a future expiry, and contain every requested scope. Verifier failures,
panics, malformed principals, duplicate scopes, and missing scopes reduce to a
stable unauthorized result without returning token or verifier detail. The
boundary validates the caller's required-scope policy before invoking the
authenticator, copies returned scopes, and performs no network I/O, token storage,
listener setup, or provider discovery. A production adapter must still supply
an authenticated HTTPS deployment, bounded context, issuer/key rotation,
audit/retention policy, and supervisor-approved tunnel configuration.

`tunnel.NewHTTPHandler` is the bounded local HTTP handoff for that seam. It
scans direct `http.Header` maps with limits and wire-compatible field-name and
field-value syntax, rejecting control, format, and line/paragraph separator
metadata before callbacks; validates raw content-length and
transfer-encoding metadata against the parsed request, rejects oversized or
contradictory framing before authentication, and accepts only the single final
`chunked` transfer coding when the standard library marks the body length
	unknown. After authentication it materializes at most 64 KiB of request body,
contains panics from the in-process body reader behind the generic invalid-body
response, requires the bytes read to match a non-negative declared content
length, and rechecks bounded trailer metadata after body consumption, rejects malformed or
security-sensitive trailer fields (`Authorization`, `Content-Length`, `Host`,
`Trailer`, and `Transfer-Encoding`), and invokes the callback only after that
bounded body/trailer check succeeds. It also binds the request authority and
escaped path to the configured protected resource before authentication;
relative server targets use `Request.Host`, absolute-form targets must match
both the configured authority and the request host, and query/fragment state
is rejected. The target guard independently retains the configured HTTPS-only
invariant even when called with an in-process resource value outside the
constructor path. The empty configured path and the HTTP root path `/` are
treated as the same protected-resource path; other escaped-path differences
remain distinct. It rejects
duplicate or differently cased authorization fields before verifier invocation,
caps callback responses at 256 KiB, and owns stable
`no-store`/`nosniff`/`Vary: Authorization` response policy. Callback errors,
panics, malformed response status or content-type values, and oversized
responses reduce to a generic internal error; verifier failures remain a
protected-resource `401` challenge. The handler does not register a route,
start a listener, terminate TLS, resolve DNS, contact a provider, or persist a
token. The callback owns application semantics and must still enforce its own
method and payload schema.

The additive `internal/v2/audit` boundary supplies the fixed-shape audit and
retention policy used by that future adapter. It still performs no storage or
deletion; see `docs/2.0/AUDIT.md` for the exact ownership and size limits.

No mature external component was reused. The package uses only the Go standard
library, has no idle process or transitive dependency footprint, performs no
network I/O, and is replaceable by removing this isolated package and document.
That is the current maintenance, security, resource, and rollback assessment;
provider adapters require a separate license, advisory, resource, and rollback
review before introduction.

This checkpoint adds provider ownership and selection evidence but does not
claim tunnel-provider reachability, authenticated-distribution deployment,
OAuth issuer/key verification, authenticated HTTPS provisioning, or P8
completion evidence. Production wiring remains a supervisor gate and must not
alter stable 1.x services.
