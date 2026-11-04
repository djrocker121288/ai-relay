# 2.0 OAuth boundary

`cmd/ai-relay-chatgpt-proxy` is the public OAuth boundary for the existing
loopback gateway. It publishes protected-resource and authorization-server
metadata, accepts HTTPS redirect URIs during dynamic registration, and keeps
the relay bearer token private between the proxy and its loopback upstream.
The proxy's `-listen` address is validated as `localhost`, `127.0.0.1`, or an
IPv6 loopback address with a valid TCP port; wildcard and non-loopback binds
fail before protected files are read. Public HTTPS termination and distribution
must therefore remain in a consented reverse proxy or private tunnel, while
the OAuth proxy itself stays on loopback.

The configured public base must be an absolute HTTPS URL without credentials,
query, or fragment. An explicit TCP port must be in the `1..65535` range. The
loopback upstream may use HTTP or HTTPS, but its authority must have a
localhost/IP-loopback host and, when present, the same valid TCP port range;
zero, out-of-range, and empty trailing ports fail before metadata construction
or upstream dialing.

The two discovery endpoints are read-only: they accept `GET` and `HEAD`, reject
other methods with `405 Method Not Allowed`, and send `Cache-Control: no-store`,
`Pragma: no-cache`, and `X-Content-Type-Options: nosniff`. `HEAD` returns the
same successful metadata status without a body. This is a library/handler
boundary only; the supervisor still controls listener, TLS, DNS, and public
distribution decisions.

All OAuth endpoint responses send `Cache-Control: no-store`, `Pragma: no-cache`,
and `X-Content-Type-Options: nosniff`, including the approval HTML page and
generic error responses. Client identifiers, redirect URIs, state values,
client secrets, and access tokens must not be retained by an intermediary or
browser. The public
`/mcp` response boundary applies the same no-store/nosniff policy to both
success and error responses and sends `Vary: Authorization`, because the
response is authenticated and resource-dependent. The proxy does not cache or
reinterpret the loopback upstream's response body.

Authorization-code requests may use RFC 7636 `S256` PKCE. The authorization
server advertises `code_challenge_methods_supported: ["S256"]`, stores only the
bounded challenge with the one-time authorization code, and verifies the
bounded `code_verifier` at token exchange using a constant-time comparison.
Unsupported methods and malformed challenges fail closed. Existing registered
confidential clients that do not send a challenge remain compatible; new
public integrations should use S256 and still validate the returned `state`.
The approval POST preserves the bounded request's non-empty state value on the
redirect, while omitting an absent state rather than inventing one.
Critical authorization and token form parameters (`client_id`, redirect URI,
approval/code values, client secret, PKCE fields, resource, and state) must
occur exactly once across the URL query and form body. Duplicate values are
rejected instead of applying first-value semantics, preventing a proxy and
this boundary from authenticating different parameter sets. Unrelated form
fields remain ignored for compatibility.
Authorization requests and issued tokens are bound to the exact protected
resource URL (`<public-base>/mcp`). The authorization form carries that resource
forward, and token exchange rejects a different resource before issuing a token.
For compatibility, omission is treated as this proxy's only resource; a token
cannot be used after the proxy's configured resource changes. Legacy in-memory
authorization codes without a resource field are accepted once and are bound to
the same `/mcp` resource when exchanged.
Authorization and token form bodies are capped at 16 KiB, require one bounded
form media-type header, and require any non-negative declared content length to
match the bytes actually read. The form and JSON boundaries scan header names
case-insensitively, so direct callers cannot hide duplicate `Content-Type`
values under differently cased map keys. Direct library calls are also bounded
to 256 header fields and 256-byte field names before any authentication,
media-type, or framing lookup; raw and parsed framing values are bounded to
256 bytes before inspection. Verifier strings
are restricted to the RFC 7636 unreserved-character and length bounds.
Direct-call handlers reject nil request/URL inputs with a bounded `400` response
before parsing or authentication; normal `net/http` serving supplies these
fields, while the guard keeps malformed library/test integrations fail-closed.
The public OAuth and `/mcp` handlers close a supplied request body on early,
successful, and direct-library paths; their cleanup boundary contains a panic
from a malformed direct caller's `Request.Body.Close` implementation. This
keeps caller-owned resources bounded without changing normal `net/http`
ownership or exposing cleanup details in responses.
Dynamic registration requires one bounded `application/json` content type and a
complete JSON body capped at 64 KiB; duplicate media types, malformed or
mismatched framing, trailing JSON, and nil direct-call bodies fail closed before
a client is stored. A valid registration is stored in the restricted client
registry through a temporary-file replacement before `200 OK` is returned; a
registry write failure rolls back the in-memory client and returns `500`, so a
successful response cannot claim a client that will disappear on restart.
Each registered redirect must be an absolute HTTPS URI with a host and no
userinfo, opaque form, or fragment. Media-type parameters such as
`charset=utf-8` remain accepted.

The client registry is bounded to 8 MiB and 1024 clients. Startup reads it
through a bounded strict JSON decoder, rejects unknown/trailing data and
invalid stored redirect or secret records, and fails closed instead of
silently discarding malformed state. On Unix-like hosts, startup and each
replacement also reject a symlink/non-regular registry, a registry with any
group/other permission bits, or an existing group/other-writable or symlinked
parent; a sticky shared parent such as `/tmp` is allowed only when the private
directory below it is the ownership boundary. The boundary is checked again
before replacement. Windows ACLs are not represented by portable mode bits and
remain a supervisor-host gate. Registry replacement uses a newly created
exclusive `0600` temporary file, flushes it before rename, and never uses a
predictable shared `.tmp` path; a failed registration rolls back its in-memory
record before returning an error. The registry contains client secrets, so its
path must remain in the protected local approval-file directory and must never
be included in logs or checkpoint evidence.

The in-memory authorization-code and access-token registries are each bounded
to 4096 live entries. New authorization or token issuance prunes expired
entries first; if the corresponding live bound is still full, the flow returns
a bounded `503` without issuing another code or token. This keeps abandoned
OAuth flows from growing process memory without evicting a live credential.
Expiry is inclusive: a code or token is rejected at its `Until` instant, using
the same boundary as registry pruning.

The `/mcp` forwarding boundary requires exactly one `Authorization` header no
larger than 4096 bytes and an explicit, case-insensitive `Bearer` scheme before
token lookup, as required for HTTP authentication schemes.
Header-name matching is case-insensitive even for direct `http.Header` maps, so
differently cased duplicate credentials or media types fail closed.
The proxy retains at most two matching values before validation, enough to
distinguish a singleton from any duplicate without allocating from an
attacker-sized direct-call slice. Duplicate, oversized, malformed, or empty credentials fail closed with the
same protected-resource challenge and never reach the loopback upstream. The
relay bearer remains private and is the only credential sent to that upstream.
After authentication, the configured loopback upstream must be an absolute
HTTP(S) URL whose host is `localhost`, an IPv4 loopback address, or `::1`;
credentials, query strings, and fragments are rejected both at startup and at
request time. The default upstream client does not follow redirects, so a
local service cannot redirect a bounded request toward a non-loopback
destination. After authentication, the boundary accepts only `POST` requests
with exactly one `Content-Type` value no larger than 256 bytes that parses as
`application/json`. Request bodies are capped at 64 KiB and any non-negative
declared content length must match the bytes actually read before forwarding.
Direct-call request framing is also fail-closed: raw `Content-Length` and
`Transfer-Encoding` header entries are checked case-insensitively for
duplication, empty entries, HTTP grammar, and agreement with the parsed request fields.
Transfer metadata must be absent, or be exactly one final `chunked` token
paired with net/http's `-1` unknown-length sentinel. Repeated, unsupported,
signed, or content-length-conflicting transfer metadata is rejected before
forwarding. The same rule applies to the OAuth form and JSON registration
boundaries before they parse or persist input.
Upstream responses are capped at 256 KiB. The default loopback upstream client
also has a 30-second total request deadline. Malformed framing, over-limit
messages, and upstream timeout or transport failures are rejected as bounded
`502` responses without partial response streaming; direct-library framing
errors are rejected before the upstream is contacted. Tests may inject a
shorter client deadline to prove the timeout mapping; production wiring keeps
the default bounded client and does not expose the upstream outside the
configured loopback boundary.

This checkpoint does not claim account-side discovery, external consent,
public listener deployment, certificate/HTTPS termination, or Gemini linking.
The supervisor must provide those gates and preserve the loopback 1.x gateway
route. No credentials or verifier values are logged or written to evidence.
