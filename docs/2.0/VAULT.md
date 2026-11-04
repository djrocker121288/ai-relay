# P5 vault boundary

`internal/v2/vault` is the isolated secret-storage boundary for 2.0. The
current implementation is the encrypted-file fallback: it uses a random
32-byte key in a separate `0600` file, AES-256-GCM authenticated ciphertext,
atomic `fsync` + rename updates, and a containing-directory sync on Unix-like
hosts, versioned records, and no secret values in errors or audit identifiers.

On Unix-like hosts, opening the fallback also fails closed if an existing vault
or key is not the configured regular file, is a symlink, or has any group/other
permission bits. An existing immediate parent must be a real directory with
no group/other write bits; missing parents are created with mode `0700`. The
atomic-write helper creates missing directory components one at a time,
without following an existing symlink, and rechecks that boundary immediately
before every temporary replacement, including a bounded recovery replacement
after a post-rename directory-sync failure. If the failed write created a new
checkpoint, recovery also rechecks the boundary before removing that
checkpoint. This protects atomic replacement and recovery from a writable or redirected parent without
claiming recursive ancestor locking. Windows ACLs
are not represented by portable mode bits; native Windows ACL verification is
therefore a supervisor-host gate rather than a synthetic pass.
The vault and key paths are validated before either is read or created, so a
rejected symlink/non-regular path or equivalent path spelling has no indirect
secret read or key-file side effect. Absolute path identity is compared before
first-run creation (case-insensitively on Windows), and existing files are
also compared by filesystem identity so hard links cannot make ciphertext and
key material share one inode.
If an envelope already exists while its separate key is missing, opening the
fallback returns the missing-key error without creating replacement key
material; only a first-run empty vault may create its key. This avoids leaving
a misleading recovery artifact beside an unreadable checkpoint.
The two configured paths must also refer to different files, not merely have
different strings: existing hard-linked vault/key paths are rejected before
any key material is created or read.

Read-only opens on Linux and macOS walk each existing ancestor through
`O_NOFOLLOW|O_DIRECTORY` descriptors, then use `O_NOFOLLOW|O_NONBLOCK` for the
final file; Windows uses a `FILE_FLAG_OPEN_REPARSE_POINT` handle. Each platform
validates the opened descriptor before reading. The nonblocking flag keeps a
configured path that is swapped to a FIFO or device from holding a vault
operation indefinitely. Binding the parent descriptor before the final open
closes the preflight/read time-of-check-to-time-of-use window for both a
configured file and its ancestors: a replacement cannot redirect the read
through another directory. Windows ACL verification remains a supervisor gate.

All fallback lifecycle writes are transactional in memory as well as on disk:
if an atomic update fails, the prior live record is restored so callers cannot
observe a put, rotation, revoke, or migration that was not durably checkpointed.
Migration validates a sorted, read-only legacy entry set into a candidate map,
then publishes that map only for its one atomic checkpoint; a failed migration
therefore preserves both the live map and the last valid durable checkpoint.
Tests reopen the last valid checkpoint after failed put, rotation, and
migration attempts.

Fallback opens and lifecycle operations also take an exclusive `<vault>.lock`
sidecar using the platform advisory primitive (`flock` on Linux/macOS and
`LockFileEx` on Windows). The lock contains no secret bytes and is held only
for the bounded open or operation. A live `FileVault` reloads the latest
authenticated checkpoint while holding that lock before each read or
mutation, so two independently opened instances do not overwrite one
another's records. Lock contention returns `ErrVaultBusy` without changing
live or durable state. The lock pathname is rechecked with no-follow identity
observations immediately after acquisition, before the operation proceeds, and
again immediately before a durable replacement; if the pathname is swapped to
another inode, a symlink, or a non-private file, the operation returns
`ErrVaultBusy` without publishing its candidate state. This closes the split
ownership case where a replacement pathname could otherwise admit a second
writer while the original descriptor remained locked. The wrapper also
revalidates before reporting a callback successful, while `OpenFile` checks
again before key creation and after loading the authenticated checkpoint.
The configured vault and key paths must also be physically distinct from the
lock sidecar: direct path aliases and existing hard-link aliases are rejected
before the lock is opened or key material is created. This keeps ciphertext
out of the sidecar name and prevents the key file from sharing the lock inode.
Other targets keep the prior in-process behavior until a native advisory-lock
primitive is added; this is a documented portability boundary, not a
synthetic cross-process guarantee. The lock adds no Go dependency or resident
worker and rollback is removing the sidecar-lock adapter while retaining the
unchanged encrypted envelope/key format.

The API supports `Put`, `Get`, `Rotate`, `Revoke`, read-only JSON migration,
redaction for diagnostics, and recovery by reopening the last valid atomic
checkpoint. Supervisor native verification additionally requires the
`NativeCreateOnly.PutIfAbsent` boundary. It reports whether that invocation
passed the absence check, so a pre-existing live or revoked item is never
treated as owned by the verifier or deleted during failure cleanup. Native
adapters require the low-level create-only call itself to use the dedicated
non-production `supervisor/` namespace, before they inspect the native store,
and serialize this check with their writes within one process; a
cross-process race is still a supervisor-host limitation and must be avoided
with the documented unique-name/pre-existing-item check. An explicit
`ErrAlreadyExists` result is treated as non-ownership even if a malformed
adapter also reports `created=true`, so cleanup cannot delete an item that the
boundary classified as pre-existing. Migration requires
exactly one JSON object (with optional trailing
whitespace) and rejects `null`, trailing values, or malformed data. On Unix-like hosts,
the legacy source must also be a private regular file rather than a symlink;
Windows ACL verification remains a native supervisor gate. It intentionally
leaves the legacy source untouched so an operator can verify and roll back
before removal. The source must be physically distinct from both the vault
checkpoint and key file; direct path aliases and existing hard-link aliases are
rejected before the source is opened. Migration also refuses to overwrite a
revoked record, matching the lifecycle write rule. Revoked records cannot be
read or overwritten;
repeated revocation is an idempotent successful no-op across all backends;
rotation increments the record version. The shared increment rejects a
`uint64` maximum instead of wrapping to zero, and the fallback/native write is
left unchanged when the version is exhausted. Redaction replaces live values and
clears values on revoked records, including if a caller hands the diagnostic
helper a malformed revoked record. `Record` also implements secret-safe
`String` and `GoString` formatting, so ordinary `%v`, `%+v`, `%#v`, and `%s`
diagnostics cannot copy the value into an error or test report. Structured
diagnostics should still call `Redact`; JSON serialization remains intentionally
unchanged for the storage boundary. This prevents stale secret bytes from being
copied into diagnostics and preserves the value-less revoked-record invariant.

The fallback creates temporary replacement files through a descriptor-bound
parent on Linux and macOS, and removes failed temporary entries through that
same descriptor; other platforms retain their native temporary-file helper
until an equivalent descriptor primitive is added. It then syncs the temporary
file before replacement and, on Linux/macOS, retains the already-validated
replacement-parent descriptor through the containing-directory sync. This
keeps the directory-entry durability step bound to the directory used by
`renameat`, even if an ancestor is renamed after replacement. Other Unix
targets retain pathname-based directory sync until an equivalent descriptor
primitive is added. If the
post-rename directory sync reports an error, the helper treats the write as
failed and makes one bounded atomic attempt to restore the previous ciphertext
(or remove a newly created checkpoint), then returns the original durability
error. If restoration or its confirming directory sync also fails, the joined
error is an ambiguous durability hold and the supervisor must recover or
inspect the checkpoint before retrying. Windows uses `MoveFileExW` with
`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` so rotation and
revocation replace an existing checkpoint atomically; native ACL verification
remains a supervisor-host gate.

All backends require valid UTF-8 and enforce a 48 KiB secret-value limit plus a
64 KiB serialized payload limit. Rejecting invalid UTF-8 at the API boundary is
important because JSON encoders replace invalid byte sequences; accepting them
would allow a secret to change during a file or native-store round trip. These
limits bound file growth, native credential blobs, and keyring command output;
oversized native records are rejected before JSON parsing (and, where the
platform API permits, before copying into Go memory).
`Rotate` validates its replacement value before reading the existing native
item, so malformed input cannot trigger keyring access or reveal item
existence through error precedence. This keeps invalid-request handling
consistent with `Put` across Secret Service, Keychain, Credential Manager,
and the encrypted-file fallback.

The encrypted-file fallback also caps a vault at 512 records. New records
and migration entries are rejected at that boundary, while updates to existing
records remain possible. Reopen validation and the final atomic save apply the
same cap, so an authenticated but oversized checkpoint cannot create an
unbounded map or bypass the live-state policy. A rejected put or migration
leaves the in-memory map and last durable checkpoint unchanged.

The fallback also bounds every file read before parsing: encrypted envelopes are
limited to 128 KiB, legacy migration input to 64 KiB, and key files to 33 bytes
before the exact 32-byte check. This prevents malformed files from turning the
read/parse boundary into an unbounded allocation path.

Every read boundary also applies the same record invariants: names must match
the requested key, versions are non-zero, timestamps are present, live records
contain a non-empty bounded value, and revoked records contain no value. This
keeps malformed or tampered payloads from being interpreted differently by
different backends. The fallback applies the same check to its in-process live
map before Get, Put, Rotate, Revoke, or migration derives state; this matters
for zero-path test seams and future internal callers that do not first reload an
authenticated checkpoint. A malformed live record fails closed without
classification as revoked and without changing the map.
Native write helpers apply the same record validation immediately before
serialization and the platform API/runner call. Thus a malformed internal
payload cannot reach a keyring or credential store even if future lifecycle
code bypasses a public method's normal construction path.
The Linux Secret Service context-aware write helper repeats that validation
after receiving its pre-marshaled bytes and verifies that the encoded name,
value, version, revocation state, and timestamp match the record metadata.
Malformed or mismatched bytes therefore cannot reach the injected or
subprocess-backed runner through a lower internal seam.
The macOS Keychain and Windows Credential Manager write helpers apply the same
lower-seam validation before calling their platform APIs, including strict
JSON decoding and field-for-field metadata correspondence. This keeps future
native write paths from bypassing the shared record checks after serialization.
The Keychain lower write helper also rechecks receiver/API availability after
those payload checks, so a direct or future in-process call with an unavailable
adapter fails closed before reaching the native write boundary.
The Linux Secret Service lower read, write, and cleanup helpers apply the same
receiver/runner guard after their context, name, and payload checks. Cleanup
also validates its name at the lower seam, after the established context and
unavailable-runner precedence, so direct or future in-process calls cannot
dispatch malformed input. These calls therefore return the bounded
unavailable-runner or name-validation error instead of dereferencing a nil
adapter or dispatching an incomplete native command boundary.
Persisted and native JSON payloads are decoded as exactly one document with
unknown struct fields and duplicate object keys rejected; trailing values and
malformed trailing data fail closed before record validation. The shared
pre-scan also rejects JSON nested beyond 128 object/array levels, keeping a
bounded file or native blob from causing disproportionate recursive work or
parser stack growth. This applies equally to legacy migration, encrypted
checkpoints, and native keyring payloads.
The raw JSON bytes must also be valid UTF-8 before decoding. Go's JSON decoder
otherwise replaces malformed UTF-8 with U+FFFD, which could change a persisted
or native secret before the normal record validation sees it.
The encrypted disk envelope also rejects unsupported envelope versions before
attempting decryption.

`Store` is the shared narrow contract, and the encrypted-file fallback plus
each platform-native adapter assert conformance at compile time. On Linux,
`OpenSecretService` now
performs a bounded, read-only lookup of a reserved capability name and uses
the OS `secret-tool` command when the current user Secret Service session is
usable. The probe never creates or changes a secret; an absent reserved item
is success evidence for the session. Values are passed on stdin,
never argv; command execution is direct (no shell), output is bounded, and the
payload carries the same version/rotation/revocation semantics as the file
fallback. An absent helper returns `ErrUnavailable`; callers must explicitly
choose the fallback. Other native probe failures, including permission/runtime
errors, propagate instead of being mistaken for unavailability. The read-only
lookup establishes that the helper can reach the current Secret Service
session without creating an item; native operation errors therefore remain
visible. The probe, lookup, and store boundaries each re-check injected or
future runner output before classifying the operation, so a runner cannot
bypass the limit by returning an oversized buffer directly; lookup checks
the bound before interpreting a missing-item error. Tests inject a runner
and do not touch DBus.
Each lookup/store operation also receives a 10-second context deadline, so a
native helper that stops responding cannot hold a 2.0 vault operation forever.
Native cancellation and deadline errors remain errors; they are not converted
to `ErrNotFound` or `ErrUnavailable`.
The internal lookup, store, and supervisor-cleanup operation boundaries also
reject literal and typed-nil contexts before invoking the runner. This keeps a
malformed future or injected adapter call from reaching a context method or
native helper and turning a wiring error into a panic or misleading lifecycle
result.
The shared runner wrapper repeats this validation and rejects a nil runner, so
the lowest native boundary remains fail-closed even if a future operation path
omits an operation-specific preflight. After the runner returns, that same
boundary rechecks the operation context and rejects oversized output before
returning bytes to an operation-specific caller. This keeps a future
operation from inspecting or classifying an oversized response before the
shared 64 KiB limit is applied; cancellation or deadline state remains
authoritative.
The concrete Linux `secret-tool` subprocess helper repeats the context and
fixed-operation/argument validation immediately before `exec.CommandContext`.
This defense-in-depth check keeps a direct or future in-process call from
reaching the process boundary with a nil context or turning the helper into a
generic command path, even if it bypasses the shared runner wrapper.
Malformed command-error wrappers are also treated as ordinary opaque native
failures: a typed-nil nested process error cannot be classified as a missing
item or dereferenced during error formatting. This keeps injected and future
runner seams fail-closed without changing the real subprocess classification.
The missing-item classifier itself repeats the typed-nil rejection before
`errors.As`/`errors.Is`, so a direct or future internal caller cannot turn a
typed-nil error into a panic or an absent-item result.
The same lowest runner seam allowlists only `lookup`, `store`, and `clear`;
unsupported helper subcommands are rejected before runner dispatch. This keeps
future or malformed internal wiring from expanding the `secret-tool` command
surface, while preserving the existing context, output, and opaque-error
boundaries. It also requires the exact adapter argument shape: lookups and
clears use only the `ai-relay-v2` application and `name` attributes, stores add
only the fixed `AI Relay 2.0` label, and lookup/store names must pass the shared
name validator. Store stdin must also be one bounded, exact JSON record whose
name matches the command attribute and whose version, timestamp, revocation,
and value invariants pass the shared record validator. The `clear` seam additionally accepts only the dedicated
`supervisor/` namespace used by native verification. Malformed attributes,
labels, names, or stdin placement are rejected before runner dispatch, so a
future caller cannot turn this adapter into a generic keyring query or a
store-wide cleanup primitive.
The shared native-runner boundary rejects an already-canceled or expired
operation context before invoking the helper. After each bounded runner returns,
the adapter rechecks that operation context
before interpreting returned bytes or a missing-item result. This check comes
before output-size classification, so cancellation or deadline state remains
the authoritative result even when a malformed runner also returns oversized
output. An injected or future runner that returns a successful-looking value
after cancellation therefore cannot turn an expired lookup into `ErrNotFound`,
a store into success, or cleanup into an idempotent success.
The direct helper runner also returns the caller's `context.Canceled` or
`context.DeadlineExceeded` after child termination, rather than exposing only
the platform-specific signal error.

Cancellation classification also takes precedence over runner diagnostics. If
an injected or future runner wraps either context sentinel with native or
secret-bearing text, the Secret Service boundaries return the canonical
`context.Canceled` or `context.DeadlineExceeded` value rather than the wrapper.
This preserves `errors.Is` behavior without allowing a diagnostic-bearing
wrapper to escape through a cancellation path.

The no-write capability probe has the same 10-second upper bound. A caller's
shorter deadline is preserved, and either deadline error remains fail-closed;
an unresponsive probe cannot silently select the encrypted-file fallback.

Lookup failures are fail-closed: only the helper's explicit missing-item result
is treated as `ErrNotFound`, and only when the helper returned no stdout bytes.
For the real `secret-tool` runner, that means an exit-1 lookup with empty
stderr and no output; an exit-1 result carrying native/session diagnostics or
any output remains an error. Native stderr and malformed output are bounded
and never included in returned error text. Runner errors are also wrapped in an
opaque error that preserves `errors.Is`/`errors.As` classification without
copying runner diagnostic text into the vault error boundary. Cancellation, an unavailable
session, and other native errors are returned to the caller rather than being
mistaken for an empty vault. The same rule applies to the read-only capability
probe and named cleanup, so a malformed runner cannot turn a non-empty native
response into absence or cleanup success.
An injected or future command wrapper cannot bypass this rule by wrapping the
missing sentinel: any non-empty stderr keeps the result an ordinary native
failure before missing-item classification.
The concrete `secretToolCommandError` wrapper also has stable opaque text for
direct internal callers; its `Unwrap` method retains machine-readable
classification without exposing the subprocess diagnostic.
Unexpected runner panics at the probe, lookup, store, and cleanup boundaries
are also converted to one opaque error; panic values are never returned. A
panic after a native write remains an ambiguous operation and is not treated as
successful.

The no-write capability probe follows the same rule: a canceled or timed-out
probe is returned unchanged, so `OpenDefault` cannot mistake caller shutdown
for native unavailability and silently select the file fallback.

The constructor also rechecks the bounded probe context after the runner
returns. This fail-closed check covers injected or future runners that return
a successful-looking result without enforcing cancellation themselves; an
expired probe cannot select the native backend.

The direct Linux `OpenSecretService` constructor applies the same nil and
typed-nil context validation before invoking its injected or native probe.
This keeps callers that require the native backend from reaching a context
method through a malformed interface, and it does not create or select the
encrypted-file fallback after rejecting that boundary. The constructor also
applies the 64 KiB native-output limit to probe bytes returned by an injected
or future runner, so backend selection cannot bypass the resource boundary
before lifecycle operations begin. Focused injected-runner regressions prove
the probe is not called after typed-nil rejection and oversized probe output is
rejected.

`OpenDefault` is the centralized platform policy. Linux selects Secret Service
after that no-write probe and otherwise opens the encrypted-file fallback;
macOS follows the same rule for the login Keychain; Windows selects Credential
Manager because its API is present in the supported native runtime. Windows
also passes through the shared selector, so malformed native construction
	cannot bypass the nil-store guard. Only the explicit `ErrUnavailable`
	capability result permits fallback. The selector accepts that result only when
	the actual sentinel appears by identity in a bounded ordinary unwrap chain; a
	custom `Is(ErrUnavailable)` claim, typed-nil child, panicking unwrap, or
	cyclic/overlong unwrap graph is rejected. The complete bounded graph is
	validated before a sentinel match is accepted, while ordinary `errors.Join`
	trees remain supported. Permission, cancellation, corruption, and other native errors
	therefore propagate, so a broken keyring cannot be mistaken for an empty
	vault. `OpenFile` remains the explicit rollback path when native storage is
	mandatory or an operator needs to avoid the platform store.

`OpenNative` is the explicit no-fallback policy for supervisor verification and
callers that require an OS-backed store. It selects Secret Service, the login
Keychain, or the current-user Credential Manager on the supported platforms and
returns `ErrUnavailable` elsewhere; it never creates or opens the encrypted
file fallback. It rejects a canceled or expired context before native selection
so a withdrawn native-only request cannot inspect a platform credential store.
Because macOS and Windows constructors cannot be interrupted through the narrow
store interface, the shared native-only selector also rechecks the active
context after construction and rejects a late backend before returning it.
The `ai-relay-vault-native-check` command uses this API and
`VerifyNativeLifecycleContext`, so an accidental missing-session run cannot silently
write fallback files. `vault.ValidateName` runs before `OpenNative`, so an
invalid name fails without probing or opening the native session. It accepts
only a unique non-secret item name in the dedicated `supervisor/` namespace, generates
verification values in memory, prints non-secret version/boolean evidence, and
cleans only that named item. The command remains a supervisor action: it must
not be run until the corresponding user-session consent and pre-existing-item
check are complete.

The checker also treats native-construction errors as untrusted before they
reach its stderr boundary: it emits stable operation-level text while
preserving `errors.Is`/`errors.As` classification for callers and tests. The
operation label itself is allow-listed; an unknown caller-supplied label is
reduced to the generic `operation` label instead of being copied into the
error. This keeps platform/session diagnostics, including accidental
secret-bearing text, out of CLI output and retained evidence.

The macOS Keychain and Windows Credential Manager adapters apply the same
opaque error boundary to their injected and platform API calls. Read, write,
and delete failures retain `errors.Is`/`errors.As` identity for lifecycle
policy, but their diagnostic text is reduced to a stable operation label before
it reaches a caller. This keeps a future platform seam or test double from
turning native diagnostics into a secret-bearing application error. The change
is additive and its rollback is selecting the unchanged encrypted-file
fallback; it does not alter native item contents or the 1.x route/service
surface.

The macOS adapter also preserves each non-missing Security.framework `OSStatus`
as a typed status carrier through that opaque boundary. The stable error text
does not expose the numeric status, while callers can use `errors.As` with the
`Status() int` shape when policy needs to classify the native result. The
capability probe applies the same rule: a non-missing probe status is opaque
but remains classifiable, while the explicit no-keychain result remains the
shared `ErrUnavailable` fallback signal. The portable regression covers this
redaction/classification seam; native Keychain-session execution remains a
supervisor-host consent gate.

An explicit Keychain missing-item result is normalized to the shared exact
`ErrNotFound` sentinel before that opaque error boundary. This keeps absent
accounts distinguishable from native read failures in the same way as Secret
Service and Credential Manager, while all other Keychain diagnostics remain
opaque and classifiable.

The internal backend selector also rejects missing native or fallback opener
callbacks and rejects both literal and typed-nil stores returned without an
error. This keeps malformed adapter wiring fail-closed instead of turning a
construction error into a panic or an implicit fallback.

Native error returns are checked for typed-nil pointers before any
`errors.Is`/`errors.As` classification or redaction. A typed-nil error is a
malformed adapter result, not success and not `ErrUnavailable`; it becomes a
stable generic boundary failure so it cannot panic classification or select the
encrypted-file fallback. The same guard covers the native runner and the
supervisor verification lifecycle. The shared sanitizer also treats a custom
error that falsely claims the private probe target through `Is` or `As` as
unclassifiable, rather than retaining that error and allowing a later caller
to reach an uninspected or panicking `Unwrap` chain. Ordinary errors that do
not interfere with the private probes retain their `errors.Is`/`errors.As`
identity.
The Linux Secret Service classifier also contains panics from an injected or
future error's `Is`/`As` methods. A panicking error is never classified as a
missing item, context state, or unavailable helper, and it is not retained as
an unwrap cause that could panic again when a caller checks the returned error.
Normal sentinel and typed-error classification remains available for ordinary
native errors. The bounded sanitizer does not invoke custom `Is` or `As`
methods; direct identity, assignable status carriers, and ordinary bounded
unwrap edges retain their classification without giving a foreign method an
unbounded recursive walk.
The Secret Service probe classifier and redaction helper repeat that guard at
their direct internal seams, so a future in-process caller cannot bypass it
before probe failure classification or opaque diagnostic wrapping.
The shared Secret Service runner also redacts a returned runner error before
it leaves the lowest command boundary, while retaining `errors.Is`/`errors.As`
classification. Direct internal callers therefore cannot bypass the same
opaque diagnostic rule used by `Get`, `Put`, `Rotate`, `Revoke`, and cleanup.

The shared selector also contains a panic from either opener as a generic
opaque boundary error. Panic text is never returned, logged, or used to select
the fallback, and an unexpected native panic therefore cannot turn into an
implicit file-store downgrade. Only the explicit `ErrUnavailable` result can
select fallback storage.

Native construction failures from the shared selector use the same opaque
operation-level error boundary as native read/write/delete failures. The
underlying error remains available to `errors.Is`/`errors.As` callers, but
platform or injected diagnostics do not reach the vault caller's error text.
The explicit `ErrUnavailable` classification is checked before redaction, so
only that capability result can select the encrypted-file fallback; permission,
corruption, cancellation, and other construction failures remain failures.

Every platform's `OpenDefault` rejects a nil, typed-nil, canceled, or expired
context before invoking a native probe or opening the encrypted-file fallback.
The shared context-aware selector also rechecks cancellation after native
selection returns and immediately before choosing the fallback, so a delayed
native result cannot be accepted after caller withdrawal and a native
`ErrUnavailable` result cannot turn into fallback access after cancellation.
It rechecks once more after the fallback opener returns, so a slow file-open
operation cannot be accepted as a successful backend after cancellation. On
unsupported platforms, where there is no native probe, `OpenDefault` uses the
same post-open check rather than bypassing this invariant.
Linux additionally passes that context into the bounded Secret Service
capability probe. Callers must provide a real, active context so cancellation
and deadline state are observable; this avoids native command/runtime panics
and prevents backend selection from converting withdrawn input into an
implicit fallback. The shared regressions prove that canceled default opens
return `context.Canceled` without selecting a store or opening the fallback.
`OpenDefault(nil, ...)` is covered by a regression that also proves no
encrypted-file vault or key is created when that boundary is rejected.
The Windows regression also exercises this boundary before Credential Manager
selection, while a valid background context proves that native-first selection
does not create fallback files.
The internal native-runner boundary is also rejected when nil, so a malformed
adapter construction cannot panic or silently select the encrypted-file
fallback.

Native lifecycle adapters also reject nil receivers and nil injected API/runner
boundaries before validation or locking, including an interface containing a
typed-nil implementation. This keeps malformed internal construction
fail-closed across every `Store` operation instead of converting a test seam or
future wiring error into a panic. This applies to Secret Service, macOS
Keychain, Windows Credential Manager, and the encrypted-file fallback alike;
the fallback applies the same guard to read-only migration as well.

The macOS Keychain adapter also contains panics from its low-level API calls at
the `Get`, `Put`/`Rotate`, and cleanup boundaries, returning stable opaque
native-store errors to ordinary `Store` callers. A panic during a create-only
write remains an error after the absence check, so supervisor verification keeps
the item armed for its named cleanup attempt; this does not claim native
Keychain/TCC runtime evidence.

Each native adapter serializes lifecycle operations per store instance. This
keeps read-then-write version increments atomic for concurrent callers in the
same 2.0 process. It is not a cross-process lock or a distributed transaction;
supervisor-host native verification must still confirm the OS store's
cross-process behavior and ownership policy.

Native adapters additionally implement the optional `NativeCleanup` boundary.
Its `Delete` method removes one named item and treats an already-missing item
as success, so a supervisor can safely retry cleanup after a failed native
verification. It is intentionally excluded from `Store`: production lifecycle
code must revoke credentials rather than delete them, and the encrypted-file
fallback does not expose a destructive delete operation. The method accepts
only a non-empty name in the dedicated `supervisor/` namespace and rejects
production names before reaching the native API; it is not a store-wide reset.

This avoids a new DBus dependency: `secret-tool` is maintained by the distro's
libsecret stack, whose OS keyring and session policy remain the security
boundary. Native stdout and stderr are captured with fixed 64 KiB + 1 byte
sentinel buffers, and oversized output is rejected without first accumulating
an unbounded child response. Lookup output is interpreted only on a successful
read or an empty missing-item result; successful store and clear operations
must return no stdout, and any unexpected mutation output fails closed without
including the bytes in an error. Stderr is used only to distinguish an
explicit missing-item result and is never returned or logged. The tradeoff is a runtime
binary/session dependency and less direct error detail than a native library.
Rollback is deleting this adapter and selecting the unchanged file backend.

Reuse-first assessment for the Linux adapter: `secret-tool` is part of the
libsecret project and is distributed under the LGPL-2.1-or-later license;
the distro package and upstream project provide the maintained release line,
security update path, and the Secret Service/D-Bus protocol boundary. The
adapter adds no Go or vendored transitive dependencies, performs no network
access, and remains offline except for the local keyring session. Its idle
worker footprint is limited to one short-lived helper per operation; stdout is
bounded at 64 KiB plus one sentinel byte and each operation is capped at ten
seconds. The native keyring, desktop session, and helper availability are
security and operational dependencies, so missing-session, permission,
cancellation, and malformed-payload failures remain visible rather than being
silently replaced by an empty vault. The narrow injected runner makes the
component replaceable with a direct Secret Service client if the distro
helper is unavailable or its maintenance/security posture changes. The
encrypted-file backend is the documented rollback path and existing native
items are never deleted.

On Windows, `OpenCredentialManager` uses the OS Credential Manager API directly
(`CredReadW`/`CredWriteW`) with generic credentials scoped to the current user.
The versioned JSON payload is held in the native credential blob, so no secret
passes through a shell, command-line argument, or environment variable. The
adapter has no added runtime dependency beyond Windows itself; its replaceable
boundary is the small `credentialAPI` interface. The tradeoff is that native
runtime verification requires a consent-aware Windows user profile and cannot
be truthfully simulated by the Linux worker. Rollback is selecting the
unchanged encrypted-file fallback; existing credentials are not deleted.
Credential Manager read, write, and delete failures use the same opaque
operation-level error boundary as the other native stores: platform diagnostic
text is not exposed, while `errors.Is`/`errors.As` classification remains
available to callers. The Windows regression covers all three directions;
cross-built Windows tests are compile-only evidence until the trusted
supervisor runs them in an owner-approved profile.
Credential reads also pass the returned blob through the bounded-copy helper
before JSON decoding, so a malformed native response cannot create an unsafe
slice or allocate beyond the shared payload limit; a nonzero size with no blob
pointer fails closed as a generic payload error. After `CredReadW` returns, the
Windows adapter copies only the bounded blob into an owned blob-only value and
then releases the native `CREDENTIALW`; it does not retain dangling target,
comment, attribute, alias, or username pointers from that allocation.

The shared native redaction boundary also treats error-chain methods as
untrusted. Keychain, Credential Manager, backend selection, and verification
classification use panic-safe `errors.Is`/`errors.As` probes; if an injected or
future native error panics from `Is`, `As`, or `Unwrap`, it is not retained as
an unwrap cause. The caller receives only the stable opaque operation error, so
later classification cannot reproduce the native panic or expose its
diagnostic. Ordinary sentinel and status classification remains preserved.

On macOS, `OpenKeychain` first performs a no-write `SecKeychainCopyDefault`
capability probe, then uses the Security framework's generic-password API in
the current user's login Keychain. Only the explicit no-keychain result selects
the encrypted-file fallback; permission and other Security.framework failures
remain errors. The native boundary is a small cgo adapter;
secret bytes are passed directly to Security.framework and never enter argv,
shell, environment, or logs. The versioned JSON payload remains inside the
Keychain item, and the injected API tests exercise lifecycle and malformed
payload handling without a macOS login session. This adds no runtime
dependency beyond macOS, while cgo/framework availability is an explicit
capability gate; with cgo disabled, `OpenKeychain` returns `ErrUnavailable`.
Rollback is selecting the unchanged encrypted-file fallback; existing
Keychain items are not deleted. Native verification still requires a
consent-aware macOS user session and is not claimed by this Linux worker.
If Security.framework reports success without returning a default keychain
reference, the probe treats that inconsistent result as unavailable instead
of constructing an unusable native adapter.
The cgo read/write boundary also rejects contradictory successful responses
with a missing native item pointer before copying bytes or modifying an item;
this remains a generic native failure and cannot select the fallback or expose
native diagnostics.
The Keychain write helper also repeats record, size, strict-JSON, and
name/value/version/revocation/timestamp correspondence checks immediately
before calling the injected or Security.framework API. This keeps a future
write path from bypassing the lower payload boundary; malformed or
metadata-mismatched bytes are rejected without reaching the native store.
The Keychain read helper likewise repeats name and receiver/API availability
checks immediately before its native read, so a direct or future in-process
read seam cannot turn a missing adapter into an API call or panic.
The Windows Credential Manager read and write helpers likewise repeat name and
receiver/API availability checks at their lower boundaries, so direct or
future in-process calls fail closed before native dispatch. Their injected and
native API calls are wrapped with the same opaque panic boundary as Keychain;
an unexpected read, write, or delete panic cannot escape as a platform
diagnostic or terminate an ordinary `Store` caller. Cross-process Windows
profile/ACL behavior remains a native supervisor gate.

The file fallback walks every existing ancestor of its configured vault and key
paths before creating a key or atomically replacing an envelope. A symlinked
ancestor or non-private non-sticky directory is rejected, including when an
intermediate directory would otherwise be created by `MkdirAll`. This prevents
a safe-looking nested path from redirecting secret material through an
ancestor between preflight and replacement; standard sticky shared directories
such as `/tmp` remain usable when the private directory below them is the
ownership boundary.

On Linux and macOS, the final temporary-file rename is also performed relative
to no-follow descriptors for both parent paths. The source and destination
must resolve to the same protected directory, so an ancestor replacement after
the pathname checks cannot redirect the durable replacement to another
directory. Other Unix targets retain the existing pathname replacement until a
native descriptor-rename implementation is reviewed for that target; they do
not provide this Linux/macOS race-boundary evidence.

## Native supervisor verification procedure

The Linux, macOS, and Windows native gates must be run by the trusted
supervisor on the corresponding owner-approved user session. Before each run,
confirm the worktree is `<repo-root>`, the branch is
`develop/2.0`, no 1.x service is being replaced, and the native store contains
no pre-existing AI Relay 2.0 test item that must be preserved. Use a unique,
non-secret test name supplied by the supervisor; never put a secret in a
command argument, environment variable, log, screenshot, or evidence record.

Native lifecycle evidence must show, without printing values: open/select the
native backend, put version 1, get the record, rotate to version 2, get again,
revoke, confirm a revoked read fails, and confirm repeated revoke is an
idempotent success. The supervisor should use
`vault.VerifyNativeLifecycleContext(ctx, store, cleanup, uniqueName)` for this
sequence (the compatibility wrapper `VerifyNativeLifecycle` uses a background
context):
it first refuses an existing item, generates values only in memory, returns
version/boolean evidence without secret bytes, and calls
`NativeCleanup.Delete` exactly for the named item on success or after any put
attempt. A native write may commit an item and still return an error or panic
at the adapter boundary, so cleanup is deliberately attempted even when
creation cannot be proven; deleting an already-missing item is idempotent.
An explicit existing-item classification always overrides a contradictory
creation flag and disarms cleanup.
Unexpected panics from the native store or cleanup seam are contained; after a
put attempt the helper makes one cleanup attempt, reports a generic
adapter/cleanup failure, and never includes the panic value in evidence.
Adapter error text is also treated as untrusted: verification wraps native
operation failures opaquely while preserving `errors.Is`/`errors.As`, so a
future platform seam cannot copy secret-bearing diagnostics into the CLI's
stderr or supervisor evidence.
An adapter that reports neither an existing item nor a creation error is also
treated as a malformed create-only boundary and fails closed before any later
lifecycle call.
Every record returned by the native put, get, and rotate boundaries is also
checked for the shared name, version, timestamp, value, and revoked-state
invariants before the next lifecycle operation. A malformed response therefore
fails closed, still cleans an item whose create-only boundary reported
ownership, and does not continue to rotate or revoke it.
The context is checked before and after each lifecycle boundary, including
immediately after the create-only call and before interpreting its result,
immediately after every native get/put/rotate/revoke result and before
interpreting that result, after local record validation, immediately before the
next native read or write, and after the final cleanup boundary. The
create-only boundary retains one safety exception: its explicit
`ErrAlreadyExists`/created classification is resolved before a canceled result
can arm cleanup, so a contradictory adapter response can never cause deletion
of a pre-existing item. A canceled successful creation remains armed for
cleanup. Cancellation or expiry therefore stops stale result interpretation as
well as the next operation and cannot be reported as an unqualified
verification success. If cancellation arrives after the create-only absence
check, cleanup remains armed and is still attempted for that named item; a
non-creating result is never treated as owned by the canceled verifier.
Cleanup success remains recorded even when the overall result is canceled,
proving that the uniquely named item was removed.
Individual native calls retain their adapter deadlines; a context does not
grant permissions or interrupt a platform API that is already in progress.
Record whether cleanup succeeded. A failed cleanup is a hold, not a reason to
broaden permissions or use a destructive store-wide reset. Linux
additionally records that the Secret Service probe is read-only
and the current session is usable; macOS records the login-Keychain/TCC
result; Windows records the current-user Credential Manager result and
ACL/profile identity. These are native-session facts, not Linux cross-build
evidence.

The checker emits a stable, lower-snake-case JSON object containing only
`name`, `put_version`, `rotate_version`, `revoked_read_rejected`,
`repeated_revoke_ok`, and `cleanup_succeeded`. The encoder uses an explicit
allow-list, so adding an internal diagnostic field cannot expand the retained
evidence schema. It never serializes either generated verification value or
native error detail. Before a nil-error result is returned, the shared
`ValidateNativeVerificationResult` boundary also requires the dedicated
`supervisor/` name, put version 1, rotate version 2, both revoke checks, and
successful cleanup. Supervisors may retain this object as evidence, but must
keep the unique test name non-secret and must treat any error or false cleanup
result as a hold. A failed run may still return partial evidence for diagnosis;
only a result with no error and a valid evidence contract is a pass.

When retained evidence is replayed, use
`ParseNativeVerificationEvidence`. It accepts at most 4 KiB, requires exactly
one UTF-8 JSON document with no duplicate or unknown fields, and applies the
same success validation before returning a result. Parse failure or a
contradictory result is a hold; do not manually deserialize the object and
treat its fields as proof.

The portable evidence remains reproducible in this worktree:
`go test ./internal/v2/vault`, `go test ./...`, `go vet ./...`,
`GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c`,
`GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go test -c`, and `git diff --check`.
Cross-built test binaries are not execution evidence. No 1.x consumer, service,
model store, VM, or external account is changed by these checks.

After consent on a native supervisor host, invoke the checker with a unique
non-secret name beginning with `supervisor/`, for example:

```text
go run ./cmd/ai-relay-vault-native-check -name supervisor/vault-check-<unique-suffix>
```

The checker rejects `controller/` and other production namespaces, as well as
the bare `supervisor/` prefix, before opening the native backend. This keeps a
name typo from authorizing cleanup of a production item; the supervisor must
still confirm that the chosen `supervisor/` item does not already exist.

The checker's optional `-timeout` bounds native-session setup and the
context-aware verification loop to a positive duration no greater than five
minutes (the default is 45 seconds). Individual native lifecycle operations
retain the adapter's own ten-second operation bound. A timeout does not grant
permissions, select the file fallback, or authorize cleanup of any name other
than the supplied unique test item.

The checker rejects a nil or typed-nil context, and an already-canceled
context, before opening the native backend; it also validates the item name
before native access. It rechecks cancellation immediately after native setup
returns, before inspecting the cleanup boundary, so a late backend result
cannot replace caller cancellation with a misleading malformed-store error.
Local tests cover the positive timeout bounds and prove that malformed,
canceled, or invalid requests do not invoke the native opener, including
cancellation raised during native setup.

For a retained result, the checker also supports offline evidence replay:

```text
go run ./cmd/ai-relay-vault-native-check -evidence-file /path/to/evidence.json
```

Replay opens only a regular file with a no-follow handoff on Linux, macOS, and
Windows, and rejects symlinks, directories, and a path whose filesystem
identity changes between the initial open and the bounded read. Linux and
macOS bind every existing ancestor through `O_NOFOLLOW|O_DIRECTORY`
descriptors before opening the final file with `O_NOFOLLOW|O_NONBLOCK`;
Windows protects the final component with a
`FILE_FLAG_OPEN_REPARSE_POINT` handle. Unsupported platforms retain the
identity-checked pathname fallback and do not claim these native no-follow
primitives. It reads at
most 4 KiB, requires the same strict single-document schema
and complete success contract as `vault.ParseNativeVerificationEvidence`, and
prints only the canonical non-secret fields. The identity check is repeated
after reading so a replacement during the read is not silently accepted; it
does not hash or authenticate the file contents. This bounds the replay input
handoff but is not file provenance or authenticity evidence: it does not open a
native store, inspect a keychain/session, or turn portable replay into native
execution evidence. The supervisor must preserve the original owner-approved
run provenance and continue to treat missing, partial, or failed native-session
evidence as `WAITING_CONSENT`/`WAITING_EXTERNAL`.
These checks are portable boundary evidence only; they do not replace
consent-aware execution in the owner-approved Linux, macOS, or Windows user
session.

Record the JSON evidence and whether cleanup succeeded, but never record the
generated values. A non-zero result is a hold; do not broaden permissions or
switch to a destructive store-wide cleanup.
