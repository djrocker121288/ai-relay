# 2.0 project and task lifecycle

`internal/v2/lifecycle` is the isolated P6 lifecycle core. It has no 1.x,
gateway, agent, scheduler, model, or external-controller dependency. A later
adapter may connect it to those components only after the lifecycle invariants
are reviewed.

The store persists one bounded JSON state file under a caller-selected state
directory. On Linux and macOS, `Open` requires the existing state directory to
be a private Unix directory with no group/other permission bits; it rejects an
insecure directory without changing its permissions. The state file and lock
file are separately protected at `0600`. On Linux and macOS, reopening the
state file uses `O_NOFOLLOW` plus descriptor validation, so a symlink,
hard-linked, or non-regular/non-private replacement is rejected before JSON
parsing. Windows
opens both the lock and state through `CreateFileW` with
`FILE_FLAG_OPEN_REPARSE_POINT`, rejects reparse points and directories from the
opened handle, and reads the bounded checkpoint from that validated handle.
Windows ACLs are not expressible
via Go mode bits and remain a native installer/supervisor verification gate.
`Open` resolves the state-root path to an absolute path before validation and
locking, so a later process working-directory change cannot redirect an open
store's checkpoint I/O. Root validation checks the path with `Lstat` before
and after the followed `Stat` lookup, rejecting a symlink or filesystem-object
replacement observed during that boundary. It then takes an exclusive
OS-native lock on
`.lifecycle.lock`; on Linux and
macOS the lock path is opened with no-follow semantics and must resolve to a
regular, single-link, `0600` file before ownership is acquired, so a stale or
tampered lock symlink, hard link, or permission change cannot redirect or
weaken the ownership boundary or cause an unrelated inode to be chmodded. Only
`Open` checks that the platform has a native cross-process lock before creating
the state root; unsupported platforms therefore return `ErrUnavailable` without
creating the root or touching the caller's lock path. Only one process may own a
state directory at a time, and `Close` must be called before another process
can reopen it. A competing open fails with `ErrConflict`, and an unsupported
platform returns `ErrUnavailable` before opening or changing the lock path;
callers must treat that explicit capability result as a gate rather than
claiming cross-process safety from a text error. Windows ACL
verification remains a supervisor/native gate; the no-follow handle path is
implemented and has a native-only regression, but has not been executed by
this Linux worker. A live store also reopens the lock path through the same
no-follow boundary before serving each operation and compares its filesystem
identity and private mode with the originally locked inode. If the lock
pathname is replaced, removed, symlinked, hard-linked, or weakened after
`Open`, the old store fails closed instead of continuing while a replacement
pathname could admit another writer or an exposed lock could weaken the
ownership boundary.
`Open` also repeats the no-follow lock-path and filesystem-identity check
immediately after acquiring the writer lock, before opening a state-root
descriptor or reading `lifecycle.json`, and repeats the root identity check
immediately before opening `lifecycle.json`; a root pathname
replacement observed at either boundary therefore cannot make the lock or
state read authorize a redirected state directory. A missing `lifecycle.json`
is treated as a new empty store only after the state root is revalidated; a
missing, replaced, or otherwise unavailable root fails with a conflict instead
of returning an open store whose next write cannot use its ownership boundary.
`Open` accepts zero or one `Options` value; passing more than one is rejected
before path creation so a caller cannot silently believe that later
configuration was applied when only the first value would otherwise be used.
When the state root is missing on Unix-like hosts, creation walks existing
ancestors without following symlinks and rejects an ancestor that is writable
by group/other unless it is a sticky shared directory. Missing components are
opened or created one at a time relative to an already-open parent directory,
with no-follow descriptor traversal and private modes, before the lock is
opened. This closes the pathname-check-to-`Mkdir` redirection window that a
concurrent ancestor replacement would leave in a `MkdirAll`-style
implementation. Windows keeps native ACL creation and verification as the
supervisor-host gate.
On Linux and macOS, the
final state read then opens the identity-checked root as a directory descriptor
and opens `lifecycle.json` relative to that descriptor, so a later parent rename
cannot redirect that read. Darwin uses the repository's existing
`golang.org/x/sys/unix` dependency for its exported `Openat` wrapper because
the standard `syscall` package keeps that binding internal. Mutations
serialize a complete next state to a `0600` temporary file and flush it before
replacement. Linux and macOS retain an already-open descriptor for the locked
state root, create the temporary file with `openat`, and install it with
descriptor-relative `renameat`; the final pathname preflight therefore cannot
redirect the replacement into a concurrently substituted root directory. The
same descriptor is synced after replacement; failure from either the directory
sync or its close, including a panic at that platform seam, is a post-install
durability failure, so the store quarantines itself and must be reopened. The
live Unix store also requires that captured root descriptor before any
operation; if an in-process integration removes that descriptor, the store
returns `ErrClosed` rather than using the atomic writer's portable path-based
fallback. The fallback remains available only to direct helper callers and
platforms without a descriptor-relative implementation. The
descriptor-relative atomic writer also rejects a non-nil but already-closed
directory handle with `ErrClosed` before issuing `openat` or `renameat`, so
direct helper callers receive the same bounded ownership result instead of a
platform-specific bad-descriptor error. The
descriptor-relative state reader applies the same guard before issuing `openat`,
so a nil or already-closed root descriptor cannot produce a platform-specific
bad-descriptor result or open a checkpoint outside the captured ownership
boundary. The
captured lock descriptor is also required to remain open. The shared lock
cleanup helper rejects a missing or already-closed descriptor with `ErrClosed`
before invoking platform lock-release or file-close methods, so malformed
cleanup cannot dispatch platform cleanup against an unavailable ownership
handle or turn it into a panic. The lower Unix and Windows lock acquire/release
helpers apply the same guard before dispatching `flock` or `LockFileEx`, so a
direct or malformed in-process caller cannot pass a nil or closed ownership
descriptor into the native lock primitive. Unix store-directory cleanup applies the same
closed-descriptor guard before closing the captured root handle; malformed
cleanup therefore reports `ErrClosed` instead of silently claiming that the
root-directory ownership resource was released. If malformed
in-process state closes either captured descriptor without clearing the store
field, live operations return `ErrClosed` before pathname identity checks or
mutation, so a replacement lock path cannot restore stale ownership and a
closed root cannot fall through to path-based replacement. The
Unix directory-handle seam contains `Sync` and `Close` panics before returning
to the atomic writer, and panic values are replaced with a generic
classification that never becomes lifecycle error text.
Windows uses `MoveFileExW` with
`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`, because the portable
`os.Rename` path does not replace an existing destination there; the native
write-through flag is the Windows durability boundary. Other platforms retain
the portable replacement primitive without claiming either native durability
guarantee. A failed write leaves the prior in-memory and on-disk checkpoint
selected. Before each durable mutation, and before serving a read or binding
an adapter, the store rechecks that the state root is still a private,
non-symlink directory with the same filesystem identity captured when its
writer lock was acquired. Each live recheck observes the path with `Lstat`,
followed `Stat`, and a second `Lstat`; a pathname that becomes a symlink or
another filesystem object during that sequence fails closed. Writes perform
this same observation before serialization, before creating the temporary
replacement, and again immediately before installing that replacement. A
replaced, redirected, or unavailable root fails closed for reads and writes
and leaves the prior in-memory and on-disk checkpoint selected. The same
durable-write preflights revalidate the captured `.lifecycle.lock` inode. If
the lock pathname is replaced after operation admission but before temporary
file creation or replacement, the old store fails closed before writing beside
a newly admitted replacement lock.
The lower root-observation comparison helper also rejects a missing or
typed-nil path, resolved, current, or expected observation before calling
filesystem identity methods; direct in-process callers therefore receive
`ErrInvalid` instead of turning an unavailable interface value into a panic.
The platform root validators apply the same lower-boundary rule to a missing
or typed-nil directory observation, and Unix ancestor validation rejects a
missing or typed-nil parent observation before inspecting mode or symlink bits.
The Unix and Darwin state-file validator also rejects a missing or typed-nil
descriptor observation before inspecting regular-file, permission, or
hard-link metadata; direct lower-helper callers therefore receive a bounded
error instead of a nil-observation panic. Root and lock identity validators
apply the same typed-nil rule to their `os.FileInfo` inputs.
This check does not replace the native supervisor/ACL gate. On Linux and
macOS, the stored root descriptor keeps writes in the originally opened root
even if its pathname is renamed after the final check; a missing/replaced
pathname still fails the next preflight and the caller must reopen the store.
Windows retains its native ACL and write-through boundary as a supervisor gate.
The state is capped at 8 MiB and a checkpoint payload at 1 MiB; the store
also caps projects, tasks, idempotency-index entries, and each task's
dependency list at 32 entries. The idempotency index is bounded to the task
limit before persisted entries are semantically inspected, so a malformed
checkpoint cannot allocate an unbounded retry index within the state-file
limit. Each persisted index key is also limited to the canonical
`project-id`, NUL separator, and non-empty idempotency-key bounds, and its
mapped task ID is limited to the normal task-ID bound before map lookup; malformed
or oversized entries fail closed.
The live-state validator applies the dependency-count, dependency-ID, and
checkpoint-payload bounds before recomputing a task request hash. It also
applies one shared 8 MiB raw-variable budget to all attacker-controlled state
strings (including IDs, idempotency keys, request hashes, lease/checkpoint
owners, and reverse-index entries) plus retained checkpoint payloads before a
mutation can clone the state. A direct or future in-process state seam
therefore cannot spend hash or clone work on aggregate variable data that the
lifecycle contract will reject; the later commit boundary still checks the
exact indented JSON representation, including base64 and field overhead,
against the same persisted ceiling. The preflight checks each dependency-list
count before iterating its strings, so a malformed in-process slice of empty
dependency values cannot turn the byte budget into an unbounded scan.
The lower aggregate-budget helper also owns the project, task, and idempotency
map-count ceilings when called directly. An oversized map of otherwise empty
values therefore fails before the helper scans its entries; callers retain the
same fail-closed result even if a future in-process seam bypasses the higher
state-shape preflight.
The exact serialized-size helper repeats those map-count and raw-variable
preflights before calling `json.MarshalIndent`. A direct caller therefore
cannot bypass the cheap resource boundary and make the representation check
marshal an oversized state snapshot.
The private state clone helper repeats the map-shape and aggregate-variable
preflight, applies the local identifier/name/request-hash/state-string length
ceilings, then rechecks each dependency-list and checkpoint-payload ceiling
before checking the exact indented JSON representation used for persistence and
allocating replacement maps or copying dependency slices and checkpoint
payloads. JSON base64
expansion and field overhead therefore cannot make a raw-bounded snapshot
become an oversized clone even when it bypasses the normal operation admission
path; the local length pass is a resource guard, while full UTF-8, relationship,
timestamp, and state-transition semantics remain the responsibility of
`validateState`. The individual payload check remains necessary because an
aggregate 8 MiB budget could otherwise admit one checkpoint larger than the 1
MiB contract. The lower `cloneTask` helper repeats the task identity, project
reference, idempotency/request/lease-owner/state, dependency-ID,
dependency-count, and checkpoint identity/state/payload length checks before
copying either nested slice; malformed direct callers therefore receive a zero
task rather than an oversized or invalid defensive copy. Normal store paths
have already validated these fields, so this does not change valid task
results. Mutation methods also pass the lower state clone through a shared
error boundary before dereferencing it. If a direct in-process integration
changes the live state after operation admission but before cloning, the
mutation returns `ErrInvalid` without installing an in-memory candidate or
writing a checkpoint; it does not turn the clone helper's bounded `nil`
rejection into a panic.
The lower readiness map-shape preflight owns the persisted project, task, and
idempotency-index entry-count ceilings as well as the same checkpoint-payload
and aggregate raw-variable ceiling for every task entry, including unrelated
tasks, before one candidate can be reported ready; a malformed or oversized
unrelated map therefore cannot consume unbounded validation work, retain an
oversized checkpoint, or hide state corruption behind a ready result.
After those field and aggregate-variable checks, the lower readiness preflight
also encodes the bounded snapshot with the same indented JSON representation
used by durable commits and rejects it when the serialized result exceeds
8 MiB. This accounts for checkpoint-payload base64 expansion and map/field
overhead, so a direct in-process snapshot cannot pass on raw-byte accounting
and then be retained or cloned in a form that the durable writer would reject.
`Ready` performs that complete map-wide preflight once for its locked state
snapshot, then evaluates each candidate against the already-validated graph;
it does not repeat the bounded graph walk for every task. A malformed snapshot
therefore still fails closed, while a maximum-sized valid snapshot retains a
bounded linear preflight instead of multiplying the full validation cost by
the number of candidates.
It also rejects any supplied non-zero durable-state version that is not the
current lifecycle schema version before readiness is reported. Zero remains
accepted for partial in-process readiness fixtures, but a future or incompatible
version cannot pass this lower boundary when the normal reopen validator would
reject it.
It also requires every dependency in every bounded task entry to resolve to a
different task in the same project with matching embedded identity. A missing,
self-referential, or cross-project dependency in unrelated state therefore
cannot be hidden by an otherwise-ready candidate.
	Any non-empty request fingerprint supplied by an in-process task entry must
	also equal the canonical project/dependency hash; partial lower-level task
	values may still omit that optional metadata, but a substituted fingerprint
	cannot be hidden in an unrelated entry and leave a ready result looking valid.
Once an actionable pending or running task supplies any durable retry,
dependency, lifetime, lease, or checkpoint metadata, the same lower boundary
requires its request fingerprint to be present and canonical. Otherwise
zero-value partial tasks and established terminal dependency fixtures may omit
the fingerprint, while populated malformed queued work cannot hide behind an
otherwise-ready candidate.
The same rule applies to populated terminal tasks: a terminal task that retains
retry, dependency, lifetime, or checkpoint metadata must retain its canonical
request fingerprint before it can attest that a dependency is complete. Only a
zero-value terminal dependency fixture remains eligible for the lower-level
compatibility path.
It also validates any supplied project name against the same bounded identity
contract used by project creation, while retaining zero-value names for partial
in-process readiness fixtures. A malformed unrelated project name therefore
cannot be hidden by an otherwise-ready candidate. It rejects oversized project and task map keys, plus oversized task-to-project
references, before including them in validation diagnostics; malformed in-process
state therefore cannot widen the identifier or error-output budget before the
dependency graph validator runs.
Supplied project and task lifetime metadata is all-or-none at this lower
boundary: zero-value partial fixtures may omit both endpoints, but providing
only a creation or update timestamp is rejected. Running entries are treated
as complete lease-bearing values rather than zero-value partial fixtures: their
created and updated timestamps must both be present before the lease horizon is
applied. This keeps unrelated partial or running tasks from passing direct
readiness even though the durable reopen validator would reject them.
Terminal tasks that supply durable metadata must retain their terminal checkpoint,
matching the persisted-state contract; zero-value partial terminal fixtures remain
accepted for lower-level readiness tests, but a populated unrelated terminal task
without a checkpoint cannot be hidden by an otherwise-ready candidate.
An explicitly retained checkpoint in that map-wide preflight must also carry a
non-zero, representable creation timestamp; a zero timestamp is only tolerated
when the checkpoint is absent, never as partial checkpoint metadata.
The lower dependency-graph helper applies the complete task and dependency ID
contract before sorting vertices or looking up edges, so a direct in-process
caller cannot make an empty or control-character identifier appear as a graph
vertex or dependency merely by placing the same malformed key in the task map.
The lower readiness helper also requires a bounded canonical project map with
an embedded project identity matching the candidate before it considers task
readiness; a direct in-process task cannot establish readiness from a missing
or substituted project entry. It requires both the canonical map task and its
caller-bound candidate to remain pending; completed, failed, cancelled, or
already-running tasks cannot be reclassified as ready merely because their
dependencies are complete. The caller-bound candidate's request fingerprint
must equal the canonical map entry and the bounded project/dependency hash;
a same-ID candidate with a tampered fingerprint is not ready.
Bounded checkpoint reads also reject negative, overlarge, or overflow-prone
limits before opening the reader. The helper itself enforces the 8 MiB state
ceiling, so an invalid internal bound cannot become a misleading empty read,
large allocation, or bypass of the intended size ceiling.
The shared duplicate-key JSON scanner enforces the same 8 MiB upper bound at
its own lower boundary, so a direct or future parser caller cannot bypass the
persisted-state resource ceiling before duplicate-key inspection begins.
The lower bounded-file reader also rejects a nil or already-closed descriptor
with a bounded error before dispatching the read; a malformed in-process
caller therefore cannot turn an unavailable state handle into a
platform-specific read failure.
The MCP aggregate JSON writer likewise rejects a nil receiver at its lowest
write seam with the bounded-response error before touching the embedded buffer;
direct or future in-process response builders therefore fail closed instead
of turning an unavailable writer into a panic.
All text identity fields (IDs, project names, lease owners, and idempotency
keys) must be valid UTF-8, bounded, and free of Unicode control, format,
line-separator, or paragraph-separator characters before mutation, and
durable-state validation rechecks the same lease-owner and idempotency-key
rules during reopen/repair. This prevents Go's JSON encoder from replacing
invalid bytes or preserving ambiguous control, bidi, zero-width, or
line-breaking characters during persistence and changing retry or ownership
identity after reopen. Ordinary non-ASCII text remains valid.
Mutation timestamps use a per-store
monotonic floor: if the wall clock
steps backwards, the store retains the latest observed/persisted timestamp
until the clock catches up. Reopen seeds that floor from durable project/task
and checkpoint timestamps, so clock corrections cannot create a state file that
is internally non-canonical and fails only on the next reopen. The injected
clock seam is fail-closed as well: a zero timestamp, callback panic, or time
outside the JSON year range rejects the mutation before cloning, persistence,
or advancing the floor, and the panic value is not exposed. The check also
requires the maximum one-hour lease horizon to remain JSON-representable, so
`Acquire` and `Heartbeat` cannot clone a candidate whose expiry would fail
serialization. Reopen floor seeding applies the same horizon check to every
project, task, and retained checkpoint timestamp it may adopt, so a
JSON-representable year-9999 value cannot seed a clock floor that makes the
next lease mutation fail. Production callers should leave `Options.Now` unset;
tests and deterministic supervisors must provide a non-panicking clock that
returns non-zero UTC-compatible values within that representable horizon.
The retained per-store floor is revalidated before it can be returned for a
backward clock step; malformed in-process floor state therefore fails closed
without returning an unrepresentable timestamp or advancing the floor.

The lower clock helper also returns `ErrClosed` for a nil or uninitialized
store before invoking a missing clock callback. Normal operations establish
the complete store binding first; the explicit lower guard keeps direct and
future in-process callers from turning unavailable state into a panic-shaped
clock error.

The lower timestamp-seeding helper also treats an unavailable,
unsupported-version, oversized, or aggregate-oversized in-process state as
having no timestamp instead of dereferencing or walking it. It validates both
project/task lifetime endpoints, their ordering, and retained checkpoint
timestamps against the JSON representation and task lifetime before adopting
any floor, rejects an exact indented-JSON snapshot above the 8 MiB durable
limit, and rejects an oversized checkpoint payload. An orphaned or
project-preceding task, an identity-mismatched checkpoint, an omitted or
reversed creation endpoint, or a checkpoint outside its task lifetime therefore
cannot hide behind a valid update timestamp when a direct or future in-process
caller reaches this lower boundary. `Open` still validates the decoded durable
state before adopting any floor.

The lower durable-state clone helper likewise returns no candidate for a nil or
unsupported-version receiver. Exported operations validate the live store
before cloning, and the commit boundary rejects a nil candidate; the helper
guard keeps direct and future in-process callers from adopting an incompatible
state or turning unavailable state into a panic.

Live-state validation also checks every project, task, lease, and checkpoint
timestamp against the JSON wire representation before serving a read or
deriving a candidate. Persisted decoding normally provides this guarantee,
but an integration that mutates in-process state after `Open` must fail closed
instead of returning an unrepresentable timestamp and only discovering the
problem during a later write.

Durable chronology is checked on reopen as well: a task cannot predate its
project, and a checkpoint cannot fall outside its task lifetime. This rejects
repaired or tampered state that could otherwise present an impossible resume
history while preserving archived projects and later task updates.

Projects can be archived. Archiving prevents new tasks while leaving existing
tasks inspectable and resumable. Tasks form a forward-only DAG: dependencies
must already exist in the same project, duplicate dependencies are rejected,
and `Ready` returns pending tasks with all dependencies completed in stable ID
order. Reopen also validates the complete persisted graph and rejects a
dependency cycle, so tampered or incorrectly repaired state cannot make
readiness or recovery loop indefinitely. The reopen validator walks the
bounded graph iteratively with explicit work frames rather than recursive
goroutine calls, keeping a long (up to the 10,000-task state bound) dependency
chain within the lifecycle resource budget. The lower graph helper also rejects
a nil task map or a missing dependency before traversal, so direct in-process
callers cannot turn an incomplete graph into an apparently acyclic one.
It also rejects a direct graph larger than the 10,000-task persisted bound and
dependency lists larger than the 32-entry task bound before allocating traversal
work. It rejects oversized task and dependency identifiers before sorting,
map lookup, or diagnostic formatting, so malformed in-process callers cannot
widen the graph's identifier or error-output resource budget.
Before graph traversal it also requires each task value's embedded ID to match
its validated map key, so a replaced or partially initialized direct map entry
cannot become a graph vertex under a different identity.
The readiness helper likewise returns not-ready when its state graph or task
input or receiver is unavailable, and rejects a direct dependency list above
the 32-entry or 128-byte identifier bounds before map lookup. It also applies
the persisted task-map identity rule after each lookup: a completed value whose
embedded task ID does not equal the requested map key cannot establish
readiness. This keeps direct in-process readiness checks fail-closed when a
state map entry was replaced or only partially initialized.
It also rejects task or idempotency maps larger than the persisted state
budget before a direct caller can obtain a ready result from an oversized
in-process state graph.
The canonical map definition and caller-bound dependency slice are both
checked against the 32-entry limit before they are compared, so two equally
oversized direct definitions cannot force unbounded lower-boundary comparison
work before rejection.
The candidate task itself must also have a valid project identity and match the
state-map entry for that task ID. Each completed dependency must belong to that
same project. A direct or future in-process caller therefore cannot combine an
unbound task or cross-project completed work into an affirmative readiness
result. The bound dependency definition must also remain canonical (strictly
increasing, with no duplicates), matching the persisted graph contract. The
full lifecycle ID rule is applied before each dependency lookup, so
an empty, whitespace-padded, or control-character dependency cannot make a
malformed direct task appear ready.
Direct in-process callers therefore cannot turn an incomplete dependency check
into a panic, an affirmative readiness result, or unbounded dependency
scanning. Pending resumable checkpoints are bounded and validated for both the
canonical task and caller-bound candidate before their payloads are compared,
so an oversized substituted payload is rejected before lower-boundary payload
comparison work.

`Task.CheckpointPayload()` returns a defensive copy. A task value may share its
optional checkpoint pointer with another copied task value, so the accessor
must not provide a byte-slice alias that can mutate checkpoint metadata outside
the store's locked mutation path; a task without a checkpoint still returns
`nil`. Because the method has no error return, an exported in-process `Task`
value carrying a payload above the 1 MiB checkpoint bound also returns `nil`
instead of copying unbounded caller data; valid payloads retain the established
defensive-copy behavior.

Each acquired task has an owner, monotonically increasing lease version,
attempt count, and bounded expiry. Only the current owner and version may send
heartbeats or checkpoints. A terminal checkpoint (`completed`, `failed`, or
`cancelled`) records its payload and releases the lease in the same durable
transition. `Acquire` refuses an expired running lease with `ErrLeaseExpired`
until `RecoverExpired` explicitly converts it back to pending; it never
executes or silently retries work. Reopening a store does not perform implicit
recovery, so a supervisor can record and review the recovery decision.

Attempt and lease-version counters increment together. If either counter reaches
the maximum representable value, the next acquisition is rejected before any
in-memory or durable mutation so counter wraparound cannot create version zero
or an invalid ownership record.

An idempotency key is scoped to a project and maps to the original task
request fingerprint. Retrying the same request returns the original task even
if the project was archived after the original creation; only a genuinely new
task is blocked by the archived-project policy. Reusing the key with different
dependencies fails closed. A present but malformed live reverse-index entry,
including one that points to a task with a different or missing project/key
identity, is also rejected as invalid rather than being treated as an absent
key, so a damaged in-process integration cannot return an unrelated task or
create a duplicate task while the bad index remains active. Every live
operation also revalidates the complete bounded in-memory state after the
ownership and root checks. If an in-process integration changes a task,
project, dependency, checkpoint, lease, or reverse-index invariant after
`Open`, the operation fails with `ErrInvalid` before serving that state or
deriving/persisting a replacement checkpoint. The last durable checkpoint
remains selected and the caller must repair or reopen the store. The store's mutex
serializes operations within one process, while the state-directory lock
serializes writers across processes. The persisted lease/version remains the
task ownership boundary exposed to future gateway and agent adapters; the lock
does not grant a task lease or silently recover expired work. Operations after
`Close` return `ErrClosed`. Direct calls through a nil `*Store` receiver also
return `ErrClosed` rather than panicking; adapter constructors still reject a
nil store before binding an authenticated owner. The same fail-closed result
applies to a malformed non-nil store whose ownership binding is incomplete:
every operation requires the live lock, the validated absolute state root and
identity, the decoded state, and the clock function captured by `Open`. Each
operation rechecks the root identity before serving a read or binding an
adapter, so a root pathname replacement cannot leave stale in-memory state
available through selectors or a newly bound controller. A direct or
in-process integration cannot turn a partially initialized store into a
nil-state or nil-clock panic path. The shared state validator also rejects a
nil durable-state pointer as `ErrInvalid` before inspecting its version or
maps, so lower validation seams fail closed instead of panicking when handed
an incomplete candidate.

Read selectors (`Project`, `Task`, `Tasks`, and `Ready`) validate their project
or task identifier with the same bounded ID rule used by mutations before
looking in the state maps. Invalid, oversized, whitespace-padded, or
control-character selectors therefore fail with `ErrInvalid` rather than
being treated as an ordinary not-found lookup. This keeps direct in-process
callers aligned with the MCP boundary's bounded identity contract.

The implementation otherwise uses the Go standard library. The one reused
`golang.org/x/sys` dependency is already present for the existing Windows
terminal adapter; its BSD-3-Clause license, maintained release line, and
platform syscall wrappers keep the added footprint narrow and offline. This
checkpoint uses only `unix.Open`, `Openat`, and descriptor inspection; it adds
no process, listener, model, credential, or resident-service footprint. Its
security value is limited to the Darwin descriptor-boundary read and remains
replaceable by a small native wrapper or removal of the isolated adapter. The
rollback path is reverting the Darwin file and direct dependency line, then
deleting the isolated v2 state directory or replacing the adapter; no 1.x
state is read or modified.

## Scoped controller boundary

`lifecycle.NewController` is the additive `ai-relay/lifecycle/v1` boundary for
gateway and agent adapters. It binds every lease, heartbeat, and checkpoint to
one stable authenticated principal supplied by the adapter constructor. The
principal is never read from task parameters, and a lease or checkpoint carrying
another owner is rejected before it reaches the store. Reads and project/task
creation use the same isolated store but do not grant command execution.

`lifecycle.NewScopedController` adds the transport-neutral authorization layer
for a future v2 adapter. Its `Principal` contains only an already-authenticated
stable ID and explicit lifecycle scopes; unknown, duplicate, or overlong (more
than 256 bytes) scopes fail closed. The scope claim is also bounded to the
number of currently supported scope names before the allowlist map is
allocated, and each name is bounded before hashing, so malformed authenticated
input cannot cause unbounded scope processing. Project reads/writes, task
reads/writes, task lease mutations, and expired-lease recovery have separate
scope names. The wrapper never accepts an owner parameter and delegates lease
operations to the owner-bound controller, so a transport cannot turn a scope
into cross-principal ownership. Token verification, controller registration,
HTTPS, and device authentication stay outside this package. The existing 1.x
MCP and agent routes are not wired to this API.

Scoped-controller admission validates the authenticated owner ID and bounds the
scope claim before it validates the live store or allocates the allowlist map.
An oversized, unknown, duplicate, or overlong claim therefore fails at the
cheapest boundary even if the store is concurrently malformed or unavailable;
scope rejection does not spend lifecycle-state validation work. A valid claim
then binds to the currently open store through `NewController`.

The underlying `NewController` applies the same ordering to its direct
owner-bound boundary: it validates the authenticated owner ID before checking
the live store. An invalid principal therefore cannot spend store validation
work, even when an in-process integration supplies malformed lifecycle state.

Every exported controller operation applies that ordering to its direct input:
it checks the immutable owner binding, validates the operation's bounded IDs,
names, dependency list, lease, or checkpoint payload, and only then rechecks
the live store before delegating to the core operation. This keeps malformed
direct calls from spending full state-validation work and preserves the same
`ErrInvalid` input contract used by the MCP adapter. A closed or structurally
malformed controller binding still fails as `ErrClosed` before caller input is
considered. Heartbeat and checkpoint also bound the lease's supplied owner
identity before comparing it with the authenticated owner, so an oversized
spoof cannot turn the ownership comparison into an unbounded direct-call seam;
a valid but different owner continues to return `ErrNotOwner`.

The exported scoped controller revalidates its owner-bound controller and
scope allowlist on every direct operation and accessor. A malformed in-process
binding therefore returns `ErrClosed`, exposes no owner or scope list, and
cannot retain a scope through `allows`; constructor-created bindings are
unchanged. Mutation admission checks that structural shape and the explicit
closed flag before checking the requested scope, so an ungranted operation
returns `ErrForbidden` without spending full live-state validation work even
if an in-process state is malformed. An allowed operation then rechecks the
live store through the owner-bound controller. A controller kept after
`Store.Close` exposes no owner or scopes and cannot retain authorization
through `allows`; direct operations return `ErrClosed`. The MCP adapter reuses
this invariant before request parsing and capability advertisement, while its
live-store check remains the separate closed-state boundary.

Controller construction requires a currently open, initialized store. A
zero-value or already-closed store is rejected with `ErrClosed` before an
authenticated owner is bound; an adapter that was constructed successfully
still re-checks the store on every operation after a later `Close`. This keeps
misconfigured transport setup from presenting a lifecycle backend that can
only fail after authorization.
The controller also revalidates its immutable owner binding on every exported
operation. Construction records a private owner snapshot, and the live owner
must still match that snapshot; even an in-process substitution with another
otherwise-valid ID therefore fails closed instead of widening or transferring
authority. A malformed in-process controller therefore returns `ErrClosed` for
reads and mutations, and its `Owner` accessor returns an empty value rather
than exposing a damaged principal. A controller retained after the store
closes also returns an empty owner, so identity metadata cannot outlive the lifecycle
backend it authorizes. Constructor-created controllers retain the validated
owner while the store is live; this is an additional fail-closed boundary for
direct or future integrations that cannot otherwise construct a controller
through the public constructor.

The boundary is deliberately transport-neutral: the existing 1.x agent command
protocol and MCP tools remain unchanged until a reviewed v2 gateway adapter
assigns scopes and maps authenticated controller/agent identities. The agent
adapter must pass its authenticated device identity to `NewController`; it must
not use a user-provided display name. Recovery remains an explicit supervisor
operation and does not execute or retry tasks.

## Additive MCP adapter checkpoint

`NewMCPAdapter` is the first versioned wire adapter for this boundary. It takes
an already authenticated `Principal`, constructs the owner-bound scoped
controller, and exposes `ai-relay/lifecycle/v1` through JSON-RPC 2.0 MCP
`initialize`, `ping`, `tools/list`, and `tools/call`. It is a library boundary;
it does not open a listener, authenticate bearer tokens, issue OAuth metadata,
or claim HTTPS. A future gateway or agent transport must perform those checks
before constructing the adapter and must keep the adapter instance scoped to
that authenticated principal.

The adapter rechecks its live store before parsing any request, including
`initialize`, `ping`, and `tools/list`, not only lifecycle tool dispatch. A
store close therefore invalidates existing adapters instead of leaving a stale
handshake or capability advertisement available; callers must reopen the store
and construct a new owner-bound adapter.

The adapter also validates its complete in-process controller/store binding at
that same boundary. A malformed integration value fails with the private
`ErrClosed` sentinel instead of panicking while dereferencing a missing nested
controller or store. The authenticated owner identity is part of that binding
too and must remain a valid bounded lifecycle ID; an empty or malformed owner
fails closed even when the store and scope map remain usable. The scoped
controller's authorization map is part of that binding: it must be non-empty,
contain no unknown scope, and contain no more entries than the current
lifecycle allowlist. A nil, empty, unknown, widened, or owner-invalid binding
fails closed as `ErrClosed`; callers must construct a fresh adapter through
`NewMCPAdapter` rather than repairing or reusing malformed in-process state.

The `initialize` response advertises `2025-06-18`. An incoming
`protocolVersion` may be omitted for compatibility with older trusted
in-process callers, but when supplied it must be a non-empty string matching
that version and is bounded to 64 bytes before JSON string decoding. Unsupported,
oversized, or non-string versions fail with JSON-RPC invalid parameters instead
of being silently treated as compatible. When supplied,
standard `capabilities` and `clientInfo` fields must be JSON objects whether or
not the optional version is present; their members remain opaque to the
lifecycle store, so transport-specific negotiation can evolve without
expanding task or ownership authority. Omitting the version therefore remains
compatible, but cannot weaken the shape validation of metadata that is present.

The adapter exposes only the project, task, lease, and recovery tools granted
by the authenticated principal's lifecycle scopes. `tools/list` preserves the
stable tool order while filtering out unauthorized operations; a caller with
no scope for an operation cannot discover it through this adapter. `tools/call`
still performs the authoritative scope check, so discovery is client guidance
and never an authorization substitute. The adapter exposes project
reads/writes, task creation/read/list/ready, lease acquire/heartbeat,
checkpoints, and explicit expired-lease recovery. Lease
heartbeat and checkpoint arguments contain only task/version data; the owner is
inserted from the authenticated principal and cannot be substituted by tool
input. Unknown or duplicate JSON object fields, malformed argument objects,
unsupported tools, and non-string/non-integer-number request IDs fail closed. Duplicate
keys are rejected recursively before decoding so an intermediary cannot observe
a different value from the authenticated lifecycle adapter. Side-effecting
notifications are ignored rather than executed without a response correlation
ID. If a malformed request carries an invalid JSON-RPC ID type, the error
response uses `null` rather than reflecting that uncorrelatable value.
The request-ID preflight consumes exactly one complete JSON value; a raw ID with
another trailing value is invalid even if its first token is otherwise an
accepted string or integer. The ID helper also rejects invalid UTF-8 on its own,
so this invariant remains fail-closed if a future transport calls it outside the
enclosing request decoder. The response builder repeats this check before
reflecting a correlation ID; an internal caller that supplies an invalid,
incomplete, or multi-value raw ID gets JSON `null` instead of a malformed or
attacker-controlled response ID.
Syntactically malformed JSON returns JSON-RPC parse error `-32700`; a
well-formed value that is not a request object, or whose `jsonrpc` or `method`
field has the wrong type, returns invalid request `-32600` with a `null` ID.
Well-formed envelope-policy failures, including unknown or duplicate top-level
fields, are also invalid request `-32600` rather than parse errors.

`ping` and `tools/list` accept omitted parameters or an empty object only.
They reject arrays, `null`, and unknown fields as invalid parameters; this
adapter does not implement ping options or `tools/list` pagination, so a
client cannot silently receive an incomplete or differently scoped result by
supplying an unsupported cursor.

Every advertised tool also carries MCP safety annotations. Read-only project and
task selectors are marked `readOnlyHint: true`, local lifecycle mutations are
marked `readOnlyHint: false`, terminal checkpoints/archive/recovery are marked
`destructiveHint: true`, and every tool is marked `openWorldHint: false` because
the adapter touches only its isolated local state. Idempotency is claimed only
for stable reads and the archive operation; lease, checkpoint, and task-creation
operations remain non-idempotent in their wire metadata because retries can
change ownership, advance a checkpoint sequence, or conflict on an existing ID.
These are client guidance annotations, not authorization: scope checks and the
owner-bound controller remain authoritative.

The `tools/list` schema is authoritative for client-side validation. In
particular, `lifecycle.task.create` requires both `id` and `project_id` and
advertises no additional properties. The MCP boundary enforces the explicit
task ID even though the lower-level in-process store may generate IDs for
trusted callers. The acquire schema contains only a task ID and the enforced
one-to-3600-second TTL; it does not accept a lease version because acquisition
creates that version. Heartbeat and checkpoint schemas advertise positive lease
versions; checkpoint schemas enumerate the four
non-pending states accepted by the server. Required identity and project-name
strings, including dependency items, advertise `minLength: 1` and the existing
ID/name byte ceilings (`maxLength: 128` for IDs and idempotency keys, `256` for
project names). These schema lengths are client-side code-point ceilings; the
server remains authoritative for the stricter UTF-8 byte limits and control
character rules. Task creation also advertises and enforces a maximum of 32
dependency items, keeping per-task DAG validation bounded independently of the
global task limit. Optional checkpoint payloads may be empty and advertise the
one-megabyte `maxLength` resource ceiling; the server still enforces the
one-megabyte UTF-8 byte bound and any control-character policy because JSON
Schema string length is not a UTF-8 byte length bound. Every advertised input schema
keeps `required` as a JSON array, including an empty array for the no-argument
expired-lease recovery tool; clients never receive JSON `null` for this array
keyword. For every advertised property, an omitted optional value is distinct
from an explicit JSON `null`: the former uses the schema's optional behavior,
while the latter is rejected as a typed-argument error. This prevents Go's
zero-value decoding of `null` into an optional string or array from weakening
the published MCP schema.

Requests are capped at 64 KiB, and the envelope, single-value JSON framing,
protocol-parameter, strict-object, exact-member-object, exact-member validator,
explicit-null, argument-parser, and request-ID
helpers repeat that bound for direct or future internal callers instead of
relying only on the exported adapter entry point. MCP object members must use
their exact schema spelling; case variants such as `JSONRPC` for `jsonrpc` are
rejected even though Go's generic JSON decoder normally matches struct fields
case-insensitively. The shared strict JSON decoder also serves the larger
persisted lifecycle-state boundary and therefore keeps that state limit
separate; the shared decoder itself rejects input above the 8 MiB state ceiling
before UTF-8 validation or decoder setup. This keeps response-ID validation
from decoding an oversized scalar supplied by a direct response-builder caller.
Every JSON value is scanned for duplicate keys
and nesting is capped at 128 levels (including well-formed non-object
envelopes), and encoded responses are capped at 256 KiB. MCP lease arguments
accept whole seconds from 1
through 3600; the bound is checked before conversion to `time.Duration`, so
oversized integers cannot wrap into a shorter lease. Tool failures are returned
as bounded MCP tool errors with stable codes (`INVALID_ARGUMENT`, `NOT_FOUND`,
`CONFLICT`, `ARCHIVED`, `LEASE_HELD`, `LEASE_EXPIRED`, `NOT_OWNER`,
`DEPENDENCIES_INCOMPLETE`, `TERMINAL`, `IDEMPOTENCY_CONFLICT`, `FORBIDDEN`, and
`CLOSED`); unexpected persistence or integration failures use `INTERNAL` and a
generic message so local filesystem/dependency details do not cross the
authenticated boundary. Expected lifecycle/parser detail is normalized to valid
UTF-8 in a single bounded-prefix scan, capped at 8 KiB, and truncated only at a
UTF-8 boundary, so direct callers and untrusted request text cannot turn
an otherwise classifiable tool error into an oversized response. Controller result and response encoding uses a fixed
aggregate writer bound rather than building an unbounded intermediate JSON
buffer. A controller value that cannot be JSON-encoded or exceeds the bound is
converted to that bounded `INTERNAL` tool error; its encoder diagnostic never
becomes a transport error or crosses the authenticated boundary. If the
complete MCP wrapper would exceed the aggregate response bound after a value
is represented in both `content.text` and `structuredContent`, the adapter
returns the same bounded `INTERNAL` tool error instead of a transport error.
Panics from caller-supplied JSON marshaling methods are contained at the same
encoder boundary and are converted to that generic result; panic values and
partial output never cross the MCP surface.
Error classification preserves ordinary wrapped and joined lifecycle sentinels
but traverses an in-process error unwrap graph through a fixed node budget.
Cycles, excessive depth, or panics from custom `Is`/`Unwrap` methods therefore
fail closed to the generic `INTERNAL` result instead of hanging the authenticated
adapter or leaking integration diagnostics.
The bounded JSON helper accepts only positive limits up to the fixed 256 KiB
MCP response ceiling and rejects overflow-prone maximum-integer limits before
adding the encoder's trailing-newline allowance. An invalid internal bound
therefore cannot wrap into an unbounded or negative writer ceiling, and a
future caller cannot weaken the protocol-wide response limit by passing a
larger local limit.

The duplicate-key scanner's recursive helper also rejects a nil decoder and
an invalid starting depth before calling the JSON decoder. This keeps the
lowest parser seam fail-closed for direct in-process callers; the normal
request and persisted-state paths still enter it only after their byte and
UTF-8 bounds have been applied.

The lifecycle dependency normalizer validates every dependency identifier against
the bounded ID contract before copying or sorting the list. Direct callers
therefore fail before ordering work on malformed oversized strings, while the
existing 32-item dependency ceiling remains enforced independently.
Argument parser failures retain bounded detail, while
protocol/schema failures use JSON-RPC errors. The adapter is additive and is
not wired into the existing 1.x gateway routes; ChatGPT, Codex, and Gemini
account discovery or external controller receipt remain separate authenticated
supervisor gates.

Transport adapters that own a request context should call `HandleContext` rather
than the compatibility `Handle` wrapper. It rejects literal- or typed-nil and
already-ended contexts before dispatching a mutating tool, returning the private
`ErrMCPRequestCanceled` sentinel for the HTTP layer to map to generic `408
Request Timeout`. Literal-nil, typed-nil, already-ended, and malformed
non-nil contexts whose `Err` or `Done` method panics are all treated as ended
before a mutating operation. A closed `Done` channel is also treated as ended
even if a malformed context incorrectly returns a nil `Err`; a nil `Done`
channel remains the normal non-cancelable representation. The adapter also
rechecks the context at the tool-dispatch helper boundary immediately after
argument decoding, closing the narrow post-decode window before controller
dispatch. It verifies that repeated `Done` calls return the same channel, as
required by `context.Context`, including when the first result is nil; a
changing channel is malformed and fails closed as ended before request parsing
or lifecycle mutation. `Err` is also checked again after the stable `Done`
probe, so cancellation that arrives during context inspection cannot be hidden
by a nil `Done` result. Panic values are not exposed.
The adapter does not
expose context or cancellation details in the MCP wire response, and a
canceled or malformed direct call cannot create or change a lifecycle object.

## Authenticated HTTPS transport boundary

`NewMCPHTTPHandler` is an additive `net/http` boundary for a future v2 route.
It is fail-closed at construction: the caller must provide a principal
resolver and a secure-transport verifier. The resolver is responsible for
OAuth/bearer verification, expiry, audience/resource binding, and mapping the
authenticated controller or agent to stable lifecycle scopes. The handler
never parses or logs credentials and returns generic HTTP errors for resolver
failures.

`ValidateDirectTLSConfig` and `ValidateDirectHTTPSListenPolicy` return the
opaque exported `ErrDirectTLSConfigInvalid` classification for every rejected
or panic-contained TLS preflight. Integrations may use `errors.Is` to separate
invalid local construction from other setup failures without matching error
text; the sentinel does not expose certificate, key, or callback details.

The verifier must prove the authenticated HTTPS boundary. `RequireDirectTLS`
is valid only when the handler is attached directly to an HTTPS server and
accepts only a request with a present URL and a completed handshake negotiated
at TLS 1.2 or TLS 1.3; unknown or synthetic future version values fail closed,
and the serving `tls.Config` must enforce the same explicit range.
When a direct request contains an `Origin` header, `RequireDirectTLS` requires
one bounded, well-formed HTTPS origin matching the request authority (including
the default HTTPS port rule); duplicate, empty, malformed, plaintext, path,
query/fragment-delimiter, and cross-origin values fail closed. An omitted
`Origin` remains valid for
non-browser MCP clients. This is the direct-server DNS-rebinding boundary
required by the MCP HTTP transport; a reverse-proxy verifier must apply its
own trusted-origin policy before returning true.
For direct serving, `NewDirectHTTPSHandler` is the reviewed construction path:
it composes `ValidateDirectHTTPSListenPolicy` with `RequireDirectTLS` before
constructing the handler, so a caller cannot knowingly build a direct handler
with a public/wildcard bind or an invalid TLS configuration. It performs no
listener creation or network I/O; the deployment must later serve the handler
using the same unchanged address and TLS configuration that passed the
preflight. Because this constructor does not own a listener, it requires a
concrete non-zero port; accepting `:0` here would leave every later loopback
port indistinguishable. The listener-owning `ListenDirectHTTPS` and paired
`BindDirectHTTPS` helpers may accept `:0`; the latter records the actual
OS-selected port before returning its handler. The reviewed handler also
retains the literal loopback host and approved port. For this reviewed HTTPS
authority, an omitted port is equivalent to `:443`; every other approved port
must remain explicit and canonical. Before either security callback it rejects a request whose
`Host` (or direct-call URL authority) names another host or non-equivalent port, even when its
`Origin` matches that attacker-controlled authority. `BindDirectHTTPS` replaces
an operator-supplied `:0` with the actual OS-selected port before returning the
handler. This configured-authority check closes the DNS-rebinding gap that a
generic `RequireDirectTLS` call cannot close on its own because it has no
listener configuration. Reverse-proxy integrations continue to use
`NewMCPHTTPHandler` with their own authenticated transport and host policy.
`ListenDirectHTTPS` is the additive listener handoff for a reviewed local
deployment. It repeats the same loopback and TLS preflight, binds only the
validated literal address, validates the caller-owned TLS shape before copying
any bounded collection, then validates one private TLS configuration snapshot,
and gives that same snapshot to the TLS listener. This closes the caller-
mutation gap between policy validation and listener construction; later
changes to the caller's configuration cannot alter the reviewed listener. The
snapshot also preserves nil-versus-present-empty state for the reviewed
mutable policy vectors, so an explicit empty list is not silently rewritten as
an omitted policy during the handoff. It
rejects a nil configuration before cloning or opening a socket, so malformed
direct setup returns a bounded error instead of panicking. It does not serve HTTP, load or provision
certificates, authenticate controllers, or publish the route; the caller owns
the returned listener and must attach the `NewDirectHTTPSHandler` result to an
`http.Server`. A successful local bind is therefore only construction and
loopback evidence, not native certificate-trust, authenticated distribution,
or production HTTPS evidence.
When a static `tls.Certificate` supplies both a DER chain and a private signer,
the first DER entry is parsed during preflight even when the optional `Leaf`
field is nil; its public key must match the signer. A malformed first entry or
key mismatch therefore fails before listener construction. Empty and partial
provisioning placeholders remain valid when either the chain or signer is
absent, so certificate identity and distribution remain deployment-owned.
The snapshot boundary also contains malformed or concurrently mutated
in-process configuration errors and panics as the opaque
`ErrDirectTLSConfigInvalid` construction classification; no partial handler or
listener is published. This contains the integration failure without exposing
panic detail, but does not make concurrent mutation safe or replace the
caller's ownership of the configuration.
`BindDirectHTTPS` is the paired convenience handoff when the caller wants to
construct both objects from one reviewed address/configuration pair. It takes
one private configuration snapshot before constructing the authenticated direct
handler and loopback TLS listener, and carries that exact snapshot through both
handoffs. This prevents validation and listener construction from drifting even
inside the paired helper, while later changes to the original caller input stay
isolated. A handler-construction failure therefore
cannot leave a listener behind. It returns ownership of the listener to the
caller and still does not serve HTTP, register a route, load certificates, or
claim native certificate trust or authenticated distribution evidence.
`BindDirectHTTPSServer` is the optional server-construction handoff for a
caller that wants the reviewed handler, TLS listener, and `http.Server` wired
together without starting the server. It reuses `BindDirectHTTPS`, so a
handler or listener failure returns no partial binding. The returned server
supplies explicit bounded defaults: a 64 KiB header limit, 10-second header
read timeout, 45-second request-read and write timeouts, and a 60-second idle
timeout. These are resource defaults for the serving layer; the caller still
owns shutdown, serving, certificate provisioning, authenticated distribution,
and may close the returned server, but the reviewed serving helper rejects
changes to any of those five bounds before starting. The helper performs no goroutine start,
route publication, certificate loading, or external network deployment.
It also fails closed if the caller changes the server's address metadata,
general-OPTIONS behavior, TLS configuration, connection-state or error-log
hooks, request context factories, or `HTTP2`/`Protocols` policy before
serving. A non-nil caller-supplied `TLSNextProto` map is likewise rejected
before the first serve; Go's standard library may populate that map itself
while enabling automatic HTTP/2 on the reviewed TLS listener, and a later
reuse attempt is rejected by the single-use guard before that internal state
is examined.
`ServeDirectHTTPSServer` is the bounded serving handoff for callers that want
the library to own the `Serve` goroutine until a context ends. Cancellation
requests graceful shutdown with a five-second drain bound and force-closes
remaining connections if that bound expires, then waits for serving to stop.
The shutdown operation and the final serve-result wait share that five-second
deadline; a malformed integration listener that blocks `Close` or fails to
unblock `Accept` is therefore reported as the exported
`ErrDirectHTTPSServeShutdownTimeout` sentinel instead of leaving the caller
waiting indefinitely. The binding is permanently consumed after this return,
so a later retry is rejected even if an uncooperative integration goroutine
finishes asynchronously.
The timeout sentinel is added only when the shutdown, forced-close, or final
serve wait actually reaches its bound (or returns the standard deadline cause).
Every bounded-operation timeout also preserves `context.DeadlineExceeded` as a
matchable cause, including the path where graceful shutdown returned cleanly
but the final serve wait or forced close did not finish. Panics from the
contained `Shutdown`/`Close` operations remain classified as
`ErrDirectHTTPSServeShutdownPanic` and are not mislabeled as timeouts when the
bound was not reached; any accompanying shutdown, close, or serve causes remain
matchable with `errors.Is`, even when a malformed integration reports an
operation error alongside the timeout classification.
When the force-close path is used, the returned error matches the exported
`ErrDirectHTTPSServeShutdownTimeout` sentinel and still preserves the standard
`context.DeadlineExceeded` cause. This lets callers distinguish a bounded drain
timeout from an ordinary serve failure; a successful graceful shutdown
continues to return the request context's cancellation error.
If the reviewed listener's construction-approved delegate returns a cleanup
error while `Shutdown` closes the listener, that error remains observable via
`ErrDirectHTTPSListenerCleanup` and the delegate cause, but is not mislabeled as
`ErrDirectHTTPSServeShutdownTimeout` when no drain timeout occurred.
An unexpected panic from the serving goroutine is contained as an opaque
serving error, and its result channel is always completed; callers can match
the exported `ErrDirectHTTPSServePanic` sentinel without depending on panic
text. A malformed in-process listener therefore cannot leave the caller
waiting indefinitely or expose panic text. Panics from the deadline-bounded
`Shutdown` and forced `Close` operations are likewise contained as the opaque
`ErrDirectHTTPSServeShutdownPanic` sentinel; a malformed in-process connection
or listener therefore cannot terminate the process through those cleanup
goroutines. The caller still owns cleanup of the returned listener.
The serving context is also an ownership input: literal-nil, typed-nil, and
malformed contexts whose `Err` or `Done` methods panic fail closed before the
server binding is claimed. A closed `Done` channel is treated as cancellation
even if a malformed context reports a nil `Err`; the validated `Done` channel
is retained for the serving wait so the helper does not call an untrusted
context implementation again from its select path. The helper also verifies
that repeated `Done` calls return the same channel, as required by the
`context.Context` contract; a changing channel is malformed and fails closed
before ownership is claimed. `Err` is rechecked after that stable `Done` probe,
including when the channel is nil, so cancellation that appears during context
inspection cannot be hidden by a non-cancelable result. The channel captured by
the initial validation
must also match the channel returned by the final pre-serve validation; a
context that changes channels between those probes is rejected before the
serving binding is claimed. This prevents cancellation from being detached
from the channel used by the serving wait.
Callers can match `ErrDirectHTTPSServeContextInvalid` with `errors.Is` for the
literal-nil, typed-nil, or malformed-context cases; the reviewed binding is
released without being marked served, so a corrected context may be retried
safely. Context implementations that return an error other than
`context.Canceled` or `context.DeadlineExceeded` are also malformed: the
serving boundary canonicalizes the two standard causes and returns
`ErrDirectHTTPSServeContextInvalid` for every other value, without exposing
caller-defined error detail. Panics while classifying that error remain behind
the same invalid-context sentinel.
It accepts only the private provenance-marked listener returned by
`ListenDirectHTTPS` or `BindDirectHTTPS`; a plain `net.Listener` is rejected
before serving so the helper cannot accidentally publish this HTTPS route over
plaintext. The returned listener keeps its TLS delegate private behind the
`net.Listener` interface, so an in-package handoff cannot replace the reviewed
delegate without crossing an explicit test seam. The private delegation methods
also reject a nil receiver or nil delegate with an opaque invalid-listener
error, and contain panics from the delegate's `Accept` and `Close` methods with
the same opaque error. This keeps direct listener callers fail-closed and
protects the synchronous `http.Server.Shutdown` path; a panic from the
delegate's `Addr` method returns no address. Malformed in-process construction
therefore fails closed without exposing delegate panic detail. Callers can
match the exported, opaque `ErrDirectHTTPSListenerInvalid` sentinel without
depending on error text. Immediately before claiming the serving binding, and
again after the final context validation immediately before starting
`net/http`, the helper rechecks the live address, rejects nil and typed-nil
address values, contains an address-string panic, and requires the address to
remain a literal loopback endpoint. It also rechecks the bounded server
execution policy at that final handoff. Any failure of either live-address
proof closes the construction-approved delegate once before returning; cleanup
failures remain matchable through `ErrDirectHTTPSListenerCleanup`. This
prevents a malformed or replaced in-process delegate from remaining live or
serving outside the reviewed bind scope during the handoff window.
The listener boundary also requires every successful `Accept` to return the
standard library's `*tls.Conn`; a delegate that keeps the reviewed loopback
address but returns a plaintext connection, or a TLS connection without a
non-nil underlying network connection, is closed and rejected before
`http.Server` sees it. The underlying connection must also expose a non-nil,
literal loopback local endpoint. A listener created by the reviewed
constructors also retains the exact TLS delegate object it approved, so an
in-process integration cannot replace that delegate with another loopback
listener or TLS configuration between review and `Accept`. The reviewed
constructors also retain the canonical host and port returned by the OS after
binding, including the OS-selected port for `:0`; a later authority drift is
rejected even when the replacement remains loopback. A replaced
delegate cannot retain a loopback listener address while handing the server a
TLS connection backed by a non-loopback socket. Malformed local-address values
and address-string panics fail closed at the same opaque listener boundary.
If a delegate violates the `net.Listener` contract by returning a connection
and an error together, the wrapper closes that connection, closes the
construction-approved delegate once, and returns only the opaque invalid-
listener classification; delegate error detail is not propagated. If closing
the malformed returned connection fails or panics, that failure is retained as
`ErrDirectHTTPSListenerCleanup` with an opaque panic classification, alongside
the one-shot reviewed-delegate cleanup result.
If a delegate returns no connection with a nil error, the wrapper applies the
same malformed-listener classification and closes the construction-approved
delegate once; any cleanup failure remains observable through
`ErrDirectHTTPSListenerCleanup` and a later idempotent `Close`.
An `Accept` or `Addr` panic, a malformed live address, or a malformed
successful connection also closes the construction-approved delegate once,
and exposes any cleanup failure through `ErrDirectHTTPSListenerCleanup` when
the API can return it; `Addr` returns no address for invalid live-address
evidence because it cannot return an error. This prevents a malformed handoff
from leaving the reviewed listener live or publishing an unreviewed endpoint
while retaining idempotent caller cleanup.
When replacement is detected, cleanup closes only the originally reviewed
delegate; that cleanup is idempotent, so normal caller cleanup after a failed
`Accept`, address validation, or `Close` does not close the reviewed resource a
second time and never closes the replacement. `Addr` cannot return the cleanup
error, but it still performs that one-shot cleanup before returning no address;
a later `Close` or serving-boundary result retains the cleanup classification.
A malformed in-process self-referential delegate is rejected before `Accept`,
`Addr`, or serving validation calls through the `net.Listener` interface; it
cannot recurse through the wrapper or trigger recursive cleanup.
The server handler must likewise be the private direct handler
produced by `NewDirectHTTPSHandler`/`BindDirectHTTPSServer`; replacing it with
the default mux, a generic handler, or a reverse-proxy handler is rejected
before serving. It also rejects nil inputs and an already-canceled context
before starting. The handler and listener must also be the exact pair installed
by one `BindDirectHTTPSServer` call; separately reviewed direct handlers,
listeners, or server/listener combinations are rejected before serving. This
keeps the construction-time owner relationship intact instead of treating
individual provenance markers as interchangeable. The caller must not replace
the handler, mix a server with another binding, or reuse the server or listener
after return. The serving handoff enforces this ownership as a single-use
operation: a concurrent or subsequent call with the same reviewed binding is
rejected before `http.Server.Serve` starts. This
proves only a local, caller-requested serving lifecycle; it does not provision
certificates, establish native trust, authenticate external controllers, publish
a route, or authorize deployment over the stable 1.x services.
When called as a standalone verifier, it applies the same bounded direct-call
header-map preflight before inspecting `Request.Host`, so a caller cannot turn
the duplicate-authority check into an unbounded header scan.
The exported verifier also contains panics from malformed caller-owned request
or certificate metadata and returns `false`; panic detail never crosses the
transport boundary and a malformed standalone callback cannot crash the
serving process.
`ValidateDirectTLSConfig` also rejects per-client configuration callbacks and
`KeyLogWriter`: the former could replace the preflighted policy, while the
latter exports TLS session secrets to a diagnostic sink. The preflight does not
create a listener, provision certificates, or perform network I/O.
Server-side requests normally leave `URL.Scheme` empty; if a direct library
caller supplies an explicit scheme, it must be `https` with a syntactically
valid non-empty authority; opaque URL components are rejected regardless of
scheme because they are not an HTTP request-target representation; embedded userinfo in either
the raw authority or parsed `URL.User` representation, malformed or out-of-range
ports, non-canonical non-zero leading-zero port spellings, control characters in
URL components, and path delimiters are rejected, so contradictory
	or incomplete URL metadata or a missing URL cannot override the TLS state.
	The shared handler boundary also requires a non-nil parsed URL before invoking
	either deployment-owned security callback; normal `net/http` requests always
	provide one, and a direct caller cannot substitute only an unparsed
	`RequestURI` for callback-visible request metadata.
The shared handler preflight also rejects any parsed `URL.User` value before a
custom reverse-proxy verifier sees the request; userinfo is never transport
identity metadata for this boundary.
Fragments, which are never sent in an HTTP request target, are rejected both
when present in the parsed URL and when a direct caller leaves a raw `#`
delimiter in `RequestURI`, `RawPath`, or `RawQuery`; percent-encoded `#`
remains ordinary path or query data. A direct URL's optional `RawPath` must be
a valid encoding of `Path`; this keeps transport-visible path metadata from
being discarded or reinterpreted before TLS state is accepted. An
explicit absolute-form `RequestURI` must parse as an HTTPS URI with a
non-empty, valid authority without embedded userinfo and agree with any URL
scheme and authority supplied by the caller; scheme-only, opaque, mismatched,
or malformed absolute targets
fail closed. When `RequestURI` is present, its escaped path, raw query, and
force-query marker must also match the parsed URL for both origin-form and
absolute-form targets; ordinary origin-form targets and an omitted direct-call
`RequestURI` remain compatible. A
reverse-proxy deployment must inject a verifier that
validates trusted proxy metadata and its TLS policy; an arbitrary forwarded TLS
header is not sufficient. The handler
accepts only bounded `POST` requests with exactly one `Content-Type` value no
larger than 256 bytes; the value must parse as `application/json`. Duplicate
or oversized media-type headers fail closed before authentication, including
duplicates stored under differently cased keys by a direct library caller.
The optional `MCP-Protocol-Version` header is handled case-insensitively and
must contain exactly one value naming the adapter's advertised
`2025-06-18` revision. An omitted header remains accepted for legacy
`initialize` callers; an empty, duplicate, oversized, or unsupported value
returns `400` before either security callback. The value is also included in
the transport snapshot, so a deployment-owned verifier cannot replace the
negotiated revision before principal resolution.
	The generic lifecycle boundary also applies a case-insensitive singleton rule
	to `Authorization`: an omitted field remains valid for integrations that use
	another reviewed authentication mechanism, but a present field must contain
	exactly one non-empty value before either security callback runs. The resolver
	retains ownership of bearer/OAuth scheme, token, expiry, audience, and
	resource validation; duplicate or present-empty values cannot reach a
	`Header.Get`-style resolver with ambiguous first-value semantics. Body
	collection revalidates the same rule before authentication.
The direct-call header map is structurally bounded before either the
deployment-owned transport verifier or principal resolver runs, so malformed
in-process input cannot hand an unbounded field set to a security callback.
It also rejects more than 1,024 value entries, any value larger than 16 KiB,
or more than 64 KiB of aggregate header values before those callbacks run.
Direct callers must also provide RFC 9110 token field names and field values
without forbidden control bytes; horizontal tab remains permitted by the HTTP
field-value grammar. Normal `net/http` serving remains subject to its own
wire-level header limits. The transport/body snapshot also preserves whether
each callback-visible header field's value slice is omitted or present-but-empty;
a body reader cannot change that nested presence state after transport approval.
This exact-presence rule is limited to the callback snapshot and does not alter
case-insensitive framing or content-negotiation validation.
The JSON-only response mode also negotiates `Accept`: an absent header, a
wildcard, `application/json`, or the usual MCP
`application/json, text/event-stream` pair is accepted; malformed or oversized
	values return `400`, while a value that excludes JSON (such as only
`text/event-stream`) returns `406` before authentication. Invalid media ranges,
including non-finite quality values such as `q=NaN`, exponent notation, or more
than three fractional qvalue digits, return `400` before authentication. HTTP
qvalues must use the bounded `0`/`1` form with an optional decimal point and zero
through three fractional digits; a `1` quality may contain only zero fractional
digits. Valid qvalues are compared as integer thousandths, so specificity and
zero-quality exclusions do not depend on floating-point parsing. A present
`Accept` field with a nil or empty value slice from a direct caller is malformed
	and also returns `400`; it is not treated as the absent-header default. Responses include
	`MCP-Protocol-Version: 2025-06-18` as additive protocol metadata, including on
	bounded error and notification responses, and
	`Vary: Authorization, Accept, MCP-Protocol-Version` so intermediaries that inspect
	response metadata retain the same protocol-version partition as the request
	validation boundary. Responses remain explicitly non-cacheable.
The gateway handoff applies the same case-insensitive single-value rule to
`Authorization`; normal net/http requests and direct integrations therefore
share the same ambiguity behavior. The `Bearer` authentication scheme is
case-insensitive, while duplicate, oversized, malformed, and empty values
remain rejected. A bearer that matches both one valid persisted controller and
the legacy MCP credential is rejected rather than assigned by precedence; every
credential must identify exactly one controller owner. It limits
the body to the same 64 KiB MCP request bound, rejects malformed direct-call framing
(including unsupported, repeated, or `Content-Length`-conflicting
`Transfer-Encoding` metadata; the only accepted transfer coding is one final
`chunked` token paired with the standard-library `-1` unknown-length sentinel;
the only other valid framing has no transfer-coding metadata). Direct callers
that leave raw `Transfer-Encoding` or `Content-Length` entries in the header
map must provide exactly one entry consistent with the parsed request fields;
an empty value entry is rejected even when a differently-cased key supplies a
second non-empty value, so direct map callers cannot hide malformed duplicate
framing metadata through case variation;
unsupported, repeated, malformed, or conflicting raw framing metadata is
rejected before either deployment-owned security callback. Raw `Content-Length` entries must use the
HTTP `1*DIGIT` grammar; signed values, including `-1`, are rejected even when
they match the standard-library unknown-length sentinel. The parsed request
may still use the standard-library `-1` sentinel when no raw `Content-Length`
header remains. Raw framing values and parsed transfer-coding tokens are each
bounded to 256 bytes before trimming or comparison, so a direct library caller
cannot turn framing validation into an unbounded string-inspection step. A raw
header map entry with zero values for `Content-Length` or `Transfer-Encoding` is
also malformed and is rejected rather than treated as absent. The handler also
rejects malformed negative parsed `Content-Length` values and requires a non-negative declared length to match the
bytes actually read before authentication, rejects a nil direct-call body
before authentication, rejects an already-canceled or deadline-exceeded
request context, including a typed-nil context supplied by a malformed direct
caller, with generic `408 Request Timeout` before transport
verification, immediately after the transport verifier returns, while
reading the bounded body, after bounded body framing, and after the principal
resolver returns. After body collection, the handler revalidates the header,
trailer, URL, host, request-target, protocol version, connection-close flag,
remote address, request context identity, TLS connection state, and framing
metadata, and rejects
changes to the method or metadata already seen by the transport verifier. This
includes the matched `ServeMux` pattern because a direct body reader must not
change callback-visible route or body metadata between transport approval and
principal resolution; the body reader identity itself must remain stable while
the bounded body is collected. The transport snapshot also preserves
nil-versus-present-empty `Request.TransferEncoding` state and its ordered
values, so a body reader cannot change callback-visible framing presence between
transport approval and principal resolution.
For each wildcard declared by the matched pattern, the snapshot also preserves
the callback-visible `Request.PathValue`. The boundary accepts only complete
ServeMux wildcard segments, requires `{name...}` and `{$}` to be final
segments, and rejects an opening brace that does not form a valid wildcard
before either security callback. A closing brace without an opening brace
remains a literal path character, matching the standard ServeMux parser. A
body reader cannot replace a route parameter after
transport approval, and direct callers must keep those values bounded and free
of control or format characters. This covers the public
`PathValue`/`SetPathValue` API without treating undeclared direct-only values as
authenticated route metadata: direct callers that install an undeclared value
are rejected before either security callback, and declared values remain
bounded and snapshot-protected.
Method-qualified patterns must also agree with `Request.Method` before either
security callback; an unqualified pattern matches every method and the standard
`GET`-matches-`HEAD` exception is retained.
The request context identity is also snapshotted and compared. Standard
`net/http` contexts are comparable; an uncomparable direct-call context is
rejected before either security callback because the boundary cannot prove
that a body reader or verifier preserved the exact context delivered to the
authenticated resolver.
When supplied, the callback-visible `Request.Method` must be an RFC 9110 token
of at most 256 bytes. An omitted method remains compatible with synthetic
standalone TLS-verifier callers; the handler still accepts only `POST` before
either deployment-owned security callback. This bounds direct-call method
inspection and post-transport revalidation without changing that compatibility
surface.
The request body must also be a non-nil, non-typed-nil, comparable
`io.ReadCloser` before either security callback. Normal server bodies are
pointer-backed; an uncomparable direct body could otherwise panic during the
post-read identity comparison. If a body reader replaces the body with an
uncomparable implementation after transport approval, the same comparison
fails closed before principal resolution.
Deferred cleanup also fails closed on ambiguous uncomparable identity: it may
deduplicate pointer-backed wrappers only when their comparable pointer identity
matches, but it does not use function code pointers or slice backing pointers
as resource identity. Distinct closures can share code, and distinct slice
views can share backing storage; treating either as one body could skip a
caller-owned `Close` call. Ambiguous replacements are therefore closed
independently, with cleanup panics contained at the boundary. An uncomparable
body supplied at handler entry is rejected before the verifier, body tracker,
or any other callback can replace `Request.Body`; the deferred path retains
that one captured value instead of attempting a second close through the
unchanged request field. The handler carries an explicit pre-tracking
unchanged-body fact into cleanup for every early return, including
uninitialized handlers and method rejection; it does not infer replacement
identity from the dynamic type, so distinct same-typed closures or slice views
remain independently closed. This special case prevents duplicate cleanup
without weakening the independent-close rule for replacements observed after
transport verification.
The snapshot also preserves whether the callback-visible `Header` and `Trailer`
maps themselves are omitted or allocated-but-empty, in addition to each field's
value-slice presence. A body reader cannot replace a nil map with an empty map or
remove an allocated empty map after transport approval. This exact map-presence
rule is limited to the callback snapshot and does not change HTTP's
case-insensitive field semantics.
The deployment-owned transport verifier is also observational: the handler
snapshots callback-visible request metadata before invoking it and rejects any
header, declared-trailer value, URL, framing, route, transport, or TLS-state
mutation before the principal resolver runs. Its body is guarded as well; a
verifier that reads or closes the body is rejected before authentication
because doing so could leave the resolver with a truncated or otherwise
different request. Closing that guard is idempotent, so the handler's deferred
caller-owned cleanup does not close the underlying request body twice after a
misbehaving verifier. If a malformed body panics from `Close`, the wrapper
converts that panic to an opaque close error, remains closed for the deferred
cleanup path, and the handler rejects the request before authentication. The
same direct-call bounds are reapplied immediately after
the verifier returns and before snapshot comparison, so a verifier cannot make
that comparison inspect an oversized replacement header, URL, framing, or TLS
structure. After transport verification, the normal server-side
trailer transition from declared nil values to wire-populated values remains
allowed during bounded body collection, while pre-existing trailer values
must remain unchanged, including nil-versus-present-empty value-slice presence
until a declared trailer becomes non-empty, and no trailer field may be added
or removed. This keeps
a verifier from authenticating one request and handing a different request
identity or body to the resolver; integrations should return a verdict rather
than rewriting or consuming the request.
The principal resolver is observational after that body-boundary snapshot too:
it may inspect and authenticate the request, but must not replace, read, or
close its body, context, headers, URL, route, transport metadata, or other
callback-visible fields. The resolver receives a bounded replay of the already
collected body, so body inspection cannot consume the request that the MCP
adapter will parse; any read or close is still rejected as a mutation. A
post-authentication mutation fails with generic `400` before an owner-bound
MCP adapter is invoked; this also preserves the original request context's
cancellation and deadline identity across authentication.
Before either security callback, the matched route pattern is also bounded to
8 KiB and at most 256 named wildcard declarations, must use the standard
ServeMux method/host/path envelope, and must be
valid UTF-8 without Unicode control or format characters; ordinary non-ASCII
route patterns remain valid. Empty `Request.Pattern` remains valid for direct
callers that do not attach ServeMux metadata. This keeps direct callers from
handing a transport verifier an impossible, unbounded, or visually deceptive
route label. Method-qualified patterns must also use the canonical path form
that ServeMux accepts, except for `CONNECT`, whose standard-library route
parser preserves the unclean-path exception. A host-qualified pattern must
also agree with the host view that ServeMux would use; ordinary requests use
its valid-port stripping rule, while `CONNECT` first tries `URL.Host` and then
falls back to `Request.Host` without port stripping. Path-only patterns remain
compatible with any validated request host. A non-empty pattern must also
match the request target under the standard library's current ServeMux matcher,
including wildcard unescaping and the `CONNECT` path exception; a direct caller
cannot authenticate one path while presenting another route pattern. For each
named wildcard, the boundary also routes a bounded request clone through a
private one-pattern `ServeMux` and requires the callback-visible `PathValue` to
equal the value derived by that router; a caller cannot substitute a different
route parameter while keeping the pattern and URL coherent. This probe is
in-process only and does not open a listener or invoke deployment callbacks.
The boundary also requires the server-request shape used by `net/http`: direct
callers cannot supply `GetBody`, parsed form or multipart state, a client
`Cancel` channel, or a redirect `Response`. These client-only fields are not
part of an authenticated server request and are rejected before either
security callback; the same shape check runs after body collection so a body
	reader cannot inject them before principal resolution. The normalized
	`Request.Trailer` map is the only accepted server-side trailer view; it must
	also remain a distinct map from `Request.Header`. A raw `Trailer` field left
	in `Request.Header` is rejected because `net/http` consumes that declaration
	before invoking a handler, and aliased header/trailer maps are rejected
	because they create two names for one mutable framing view. The standalone
	direct TLS verifier applies the same server-request shape check.
Before either security callback, direct callers are also limited to 64 bytes of
protocol text and 256 bytes of remote-address text, with a non-empty protocol
string required to parse to the exact `ProtoMajor`/`ProtoMinor` tuple; an
omitted protocol remains compatible only with an all-zero tuple. HTTP control
bytes, Unicode control characters, format characters (including bidi and
zero-width controls), and line/paragraph separators (U+2028/U+2029) are
rejected; the same Unicode rule applies to URL, authority, and TLS string
metadata. Ordinary non-ASCII text remains valid. This keeps callback-visible
scalar transport metadata bounded and visually stable before the
deployment-owned verifier receives it. For HTTP/1.x, `Request.Close` must also
match the standard library's version and case-insensitive `Connection` token
rules: HTTP/1.1 closes only for a `close` token, while HTTP/1.0 closes unless
`keep-alive` is present. Token boundaries match `net/http` exactly (space,
horizontal tab, or comma), including its handling of optional whitespace around
a token. This prevents a direct caller from presenting a contradictory
connection policy to the deployment-owned verifier; omitted and
non-HTTP/1 protocol metadata retain the existing compatibility boundary.
The TLS pointer and exported connection-state fields are snapshotted, along
with bounded certificate references, exported certificate DER/byte metadata,
parsed certificate names, IPs, URIs, and extensions, and byte-valued handshake
metadata, so a direct caller cannot hand a security
callback an unbounded TLS state and a body reader cannot replace, downgrade, or
mutate the transport state before authentication. This prevents a direct body
reader from introducing malformed callback-visible metadata or changing the
authenticated request while it is being consumed; trailer values may be
populated normally by the server, but the post-read map must retain exactly the
field names declared before body collection. A direct body reader cannot add a
new valid-looking trailer field after transport verification. Optional TLS byte
fields preserve presence as well as content during this comparison: for
example, a resumed TLS 1.2 state with a nil `TLSUnique` cannot become a present
empty slice after transport verification.

Callback-visible certificate SAN collections (`DNSNames`, `EmailAddresses`,
`IPAddresses`, and `URIs`) preserve nil-versus-present-empty state as well as
their bounded values during this comparison. Each `IPAddresses` element also
preserves nil-versus-present-empty state. A body reader cannot introduce an
empty SAN collection or replace an omitted IP element with a present-empty one
after transport verification, even when no SAN value is present to trigger
source-value validation.

Callback-visible certificate byte fields (`Raw`, `RawTBSCertificate`,
`RawSubjectPublicKeyInfo`, `RawSubject`, `RawIssuer`, `Signature`,
`SubjectKeyId`, and `AuthorityKeyId`) preserve nil-versus-present-empty state as
well as their bounded bytes. A body reader cannot introduce a present-empty
certificate byte field after transport verification. This exact-presence rule
is limited to the callback snapshot; parser-derived source/value rules remain
responsible for deciding which non-empty certificate bytes are coherent.

The nested identifier and value bytes of each callback-visible `pkix.Extension`
in `Extensions` and `ExtraExtensions` preserve nil-versus-present-empty state as
well as bounded content. A body reader cannot turn an omitted extension
identifier or value into a present-empty field after transport verification.
This exact nested rule is limited to the callback snapshot and does not alter
the parser's representation of source extensions.

The nested OID component slices in callback-visible `UnhandledCriticalExtensions`,
`PolicyIdentifiers`, and `UnknownExtKeyUsage` also preserve nil-versus-present-empty
state. A body reader cannot replace an omitted OID component with a present-empty
component, or make that presence change disappear after transport verification.
This exact nested rule is limited to the callback snapshot; parser-coherence
helpers continue to compare valid OID values by their components.

The callback-visible `ExtKeyUsage` collection also preserves nil-versus-present-empty
state. A body reader cannot introduce an empty known extended-key-usage collection
after transport verification. This exact-presence rule is limited to the callback
snapshot; parser-coherence helpers continue to compare extended-key-usage values by
length and content so parser-compatible representations remain accepted.

The callback-visible opaque `x509.Certificate.Policies` collection also preserves
nil-versus-present-empty state. A body reader cannot introduce an empty policy
collection after transport verification. This exact-presence rule is limited to the
callback snapshot; parser-coherence helpers continue to compare policy OID values by
length and content so Go 1.24's parser-compatible representations remain accepted.

Callback-visible Authority Information Access collections (`OCSPServer` and
`IssuingCertificateURL`) preserve nil-versus-present-empty state as well as
their bounded values during this comparison. A body reader cannot introduce an
empty AIA collection after transport verification, even when no access location
is present to trigger source-value validation.

Callback-visible Name Constraints collections (`PermittedDNSDomains`,
`ExcludedDNSDomains`, `PermittedIPRanges`, `ExcludedIPRanges`,
`PermittedEmailAddresses`, `ExcludedEmailAddresses`, `PermittedURIDomains`,
and `ExcludedURIDomains`) preserve nil-versus-present-empty state in the body
snapshot as well. For IP ranges, the nested address and mask byte slices retain
their nil-versus-present-empty state too. A body reader cannot introduce an
empty constraint collection after transport verification. The standalone
parser-coherence checks intentionally continue comparing derived Name
Constraints by length and value, because Go 1.24 may normalize parser-derived
nil and present-empty slices differently.
The callback snapshot also retains whether each IP-range pointer element is
omitted or present, including a present element whose address and mask are
empty; this nested pointer rule does not change the direct preflight's
validation of usable parsed IP ranges.

Callback-visible issuer and subject `pkix.Name` collections preserve the same
exact presence rule in the body snapshot. This includes the country,
organization, organizational-unit, locality, province, street-address, and
postal-code slices, the outer `Names` and `ExtraNames` attribute collections,
and each attribute OID slice. A body reader cannot introduce a present-empty
issuer or subject name collection after transport verification; this rule is
limited to the callback snapshot and does not change parser-derived name
coherence behavior.
	The direct verifier preserves the no-ALPN compatibility case, where
	`NegotiatedProtocolIsMutual` may be false, but rejects a non-empty selected
	protocol paired with that contradictory value. Go 1.24 documents the field
	as always true; this check prevents a synthetic completed server state from
	claiming a selected ALPN protocol with inconsistent negotiation metadata.
	Custom reverse-proxy verifiers may use a broader partial-state contract and
	are not subjected to this direct-only rule.
Parsed certificate names and URI components, including raw URI username and
password components, must also be valid UTF-8 without control or format
characters; percent-escaped rendering does not make those raw userinfo values
acceptable. Subject and issuer name attributes and policy
identifier OIDs are bounded and structurally copied, IP values must be
canonical 4- or 16-byte forms, and extension OIDs must contain valid
non-negative arcs. URI schemes, raw
paths, raw queries, raw fragments, and opaque/path combinations must also be
internally coherent with the parsed URL representation; raw `?` and `#`
delimiters in opaque data or escaped paths are rejected because they terminate
or reinterpret the serialized URI component rather than represent data, and
opaque percent escapes must be valid. Direct callers that construct synthetic
certificate metadata therefore fail closed before the transport verifier can
treat it as authenticated identity. A body reader also cannot change the bounded subject, issuer, or policy metadata between
transport verification and principal resolution. URI userinfo is copied as
structured username/password-presence metadata rather than only as a rendered
string, so the callback snapshot retains the exact parsed URI identity.
DER-shaped `RawSubject` and
`RawIssuer` values must also decode to the corresponding parsed `Subject` and
`Issuer`; as in Go 1.24's Name parser, bytes after the outer Name `SEQUENCE`
are ignored after the RDN values have been read. A DER-shaped
`RawSubjectPublicKeyInfo` must marshal to the same
bounded concrete `PublicKey` exposed alongside it; opaque non-DER partial byte
metadata remains compatible. A DER-shaped complete certificate `Raw` value
must also parse to the same bounded certificate metadata, including its TBS
bytes and signature fields. A DER-shaped `RawTBSCertificate` must be the TBS
slice of that same complete `Raw` envelope; standalone DER TBS bytes are
rejected because the parser cannot produce them. Opaque non-DER partial
`Raw` and `RawTBSCertificate` values remain
compatible with trusted reverse-proxy metadata. Certificate
validity bounds,
known signature/public-key algorithm enum values with a signature algorithm
whose key family agrees with the declared public-key algorithm and a declared
public-key algorithm matching its bounded concrete key type, parsed certificate versions
(1 through 3; zero remains allowed only for partial synthetic metadata), known
key-usage bits and extended-usage enum values, with the parser's split between
recognized extended-usage values and genuinely unknown OIDs preserved, and
non-inverted validity intervals whose bounds are
either both absent for partial metadata or both non-zero, basic constraints,
positive serial numbers bounded
both individually and across the certificate snapshot, revocation/issuance strings, e-mail names, and
DNS/e-mail/URI/IP name constraints are bounded and snapshotted too; IP
constraints require equal-width IPv4 or IPv6 address/mask pairs with a
contiguous mask matching the parser's X.509 representation. The
`PermittedDNSDomainsCritical` marker is accepted only with recognized name
constraint data or an unhandled critical name-constraints extension, matching
the parser's representation; the zero-value partial certificate remains
compatible when the marker is false. A body
reader therefore cannot change certificate authorization semantics after the
transport verifier has accepted the request.
When a full parsed `Extensions` list is supplied, a non-zero certificate
version must be v3; v1 and v2 cannot carry parsed extensions. The zero-value
version remains compatible with partial reverse-proxy metadata, including when
that metadata supplies an extension marker without a parsed version.
When a full parsed `Extensions` list is supplied, Subject Key Identifier
(`2.5.29.14`) and Authority Key Identifier (`2.5.29.35`) entries must be
non-critical, matching the parser's X.509 contract. The marker-only partial
form remains compatible when the list is omitted, and a body reader cannot
introduce a critical key-identifier extension before principal resolution.
When a full parsed `Extensions` list is supplied, a non-empty `SubjectKeyId`
or `AuthorityKeyId` field must have its corresponding parser source extension
(`2.5.29.14` or `2.5.29.35`). Empty fields remain compatible with extensions
whose parsed key identifier is empty, and the marker-only partial form remains
compatible when the list is omitted. A body reader cannot introduce a
non-empty key identifier without its source extension before principal
resolution. When either field is non-empty, its bytes must also equal the
first parser-visible key identifier in that source extension: the Subject Key
Identifier OCTET STRING or the first Authority Key Identifier context-specific
`[0]` value. Trailing extension data is ignored to match Go 1.24's parser.
When a key-identifier source is present with no derived bytes, a DER-shaped
source must still be parser-compatible, including the empty OCTET STRING or
SEQUENCE cases; opaque marker-only values retain the bounded partial-metadata
compatibility above. A body reader cannot replace a key identifier with a
value that disagrees with its source extension before principal resolution.
When a full parsed `Extensions` list is supplied, non-empty Subject Alternative
Name fields (`DNSNames`, `EmailAddresses`, `IPAddresses`, or `URIs`) must have
the parser source extension `2.5.29.17`. An empty SAN field set remains
compatible with an extension list that does not contain that OID, and the
marker-only partial form remains compatible when the list is omitted. A body
reader cannot introduce a SAN-derived value without its source extension
before principal resolution. When the fields are non-empty, their values must
also match Go 1.24's parser-visible GeneralName values, preserving order within
each category: IA5 DNS/email/URI names, 4- or 16-byte IP addresses, and parsed
URI structures. A DER-shaped SAN source value must still be parser-compatible
even if it produces no recognized fields; this preserves support for an empty
or unsupported-only SAN while rejecting malformed source bytes that could
otherwise hide behind an empty derived set. Opaque marker-only SAN values
remain compatible with partial reverse-proxy metadata. Unknown GeneralName tags
remain ignored as by the parser, but malformed recognized values and
mismatches fail closed before either security callback and are rechecked after
bounded body collection.
As in Go 1.24, bytes after the outer SAN `SEQUENCE` are ignored after the
GeneralName values have been read; malformed recognized GeneralNames still
fail closed.
URI SAN hosts follow Go 1.24's `domainNameValid(..., false)` behavior, including
rejection of a leading-dot host; the leading-dot form remains reserved for
domain-only name constraints. A body reader cannot introduce such a URI before
principal resolution.
When a full parsed `Extensions` list is supplied, a non-zero `KeyUsage` value
must have the parser source extension `2.5.29.15`. The zero value remains
compatible with an extension list that does not contain that OID, and the
marker-only partial form remains compatible when the list is omitted. The
non-zero field must also equal the first nine parser-visible bits from that
extension; malformed source values and mismatches fail closed. A body reader
cannot introduce a key-usage value without its source extension or replace it
with a value that disagrees with the source before principal resolution.
When a full parsed `Extensions` list is supplied, non-empty `ExtKeyUsage` or
`UnknownExtKeyUsage` fields must have the parser source extension
`2.5.29.37`. Empty extended-usage fields remain compatible with an extension
list that does not contain that OID, and the marker-only partial form remains
compatible when the list is omitted. A body reader cannot introduce an
extended-usage value without its source extension before principal resolution.
When those fields are non-empty, their ordered values must also match Go
1.24's parser split: recognized EKU OIDs become `ExtKeyUsage`, while genuinely
unknown OIDs become `UnknownExtKeyUsage`. Malformed source values and
representation mismatches fail closed before transport verification, and a
body reader cannot replace either list with values that disagree with the
source extension before principal resolution.
When an EKU source is supplied with no derived values, a DER-shaped source must
still be a parser-compatible sequence, including the empty-sequence case;
opaque marker-only values remain compatible with partial reverse-proxy metadata.
As in Go 1.24, bytes after the outer EKU `SEQUENCE` are ignored after the OIDs
inside that sequence have been read; malformed primitive OIDs still fail closed.
When a full parsed `Extensions` list is supplied, non-empty `OCSPServer` or
`IssuingCertificateURL` fields must have the parser source extension
`1.3.6.1.5.5.7.1.1`. Empty AIA fields remain compatible with partial metadata,
and the marker-only partial form remains compatible when the list is omitted.
A body reader cannot introduce an AIA-derived value without its source
extension before principal resolution.
When those AIA fields are non-empty, their ordered values must also match Go
1.24's parser-visible access locations: context-specific URI locations for the
OCSP method (`1.3.6.1.5.5.7.48.1`) populate `OCSPServer`, and locations for
the caIssuers method (`1.3.6.1.5.5.7.48.2`) populate
`IssuingCertificateURL`. Other access methods remain ignored as by the parser;
malformed source data and mismatches fail closed before transport verification,
and a body reader cannot replace either list before principal resolution.
When an AIA source is present with no recognized access locations, a
DER-shaped source must still be parser-compatible, including the empty
sequence case; opaque marker-only values remain compatible with partial
reverse-proxy metadata. A body reader cannot replace an empty parser-visible
AIA source with malformed bytes before principal resolution.
As in Go 1.24, bytes after the outer AIA `SEQUENCE` are ignored after the
access descriptions have been read; malformed primitive URI locations still
fail closed, and a body reader cannot introduce that parser-compatible source
mutation before principal resolution.
When a full parsed `Extensions` list is supplied, Authority Information Access
(`1.3.6.1.5.5.7.1.1`) must also be non-critical, matching the parser's X.509
contract. The marker-only partial form remains compatible when the list is
omitted, and a body reader cannot introduce a critical authority-information-
access extension before principal resolution.
When a full parsed `Extensions` list is supplied, the marker must also match
the critical bit of the Name Constraints extension (`2.5.29.30`); an omitted
extension requires the marker to be false. The marker-only partial form remains
compatible when that list is omitted, and a body reader cannot change this
representation before principal resolution.
When the Name Constraints extension is present, its recognized permitted and
excluded DNS, IP, e-mail, and URI subtrees must also match the corresponding
parser-visible fields, in order. Unsupported GeneralName forms and trailing
GeneralSubtree fields retain the parser's ignored/unhandled behavior, but
malformed recognized values, a source with both permitted and excluded subtree
lists empty, missing source extensions, and value mismatches fail closed before
either security callback and after bounded body collection. Go 1.24 accepts a
present empty permitted or excluded subtree list when the other list contains
valid values; the boundary preserves that asymmetric representation. A
critical marker with no decoded subtrees retains
opaque marker-only compatibility only when its source is not DER-shaped; a
DER-shaped source is parsed even when it produces only unsupported GeneralName
values, so malformed or empty Name Constraints cannot hide behind the marker.
Exact e-mail constraints use Go 1.24's RFC 2821 mailbox representation,
including its local-part quoting/escaping and dotted-atom rules; a value that
only contains an `@` is not parser-compatible. Domain-only e-mail constraints
retain the parser's leading-dot form. The omitted-list partial form remains
compatible.
As in Go 1.24, bytes after the outer Name Constraints `SEQUENCE` are ignored
after the permitted and excluded subtree fields have been read; malformed
subtrees and recognized values still fail closed, and a body reader cannot
introduce that parser-compatible source mutation before principal resolution.
When a full parsed `Extensions` list is supplied, every
`UnhandledCriticalExtensions` OID must also appear there with its critical bit
set, and every unknown critical extension (plus a critical SAN or name-
constraints extension with no parser-recognized values) must have its matching
marker. Parser-handled critical extensions must not be marked unhandled;
marker-only metadata remains compatible for a partial reverse-proxy certificate.
Duplicate unhandled-critical OIDs are rejected in both full and marker-only
forms because the parser derives one marker from each extension OID. A body
reader cannot introduce an unmatched, missing, or duplicate unhandled-critical
extension after transport verification.
It then constructs a fresh owner-bound adapter
per authenticated request, acknowledges valid notification POSTs with HTTP
`202 Accepted` and an empty body, and marks all
responses `Cache-Control: no-store`/`Pragma: no-cache` with
`X-Content-Type-Options: nosniff`. This prevents authenticated task or
checkpoint payloads from being retained by an intermediary and prevents a
browser MIME reinterpretation. Resolver failures return a generic `401` with
the standard `WWW-Authenticate: Bearer` challenge, without disclosing token
state or account details. Panics from either integration callback are caught
at this boundary and fail closed: a transport-verifier panic returns `403`
without invoking authentication, while a resolver panic returns the same
generic `401` challenge as any other authentication failure. An unexpected
panic while invoking the internal MCP adapter is also contained and returns a
generic `500`, without exposing the panic value or allowing one request to
crash the serving process. It does
not open a listener, terminate TLS, validate tokens, issue OAuth metadata, or
change any 1.x gateway route. The handler contains panics from malformed direct
	callers' request-body `Read` and `Close` implementations and closes the
	entry body plus every distinct replacement observed during bounded body
	reads, including intermediate values installed by a malformed callback or
	body reader, on
every path, including early method, transport, media-type, size,
authentication, and uninitialized-handler rejection, so direct library use
	cannot retain caller-owned body resources. A wrapper around the original body
	is treated as one logical body to avoid double-closing it. Uncomparable named
	function bodies are not deduplicated by code-pointer identity, because distinct
	closures can share one code pointer while owning separate caller resources.
	Cleanup is installed before
response-header work, so a malformed direct caller whose `ResponseWriter.Header`
panics cannot skip body cleanup. It also maps a store that closes during request
setup to generic HTTP `503 Service Unavailable`. The live store is checked
before either deployment-owned security callback, again after transport
verification, and once more after bounded body collection; a close observed at
those boundaries stops before authentication rather than handing a request to
an unavailable lifecycle backend. Adapter construction performs the final
race-safe check. Malformed authorization or scope construction remains `403`.
The cleanup wrapper also contains a panic
from a malformed direct caller's `Request.Body.Close` implementation after the
response path has run; ordinary `net/http` request bodies do not rely on this
fallback, but a library boundary must not let caller-owned cleanup crash its
serving process. If `Close` replaces `Request.Body`, the cleanup boundary
observes and closes distinguishable replacements too, with a fixed candidate
cap so a hostile in-process body cannot create an unbounded cleanup loop. The
body-read mutation tracker has a matching finite replacement budget below that
cleanup cap; once a direct body exceeds it, collection fails closed before
authentication while the retained replacements and final request field remain
within the cleanup budget. This bounds both tracking memory and caller-owned
cleanup work instead of relying only on the eventual cleanup queue cap.
Same-typed uncomparable values remain intentionally unmerged because their
identity cannot be proven without unsafe aliasing shortcuts. Response-writer panics are contained with a best-effort
generic `500`; if the writer cannot accept that error, no panic detail escapes.
A malformed direct body that repeatedly reports `(0, nil)` is rejected after a
finite no-progress budget instead of allowing `io.ReadAll` to spin indefinitely.
The body adapter also rejects an invalid `io.Reader` count (`n < 0` or
`n > len(p)`) before the standard-library bounded collector sees it, so a
malformed direct caller cannot turn a byte-count contract violation into an
unbounded allocation or indexing path.
Case-insensitive header collection is also bounded before semantic checks: no
more than `maxMCPAcceptBytes+1` matching values are retained. This keeps
duplicate `Content-Type`, framing, and `Accept` fields from turning a direct
library call into an unbounded intermediate allocation; the consumers still
reject duplicate or oversized values before authentication.
The direct-call `http.Header` map itself is also limited to 256 field names and
256 bytes per field name before matching-field inspection, so an attacker
cannot force an unbounded scan through unrelated map entries or enormous key
strings. Normal `net/http` serving retains its own wire-level header limits;
this library bound is an additional direct-integration guard and returns
generic `400 Bad Request` before authentication.
The same structural bound applies to the request's direct-call `Trailer` map
before either security callback; trailers are callback-visible HTTP metadata even
though normal `net/http` serving applies its own wire-level limits.
The trailer map also rejects the HTTP framing fields `Content-Length`,
`Transfer-Encoding`, and `Trailer`, matching the standard library's trailer
parser/writer so a direct caller cannot present a second, impossible framing
view after the body.
The raw `RequestURI` and aggregate textual components of a direct-call `URL`
are likewise capped at 8 KiB before either deployment-owned security callback
runs. The shared handler boundary also rejects parsed fragments, raw `#`
delimiters in request-target/path/query fields, and other fragment metadata
that an HTTP transport would discard or reinterpret; percent-encoded `#`
remains valid request-target data. `RequireDirectTLS` applies the same bound
and fragment rule when used as a standalone transport verifier, before it
parses or compares caller-supplied URL metadata.
This prevents request-target parsing or URL comparison from becoming an
unbounded pre-authentication operation while preserving ordinary origin-form
and omitted-target server requests. The separate `http.Request.Host` field is
also bounded and must be a valid authority; when both `Host` and `URL.Host`
are present they must agree case-insensitively. This closes the direct-call
metadata gap where a caller could otherwise hand a deployment-owned verifier
or resolver an unbounded or contradictory authority outside the parsed URL.
A second case-insensitive `Host` field in `Request.Header` is rejected because
the standard server promotes that field to `Request.Host`; accepting both
would create two competing authority representations for a verifier.
TLS `NegotiatedProtocol` and `ServerName` strings are likewise bounded and
reject HTTP control bytes before a deployment-owned verifier sees them.
Production wiring therefore remains a reviewed supervisor gate.

The direct boundary also bounds and snapshots callback-visible X.509 policy
metadata: raw and extra extensions, unhandled-critical extension OIDs, the
Go 1.24 opaque `Policies` OIDs, policy-mapping OIDs, and the three policy
constraint counters and zero flags. Invalid OIDs, oversized extension or OID
data, malformed constraint sentinels, and oversized policy lists fail closed
before either security callback; duplicate extension OIDs within either the
parsed `Extensions` list or the separate `ExtraExtensions` representation are
also rejected because the parser rejects duplicates in one extension sequence.
The two lists remain independently compatible for partial synthetic metadata;
an ID appearing once in each list is not treated as a duplicate across those
separate representations. Duplicate opaque certificate-policy OIDs are also
rejected because the parser rejects duplicates in one policy extension.
When `Policies` is populated, `PolicyIdentifiers` must also match the
parser-derived ordered list: every representable policy is present, while
only OIDs too large for the legacy ASN.1-int representation may be omitted.
The older partial `PolicyIdentifiers`-only form remains compatible when
`Policies` is absent. With a full `Extensions` list, non-empty `Policies`
must also have the parser source extension (`2.5.29.32`), and its ordered OIDs
must match that extension. The extension value must use the parser-compatible
constructed outer and policy-information sequences with primitive policy OIDs;
trailing policy-qualifier bytes remain ignored like Go 1.24. Malformed,
constructed, missing, or mismatched policy sources fail closed before transport
verification and after bounded body collection. An empty `Policies` list remains
compatible with an omitted or opaque marker-only source, but a DER-shaped
certificate-policy value must still parse, including the parser-compatible
empty sequence; malformed DER-shaped empty sources fail closed at both
boundaries.
As in Go 1.24, bytes after the outer certificate-policy `SEQUENCE` are
ignored after the policy-information values have been read; malformed policy
information and primitive policy OIDs still fail closed. A body reader cannot
introduce that parser-compatible source mutation before principal resolution.
When a full `Extensions` list is present, `PolicyIdentifiers` must also equal
the parser-derived legacy identifiers from that same `2.5.29.32` source; it
cannot be introduced without the source or disagree with an opaque policy that
fits the legacy representation. The omitted-list `PolicyIdentifiers`-only form
remains compatible with partial reverse-proxy metadata. A body reader cannot
introduce or replace a policy or legacy identifier before principal resolution.
A positive policy counter or explicit-zero marker must also agree with its
parser source extension: `RequireExplicitPolicy` and `InhibitPolicyMapping`
come from policy constraints (`2.5.29.36`), while `InhibitAnyPolicy` comes
from `2.5.29.54`. A full `Extensions` list cannot expose a counter/zero marker
without its extension. Go 1.24 also accepts a parser-compatible empty
policy-constraints sequence with neither optional INTEGER, so that source may
be present without a derived counter; `InhibitAnyPolicy` still requires its
source INTEGER, including the explicit-zero form. The counters and zero flags
must also match the parser-visible optional context-specific INTEGERs in
order; omitted fields retain their zero value with a false zero flag, while an
encoded zero sets the corresponding zero flag. Parser-style trailing fields
are ignored. Malformed source values and counter/zero mismatches fail closed
before transport verification, and a body reader cannot replace a
policy-constraint value before principal resolution. The zero-value and `-1`
partial reverse-proxy forms remain compatible when `Extensions` is omitted.
The extension value parsers also preserve Go 1.24's ASN.1 tag shape: outer
and nested `SEQUENCE` values must be constructed, while the recognized
context-specific GeneralName and access-location values, key identifiers, and
policy-mapping OIDs must be primitive where the standard parser requires it.
Constructed values that the parser would ignore cannot be used to justify a
non-empty derived field; constructed values that the parser rejects fail
closed. This applies equally before transport verification and after bounded
body collection.
For Authority Information Access, Go 1.24 checks an access location's tag
before decoding it: non-URI `GeneralName` values are ignored, even when their
bytes are malformed, and cannot justify an `OCSPServer` or
`IssuingCertificateURL` value. A primitive URI-tagged location is decoded
strictly; truncated or otherwise malformed URI locations fail closed. The
post-body snapshot still rejects any source mutation before principal
resolution.
The Key Usage extension (`2.5.29.15`) follows the same source/value rule even
when its parser-derived bitmask is zero: a DER-shaped BIT STRING must be
parser-compatible, including the valid zero-bit form, while malformed
DER-shaped empty sources fail closed before transport verification and after
bounded body collection. Omitted extensions and opaque marker-only partial
metadata remain compatible with trusted reverse-proxy integrations.
Policy mappings are also checked for the RFC 5280 `anyPolicy` prohibition:
the `2.5.29.32.0` OID cannot appear as either the issuer or subject policy in
a mapping. Ordinary opaque policy OIDs remain bounded and compatible with
the parser-visible Go 1.24 representation. When a full `Extensions` list is
supplied, a non-empty `PolicyMappings` list must also have its parser source
extension (`2.5.29.33`) present; the marker-only partial form remains
compatible when `Extensions` is omitted. A body reader cannot introduce or
remove that mapping representation before principal resolution. When the list
is non-empty, its ordered issuer/subject OID pairs must also match the
parser-visible opaque `x509.OID` values from that extension; malformed source
data and pair mismatches fail closed before transport verification, and a body
reader cannot replace a mapping pair before principal resolution.
The body-boundary snapshot also preserves whether the callback-visible
`PolicyMappings` collection is nil or present-but-empty, so a body reader
cannot introduce an empty mapping collection after transport verification.
This exact-presence rule is limited to the callback snapshot; parser-coherence
validation continues to compare mapping values by length and content so Go
1.24's parser-compatible nil/empty representations remain accepted.
As in Go 1.24, bytes after the outer policy-mappings sequence and trailing
fields inside an individual mapping entry are ignored after those two OIDs are
parsed; malformed OID fields still fail closed. This preserves the parser's
read-and-discard behavior without allowing malformed issuer or subject OIDs to
populate the callback-visible mapping list.
When the mapping list is empty, a DER-shaped source must still be a
parser-compatible sequence, including the empty sequence form; opaque
marker-only values remain compatible with partial reverse-proxy metadata. A
body reader cannot replace an empty parser-visible mapping source with
malformed bytes before principal resolution.
A body reader cannot replace or mutate those
fields after transport verification; the body-boundary comparison rejects the
request before principal resolution. The snapshot uses only immutable byte,
scalar, and bounded list representations and does not claim to clone arbitrary
`Certificate.PublicKey` object graphs. Public keys are now an explicit typed
boundary: standard RSA, ECDSA, Ed25519, ECDH, and DSA values are represented by
bounded PKIX bytes or copied DSA integers, while unsupported types, malformed
typed values, nil key internals, and oversized key material fail closed before
either security callback. The post-body comparison reserializes or compares
the same typed representation, so a body reader cannot replace or mutate a
certificate public key after transport verification. This policy intentionally
does not invoke methods on arbitrary user-defined key implementations.
Basic-constraints metadata is subject to the same coherence rule: path lengths
may be `-1` (unset), zero, or positive only when the CA metadata permits them;
`MaxPathLenZero` must describe a zero path length, and a non-zero path length is
not accepted when `BasicConstraintsValid` is false. The all-zero partial
certificate remains accepted for reverse-proxy callers that do not provide
these fields, while contradictory path-length metadata fails before either
security callback and is rechecked after body collection.

When a full `Extensions` list is supplied, `BasicConstraintsValid` must agree
with the presence of the Basic Constraints extension (`2.5.29.19`), matching
the parser-derived marker; the marker-only partial form remains compatible when
that list is omitted. When the marker is present, `IsCA`, `MaxPathLen`, and
`MaxPathLenZero` must also match the parser-visible extension values: the
optional CA BOOLEAN defaults to false, the optional path-length INTEGER defaults
to `-1`, and the zero flag is derived only from an encoded zero. Parser-style
trailing fields are ignored. Malformed source values and mismatches fail closed
before transport verification, and a body reader cannot introduce, remove, or
replace those Basic Constraints values after transport verification.

When a full `Extensions` list is supplied, a non-empty `CRLDistributionPoints`
field must have the parser source extension (`2.5.29.31`). The marker-only
partial form remains compatible when `Extensions` is omitted, and a body reader
cannot introduce or remove the distribution-point representation before
principal resolution.
When that field is non-empty, its ordered strings must also equal the URI values
the Go 1.24 parser extracts from each distribution point's `fullName` entry;
the parser checks the GeneralName tag before decoding it, so non-URI names are
ignored even when their encoded value is truncated, while a malformed primitive
URI name remains a hard failure because it could populate
`CRLDistributionPoints`; distribution points without a `fullName` URI remain
parser-visible omissions.
Malformed source values and mismatches fail closed before transport
verification, and a body reader cannot replace a distribution-point URI before
principal resolution. An empty field remains compatible with an omitted or
opaque marker-only source, but a DER-shaped source must still be parser-
compatible, including the empty-sequence case; malformed DER-shaped empty
sources fail closed before transport verification and after bounded body
collection.
As in Go 1.24, bytes after the outer CRL Distribution Points `SEQUENCE` are
ignored after the sequence has been read; malformed distribution points and
malformed primitive URI names that could populate the callback-visible list
still fail closed. A body reader cannot use parser-compatible trailing bytes to
replace the transport snapshot before principal resolution.

The standalone `RequireDirectTLS` verifier additionally requires the completed
connection state to report a known secure cipher suite compatible with the
negotiated TLS 1.2 or 1.3 version. Zero, unknown, insecure, or
version-incompatible suite identifiers fail closed before direct transport is
accepted. The shared callback boundary keeps its partial-state compatibility
for trusted reverse-proxy verifiers, which must authenticate their own
transport metadata rather than relying on this direct-HTTPS rule. The direct
server path also rejects client-side-only `ECHAccepted` state and any present
(`nil` is required) `TLSUnique` value on TLS 1.3, matching the standard
library's current `ConnectionState` contract. For TLS 1.2, a non-resumed
connection must expose the fixed 12-byte Finished verify_data value in
`TLSUnique`; a resumed connection may legitimately leave it nil when Extended
Master Secret was not negotiated, but any present value must still be 12 bytes.
Present-but-empty or otherwise mis-sized TLS 1.2 values are rejected because
the standard library does not emit them. The direct server path also requires
the outer `PeerCertificates` and `VerifiedChains` collections to remain nil when no client-certificate
chain was received or verified; present empty collections are not emitted by the
standard library. When chains are present, every verified
client-certificate chain must be non-empty and start with the first
`PeerCertificates` leaf, as the
server-side contract specifies. A callback-visible `OCSPResponse` must likewise
be nil or non-empty: the server-side certificate parser rejects an empty
stapled response, so a present empty slice is not a completed direct-server
state. These semantic checks are intentionally scoped to the direct verifier;
reverse-proxy integrations retain their own authenticated transport metadata
contract.
When a direct server state reports a negotiated ALPN protocol, that selected
opaque protocol value must be at most 255 bytes, matching the one-byte ALPN
name length field, and its mutuality marker must remain true. An omitted
protocol remains valid when no ALPN was negotiated even if that marker is
false; reverse-proxy metadata retains the broader shared string bound.
When the direct server state carries a non-empty SNI `ServerName`, it must not
use a trailing-dot absolute-FQDN spelling. Go's TLS ClientHello parser rejects
that form before producing a server connection state; the standalone verifier
keeps the same boundary while preserving an omitted SNI name and ordinary
mixed-case host names. Static `NameToCertificate` keys apply the same rule
because a trailing-dot key cannot be selected by the direct server handshake.
The direct verifier also rejects an exact repeated certificate identity within
`PeerCertificates` or within any individual `VerifiedChains` entry. Parsed
certificates are compared by their non-empty DER `Raw` bytes, while synthetic
metadata with no `Raw` bytes is rejected when the same parsed object is
repeated. The peer leaf is expected to appear again across collections when it
starts a verified chain, so that cross-collection repetition remains valid.
This direct-only check prevents a malformed completed state from presenting a
duplicated chain as authenticated evidence without narrowing the shared
reverse-proxy metadata contract.
The shared body-boundary snapshot also preserves nil-versus-empty presence for
the outer `PeerCertificates`, `VerifiedChains`, and
`SignedCertificateTimestamps` collections, including each verified-chain
collection. A body reader cannot replace an omitted TLS collection with a
present empty collection after transport verification, even when both have zero
elements. Individual callback-visible SCT entries must be non-empty, no larger
than the TLS two-byte element limit, and exact duplicates are rejected; the
complete encoded SCT vector, including each entry prefix and the outer vector
prefix, is bounded by the same two-byte limit, while distinct entries remain
valid. Static certificate SCTs use the same per-entry and encoded-vector
limits. The SCT bytes are also included in the broader handshake/metadata
budget before any entry is copied or compared.
The same exact-presence rule applies to the callback-visible raw certificate
`Extensions`, `ExtraExtensions`, and `CRLDistributionPoints` collections. Their
outer nil versus present-empty state is retained in the transport snapshot and
compared after body collection, so an empty raw extension or CRL list cannot be
introduced or removed before principal resolution. Parser-derived policy/OID
and Extended Key Usage fields retain their existing compatibility rule: Go may
normalize an empty derived sequence as either omitted or present-empty metadata.

## Additive gateway handoff checkpoint

`gateway.Server.NewLifecycleHTTPHandler` is the narrow handoff for a future v2
route. It reuses the gateway's already-authenticated controller lookup, copies
only explicitly issued lifecycle scopes into a stable snapshot before the
gateway lock is released, and delegates the request to
`lifecycle.NewMCPHTTPHandler`. Legacy `job.*`, agent, and existing `/mcp`
authority is not translated into lifecycle authority; a controller must be
issued one or more of the `lifecycle.*` scopes explicitly. Controller scope
issuance rejects claims longer than the complete known gateway vocabulary before
allocating its duplicate-detection map, as well as unknown and duplicate scope
names; the legacy default scope set is unchanged. The handoff also bounds the
persisted controller scope claim to that vocabulary before filtering lifecycle
scopes; oversized, overlong, unknown, or duplicate local controller state fails
closed as generic authentication failure and cannot trigger unbounded scope
processing or retain partial authority from a malformed claim. Known legacy
controller scopes remain accepted but grant no lifecycle authority, and their
default set remains unchanged.
Controller issue and revoke mutations are durable-state transactions: if the
encrypted gateway state cannot be saved, an issued controller is removed from
the in-memory map and a failed revoke restores the prior active state. The
handler returns a generic persistence failure instead of exposing a credential
whose issuance was not durable or claiming a revocation that was not saved.
Successful revocation audit entries snapshot the controller's non-secret kind
while the gateway lock is held; the audit writer never retains a mutable
controller record after ownership has been released.
The shared HTTP boundary rejects malformed direct-call URL structure before
either deployment-owned security callback: opaque or scheme-only URLs,
invalid authorities, inconsistent request-target/URL views, inconsistent
escaped paths, and malformed percent escapes in the query are not transport
identity metadata. Normal server origin-form
requests remain compatible; the deployment-owned reverse-proxy verifier still
controls the authenticated external transport decision. The shared gateway controller lookup also requires exactly one bounded
`Authorization` header value before hashing or comparing a bearer token;
duplicate or oversized values fail closed without reaching lifecycle state.
The lookup also treats a nil gateway receiver or nil request as an unauthenticated
call, so direct handler wiring cannot turn a missing gateway owner into a
process panic or a partial principal.
Its case-insensitive header collector retains at most the first two matching
values, which is sufficient to distinguish a valid singleton from any
duplicate without allocating for an attacker-controlled direct `Header` map.
A direct gateway caller must also stay within 256 field names, 1,024 values per
field, 256 bytes per field name, 16 KiB per value, and 64 KiB of aggregate
header bytes; an
oversized or malformed map fails closed before the collector scans it. These
limits apply to the legacy admin-token check as well as the additive lifecycle
controller handoff, while ordinary `net/http` requests retain their own wire
header limits.
A case-insensitive matching header key with zero values is treated as a
malformed empty value, so a direct caller cannot combine it with one valid
value and silently pass the singleton check.
The legacy gateway's admin-token checks use the same single-value, bounded
bearer-header rule and a constant-time comparison, so admin-only enrollment
and controller-management routes do not apply ambiguous first-header
semantics.
Malformed persisted controller map entries also fail closed: a JSON `null`
controller is skipped during authentication and administrative listing rather
than being dereferenced. The persisted map key must also match the record's
embedded controller ID, and that ID must remain a bounded, valid lifecycle
identity (at most 128 bytes, no surrounding whitespace, path delimiters,
fragment/query delimiters, or control/format characters). Its kind must remain
one of the supported controller kinds; its token hash must also remain the canonical lowercase SHA-256
hexadecimal representation produced by the gateway. Records that fail this
integrity check, including unknown, duplicate, overlong, or oversized scope
claims, are skipped from both authentication and administrative
listing, and an administrative delete treats them as not found without
revoking or auditing the malformed entry. This keeps
damaged local gateway state from turning an authenticated request or controller
management operation into a process panic, an unbounded or misleading principal
identity, or a lifecycle mutation. Authentication also requires a credential to match
exactly one persisted controller; duplicate matching records fail closed
instead of letting map iteration order select an owner. This is local-state
integrity handling, not a claim that controller records replace the external
OAuth/token verification boundary.

The helper is intentionally not registered by `Server.Routes()`. It does not
open a listener, terminate TLS, discover accounts, issue OAuth credentials, or
change any 1.x route. The caller must provide an isolated lifecycle store and
the deployment's completed-TLS or trusted reverse-proxy verifier. For direct
HTTPS serving, `lifecycle.ValidateDirectTLSConfig` provides a pure preflight
that requires an explicit, currently supported TLS 1.2 or 1.3 minimum and
rejects unknown versions or an inverted version range; it does not create a
listener, load certificates, or prove authenticated distribution. Supervisor
review is still required before a v2
route is mounted, distributed, or exposed outside loopback; the in-process
tests are boundary evidence only.

Before creating that listener, deployment code should call
`lifecycle.ValidateDirectHTTPSListenPolicy`, which composes both required
preflights in a fixed order: it accepts only a literal loopback IP with a
numeric port (including port zero for tests), then requires an explicit
TLS 1.2-or-newer range using only currently supported TLS versions. It rejects
wildcard/public addresses, all DNS-dependent hostnames including `localhost`,
service names, zones, malformed endpoints, implicit
 TLS defaults, legacy TLS, and inverted ranges without resolving names, opening
a socket, loading certificates, or doing network I/O. The lower-level
`ValidateLoopbackListenAddress` and `ValidateDirectTLSConfig` helpers remain
available for independently tested deployment components. This composition
does not replace supervisor review of the actual bound socket or authorize
public distribution. The preflight requires `tls.Config.CipherSuites` to name
at least one current secure TLS 1.2 suite whenever the configured minimum is
TLS 1.2; omitting the field is rejected rather than silently selecting a future
standard-library default. It also rejects unknown or known-insecure suites.
TLS 1.3 cipher suites remain governed by Go's TLS 1.3 defaults because that
field does not configure TLS 1.3; a TLS 1.3-only configuration must therefore
leave the field empty rather than carrying an ignored policy. A TLS 1.2-to-1.3
range may also carry TLS 1.3 IDs, but only alongside a TLS 1.2 suite because
those IDs cannot serve the lower floor. The explicit cipher-suite list is also
capped at
32,767 entries, the largest count representable by its two-byte TLS vector
length, and exact duplicate suite IDs are rejected because they add no
capability to the server policy. When a caller supplies
`tls.Config.CurvePreferences`, the preflight rejects unknown groups and
requires at least one TLS 1.2-compatible group whenever the minimum version is
TLS 1.2. TLS 1.3-only hybrid groups may be selected for a TLS 1.3-only
configuration, but cannot make a range that advertises TLS 1.2 unservable. An
omitted curve list retains the standard library defaults. The explicit
supported-group list is likewise capped at 32,767 two-byte entries and exact
duplicate group IDs are rejected because they do not change TLS selection. If
the static certificate `SupportedSignatureAlgorithms` list is supplied, it is
subject to the same 32,767-entry bound and exact duplicate schemes are
rejected; duplicate entries cannot add a usable signature policy and would
otherwise consume the reviewed vector budget without changing the handshake.
If
`tls.Config.NextProtos` is supplied, the preflight mirrors the Go TLS ALPN
wire limits: every protocol name must be non-empty and at most 255 bytes, the
encoded protocol vector must fit within 65,535 bytes, and the configured list
is bounded to 1,024 names before it is summed. ALPN names remain opaque bytes;
duplicate names are rejected so the reviewed preference list has one
unambiguous entry for each exact wire value. This check does not choose a
protocol or claim authenticated controller negotiation. The preflight also
requires `tls.Config.Renegotiation` to remain
`tls.RenegotiateNever`; accepting post-handshake renegotiation expands the
transport state machine and is outside the direct v2 HTTPS policy. This
configuration check also requires an explicit `tls.Config.MaxVersion` of
TLS 1.2 or TLS 1.3; leaving the maximum at the standard library default could
allow a future protocol version to reach the handshake and then be rejected
only after connection setup. It also rejects unknown `tls.ClientAuthType` values while
leaving the deployment's defined client-certificate mode unchanged. When the
mode verifies client certificates (`VerifyClientCertIfGiven` or
`RequireAndVerifyClientCert`), `ClientCAs` must be an explicit pool; a nil pool
would make Go fall back to host system roots and let host configuration change
the accepted client identity. The pool remains deployment-owned trust material
and is not parsed or replaced by this preflight. For every mode that requests
a client certificate, including `RequestClientCert` and `RequireAnyClientCert`,
its exported subject vector is bounded to 256 entries, each at most 16 KiB and
1 MiB in aggregate, before a future listener consumes the configuration; an
empty explicit pool remains valid and still represents an operator-selected
trust set. When `ClientAuth` is `NoClientCert`, a non-nil `ClientCAs` pool is
rejected because the Go server ignores it; direct HTTPS must not carry an
unused trust policy that appears reviewed but has no handshake effect. A
non-nil `tls.Config.GetConfigForClient` is rejected because the callback can
replace the validated base configuration during the TLS handshake, including
its version, cipher, curve, ALPN, renegotiation, and client-auth policy. Static
certificate selection through `Certificates` and the optional
`NameToCertificate` map remains inside this guard's reviewed data boundary.
Non-nil `tls.Config.GetCertificate` is rejected because it can replace that
selection during the handshake; deployments that need dynamic certificate
selection must terminate TLS outside this direct v2 boundary. Client-role-only
settings are rejected as well: `GetClientCertificate`, `RootCAs`,
`ServerName`, `InsecureSkipVerify`, `ClientSessionCache`, and the client-only
ECH fields (`EncryptedClientHelloConfigList` and
`EncryptedClientHelloRejectionVerify`) are ignored by a server but can make a
mixed-role configuration look as if it controls client authentication or
hostname verification. Direct HTTPS must receive a server-only configuration;
client behavior belongs to a separately reviewed outbound transport. A true
`tls.Config.PreferServerCipherSuites` value is rejected as well: the field is
deprecated and ignored by the current standard library, so setting it cannot
establish a reviewed server cipher-order policy. Direct HTTPS keeps the
standard library's server cipher-selection behavior; a deployment that needs
different ordering must use a separately reviewed TLS terminator. Non-nil
static certificate configuration is bounded before listener construction: at
most 64 certificate chains, 64 certificates and 64 SCT entries per chain, the
complete encoded SCT vector remains within its two-byte length field, and 1 MiB
of aggregate DER/OCSP/SCT bytes are inspected; empty or repeated DER
entries within one chain are rejected because an empty entry cannot be a
certificate, while a repeated entry adds no trust information and makes the
reviewed wire identity ambiguous. Each SCT entry must also be non-empty because
the TLS serialized-SCT vector carries a serialized SCT rather than an empty
placeholder; exact duplicate SCT entries are rejected within one certificate
and across the complete static certificate vector because repeating the same
serialized timestamp adds no certificate evidence and an SCT is specific to the
certificate it signs. Distinct entries remain valid, and nil or present-empty
outer SCT collections remain compatible when no individual entry is supplied.
The optional static `OCSPStaple` follows the server certificate-message
boundary as well: nil means no stapled response, while a present empty slice is
rejected because Go emits it as an empty OCSP extension that the peer parser
rejects. A non-empty response remains deployment-owned opaque bytes subject to
the aggregate metadata bound; the preflight does not parse or validate OCSP
status semantics. When a static `tls.Certificate.Leaf` is supplied, its raw
bytes must remain the first chain entry and its bounded parsed metadata must be
valid; when a private signer and a non-empty static chain are supplied, every
chain entry is parsed during preflight even if `Leaf` is present, so an opaque
or malformed leaf/intermediate DER handoff cannot defer failure until handshake
time.
The leaf public key must match that signer. This rejects an inconsistent
in-process certificate handoff before listener construction while preserving
empty/partial provisioning placeholders when either the signer or chain is
absent, and preserving the existing deployment ownership of certificate
loading and trust review. The check does not provision a certificate or expose
private-key material.
`NameToCertificate` is limited to 256
mappings. Each SNI name mapping is non-empty, at most 255
bytes, already uses Go's lowercased SNI lookup spelling, and contains no
control, Unicode format, or line/paragraph separator characters, and does not
end in a trailing dot; mixed-case keys are rejected because
`crypto/tls` lowercases the client SNI before map lookup and would otherwise
leave an accepted mapping unreachable. Every mapping must point to an element of the reviewed
`Certificates` slice; nil or detached certificate pointers fail closed. Empty
certificate configuration remains valid because
certificate provisioning, private-key handling, and identity/trust review are
deployment-owned. These limits bound preflight resource use and do not parse,
load, or provision certificate material. When multiple static certificates
provide a pre-parsed `Leaf`, their parsed metadata shares the same 1 MiB
aggregate certificate-metadata budget; this prevents individually valid leaves
from multiplying direct preflight memory work across the certificate vector.
Exact repeated non-empty DER chain sequences across separate static certificate
entries are rejected because they do not add a distinct identity and make
certificate selection ambiguous; distinct chains and empty deployment-owned
placeholder chains remain valid.
Each certificate's optional
`SupportedSignatureAlgorithms` vector is also capped at 32,767 two-byte TLS
entries before listener construction, and every entry must be one of the
signature schemes defined by the reviewed Go TLS version. Legacy TLS 1.2
SHA-1 schemes remain accepted for compatibility; the negotiated protocol and
certificate key still determine whether a defined scheme is usable. Unknown
entries fail closed instead of being silently ignored by `crypto/tls`, which
could make a non-empty operator policy empty or change its meaning when a
future library assigns a new numeric value. The values are not rewritten or
guessed by this preflight. When a static certificate supplies the optional
`tls.Certificate.Leaf`, its `Raw` bytes must exactly
match the first DER chain entry and its parsed metadata must satisfy the same
bounded, structurally coherent certificate rules used at the direct TLS
boundary. A nil `Leaf` remains valid and leaves parsing to `crypto/tls`; this
guard does not parse, replace, or mutate the supplied certificate. Non-nil
static `tls.Certificate.PrivateKey` values must implement `crypto.Signer`, must
not be typed-nil signer pointers, and must have internally consistent standard
RSA or ECDSA key material before the independent snapshot is built. RSA
validation runs on a copy so preflight does not populate the caller's CRT
cache; malformed keys and validator panics fail closed. Nil private keys remain
valid for the existing deployment-owned certificate provisioning contract, and
the actual certificate/key match and hardware-backed signer behavior remain
deployment responsibilities. The exported preflight also contains panics from
malformed in-process
certificate/configuration metadata as the opaque `lifecycle TLS config
validation failed` result; panic text never crosses the transport boundary and
no listener is created from a failed validation.
`tls.Config.VerifyPeerCertificate` and
`VerifyConnection` callbacks are also rejected: their authentication decisions
run at handshake time, and the former is skipped on resumed connections while
the latter runs on both full and resumed connections. Keeping both callbacks
outside direct HTTPS prevents a deployment from adding resumption-sensitive
certificate policy after preflight; deployments that need custom verification
must terminate TLS outside this direct v2 boundary. Non-nil `tls.Config.Rand` and
`tls.Config.Time` hooks are
also rejected: direct HTTPS keeps the standard cryptographic randomness and
handshake clock rather than allowing a callback to replace those security
inputs after preflight. Non-nil `tls.Config.WrapSession` or `UnwrapSession`
hooks are rejected as well because custom ticket serialization and resumption
storage would replace the standard session state and add an unreviewed
cross-process/session-identity boundary during handshake. Deployments that
need custom ticket storage must terminate TLS outside this direct v2 boundary.
The preflight also rejects a non-zero `tls.Config.SessionTicketKey`: that
deprecated override disables the standard library's automatic ticket-key
rotation and would introduce an unreviewed long-lived secret and
cross-process-sharing policy. The zero value retains standard rotating ticket
management; deployments that need explicit synchronized ticket keys must
terminate TLS outside this direct v2 boundary.
`tls.Config.SessionTicketsDisabled` must also remain false. Disabling tickets
changes the direct boundary's reviewed resumption behavior even though it does
not add a custom callback or secret; deployments that intentionally require no
TLS resumption need a separately reviewed TLS terminator and policy.
`tls.Config.DynamicRecordSizingDisabled` must also remain false. The direct
boundary keeps crypto/tls's adaptive record sizing so a deployment cannot
silently switch to largest-record behavior with different latency and resource
characteristics after preflight; a fixed TLS record policy requires a separately
reviewed TLS terminator.
The preflight also rejects a non-empty `tls.Config.EncryptedClientHelloKeys`:
server-side ECH changes handshake and retry behavior and carries private key
material whose distribution and rotation are not part of this direct boundary.
ECH server termination therefore requires a separately reviewed transport
contract.
The preflight does not create a listener or prove that a deployment used the
validated configuration. The direct listener handoff then takes a private
snapshot of the reviewed mutable collections: certificate DER, OCSP/SCT
vectors, signature-scheme lists, ALPN, cipher-suite and curve lists, SNI
mapping, and client-CA pool. It rebuilds a fresh server-only `tls.Config`
from the synchronized public snapshot instead of using `tls.Config.Clone`
directly, because the standard clone also carries unexported session-ticket
state, including keys installed through `SetSessionTicketKeys` while the
exported `SessionTicketKey` remains zero. This closes the shallow-copy
behavior of the standard clone for the reviewed collections and prevents
caller-owned hidden ticket history or static ticket policy from crossing the
handoff. The optional parsed `tls.Certificate.Leaf` pointer is not retained;
`crypto/tls` reparses the snapshotted DER when needed. Private-key
implementations are also part of the snapshot: standard RSA, ECDSA, and
Ed25519 private keys within the bounded key-size policy are copied into
independent signer objects, while custom
`crypto.Signer` implementations are rejected because their external state or
private handles cannot be copied safely. A caller may therefore retain and
rotate its original standard key after handoff without changing the reviewed
listener; the deployment still owns certificate identity, provisioning, and
trust review.
The private reviewed listener also retains the exact TLS delegate selected at
construction and the canonical host/port actually returned by the OS. If an
in-process integration replaces that delegate, or its reported authority drifts
from the bound host/port, `Accept` and `Addr` fail closed without invoking the
replacement; `Close` remains an unconditional cleanup path for the originally
reviewed delegate. The construction-approved delegate has
one recorded close attempt, whether it is closed through normal caller cleanup
or replacement cleanup, so a malformed replacement cannot cause a second close
of the reviewed object. Concurrent cleanup callers wait for that one attempt to
finish and observe its same result; a caller cannot observe an unfinished
	zero-value result. `ErrDirectHTTPSListenerCleanup` is joined with the original
	delegate error (or the generic panic classification), so callers can distinguish
	a rejected replacement whose approved listener was cleaned up from one whose
	cleanup needs supervisor review; the replacement/invalid-listener error remains
present as well. A nil replacement follows the same ownership rule rather than
an early invalid-listener return that could leave the approved delegate live.
Non-comparable listener implementations are rejected without
allowing interface identity comparison to panic. This keeps the serving and
cleanup paths inside the same construction-time ownership boundary even when
caller-owned objects are malformed.

The bind preflight also accepts only a canonical unsigned decimal port spelling.
Signed forms such as `:+8743` and non-zero leading-zero forms such as `:08743`
are rejected before any listener code can normalize them; the single spelling
`:0` remains valid for test harnesses.

Supervisor handoff for this boundary is limited to an additive v2 route. The
integration must provide a resolver that authenticates the request and binds a
stable controller identity to least-privilege scopes, plus either direct TLS
verification or trusted reverse-proxy transport evidence. It must configure
the serving TLS policy at TLS 1.2 or newer, keep the route loopback-only until
authenticated distribution is separately approved, and preserve the existing
1.x gateway and agent routes. This library checkpoint does not provide OAuth
metadata, account discovery, token issuance, a listener, or deployment
evidence; those remain explicit supervisor gates.

On reopen, persisted state is decoded through the same strict JSON boundary as
the MCP adapter: invalid UTF-8, duplicate object keys, and unknown
fields and trailing values are rejected, and nesting is capped at 128 levels
before semantic validation. Persisted state is therefore unambiguous even if
a repair or inspection tool uses different JSON defaults. Project and task
creation/update timestamps must be present and ordered; checkpoint timestamps
must fall within every supplied non-zero owning-task lifetime endpoint. Dependency lists must be
sorted and unique, the complete dependency graph must remain acyclic, each task
request fingerprint must match its project and dependency graph, checkpoint
owners must be valid bounded IDs, checkpoint
timestamps, sequences, and lease versions must be present and bounded by the
task/state metadata, and checkpoint sequences must be unique across tasks. A
terminal checkpoint must carry the task's current lease version; only a
pending or running task may retain a checkpoint from an earlier lease after
explicit expiry recovery.
Attempt counters and lease versions must remain equal
because acquisition increments them together, and an active lease must outlive
the task's last durable update but may not extend beyond the one-hour maximum
lease duration from that update. Pending is not a valid checkpoint state. A
resumable task may only retain a running checkpoint. After an expired lease is
recovered and a new owner acquires the task, the retained checkpoint may carry
the previous lease's lower version and owner as historical resume metadata; a
same-version owner mismatch is rejected, and the new owner must write a fresh
checkpoint before its metadata can match the active lease. A terminal task must
have a checkpoint with the same terminal state. Every task carrying an idempotency key must have
the matching reverse index entry, and every index entry must match the task's
project and key. A malformed or non-canonical file is rejected rather than
silently normalized, preserving deterministic retries and making recovery
reviewable. Direct readiness checks bind the candidate task's dependency list
to the canonical task-map entry and require its request fingerprint to match
that definition before evaluating completion, so a caller cannot omit or
substitute same-project dependencies or use a malformed task entry. The lower
readiness boundary also validates the bounded structural shape of all project
and task map entries and every idempotency reverse-index entry before any
dependency lookup. That shape includes task-state validity, project binding,
validation of every supplied non-zero project, task, lease, and checkpoint
timestamp, with project and task lifetime endpoints supplied together and in
order,
bounded canonical dependency lists, retry and lease-version counters that
advance together, lease ownership only on running tasks, and checkpoint
identity/state shells whose
sequences do not exceed the durable state's `NextSequence`. When task-lifetime
endpoints are supplied, the same lower boundary also requires each supplied
checkpoint timestamp to remain within those endpoints, task creation to follow
its project, running leases to outlive the task update without exceeding the
one-hour horizon. Checkpoints cannot exceed the task lease version; resumable and
terminal checkpoint states must match their task state, and a same-version
running checkpoint owner must match the active lease owner. Malformed
unrelated state cannot be hidden by a valid candidate. The
same lower boundary requires an explicit checkpoint to carry both task-lifetime
endpoints, so checkpoint metadata cannot be detached from an otherwise omitted
task lifetime. The
dependency identifier and ordering bounds are checked before hashing any
supplied task fingerprint, so malformed in-process dependency text cannot
consume avoidable lower-boundary work. The
same bounded preflight also walks the complete task graph and rejects missing
edges and dependency cycles, including cycles in tasks unrelated to the
candidate, before readiness can be reported. The
same lower boundary also requires every task carrying an idempotency key to
have its project-scoped reverse-index entry, so a keyed unrelated task with a
missing forward index cannot be hidden by a valid candidate. The
caller-bound fingerprint must also equal the canonical map entry and the
bounded project/dependency hash, so a tampered same-ID task cannot establish
readiness. The candidate's optional idempotency key must also satisfy the
bounded UTF-8 and control-character contract before it is compared with the
canonical task entry. The caller-bound idempotency key must also equal the
canonical task entry; this binding is checked separately because the request fingerprint
intentionally covers project and dependency identity, not the retry key. The keyed task
and its canonical caller-bound candidate must also resolve through the project-scoped
reverse index to that same task ID; a missing or substituted live index entry cannot
establish readiness. Both
the canonical pending task and the caller-bound candidate must
also have equal attempt and lease-version counters, both internally consistent,
remain below their maximum representable value, and have no active lease owner
or expiry; readiness never advertises a retry whose next acquisition would
overflow those counters. The caller-bound candidate must also carry the same
timestamps and checkpoint snapshot as the canonical pending task; a pending
task may retain only a bounded, valid running checkpoint whose identity,
sequence (no greater than the durable state sequence), lease version, owner,
payload, and timestamp remain consistent with that task. The lower readiness
preflight also rejects every unrelated pending task whose retry/lease counter
is already exhausted, because that task cannot be acquired; running or
terminal history may retain the maximum counter without being actionable.
The same preflight applies one shared durable 8 MiB budget to dependency
identifier text and retained checkpoint payload bytes before the graph walk or
candidate cloning. This prevents separately bounded dependency text and
historical checkpoints from combining into an in-process snapshot that could
not cross the durable state boundary or force an oversized readiness scan.
	The same boundary also rejects a checkpoint sequence shared by another task in the
direct state map, matching the durable validator's global sequence-uniqueness
rule. The direct readiness preflight also scans every task in that bounded map
for duplicate checkpoint sequences, so two unrelated malformed entries cannot
be hidden by an otherwise-ready candidate. Completed dependencies used by that boundary must also have no active
lease; if a completed dependency retains an explicit checkpoint, its terminal
identity, lease version, sequence, state, owner, timestamp lifetime, and payload bounds are checked, and its sequence must remain unique across the direct task map
before it can establish readiness. When a completed dependency supplies a
request fingerprint or dependency list, that lower helper also requires the
fingerprint to match the project-local dependency graph and the list to stay
within the bounded canonical representation; empty values remain compatible
with partial in-process completed-task fixtures. The supplied completed
dependency is also required to equal the canonical task-map snapshot before
its completion state can establish readiness, so a same-ID substitution cannot
smuggle different retry, timestamp, checkpoint, or dependency metadata through
the lower helper. Recovery may preserve attempt counters and an earlier running
checkpoint, but it cannot make a leased task
look pending. Store
commits recheck the
locked state-root identity before
serialization, immediately before creating the temporary replacement, and again
after it is flushed but immediately before installation, so a pathname/root
swap during the write boundary fails without replacing the durable checkpoint.
Each commit also revalidates its complete candidate state before JSON
serialization, so a malformed in-process clock or integration seam cannot
install a checkpoint that the same strict reopen validator would reject.
On Windows, checkpoint reads open the state root with a reparse-point-safe
directory handle, compare that handle's identity with the locked root, open the
child through the separately validated reparse-point-safe state path, and repeat
the root identity check before reading because the standard syscall surface has
no `openat` equivalent. The regular-file validator also requires a single
hard-link count for the lock and checkpoint handles, matching the Unix boundary
and preventing an unrelated same-file alias from entering the state or
ownership path. Native Windows ACL verification and execution remain supervisor
gates; this handle/path sequence is not a substitute for those native checks.
If installation succeeds but the final containing-directory sync fails, the
store is quarantined and releases its writer lock; it returns `ErrClosed` for
later operations and must be reopened so its in-memory state is rebuilt from
the installed checkpoint instead of risking a stale-state overwrite. The Unix
directory-sync helper also rejects a malformed nil or typed-nil directory
handle before calling `Sync` or `Close`; this remains an installed-write
failure at the atomic boundary and follows the same quarantine/reopen rule.
The global checkpoint sequence is monotonic; if it reaches the
maximum representable value, the next checkpoint is rejected with `ErrInvalid`
before memory or disk state changes, rather than wrapping to an invalid zero
sequence. The lower direct readiness boundary rejects that exhausted sequence
counter as well, so it cannot advertise pending work whose next durable
checkpoint is impossible.

## Verification

Run the focused race suite with the mandated toolchain:

```text
go test -race ./internal/v2/lifecycle
go vet ./internal/v2/lifecycle
```

The tests cover deterministic DAG resume, lease ownership and expiry
recovery, idempotent creation, archive behavior, atomic checkpoint failure,
replacement of an existing checkpoint on the atomic-write path, post-install
directory-sync failure quarantine, competing
state opens and explicit close/reopen, concurrent lease admission,
state-file descriptor/symlink replacement, state-size bounds, symlink rejection,
and fail-closed rejection of
non-canonical persisted indexes/dependencies. Controller-adapter tests cover
fixed owner binding, spoofed lease rejection, heartbeat/checkpoint flow,
closed-store behavior, explicit scope validation, scope separation, and
recovery authorization. MCP-adapter tests cover versioned initialization,
explicit protocol-version negotiation,
strict request/argument schemas, bound-owner lease flow, scope denial,
side-effecting notification suppression, request/response bounds, and
panic containment around integration-supplied lifecycle errors. Expected
errors keep their bounded stable code/detail vocabulary; a malformed error
matcher or formatter fails closed to the generic `INTERNAL` response without
exposing panic text or local error details.
HTTP-boundary tests cover mandatory security callbacks, direct-TLS and media
type rejection, generic authentication failure, authenticated principal
binding, callback-panic containment, bounded bodies, notification suppression,
and no-store/MIME-safety headers, plus bounded X.509 policy metadata and
post-transport body-mutation rejection. Gateway handoff tests cover explicit
lifecycle scope mapping and prove that legacy controller scopes do not grant
lifecycle authority; authenticated HTTPS deployment and production route
integration require supervisor review.
