# P8 bounded audit boundary

`internal/v2/audit` is the additive 2.0 policy boundary for audit records. A
record has a fixed vocabulary: identifier, timestamp, authenticated controller
identifier, action, outcome, and opaque resource identifier. There is no free-
form detail, request body, token, credential, or error-text field, which limits
accidental log injection and exposure; callers must still supply identifiers
only and must never place secrets in any field.

`Policy` requires explicit bounded retention between one hour and 90 days and
a bounded JSON-record size between 256 bytes and 64 KiB. `Record.Validate`
rejects empty, padded, oversized, invalid-UTF-8, control, and Unicode format
text. `Policy.Accepts` rejects a backwards clock, treats the exact retention
boundary as expired, and rejects records whose standard JSON representation
exceeds the configured limit. These methods evaluate policy only; they do not
write, delete, compact, encrypt, or authenticate records.

`audit.FileStore` is the bounded local durability adapter. It stores a versioned
JSON envelope through a private temporary file, flushes before replacement, and
syncs the containing directory on Unix-like hosts. Reloads reject unknown or
trailing JSON, unsupported versions, malformed records, and more than 4096
records; the serialized envelope is capped at 8 MiB. `AppendAt` prunes expired
records in the same locked checkpoint, while `List` filters without rewriting
and `Prune` removes only records outside retention. Every read and mutation
acquires the private `<audit-path>.lock` sidecar; writers reload the latest
checkpoint while holding that lock before applying a change, so separate
processes cannot overwrite one another from stale in-memory snapshots. A busy
or non-private lock fails closed. The store does not authenticate `Controller`
or `Resource`; an authenticated caller must bind those fields before appending.
Windows ACL verification remains a supervisor gate.

`audit.Bind` supplies that narrow binding for a caller that has already been
authenticated by its transport or identity adapter. Its `Event` input cannot
provide `Controller` or `Resource`; the adapter inserts the immutable values
captured by `Bind`. Bound listing filters to the exact pair, and bound prune
and append retention affect only that pair. `Bind` itself is not an
authentication mechanism and does not verify tokens, issuers, scopes, or
resource authorization.

A future authenticated adapter must bind the controller and resource to its
verified request before using the store, serialize the fixed record through a
bounded canonical format, append it atomically, and apply deletion/retention
only to records it owns. It must also include any envelope or line framing in
its own size limit.
The legacy 1.x `internal/audit` logger remains unchanged and is not upgraded by
this package.

The package uses only the Go standard library and OS file-lock primitives. It
has no helper process, network, credential, or transitive dependency footprint;
the sidecar is bounded to one small lock file per audit path and is removed by
the same package rollback as the store. Removing the package and this document
is the rollback path; no 1.x route or service is affected. Provider health,
authenticated distribution, and supervisor-host Windows ACL review remain open
P8 gates; this checkpoint supplies bounded local storage, retention, and
cross-process writer ownership.
