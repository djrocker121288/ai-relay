# 2.0 upgrade and rollback boundary

The current P9 checkpoint adds a local, explicit dry-run gate around the
existing signed-update path. The agent fetches a signed platform manifest over
HTTPS, verifies the Ed25519 signature and SHA-256 artifact hash, then
`-update-dry-run` validates the current executable and artifact size without
renaming, overwriting, deleting, or installing any file. `-install-update`
remains the separate approval-bearing mutation; `-rollback-update` restores the
single `.previous` image. The flags cannot be combined, so a dry run cannot
silently become an install.

Manifest responses are read into a strict 128 KiB envelope before signature
validation. Oversized bodies and trailing JSON documents are rejected, while
unknown object fields remain accepted for additive manifest evolution. This is
a local parser/resource bound; it is not evidence of a reachable public update
origin or authenticated distribution deployment.

`distribution.ValidateInstall` is intentionally side-effect free. It rejects
downgrades, empty or over-512 MiB artifacts, symlink/non-regular executable
targets, and targets with no usable permission bits. The mutating installer
reuses this gate, writes a private temporary sibling, flushes it, preserves the
existing executable mode, stages any prior `.previous` image instead of
deleting it first, and then performs the replacement/rollback sequence. Unix
like builds sync the containing directory after the rename and restore the
prior active/rollback pair if that sync fails. No 1.x service, gateway state,
credential, or model store is touched.

Rollback applies the same local trust boundary to both sides of the swap: the
current executable and `.previous` must be regular, non-symlink files, and the
rollback image must retain usable permission bits. The checks happen before any
rename, so a tampered or incomplete rollback slot leaves the active executable
and rollback slot unchanged. A pre-existing `.rollback-tmp` slot is also
treated as an interrupted or ambiguous operation and refuses to overwrite it.
After the swap, Unix-like builds sync the containing directory before removing
the old active image; if that durability sync fails, the prior active/rollback
pair is restored and synced before the error is returned. This keeps rollback
failure recoverable without deleting the only known active image.

This slice uses only Go standard-library components already in the module:
`crypto/ed25519`, `crypto/sha256`, `net/http`, and filesystem primitives. They
have no added transitive dependency or resident service footprint, follow the
Go security-maintenance path, and are replaceable behind the existing
`distribution.Client` boundary. The rollback path is the retained `.previous`
image plus the encrypted-file/native credential stores; no new persistent
secret is introduced.

The dry-run is not a release or deployment claim. Public distribution,
authenticated telemetry, platform-native installer execution, 1.x state
migration, side-by-side canary health, automatic service rollback, and native
Windows/macOS evidence remain P9/P10 supervisor gates. The distribution
service remains loopback-only and its public deny rule must remain in place
until those gates have concrete evidence.

The artifact download method repeats the platform and architecture check after
signature verification. A signed manifest for another target is rejected before
the artifact request, even when an in-process caller bypasses the normal
manifest-check flow; this keeps the direct download boundary from fetching an
unusable or misrouted release image.
