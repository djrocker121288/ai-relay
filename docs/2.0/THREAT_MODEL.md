# P10 threat model and release boundary

This is the first P10 implementation slice. It records the local abuse cases
and adds a reusable archive-boundary check; it is not a release approval and
does not claim native, signing, distribution, or deployment evidence.

## Assets and trust boundaries

- Credentials, private keys, tokens, model state, runtime state, and local
  supervisor metadata are local-only assets and must not enter a public archive.
- Release builders are untrusted input boundaries: a stale checkout, generated
  path, symlink, or archive member must not silently broaden the release.
- The trusted supervisor owns native execution, signing, notarization, public
  distribution, and the final tag. This worktree worker owns only bounded local
  source and test changes.

## Abuse cases and controls

| Abuse case | Control in this slice | Evidence or remaining gate |
| --- | --- | --- |
| Development state or credentials are packaged | `verify-release-boundary.sh` rejects runtime, cache, credential, and secret-looking members | Shell regression rejects unsafe TAR/ZIP members; final source-export review remains open |
| A traversal member escapes the extraction root | Archive listings normalize `\\` to `/` and reject absolute or `..` path segments | Listing-only check is portable; extraction behavior still needs native/archive-host review |
| A builder skips the safety check | `build-github-release.sh` invokes the shared checker after producing archives | `sh -n` and the focused shell test are local evidence; CI/release-host execution remains required |
| An artifact is mistaken for a trusted release | Documentation distinguishes checksums from signatures and native validation | Signing, notarization, native install, and public distribution remain `WAITING_EXTERNAL` |
| 2.0 is activated over stable 1.x | Release/upgrade docs retain side-by-side and rollback gates; this slice has no service activation | Supervisor must provide upgrade/rollback evidence before any deployment |

The checker uses only POSIX shell plus the standard host `tar`, `unzip`, and
`awk` listing tools. It adds no resident
process, network access, credential store, model operation, or transitive Go
dependency. Its rollback is removing the checker and the one build-script
call; the release builder otherwise remains unchanged.

## P10 evidence boundary

The focused shell test covers a safe TAR and rejects unsafe TAR and ZIP
members. It does not inspect a real release, execute foreign binaries, verify
signatures, contact a provider, or publish anything. The following evidence is
still required before P10 or `2.0 COMPLETE` can be claimed: dependency/license
and advisory review, race/vet/static checks, native Linux/macOS/Windows
execution, controller discovery, authenticated tunnel distribution,
performance/resource evidence, upgrade/rollback proof, checksums, and a
trusted-supervisor release-candidate review.
