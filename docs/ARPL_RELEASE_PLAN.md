# ARPL Hardening Release Plan

This plan tracks the ARPL hardening release without changing the live fleet.
The candidate is built and tested locally under `dist/arpl-candidate-*`; deployment
is a separate gate after the complete report is reviewed.

## Phases and acceptance criteria

1. **Baseline and protocol foundations** — preserve the existing WSS/TLS paths;
   document the release, add capability-aware authorization, audit primitives,
   durable peer/session metadata, and redaction tests.
2. **Platform terminal and supervision** — provide Unix PTY and native Windows
   ConPTY adapters, reconnect-safe terminal ownership, and idempotent ARPL-owned
   supervision with OS-native service rendering.
3. **Settings and enrollment** — validate and atomically apply settings, render
   systemd/launchd/Windows/Termux persistence, and add single-use signed native
   enrollment with expiry and replay rejection.
4. **Routes and durable operations** — add explicit direct/LAN/relay route
   selection, session reattach, resumable tree sync, and durable bounded jobs.
5. **Android companion and installers** — provide a real buildable Android
   companion project when the SDK is available, plus honest platform installers
   and the existing Termux fallback.
6. **Diagnostics and fleet/update UX** — add `doctor`, `fleet`, signed staged
   updates with health rollback, and local audit querying.
7. **Release validation** — run formatting, focused/race/vet tests, supported
   cross-builds, platform/runtime checks available in this environment, and
   produce the candidate checksums and release test report. No deployment occurs
   in this run.

## Release gates

- Existing production connectivity remains untouched and reachable throughout.
- Every security-sensitive operation is authorized server-side by explicit peer
  capabilities; secrets and private keys never appear in output or artifacts.
- Settings and updates validate before replacement, write atomically, preserve a
  rollback copy, and are idempotent.
- Runtime claims are limited to platforms and paths actually tested.
- A release is not declared green when a required platform runtime check is
  blocked; the exact blocker is recorded in `ARPL_RELEASE_TEST_REPORT.md`.

## Candidate identity

The candidate version/build ID is generated at build time. Artifact hashes are
written to `dist/arpl-candidate-*/SHA256SUMS`; signing is external and uses a
key supplied at release time, never a private key committed to this repository.
