# Changelog

## 2.1.2 — 2026-11-04

- Added first-class `grok` controller kind so Grok CLI, Grok Build, and grok.com custom MCP connectors can authenticate against the loopback `/mcp` endpoint. See [docs/GROK.md](docs/GROK.md).
- Hardened resident and direct-client reconnection against scheduling jitter with
  a minimum 1-second inbound stale-link threshold and minimum 500-ms
  heartbeat write deadline for unusually short heartbeat intervals.
- Preserved Android network-loss recovery, half-open link detection, bounded
  heartbeat writes, safer notification updates, and session-state locking.
- Rebuilt the all-in-one installers for Linux, macOS, Windows and Android/Termux,
  including the Android companion debug APK.
- Hardened the public-source exporter to exclude retired build caches, work
  backups, and private local files.
- Verified the native Linux full Go test suite and vet, repeated reconnect
  regression checks, Linux installer safety, and native macOS functionality.
- Native Windows hardware, Intel macOS, and Android physical-device acceptance,
  plus production app/code signing, remain separate release limitations.


## 2.1.1-rc

- Advanced the combined AI Relay + ARPL GitHub candidate to 2.1.1 with all
  current repository updates included.
- Added a sanitized public-source exporter that excludes local supervisor,
  runtime, credential, machine-specific, and private handoff material and can
  fail closed on owner-supplied deny patterns.
- Added native Apple-silicon validation for the 2.1.1 Finder installer and
  produced verified unsigned arm64 `.pkg` and `.dmg` artifacts.
- Fixed the Termux one-click bootstrap default version so the 2.1.1 bundle
  selects its matching Android/Termux payload.
- Added/validated Android companion build tooling and native GitHub CI paths
  while keeping Android permissions, signing, and real-device gates explicit.
- Refreshed GitHub release documentation so the public repository is created
  from the sanitized export rather than the private development worktree.

## 2.1.0-rc

- Added the cross-platform `ai-relay-installer` bootstrap command.
- Added Windows double-click setup bundles for amd64 and arm64.
- Added Finder-launchable macOS app bundles and conditional native package
  tooling.
- Added Linux self-extracting `.run` launchers, a desktop entry, and a
  documented Termux bootstrap bundle.
- Added an Android companion build path that embeds ARM64 ARPL and AI Relay
  runtimes, uses app-private enrollment payload files, and has a GitHub native
  Android CI artifact job.
- Removed private deployment hostnames from public runtime defaults; updater,
  telemetry, reporting, relay, and tunnel endpoints are now explicitly
  configured by each deployment.
- Added public-source documentation, contribution/security/support policy,
  issue/PR templates, CI build checks, release checksums, and source archives.
- Preserved the v2.0.3 unified installer staging and ARPL activation semantics.

## 2.0.3

See the preserved all-in-one release documentation in
[docs/ALL_IN_ONE_INSTALLER.md](docs/ALL_IN_ONE_INSTALLER.md).

