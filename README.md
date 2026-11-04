# AI Relay + ARPL

AI Relay is a self-hosted, authenticated relay for machines that an operator
owns or is explicitly authorized to administer. It consists of a loopback
gateway, enrolled endpoint agent, MCP/HTTP control surface, and portable
diagnostics. ARPL (AI Relay Persistent Link) adds an encrypted, reconnecting
peer link for long-lived remote sessions and bounded file/command operations.

This repository is the public source project. It does not include production
credentials, private keys, enrollment state, Cloudflare/DNS configuration, or
runtime caches.

## Features

- Staging-first AI Relay + ARPL installation with endpoint, full, and server
  roles where the platform supports them.
- Single-use AI Relay enrollment tokens and protected credential files.
- ARPL Ed25519 identities, authenticated encrypted sessions, peer allowlists,
  revocation, reconnect, bounded exec, and resumable file transfer.
- MCP JSON-RPC gateway with versioned request envelopes, replay protection,
  audit storage, and explicit operator-controlled activation.
- Cross-built archives plus one-click bootstrap entry points for supported
  desktop platforms and Termux.
- Portable status, doctor, repair, and source-build workflows.

## Supported platforms and one-click matrix

| Platform | Architectures | Recommended public entry point | Current boundary |
|---|---|---|---|
| Linux | amd64, arm64 | `AI-Relay-ARPL-Setup_<version>_linux_<arch>.run` | User service activation is opt-in; no root or service manager is invoked by default. |
| macOS | amd64, arm64 | `AI-Relay-ARPL-Setup_<version>_darwin_<arch>.app.zip` | Apple-silicon Finder staging is natively accepted; Intel remains cross-build-only. Native permissions remain macOS-controlled. |
| Windows | amd64, arm64 | `AI-Relay-ARPL-Setup_<version>_windows_<arch>.zip`, then double-click `AI-Relay-ARPL-Setup.exe` | Uses Windows PowerShell without a manual PowerShell window; no UAC bypass. |
| Android / Termux | arm64 | `AI-Relay-ARPL-Termux-Bootstrap_<version>_android_arm64.zip` | User-space Termux staging only; Android permission prompts and foreground service policy remain OS-controlled. |
| Android companion | arm64 APK source/build | `deploy/android/` / GitHub `android-native` artifact | Bundles ARM64 ARPL + agent runtimes; real-device install/runtime and production signing remain native gates. |

The default installation role is `endpoint`. `full`/`server` stages the
loopback gateway on Linux, macOS, and Windows. Android/Termux intentionally
rejects the full gateway role.

## Quick start

Download and verify the release assets from GitHub, extract the matching
platform bundle, and run the canonical entry point:

~~~sh
./AI-Relay-ARPL-Setup_2.1.2_linux_amd64.run --role endpoint
~~~

The default is a staged install. If no protected AI Relay credential exists,
the result is explicitly:

    ENROLLMENT REQUIRED

To enroll, place a single-use token in a protected regular file and pass only
its path:

~~~sh
chmod 600 ./enroll.token
./AI-Relay-ARPL-Setup_2.1.2_linux_amd64.run \
  --gateway https://relay.example.invalid \
  --enroll-token-file ./enroll.token
~~~

The installer never accepts token contents on a command line, never prints
them, and never silently enrolls. Use `status`, `doctor`, or `repair` with the
same entry point. Native persistence requires explicit `--activate`.

For an existing source checkout, the Go bootstrap can be run directly:

~~~sh
go run ./cmd/ai-relay-installer status
go run ./cmd/ai-relay-installer install --role endpoint
~~~

## Security model

AI Relay credentials, enrollment tokens, ARPL identity keys, settings, and
runtime state are local operator data. Installers require regular files and
owner-only permissions for secret inputs, preserve existing identity/settings
when present, create new secrets with restrictive modes, and use ACL
protection on Windows. Release builders exclude `.git`, caches, state,
credentials, private-key material, local environment files, and operational
handoffs.

AI Relay requests use device identity, timestamps, nonces, canonical
parameters, and HMAC-SHA-256. Revocation, stale-request rejection, and nonce
replay protection are enforced by the gateway. ARPL uses local Ed25519
identity keys, signed handshakes, ephemeral X25519 key agreement, directional
AES-256-GCM payload keys, bounded frames, and reconnect state. Remote
gateways should use trusted TLS 1.2+ (prefer TLS 1.3); do not expose a
development listener directly to the internet.

The project is not a rootkit, does not bypass UAC/TCC/Android permissions, and
does not provide arbitrary privileged remote execution. Review [SECURITY.md](SECURITY.md)
before operating a relay.

## Architecture

The public flow is:

    operator -> one-click bootstrap -> existing unified installer
      -> verified platform archive -> AI Relay agent + ARPL + optional gateway
      -> explicit enrollment -> optional native activation

The Go bootstrap detects its own host platform, safely locates the existing
Unix or PowerShell installer, forwards only file paths and ordinary options,
and reports the child exit status. Installation logic remains in
`packaging/all-in-one/`; ARPL owns its settings schema and native persistence
rendering. The gateway is loopback-oriented, while remote access belongs
behind an authenticated TLS or relay boundary.

See [docs/ARPL.md](docs/ARPL.md), [docs/INSTALL.md](docs/INSTALL.md), and
[docs/ALL_IN_ONE_INSTALLER.md](docs/ALL_IN_ONE_INSTALLER.md).

## GitHub Actions workflow templates

CI workflow YAML files are included under `ci/workflow-templates/` and in the complete versioned source archives. Installing them in `.github/workflows/` requires the repository uploader to authorize the GitHub `workflow` scope. The release itself is tested separately on the build hosts.

## Building from source

Requirements: Go 1.24 or newer, POSIX `sh`, `tar`, `zip`, and SHA-256 tooling.
Go and Python are not required on an end-user machine when using a release
artifact.

~~~sh
gofmt -w cmd/ai-relay-installer/*.go
go test ./...
go vet ./...
./scripts/build-github-release.sh 2.1.2
~~~

The release builder refuses to overwrite an existing versioned directory.
It first reuses the validated all-in-one builder, then adds checksummed
bootstrap, Windows, macOS, Linux, Termux, and source artifacts. The GitHub
release workflow also provisions Java/Android SDK/Gradle to build an ARM64
companion debug APK with bundled ARPL/agent runtimes. macOS `.pkg`/`.dmg`,
Android production signing, Apple signing, and notarization remain conditional
on the required native toolchains and owner-controlled certificates.

See [docs/BUILD.md](docs/BUILD.md) for reproducible build details and
[docs/GITHUB_RELEASE_GUIDE.md](docs/GITHUB_RELEASE_GUIDE.md) for owner release
steps.

## Project status

The 2.1.2 release candidate is source/build ready after the local validation
gates pass. Core Go tests, vet, Unix installer staging, cross-builds, sanitized
public-source checks, and checksum verification are intended to run in CI and
on the release host.

Native Windows execution/ACL/task validation, Intel-mac execution,
macOS LaunchAgent activation, Android/Termux arm64 runtime validation, and any
signed APK or Apple artifact remain device/toolchain gates. Apple-silicon
macOS Finder staging has passed on a real Mac. Windows interactive ConPTY and
native screen/input/USB/elevation helpers are not advertised as complete.

## Limitations

- No installer can silently grant platform permissions or create a trusted
  signature without the owner's OS/certificate approval.
- Android native installation is not equivalent to Termux staging.
- Remote server registry durability, QUIC/NAT traversal, and some native
  terminal integrations remain future work.
- A configured credential proves local configuration only; installer status
  does not claim network connectivity.
- Production deployment, DNS, Cloudflare, tunnels, and credential enrollment
  are intentionally outside this public source release.

## Troubleshooting

- `ENROLLMENT REQUIRED`: install staging succeeded, but no protected AI Relay
  credential was provided. Obtain a new one-use token through the operator's
  approved gateway and pass its file path.
- Check `status` and `doctor`; they report local staged/configured state and
  do not pretend that connectivity was tested.
- A checksum failure means the artifact and `SHA256SUMS` do not match. Delete
  the download and obtain both from the same release.
- `PowerShell was not found` means the Windows host policy/tooling is broken;
  the setup executable does not install PowerShell or bypass policy.
- On Android, use Termux:Boot or the documented foreground companion controls
  only after Android grants the requested permissions.

## Uninstall

Stop any explicitly activated user services/tasks first. Then remove only the
installation prefix, AI Relay config/state, ARPL settings/identity, and
operator-created service entries after review. Do not delete credentials or
production state blindly. The exact paths are those shown by `status`; see
[docs/INSTALL.md](docs/INSTALL.md) for a reversible checklist.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[SUPPORT.md](SUPPORT.md). Changes must preserve explicit enrollment, protected
file handling, staging-first activation, and the no-secrets release boundary.
Do not include live deployment evidence or private operational data in issues or
pull requests.

## License

Apache License 2.0. See [LICENSE](LICENSE).
