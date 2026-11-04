# AI Relay + ARPL all-in-one installer

The all-in-one release is the preferred front door for new installations. It
ships one platform archive containing AI Relay and ARPL together. Existing
`deploy/install-*`, `packaging/arpl/*`, ARPL settings, updater, enrollment, and
live deployment paths remain available and are not replaced.

## Supported matrix

| OS | Architectures | Package contents | Persistence path |
|---|---|---|---|
| Linux | amd64, arm64 | agent, ARPL, loopback gateway | user systemd when explicitly activated; ARPL renders a cron fallback when no user bus is available |
| macOS | amd64, arm64 | agent, ARPL, loopback gateway | per-user LaunchAgents when explicitly activated; no TCC bypass |
| Windows | x64, ARM64 | agent, ARPL, loopback gateway | current-user Scheduled Tasks when explicitly activated; no UAC bypass |
| Android/Termux | arm64 | agent, ARPL; no gateway | ARPL Termux supervisor scaffold; Termux:Boot availability is reported |

iOS and other unsupported platforms are not claimed.

## Build a release

From the repository root:

```sh
AI_RELAY_VERSION=2.0.3 ./scripts/build-all-in-one.sh
```

This creates `dist/ai-relay-all-in-one-v2.0.3/`, seven platform archives,
both installer entrypoints, this document, and `SHA256SUMS`. The build uses
`CGO_ENABLED=0`; Android is built only for arm64 and intentionally omits the
gateway. The script refuses to overwrite an existing versioned release
directory. It never reads or packages credentials, state, caches, or private
keys.

## One-command local install

Run the one entrypoint from a release directory. It verifies the selected
archive against `SHA256SUMS` before extracting it.

Unix:

```sh
./install-unix.sh --source-dir "$PWD" --role endpoint
./install-unix.sh --source-dir "$PWD" --role full
```

Windows PowerShell:

```powershell
.\install-windows.ps1 -SourceDir (Get-Location) -Role endpoint
.\install-windows.ps1 -SourceDir (Get-Location) -Role full
```

For a release server, replace `--source-dir`/`-SourceDir` with
`--base-url URL`/`-BaseUrl URL`. The Unix entrypoint detects Linux, macOS, and
Android/Termux and maps x86_64/aarch64 to amd64/arm64. The PowerShell
entrypoint detects Windows x64/ARM64.

The default role is `endpoint`: agent plus ARPL. `full` and `server` also
install the gateway on Linux and macOS or Windows. Android/Termux rejects the
full role because the gateway is not an appropriate package runtime there.

## Configuration and enrollment

Every option has an environment equivalent:

| Purpose | Unix option / environment | PowerShell option / environment |
|---|---|---|
| release source | `--source-dir`, `AI_RELAY_SOURCE_DIR` | `-SourceDir`, `AI_RELAY_SOURCE_DIR` |
| release URL | `--base-url`, `AI_RELAY_BASE_URL` | `-BaseUrl`, `AI_RELAY_BASE_URL` |
| version | `--version`, `AI_RELAY_VERSION` | `-Version`, `AI_RELAY_VERSION` |
| role | `--role`, `AI_RELAY_ROLE` | `-Role`, `AI_RELAY_ROLE` |
| binaries | `--prefix`, `AI_RELAY_PREFIX` | `-Prefix`, `AI_RELAY_PREFIX` |
| config | `--config-dir`, `AI_RELAY_CONFIG_DIR` | `-ConfigDir`, `AI_RELAY_CONFIG_DIR` |
| state | `--state-dir`, `AI_RELAY_STATE_DIR` | `-StateDir`, `AI_RELAY_STATE_DIR` |
| gateway | `--gateway`, `AI_RELAY_GATEWAY` | `-Gateway`, `AI_RELAY_GATEWAY` |
| existing credential | `--credential-file`, `AI_RELAY_CREDENTIAL_FILE` | `-CredentialFile`, `AI_RELAY_CREDENTIAL_FILE` |
| one-use token file | `--enroll-token-file`, `AI_RELAY_ENROLL_TOKEN_FILE` | `-EnrollTokenFile`, `AI_RELAY_ENROLL_TOKEN_FILE` |
| ARPL enrollment payload file | `--enrollment-payload-file`, `ARPL_ENROLLMENT_PAYLOAD_FILE` | `-EnrollmentPayloadFile`, `ARPL_ENROLLMENT_PAYLOAD_FILE` |
| ARPL peer name | `--peer-name`, `AI_RELAY_PEER_NAME` | `-PeerName`, `AI_RELAY_PEER_NAME` |

An existing credential must be a protected regular file. A one-use enrollment
token is accepted only by file path and requires an explicit gateway URL; its
contents are never printed. Enrollment writes a protected credential file and
the installer does not report connectivity merely because enrollment
succeeded. If neither credential nor token is supplied, the result is an
intentional staged install with the literal status `ENROLLMENT REQUIRED`.

An optional ARPL enrollment payload is passed by file path to the existing
`arpl enroll consume` logic together with `--peer-name`; payload contents are
not printed or included in the package.

The gateway remains loopback-only. Full installs create a protected,
secret-free `gateway.env` scaffold; operators add paths to separately managed
0600 token files when configuring MCP. No token is generated, copied into a
package, or placed in logs.

ARPL identity and settings are initialized only when absent. Existing
`identity.json`, `settings.json`, peer profiles, and enrollment state are
preserved. Every install first renders ARPL persistence files into the private
install scaffold. This staging step is non-mutating to native persistence: it
does not touch a user bus, crontab, LaunchAgent, or Scheduled Task.

Use `--activate` or `-Activate` only after reviewing the local settings and
credentials. On Linux and macOS, explicit activation invokes ARPL's existing
native `settings apply` path without `--output-dir`; ARPL therefore owns its
systemd/cron or LaunchAgent activation and an activation error fails the
installer. The installer separately activates AI Relay's own configured
components. Windows follows the same ARPL native path, which registers ARPL's
configured current-user Scheduled Tasks, in addition to AI Relay tasks; no UAC
bypass is used. Without an AI Relay credential, the AI Relay agent remains
unactivated and reports `ENROLLMENT REQUIRED`, while ARPL activation may still
proceed according to ARPL settings. Android/Termux never claims native gateway
or Termux:Boot activation: `--activate` remains manual/foreground-supervisor
oriented and reports the available Termux start signal.

## Status and doctor

```sh
./install-unix.sh --status
./install-unix.sh --doctor
```

```powershell
.\install-windows.ps1 -Status
.\install-windows.ps1 -Doctor
```

These commands report staged/configured state and invoke ARPL's existing
`doctor` checks. A configured credential means only that a protected local
credential exists; it does not claim that an agent is connected.

## Legacy and live deployment boundaries

The unified package is additive. It does not alter Cloudflare, DNS, live
services, production ARPL links, enrollment state, or updater configuration.
It also does not remove the legacy installers. Native macOS GUI, Windows
PowerShell/task, Android companion, TCC, and Termux:Boot behavior must still
be validated on their respective hosts before claiming native runtime
success.
