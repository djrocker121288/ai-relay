# ARPL v0.1

ARPL (AI Relay Persistent Link) is the additive encrypted transport for AI Relay. It is designed to keep a logical device session alive across ordinary network loss and reconnect automatically until the operator disconnects, revokes a device, or stops the service. SSH remains available only as a fallback during rollout.

## Security model

Every device generates its own long-term Ed25519 identity key locally. Private keys are never sent in the handshake, frames, logs, or enrollment data. Peers are explicitly allowlisted by public key and may be revoked. Each connection exchanges fresh challenges and ephemeral X25519 keys, signs the ordered handshake transcript, and derives directional AES-256-GCM payload keys. The outer transport is TLS 1.3 with ALPN `arpl/0.1`.

The portable key store is an owner-only file. The `KeyStore` interface is ready for macOS Keychain, Windows protected storage/TPM, Linux secret/TPM storage, and Android Keystore adapters; those native adapters are not yet wired in v0.1.

Frames are bounded and authenticated and contain channel, logical session, stream ID, sequence, acknowledgement, deadline, payload size, and a monotonic directional counter. Replays, counter gaps, duplicate stream sequences, wrong-session frames, expired frames, malformed lengths, and altered ciphertext are rejected.

## Persistence and reconnect

The persistent client stores a logical session ID plus acknowledgement/send-sequence state in a 0600 session file. It sends heartbeats and reconnects indefinitely with jittered exponential backoff. The server keeps logical session state independently of accepted sockets, so a dropped TCP/TLS connection can reconnect with the same session ID.

The server registry is currently memory-backed. A full server-process restart therefore starts a fresh server registry, although file-transfer `.part` data remains resumable on disk. Durable gateway session registry storage is a next step.

## Remote operations

`serve` accepts an allowlisted peer and may enable:

- `-allow-exec`: encrypted argv-only command execution. It is disabled by default. No shell command string is constructed. Output and runtime are bounded.
- `-file-root PATH`: enables file upload/download only under the configured root. Empty means file operations are disabled.
- `-max-file`, `-max-output`, and `-command-timeout`: safety limits.

Working CLI operations:

- `arpl exec ... -- PROGRAM ARG...` sends an encrypted argv request and returns bounded stdout, stderr, and exit code.
- `arpl send -src LOCAL -dest REMOTE` computes SHA-256, resumes from the server `.part` offset, acknowledges chunks, verifies final size/hash, and atomically renames.
- `arpl pull -src REMOTE -dest LOCAL` resumes a local `.part`, validates the server path against the allowed root, verifies SHA-256, and atomically renames. Existing destinations require `-overwrite`.
- `arpl terminal ...` currently uses the encrypted argv execution path. Native interactive PTY/ConPTY support is not yet present.
- `arpl connect` is the persistent heartbeat/reconnect link.
- `arpl status`, `key fingerprint`, `key rotate`, and `disconnect` provide identity/session administration.

File paths reject traversal and symlink escapes. Uploads use owner-only `.part` files and atomic completion.

## Platforms and packaging

| Platform | Build | Installer/status |
|---|---|---|
| Linux amd64/arm64 | PASS | shell installer validated on Linux; systemd scaffold included |
| macOS arm64/amd64 | PASS | shell installer natively validated on Apple Silicon; launchd scaffold included |
| Windows amd64/arm64 | PASS cross-build | PowerShell installer included; native Windows installer execution still requires an online Windows test node |
| Android arm64 | PASS smoke build | terminal/core package included; foreground service + Keystore app glue remains future work |

The preserved v0.1 release is `dist/arpl-v0.1.0`. The resident-link release is `dist/arpl-v0.2.0` and contains prebuilt packages for Linux, macOS, Windows, and Android plus `SHA256SUMS`, `install.sh`, `install.ps1`, and `install-homebrew.sh`.

The Homebrew installer creates a local tap `ai-relay/local`, builds ARPL with the Mac's already-installed Go toolchain, and installs the resulting standalone binary through a dependency-free Homebrew Cask. This path was installed successfully on the connected Apple Silicon Mac and avoids Homebrew's unrelated Xcode Formula dependency gate.

## Validation

Current validation includes:

- `go test ./...`
- focused ARPL tests for allow/revoke, mutual signed handshake, replay/tamper rejection, session resume, exec enable/disable, interrupted upload resume/hash, download, traversal rejection, and unknown-operation rejection
- `go test -race ./internal/arpl`
- `go vet ./...`
- cross-builds for Linux amd64/arm64, macOS amd64/arm64, Windows amd64/arm64, and Android arm64
- extracted source bundle test/build
- `sha256sum -c SHA256SUMS`
- clean shell-installer test on Linux
- native shell-installer test on Apple Silicon macOS

## Known v0.1 limits

QUIC and NAT traversal are not implemented; TLS 1.3/TCP and the authenticated WSS relay are the transport adapters behind a replaceable `Transport` interface. Unix PTY and Windows ConPTY are implemented behind the terminal adapter, and Android persistence is provided by the companion source project with Termux fallback. The one-shot commands remain available while the resident daemon provides multiplexing, reconnect, and terminal reattach.

Do not expose identity files, TLS private keys, session files, or payloads in logs. Keep the existing SSH path available until ARPL is deployed and verified on each production device.


## v0.2 resident persistent link

ARPL v0.2 adds a resident client daemon so separate shell, PowerShell, and Homebrew-installed `arpl` commands reuse one authenticated encrypted upstream connection instead of opening a fresh network socket for every operation.

`arpl connect` is a compatibility alias for `arpl link run`. The resident daemon:
- binds its local control API to `127.0.0.1` only;
- authenticates local requests with a random 256-bit token kept in an owner-only state file;
- multiplexes exec/file/tool streams over the active encrypted ARPL connection;
- sends encrypted heartbeats;
- automatically reconnects indefinitely while preserving the logical ARPL session ID;
- does not blindly replay an exec whose result became ambiguous during a disconnect;
- resumes send/pull from verified offsets after reconnect;
- recognizes an already-completed upload by matching size and SHA-256.

Useful commands:

    arpl link run -addr host:9443 -peer-key SERVER_PUBLIC_KEY -ca-file ca.pem
    arpl link status
    arpl exec -- printf hello
    arpl send -src ./file.img -dest file.img
    arpl pull -src logs/build.log -dest ./build.log
    arpl link stop

A process-level TLS test forcibly stopped and restarted the server while the client daemon stayed running; it reconnected automatically with the same logical session and successfully executed and transferred files afterward.

## v0.2 settings supervision and intentional disconnect

On Linux, `arpl settings apply` renders one ARPL-owned supervisor service. The
supervisor rereads settings, owns at most one host child for each enabled
`inbound_pair` and one resident client child for each enabled `outbound_pair`,
and passes every peer selection explicitly (`--peer-key`, pair, relay URL,
session file, control state, and heartbeat). It uses a PID lock directory under
the settings directory, recovers a dead/stale lock, terminates children on
shutdown, and restarts failed children with bounded 1-second to 60-second
exponential backoff. A child that runs for at least 30 seconds resets its
restart delay.

The deterministic ARPL-owned state directory is:

    <settings-directory>/.arpl-supervisor/

Default per-peer session and control files are under
`.arpl-supervisor/peers/<sha256(public-key)>/`; intentional disconnect markers
are `.arpl-supervisor/stopped/<sha256(public-key)>.marker`. A configured
`session_file` or `control_state` remains authoritative for those two state
files, while the stop marker stays under the ARPL settings directory. `peer
disable` writes the marker and `peer enable` clears it. `client disconnect`
with `--settings-file` and `--peer-key` writes the same marker, so a supervisor
does not reconnect the deliberately stopped peer. The existing single-peer
link commands retain their original control-file marker behavior.

If a persistent systemd user manager is not available (including the common
no-linger user-session case), apply installs one tagged per-user cron entry
(`*/1 * * * *`) that invokes the same supervisor. Reapplying replaces the
tagged entry rather than duplicating it. The generated service, shell fallback,
and cron text can be inspected with `settings apply --dry-run`; tests never
write the real user's crontab.

Android executable resolution prefers the actual invoked ARPL `argv[0]` and
rejects ART linker paths such as `/apex/com.android.runtime/bin/linker64`,
falling back to the ARPL command name when no safe path is available. Linux
supervisor children use parent-death signaling so a hard-killed supervisor
cannot leave orphan processes that are duplicated after stale-lock recovery.


## macOS packaging note

The supported macOS install path is the native Homebrew Cask installer in packaging/homebrew/install-homebrew.sh. The release pipeline intentionally does not ship CGO_ENABLED=0 Darwin cross-builds: on macOS 27.0.1 those binaries were observed stalling in _dyld_start before Go runtime entry. Build natively on the target Mac using its installed Go toolchain, then install the resulting binary through the local Homebrew Cask. The installer verifies its own build artifact, clears Homebrew quarantine for that locally built artifact, and verifies arpl status after installation.


## Relay fallback status

HTTP(S) relay fallback is implemented and covered by full-duplex/reconnect tests, including repeated race-detector runs. The receive path performs ResponseWriter writes on the request handler goroutine to avoid net/http lifetime races. QUIC, direct peer-to-peer discovery, and NAT traversal remain future transport work.
