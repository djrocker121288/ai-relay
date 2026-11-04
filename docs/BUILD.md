# Build from source

## Requirements

- Go 1.24 or newer with the toolchain selected by `go.mod`.
- POSIX shell, `tar`, `zip`, `unzip`, and SHA-256 tooling.
- Optional native tools: Java/Gradle for the Android companion, macOS
  `pkgbuild`/`hdiutil` for unsigned package/disk-image outputs, and signing
  certificates only when the owner intends to sign.
- No production service, network endpoint, or credential is needed.

## Validation

Use a writable temporary Go cache when the host's default cache is not
writable:

~~~sh
umask 022
export GOCACHE=/tmp/ai-relay-go-build
go test ./...
go vet ./...
gofmt -l cmd/ai-relay-installer/*.go
sh -n scripts/build-github-release.sh scripts/build-all-in-one.sh
sh -n packaging/all-in-one/install-unix.sh packaging/one-click/*.sh
sh scripts/test-all-in-one-installer.sh
~~~

Installer smoke tests must use disposable HOME, XDG, prefix, config, and state
directories and omit `--activate`. They must not contact production systems.

## Release candidate build

~~~sh
AI_RELAY_VERSION=2.1.2 ./scripts/build-github-release.sh
~~~

The script refuses to overwrite `dist/ai-relay-all-in-one-v2.1.2/`. It first
calls the preserved all-in-one builder, then cross-builds the bootstrap for
Linux, macOS, and Windows, creates one-click bundles, creates source
tar/zip archives, optionally attempts an already-available Android build, and
writes a checksum for every release file.

The script is intentionally not a signing service. It reports native
`.pkg`, `.dmg`, APK, code-signing, and notarization results only if the
tools and credentials/certificates are already present.

## Cross-build matrix

The bootstrap targets are:

~~~sh
GOOS=linux   GOARCH=amd64
GOOS=linux   GOARCH=arm64
GOOS=darwin  GOARCH=amd64
GOOS=darwin  GOARCH=arm64
GOOS=windows GOARCH=amd64
GOOS=windows GOARCH=arm64
~~~

The all-in-one payload additionally builds AI Relay/ARPL Linux, macOS,
Windows, and Android/Termux arm64 archives. The Android companion APK is built
separately with `scripts/build-android-companion.sh`; the GitHub release
workflow provisions Java 17, Android SDK 35, and Gradle for that native build.

## File boundary

Never stage `.git`, `.cache`, `.release-*`, `work`, `dist`, runtime
state, credentials, environment files, private keys, or production reports
into a public archive. Inspect the generated archive names and
`SHA256SUMS` before upload.
