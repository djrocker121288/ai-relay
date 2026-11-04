# GitHub release guide

These steps are for the repository owner. They do not publish anything
automatically and do not require production credentials.

The local development worktree can contain supervisor notes, machine-specific
automation, and operational state that are intentionally **not** part of the
public project. Do not push a live development worktree directly. The release
tooling creates a sanitized public-source export for GitHub.

## 1. Build and verify the release

Set the intended version once:

~~~sh
VERSION=2.1.2
umask 022
GOCACHE=/tmp/ai-relay-go-build go test ./...
GOCACHE=/tmp/ai-relay-go-build go vet ./...
sh -n scripts/build-github-release.sh scripts/export-public-source.sh
AI_RELAY_VERSION="$VERSION" ./scripts/build-github-release.sh
(cd "dist/ai-relay-all-in-one-v$VERSION" && sha256sum -c SHA256SUMS)
~~~

On hosts without `sha256sum`, use `shasum -a 256` and compare every entry.

The build creates:

- platform archives and one-click installers;
- `SHA256SUMS`;
- `ai-relay_<version>_source.tar.gz`;
- `ai-relay_<version>_source.zip`.

The source archives are produced by `scripts/export-public-source.sh`. That
export excludes local supervisor/status files, caches, runtime state,
credentials, local development workers, and machine-specific service files. It
also fails if the build host's concrete checkout/home path survives in the
public tree.

For an additional organization/private-domain check, set a deny regex locally
when exporting. Keep organization-specific values out of the repository:

~~~sh
AI_RELAY_PUBLIC_SOURCE_OVERWRITE=1 \
AI_RELAY_PUBLIC_DENY_REGEX='YOUR_PRIVATE_PATTERN' \
  ./scripts/export-public-source.sh "$VERSION" "dist/ai-relay-all-in-one-v$VERSION"
~~~

## 2. Inspect the public source

Never assume the archive is safe merely because the build completed. Review it:

~~~sh
tar -tzf "dist/ai-relay-all-in-one-v$VERSION/ai-relay_${VERSION}_source.tar.gz"
unzip -l "dist/ai-relay-all-in-one-v$VERSION/ai-relay_${VERSION}_source.zip"
~~~

Then test the public source itself from a clean temporary directory:

~~~sh
tmp=$(mktemp -d)
tar -xzf "dist/ai-relay-all-in-one-v$VERSION/ai-relay_${VERSION}_source.tar.gz" -C "$tmp"
(
  cd "$tmp"
  go test ./...
  go vet ./...
  sh -n scripts/*.sh packaging/all-in-one/*.sh packaging/one-click/*.sh
)
~~~

The public root should contain normal project material such as `README.md`,
`LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`, source directories,
documentation, examples, and `.github`. It should not contain local runtime
state, credentials, internal supervisor handoffs, or private infrastructure
details.

## 3. Create the GitHub repository from the sanitized export

1. Create an empty GitHub repository with the intended public name.
2. Do not initialize it with a README or license; the public export already
   contains them.
3. Extract the sanitized source archive into a **new clean directory**.
4. Initialize Git in that clean directory, review everything, then push.

Example:

~~~sh
mkdir ai-relay-public
tar -xzf "ai-relay_${VERSION}_source.tar.gz" -C ai-relay-public
cd ai-relay-public

git init
git add .
git status
git diff --cached
git commit -m "Initial public AI Relay + ARPL source"
git branch -M main
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
~~~

Do not substitute the private development worktree for `ai-relay-public`
unless it has independently passed the same public-source audit.

## 4. GitHub Actions

The public project includes:

- `.github/workflows/test.yml` for Go tests, vet, shell checks, and build
  validation;
- `.github/workflows/release-artifacts.yml` for release artifacts and native
  platform jobs;
- issue templates and a pull-request template.

Workflows must remain safe for forks and must not contain production secrets.
Signing identities, notarization credentials, private tunnel credentials, and
release tokens belong in protected repository/environment secrets only when the
owner intentionally configures them.

## 5. Tag and draft a release

After native gates for the claimed platforms pass:

~~~sh
git tag -a "v$VERSION" -m "AI Relay + ARPL v$VERSION"
git push origin "v$VERSION"
~~~

On GitHub:

1. Open **Releases** and choose **Draft a new release**.
2. Select the matching tag.
3. Attach the files from `dist/ai-relay-all-in-one-v$VERSION/`.
4. Attach `SHA256SUMS`.
5. Use `CHANGELOG.md` plus the reviewed release-candidate status for notes.
6. Keep the release as a draft until disposable/native install testing has
   passed for every platform you plan to claim.

Do not attach the entire `dist` parent, cache directories, runtime state, or
local handoff files.

## Artifact checklist

Typical public assets are:

- Windows architecture-specific setup ZIPs and executables;
- macOS app ZIPs plus native `.pkg`/`.dmg` only when actually built and
  validated;
- Linux self-extracting `.run` installers;
- Android/Termux bootstrap assets and an APK only when that APK was actually
  built and validated;
- platform archives;
- sanitized source ZIP/TAR;
- `SHA256SUMS`.

## Signing and notarization roadmap

Before claiming signed production installers:

- sign Windows executables/installers with an owner-controlled Authenticode
  certificate;
- sign and notarize macOS app/pkg/dmg artifacts with Apple Developer ID;
- sign the Android release APK with an owner-controlled keystore and publish
  the certificate fingerprint;
- keep all private keys, certificates, passwords, tokens, and tunnel
  credentials out of source and release archives;
- verify signatures as part of release CI and document verification steps for
  users.

Unsigned artifacts must be described as unsigned. Never imply notarization,
production signing, or native-platform validation that has not actually been
performed.
