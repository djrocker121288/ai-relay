#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=${1:-}
OUT=${2:-}
if [ -z "$VERSION" ] || [ -z "$OUT" ]; then
  echo "usage: $0 VERSION OUTPUT_DIR" >&2
  exit 2
fi

case "$VERSION" in
  *[!0-9A-Za-z.-]*) echo "invalid version: $VERSION" >&2; exit 2 ;;
esac

command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
command -v zip >/dev/null 2>&1 || { echo "zip is required" >&2; exit 1; }
command -v grep >/dev/null 2>&1 || { echo "grep is required" >&2; exit 1; }
command -v sed >/dev/null 2>&1 || { echo "sed is required" >&2; exit 1; }

mkdir -p "$OUT"
TAR_OUT="$OUT/ai-relay_${VERSION}_source.tar.gz"
ZIP_OUT="$OUT/ai-relay_${VERSION}_source.zip"
if [ -e "$TAR_OUT" ] || [ -e "$ZIP_OUT" ]; then
  if [ "${AI_RELAY_PUBLIC_SOURCE_OVERWRITE:-0}" != 1 ]; then
    echo "public source archives already exist; set AI_RELAY_PUBLIC_SOURCE_OVERWRITE=1 to replace them" >&2
    exit 2
  fi
  rm -f "$TAR_OUT" "$ZIP_OUT"
fi

TMPBASE=${TMPDIR:-/tmp}
TMP=$(mktemp -d "$TMPBASE/ai-relay-public-source.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
STAGE="$TMP/source"
mkdir -p "$STAGE"

# Copy the public project while deliberately leaving local operations,
# credentials/state, generated releases, and private supervisor handoffs out.
tar -cf - -C "$ROOT" \
  --exclude='./.git' \
  --exclude='./.cache' \
  --exclude='./.cache.*' \
  --exclude='./.release-*' \
  --exclude='./.accept' \
  --exclude='./.agents' \
  --exclude='./.aws' \
  --exclude='./.codex' \
  --exclude='./darwin}' \
  --exclude='./work' \
  --exclude='./work.*' \
  --exclude='./work-*' \
  --exclude='./dist' \
  --exclude='./deploy/android/app/build' \
  --exclude='./deploy/android/.gradle' \
  --exclude='./scripts/__pycache__' \
  --exclude='*.bak-*' \
  --exclude='*.backup-*' \
  --exclude='*.token' \
  --exclude='*.pem' \
  --exclude='*.key' \
  --exclude='.env' \
  --exclude='.env.*' \
  --exclude='*/state' \
  --exclude='*/credentials' \
  --exclude='./STATUS.md' \
  --exclude='./SUPERVISOR_STATUS.md' \
  --exclude='./ALL_IN_ONE_INSTALLER_STATUS.md' \
  --exclude='./GITHUB_RELEASE_CANDIDATE_STATUS.md' \
  --exclude='./ARPL_*_STATUS.md' \
  --exclude='./ARPL_*_TASK.md' \
  --exclude='./ARPL_*_REPORT.md' \
  --exclude='./ARPL_BUILD_REPORT.md' \
  --exclude='./ARPL_DEPLOYMENT_STATUS.md' \
  --exclude='./ARPL_HARDENING*' \
  --exclude='./ARPL_RELEASE_TEST_REPORT.md' \
  --exclude='./ARPL_V0.2_BUILD_REPORT.md' \
  --exclude='./COMPLETION_HANDOFF.md' \
  --exclude='./docs/2.0/PLAN.md' \
  --exclude='./scripts/development-worker.py' \
  --exclude='./scripts/ai-relay-watchdog.py' \
  --exclude='./deploy/systemd/user/ai-relay-2-development.service' \
  . | tar -xf - -C "$STAGE"

# The public copy may retain architecture/design docs, but local absolute
# toolchain/check-out paths are rewritten in the export only.
escape_sed() {
  printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}
ROOT_ESC=$(escape_sed "$ROOT")
HOME_ESC=$(escape_sed "${HOME:-}")

rewrite_if_present() {
  file=$1
  shift
  [ -f "$file" ] || return 0
  tmp="$file.public-tmp"
  sed "$@" "$file" >"$tmp"
  mv "$tmp" "$file"
}

rewrite_if_present "$STAGE/docs/2.0/LIFECYCLE.md" \
  -e "s|${HOME_ESC}/.local/go/bin/go|go|g" \
  -e "s|${ROOT_ESC}|<repo-root>|g"
rewrite_if_present "$STAGE/docs/2.0/VAULT.md" \
  -e "s|${ROOT_ESC}|<repo-root>|g"
rewrite_if_present "$STAGE/scripts/build-arpl-candidate.sh" \
  -e "s|${HOME_ESC}/bin/go|go|g" \
  -e "s|${HOME_ESC}/.local/go/bin/go|go|g"

# Required public-repository surfaces.
for required in \
  README.md LICENSE CONTRIBUTING.md SECURITY.md SUPPORT.md CODE_OF_CONDUCT.md CHANGELOG.md \
  docs/GITHUB_RELEASE_GUIDE.md docs/INSTALL.md docs/BUILD.md \
  .github/workflows/test.yml .github/workflows/release-artifacts.yml
do
  [ -f "$STAGE/$required" ] || { echo "public source is missing required file: $required" >&2; exit 1; }
done

# Fail closed if this build host's concrete checkout/home paths survive.
for needle in "$ROOT" "${HOME:-}"; do
  [ -n "$needle" ] || continue
  matches=$(grep -RIlF "$needle" "$STAGE" 2>/dev/null || true)
  if [ -n "$matches" ]; then
    echo "public source still contains a build-host-specific path:" >&2
    printf '%s\n' "$matches" >&2
    exit 1
  fi
done

# Callers can add organization/private-domain patterns without hard-coding
# those values into the public project itself.
if [ -n "${AI_RELAY_PUBLIC_DENY_REGEX:-}" ]; then
  matches=$(grep -RniI -E "$AI_RELAY_PUBLIC_DENY_REGEX" "$STAGE" 2>/dev/null || true)
  if [ -n "$matches" ]; then
    echo "public source deny-pattern scan failed:" >&2
    printf '%s\n' "$matches" >&2
    exit 1
  fi
fi

# Final filename/path safety gate.
unsafe=$(find "$STAGE" -type f | grep -Ei '(^|/)(\.env($|\.)|.*\.(pem|key|p12|pfx|token)$|.*credential(s)?(/|$))' || true)
if [ -n "$unsafe" ]; then
  echo "unsafe credential-like path found in public source:" >&2
  printf '%s\n' "$unsafe" >&2
  exit 1
fi

tar -czf "$TAR_OUT" -C "$STAGE" .
(cd "$STAGE" && zip -q -r "$ZIP_OUT" .)
chmod 0644 "$TAR_OUT" "$ZIP_OUT"

echo "Public source export created:"
echo "  $TAR_OUT"
echo "  $ZIP_OUT"
