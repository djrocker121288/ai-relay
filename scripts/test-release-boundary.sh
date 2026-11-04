#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CHECKER=$ROOT/scripts/verify-release-boundary.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ai-relay-release-boundary-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

mkdir -p "$tmp/safe/bin" "$tmp/unsafe-tar/.cache" "$tmp/unsafe-zip/credentials"
printf '%s\n' 'safe' >"$tmp/safe/bin/relay"
printf '%s\n' 'cache' >"$tmp/unsafe-tar/.cache/index"
printf '%s\n' 'secret' >"$tmp/unsafe-zip/credentials/access.token"

(cd "$tmp/safe" && tar -czf "$tmp/safe archive.tar.gz" .)
(cd "$tmp/unsafe-tar" && tar -czf "$tmp/unsafe.tar.gz" .)
(cd "$tmp/unsafe-zip" && zip -q -r "$tmp/unsafe.zip" .)

"$CHECKER" "$tmp/safe archive.tar.gz"
if "$CHECKER" "$tmp/unsafe.tar.gz" >/dev/null 2>&1; then
  echo "checker accepted unsafe TAR path" >&2
  exit 1
fi
if "$CHECKER" "$tmp/unsafe.zip" >/dev/null 2>&1; then
  echo "checker accepted unsafe ZIP path" >&2
  exit 1
fi

printf '%s\n' 'Release boundary tests passed (safe TAR; unsafe TAR and ZIP rejected).'
