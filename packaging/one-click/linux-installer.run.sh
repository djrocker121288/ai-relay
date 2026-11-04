#!/bin/sh
set -eu

# This file is a template. The release builder appends a gzip-compressed tar
# payload after the marker below. It contains the Linux bootstrap, installer,
# checksum file, and matching platform archive.
self=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")
marker=$(awk '/^__AI_RELAY_PAYLOAD_BELOW__$/ { print NR; exit }' "$self")
[ -n "$marker" ] || { echo 'AI Relay self-extracting payload marker is missing.' >&2; exit 1; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ai-relay-setup.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
tail -n +$((marker + 1)) "$self" | tar -xzf - -C "$tmp"
export AI_RELAY_SOURCE_DIR="$tmp/release"
exec "$tmp/ai-relay-installer" "$@"

__AI_RELAY_PAYLOAD_BELOW__
