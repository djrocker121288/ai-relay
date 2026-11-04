#!/data/data/com.termux/files/usr/bin/sh
set -eu

# Termux is a user-space environment. This launcher never attempts a native
# Android install, root operation, or permission bypass. It stages the arm64
# endpoint package and leaves activation to Termux/Android controls.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
release=${AI_RELAY_SOURCE_DIR:-$here/release}
bootstrap=${AI_RELAY_BOOTSTRAP:-$here/ai-relay-installer}
[ -x "$bootstrap" ] || { echo "Missing Termux bootstrap binary: $bootstrap" >&2; exit 1; }
[ -d "$release" ] || { echo "Missing bundled release directory: $release" >&2; exit 1; }
export AI_RELAY_SOURCE_DIR="$release"
export AI_RELAY_VERSION="${AI_RELAY_VERSION:-2.1.2}"
exec "$bootstrap" --role endpoint "$@"
