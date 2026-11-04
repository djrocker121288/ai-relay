#!/bin/sh
set -eu

VERSION="${ARPL_VERSION:-0.2.0}"
SOURCE_DIR="${ARPL_SOURCE_DIR:-}"
BASE_URL="${ARPL_BASE_URL:-}"
PREFIX="${ARPL_PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
ENROLLMENT_PAYLOAD="${ARPL_ENROLLMENT_PAYLOAD:-}"
PEER_NAME="${ARPL_PEER_NAME:-enrolled-peer}"

usage() {
  echo "Usage: install.sh [--source-dir DIR | --base-url URL] [--prefix DIR]"
  echo "Optional: --enrollment-payload PAYLOAD --peer-name NAME"
  echo "Installs ai-relay-arpl, initializes settings, and applies native user configuration."
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-dir) SOURCE_DIR="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; BIN_DIR="$PREFIX/bin"; shift 2 ;;
    --enrollment-payload) ENROLLMENT_PAYLOAD="$2"; shift 2 ;;
    --peer-name) PEER_NAME="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
esac

if [ -n "${ANDROID_ROOT:-}" ] || [ -n "${ANDROID_DATA:-}" ]; then
  os="android"
elif [ "$os" = "darwin" ]; then
  os="darwin"
elif [ "$os" = "linux" ]; then
  os="linux"
else
  echo "Unsupported OS: $os" >&2
  exit 1
fi

if [ "$os" = "android" ] && [ "$arch" != "arm64" ]; then
  echo "Android package currently supports arm64 only." >&2
  exit 1
fi

pkg="ai-relay-arpl_${VERSION}_${os}_${arch}.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

if [ -n "$SOURCE_DIR" ]; then
  cp "$SOURCE_DIR/$pkg" "$tmp/$pkg"
  cp "$SOURCE_DIR/SHA256SUMS" "$tmp/SHA256SUMS"
elif [ -n "$BASE_URL" ]; then
  command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
  curl -fL --retry 3 "$BASE_URL/$pkg" -o "$tmp/$pkg"
  curl -fL --retry 3 "$BASE_URL/SHA256SUMS" -o "$tmp/SHA256SUMS"
else
  here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
  candidate="$here/dist"
  [ -f "$candidate/$pkg" ] || candidate="$here/../../dist/arpl-v$VERSION"
  if [ ! -f "$candidate/$pkg" ]; then
    echo "No package source found. Pass --source-dir or --base-url." >&2
    exit 1
  fi
  cp "$candidate/$pkg" "$tmp/$pkg"
  cp "$candidate/SHA256SUMS" "$tmp/SHA256SUMS"
fi

expected="$(awk -v f="$pkg" '$2==f {print $1}' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || { echo "Package missing from SHA256SUMS" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$pkg" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$pkg" | awk '{print $1}')"
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi
[ "$expected" = "$actual" ] || { echo "SHA-256 verification failed" >&2; exit 1; }

mkdir -p "$tmp/unpack" "$BIN_DIR"
tar -xzf "$tmp/$pkg" -C "$tmp/unpack"
install -m 0755 "$tmp/unpack/ai-relay-arpl" "$BIN_DIR/ai-relay-arpl"
ln -sfn "ai-relay-arpl" "$BIN_DIR/arpl"

key_file="${XDG_CONFIG_HOME:-$HOME/.config}/ai-relay/arpl/identity.json"
if [ ! -f "$key_file" ]; then
  "$BIN_DIR/ai-relay-arpl" key rotate -key-file "$key_file"
fi
settings_file="${XDG_CONFIG_HOME:-$HOME/.config}/ai-relay/arpl/settings.json"
if [ ! -f "$settings_file" ]; then
  "$BIN_DIR/ai-relay-arpl" settings init --file "$settings_file"
fi
if [ -n "$ENROLLMENT_PAYLOAD" ]; then
  "$BIN_DIR/ai-relay-arpl" enroll consume --payload "$ENROLLMENT_PAYLOAD" --settings-file "$settings_file" --name "$PEER_NAME" --key-file "$key_file"
fi
services="$PREFIX/share/ai-relay/arpl"
mkdir -p "$services"
"$BIN_DIR/ai-relay-arpl" settings apply --file "$settings_file" --platform "$os" --output-dir "$services"

echo "Installed: $BIN_DIR/ai-relay-arpl"
echo "Alias:     $BIN_DIR/arpl"
echo "Settings:  $settings_file"
echo "Services:  $services"
echo "Enrollment is required before a client can authenticate; no private key or secret was printed."
"$BIN_DIR/ai-relay-arpl" status -key-file "$key_file"
case ":${PATH:-}:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Add $BIN_DIR to PATH to use 'arpl' from any terminal." ;;
esac
