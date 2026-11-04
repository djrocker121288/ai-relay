#!/bin/sh
set -eu

VERSION="${ARPL_VERSION:-0.1.0}"
TAP="${ARPL_BREW_TAP:-ai-relay/local}"
command -v brew >/dev/null 2>&1 || { echo "Homebrew is required." >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "Go is required for the native macOS ARPL build." >&2; exit 1; }

here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
src="${1:-$here/../../dist/arpl-v$VERSION/ai-relay-arpl_${VERSION}_source.tar.gz}"
[ -f "$src" ] || { echo "Source bundle not found: $src" >&2; exit 1; }

case "$(uname -s)/$(uname -m)" in
  Darwin/arm64|Darwin/x86_64) ;;
  *) echo "This Homebrew installer is for macOS." >&2; exit 1 ;;
esac

if ! brew tap | grep -qx "$TAP"; then
  HOMEBREW_NO_AUTO_UPDATE=1 brew tap-new "$TAP" >/dev/null
fi

taprepo="$(brew --repository "$TAP")"
[ -n "$taprepo" ] && [ -d "$taprepo" ] || { echo "Unable to resolve Homebrew tap $TAP" >&2; exit 1; }
mkdir -p "$taprepo/Casks" "$taprepo/Artifacts"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/arpl-native.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
tar -xzf "$src" -C "$tmp"
root="$tmp/ai-relay-arpl-$VERSION"
[ -d "$root" ] || { echo "Invalid ARPL source bundle." >&2; exit 1; }

artifact="$taprepo/Artifacts/ai-relay-arpl-native"
(
  cd "$root"
  go build -buildvcs=false -trimpath -o "$artifact" ./cmd/ai-relay-arpl
)
chmod 0755 "$artifact"

if command -v sha256sum >/dev/null 2>&1; then
  sum="$(sha256sum "$artifact" | awk '{print $1}')"
else
  sum="$(shasum -a 256 "$artifact" | awk '{print $1}')"
fi

cat > "$taprepo/Casks/ai-relay-arpl.rb" <<RUBY
cask "ai-relay-arpl" do
  version "$VERSION"
  sha256 "$sum"
  url "file://$artifact"
  name "AI Relay ARPL"
  desc "AI Relay Persistent Link encrypted cross-platform transport"
  homepage "https://github.com/ai-relay/ai-relay"
  binary "ai-relay-arpl-native", target: "ai-relay-arpl"
  binary "ai-relay-arpl-native", target: "arpl"
end
RUBY

HOMEBREW_NO_AUTO_UPDATE=1 brew uninstall --cask "$TAP/ai-relay-arpl" >/dev/null 2>&1 || true
HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 brew install --cask "$TAP/ai-relay-arpl"

binpath="$(brew --caskroom ai-relay-arpl)/$VERSION/ai-relay-arpl-native"
xattr -d com.apple.quarantine "$binpath" >/dev/null 2>&1 || true

key_file="$HOME/Library/Application Support/ai-relay/arpl/identity.json"
legacy_key="${XDG_CONFIG_HOME:-$HOME/.config}/ai-relay/arpl/identity.json"
mkdir -p "$(dirname "$key_file")"
if [ ! -f "$key_file" ]; then
  if [ -f "$legacy_key" ]; then
    cp "$legacy_key" "$key_file"
    chmod 0600 "$key_file"
  else
    arpl key rotate -key-file "$key_file"
  fi
fi

echo "Homebrew installed $TAP/ai-relay-arpl. Use: arpl"
arpl status
