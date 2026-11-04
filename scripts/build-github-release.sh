#!/bin/sh
set -eu

# Build a new, immutable public release directory. The existing all-in-one
# builder remains responsible for the tested platform archives; this script
# adds the cross-platform bootstrap and OS-native one-click wrappers.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=$(printenv GO 2>/dev/null || true)
[ -n "$GO_BIN" ] || GO_BIN=go
VERSION=$(printenv AI_RELAY_VERSION 2>/dev/null || true)
if [ -z "$VERSION" ]; then
  if [ "$#" -gt 0 ]; then VERSION=$1; else VERSION=2.1.2; fi
fi
DIST=$(printenv AI_RELAY_DIST_DIR 2>/dev/null || true)
[ -n "$DIST" ] || DIST=$ROOT/dist
RELEASE="$DIST/ai-relay-all-in-one-v$VERSION"

case "$VERSION" in
  *[!0-9A-Za-z.-]*) echo "Invalid release version: $VERSION" >&2; exit 2 ;;
esac
[ ! -e "$RELEASE" ] || { echo "Refusing to overwrite existing release directory: $RELEASE" >&2; exit 2; }
command -v "$GO_BIN" >/dev/null 2>&1 || { echo "Go toolchain not found: $GO_BIN" >&2; exit 1; }
command -v zip >/dev/null 2>&1 || { echo "zip is required for release bundles." >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required for release bundles." >&2; exit 1; }
command -v unzip >/dev/null 2>&1 || { echo "unzip is required for archive inspection." >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  hash_file() { sha256sum "$1"; }
else
  command -v shasum >/dev/null 2>&1 || { echo "sha256sum or shasum is required." >&2; exit 1; }
  hash_file() { shasum -a 256 "$1"; }
fi

TMPBASE=$(printenv TMPDIR 2>/dev/null || true)
[ -n "$TMPBASE" ] || TMPBASE=/tmp
tmp=$(mktemp -d "$TMPBASE/ai-relay-github-release.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

AI_RELAY_VERSION="$VERSION" AI_RELAY_DIST_DIR="$DIST" "$ROOT/scripts/build-all-in-one.sh"

build_bootstrap() {
  os=$1
  arch=$2
  output=$3
  echo "building installer bootstrap $os/$arch"
  env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$GO_BIN" build     -buildvcs=false -trimpath -ldflags="-s -w -X main.version=$VERSION"     -o "$output" "$ROOT/cmd/ai-relay-installer"
}

build_bootstrap linux amd64 "$RELEASE/ai-relay-installer_linux_amd64"
build_bootstrap linux arm64 "$RELEASE/ai-relay-installer_linux_arm64"
build_bootstrap darwin amd64 "$tmp/ai-relay-installer_darwin_amd64"
build_bootstrap darwin arm64 "$tmp/ai-relay-installer_darwin_arm64"
build_bootstrap windows amd64 "$RELEASE/AI-Relay-ARPL-Setup_windows_amd64.exe"
build_bootstrap windows arm64 "$RELEASE/AI-Relay-ARPL-Setup_windows_arm64.exe"

make_private_sums() {
  directory=$1
  output=$2
  (
    cd "$directory"
    find . -maxdepth 1 -type f ! -name "$(basename "$output")" -printf '%f\n' 2>/dev/null ||
      find . -maxdepth 1 -type f ! -name "$(basename "$output")" -exec basename {} \;
  ) | sort | while IFS= read -r file; do
    (cd "$directory" && hash_file "$file")
  done >"$output"
}

make_windows_bundle() {
  arch=$1
  exe="$RELEASE/AI-Relay-ARPL-Setup_windows_"$arch".exe"
  package="ai-relay-all-in-one_"$VERSION"_windows_"$arch".zip"
  stage="$tmp/windows-bundle-"$arch
  mkdir -p "$stage"
  cp "$exe" "$stage/AI-Relay-ARPL-Setup.exe"
  cp "$RELEASE/install-windows.ps1" "$stage/install-windows.ps1"
  cp "$RELEASE/$package" "$stage/$package"
  hash_file "$stage/$package" | sed "s#  $stage/#  #" >"$stage/SHA256SUMS"
  chmod 0644 "$stage/AI-Relay-ARPL-Setup.exe" "$stage/install-windows.ps1" "$stage/$package" "$stage/SHA256SUMS"
  (cd "$stage" && zip -q -r "$RELEASE/AI-Relay-ARPL-Setup_"$VERSION"_windows_"$arch".zip" .)
}

make_windows_bundle amd64
make_windows_bundle arm64

make_mac_app() {
  arch=$1
  bootstrap=$2
  package="ai-relay-all-in-one_"$VERSION"_darwin_"$arch".tar.gz"
  stage="$tmp/mac-app-$arch"
  app="$stage/AI-Relay-ARPL-Setup.app"
  resources="$app/Contents/Resources"
  rm -rf "$stage"
  mkdir -p "$app/Contents/MacOS" "$resources"
  cp "$ROOT/packaging/one-click/macos-app-launcher.sh" "$app/Contents/MacOS/AI Relay ARPL Setup"
  cp "$bootstrap" "$resources/ai-relay-installer"
  cp "$RELEASE/install-unix.sh" "$resources/install-unix.sh"
  cp "$RELEASE/$package" "$resources/$package"
  hash_file "$resources/$package" | sed "s#  $resources/#  #" >"$resources/SHA256SUMS"
  cat >"$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><string>AI Relay ARPL Setup</string>
<key>CFBundleExecutable</key><string>AI Relay ARPL Setup</string>
<key>CFBundleIdentifier</key><string>com.ai-relay.arpl.setup</string>
<key>CFBundleName</key><string>AI Relay ARPL Setup</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundleVersion</key><string>$VERSION</string>
</dict></plist>
EOF
  chmod 0755 "$app/Contents/MacOS/AI Relay ARPL Setup" "$resources/ai-relay-installer"
  chmod 0644 "$app/Contents/Info.plist" "$resources/install-unix.sh" "$resources/$package" "$resources/SHA256SUMS"
  (cd "$stage" && zip -q -r "$RELEASE/AI-Relay-ARPL-Setup_"$VERSION"_darwin_"$arch".app.zip" "$(basename "$app")")
  if command -v pkgbuild >/dev/null 2>&1; then
    pkgbuild --root "$app" --identifier com.ai-relay.arpl.setup --version "$VERSION"       --install-location "/Applications/AI-Relay-ARPL-Setup.app"       "$RELEASE/AI-Relay-ARPL-Setup_"$VERSION"_darwin_"$arch".pkg" >/dev/null
  fi
  if command -v hdiutil >/dev/null 2>&1; then
    hdiutil create -quiet -volname "AI Relay ARPL Setup" -srcfolder "$app" -format UDZO       -ov "$RELEASE/AI-Relay-ARPL-Setup_"$VERSION"_darwin_"$arch".dmg"
  fi
}

make_mac_app amd64 "$tmp/ai-relay-installer_darwin_amd64"
make_mac_app arm64 "$tmp/ai-relay-installer_darwin_arm64"

make_linux_run() {
  arch=$1
  bootstrap="$RELEASE/ai-relay-installer_linux_"$arch
  package="ai-relay-all-in-one_"$VERSION"_linux_"$arch".tar.gz"
  stage="$tmp/linux-run-"$arch
  mkdir -p "$stage/release"
  cp "$bootstrap" "$stage/ai-relay-installer"
  cp "$RELEASE/install-unix.sh" "$stage/release/install-unix.sh"
  cp "$RELEASE/$package" "$stage/release/$package"
  hash_file "$stage/release/$package" | sed "s#  $stage/release/#  #" >"$stage/release/SHA256SUMS"
  run="$RELEASE/AI-Relay-ARPL-Setup_"$VERSION"_linux_"$arch".run"
  cp "$ROOT/packaging/one-click/linux-installer.run.sh" "$run"
  (cd "$stage" && tar -czf - ai-relay-installer release) >>"$run"
  chmod 0755 "$run"
}

make_linux_run amd64
make_linux_run arm64

make_termux_bundle() {
  stage="$tmp/termux-bundle"
  package="ai-relay-all-in-one_"$VERSION"_android_arm64.tar.gz"
  mkdir -p "$stage/release"
  cp "$RELEASE/ai-relay-installer_linux_arm64" "$stage/ai-relay-installer"
  cp "$ROOT/packaging/one-click/termux-bootstrap.sh" "$stage/AI-Relay-ARPL-Termux-Bootstrap.sh"
  cp "$RELEASE/install-unix.sh" "$stage/release/install-unix.sh"
  cp "$RELEASE/$package" "$stage/release/$package"
  hash_file "$stage/release/$package" | sed "s#  $stage/release/#  #" >"$stage/release/SHA256SUMS"
  chmod 0755 "$stage/ai-relay-installer" "$stage/AI-Relay-ARPL-Termux-Bootstrap.sh"
  chmod 0644 "$stage/release/install-unix.sh" "$stage/release/$package" "$stage/release/SHA256SUMS"
  (cd "$stage" && zip -q -r "$RELEASE/AI-Relay-ARPL-Termux-Bootstrap_"$VERSION"_android_arm64.zip" .)
  cp "$ROOT/packaging/one-click/termux-bootstrap.sh" "$RELEASE/AI-Relay-ARPL-Termux-Bootstrap.sh"
  chmod 0755 "$RELEASE/AI-Relay-ARPL-Termux-Bootstrap.sh"
}

make_termux_bundle
cp "$ROOT/packaging/one-click/AI-Relay-ARPL-Setup.desktop" "$RELEASE/AI-Relay-ARPL-Setup.desktop"
chmod 0644 "$RELEASE/AI-Relay-ARPL-Setup.desktop"

make_source_archives() {
  "$ROOT/scripts/export-public-source.sh" "$VERSION" "$RELEASE"
}

make_source_archives

# An optional Android companion APK is built only when the native Android
# toolchain is already present. No download, signing, or permission bypass is
# attempted by this release script.
if command -v gradle >/dev/null 2>&1 && command -v java >/dev/null 2>&1; then
  android_out="$tmp/android-companion"
  if "$ROOT/scripts/build-android-companion.sh" "$VERSION" "$android_out"; then
    apk=$(find "$android_out" -maxdepth 1 -type f -name '*.apk' -print -quit 2>/dev/null || true)
    if [ -n "$apk" ]; then
      cp "$apk" "$RELEASE/AI-Relay-ARPL-Companion_"$VERSION"_android_arm64_debug.apk"
    fi
  else
    echo "Android companion APK build did not complete; Termux bootstrap remains available." >&2
  fi
else
  echo "Android companion APK gate: gradle/java unavailable; Termux bootstrap remains available."
fi

# Normalize release permissions. The release checksum file is recreated last
# so every artifact, including optional native outputs, is covered.
find "$RELEASE" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' -o -name '*.pkg' -o -name '*.dmg' -o -name '*.apk' -o -name '*.md' -o -name '*.plist' -o -name '*.ps1' -o -name '*.desktop' -o -name '*.exe' \) -exec chmod 0644 {} \;
find "$RELEASE" -maxdepth 1 -type f \( -name 'ai-relay-installer_*' -o -name '*.run' -o -name '*.sh' \) -exec chmod 0755 {} \;
chmod 0755 "$RELEASE/ai-relay-installer_linux_amd64" "$RELEASE/ai-relay-installer_linux_arm64"
make_private_sums "$RELEASE" "$RELEASE/SHA256SUMS"
chmod 0644 "$RELEASE/SHA256SUMS"

# Fail closed on runtime, traversal, and obvious secret paths in every archive.
for archive in "$RELEASE"/*.tar.gz "$RELEASE"/*.zip; do
  [ -f "$archive" ] || continue
  "$ROOT/scripts/verify-release-boundary.sh" "$archive"
done

echo "Built GitHub release candidate: $RELEASE"
cat "$RELEASE/SHA256SUMS"
