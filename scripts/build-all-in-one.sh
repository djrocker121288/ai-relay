#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GO_BIN=${GO:-go}
VERSION=${AI_RELAY_VERSION:-${1:-2.0.0}}
DIST=${AI_RELAY_DIST_DIR:-$ROOT/dist}
RELEASE="$DIST/ai-relay-all-in-one-v$VERSION"
if [ -e "$RELEASE" ]; then
  echo "Refusing to overwrite existing release directory: $RELEASE" >&2
  exit 2
fi
command -v "$GO_BIN" >/dev/null 2>&1 || { echo "Go toolchain not found: $GO_BIN" >&2; exit 1; }
command -v zip >/dev/null 2>&1 || { echo "zip is required for Windows artifacts." >&2; exit 1; }
mkdir -p "$DIST"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ai-relay-aio-build.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$RELEASE"

build_target() {
  os=$1; arch=$2
  stage="$tmp/${os}_${arch}"
  mkdir -p "$stage/bin"
  ext=""
  [ "$os" = windows ] && ext=.exe
  echo "building $os/$arch"
  if [ "$os" = android ]; then
    api=${ANDROID_API:-21}
    cc=${ANDROID_CC:-}
    if [ -z "$cc" ] && [ -n "${ANDROID_NDK_HOME:-}" ]; then
      cc="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android${api}-clang"
    fi
    if [ ! -x "$cc" ]; then
      echo "Android ARM64 build requires ANDROID_NDK_HOME or ANDROID_CC (CGO_ENABLED=1 is required for reliable Termux argv/runtime behavior)." >&2
      exit 1
    fi
    cxx="${ANDROID_CXX:-${cc}++}"
    env GOTOOLCHAIN=local CGO_ENABLED=1 GOOS="$os" GOARCH="$arch" CC="$cc" CXX="$cxx" "$GO_BIN" build -buildvcs=false -trimpath -ldflags='-s -w' -o "$stage/bin/ai-relay-arpl$ext" "$ROOT/cmd/ai-relay-arpl"
    env GOTOOLCHAIN=local CGO_ENABLED=1 GOOS="$os" GOARCH="$arch" CC="$cc" CXX="$cxx" "$GO_BIN" build -buildvcs=false -trimpath -ldflags='-s -w' -o "$stage/bin/ai-relay-agent$ext" "$ROOT/cmd/ai-relay-agent"
  else
    env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$GO_BIN" build -buildvcs=false -trimpath -ldflags='-s -w' -o "$stage/bin/ai-relay-arpl$ext" "$ROOT/cmd/ai-relay-arpl"
    env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$GO_BIN" build -buildvcs=false -trimpath -ldflags='-s -w' -o "$stage/bin/ai-relay-agent$ext" "$ROOT/cmd/ai-relay-agent"
  fi
  if [ "$os" != android ]; then
    env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$GO_BIN" build -buildvcs=false -trimpath -ldflags='-s -w' -o "$stage/bin/ai-relay-gateway$ext" "$ROOT/cmd/ai-relay-gateway"
  fi
  cp "$ROOT/packaging/all-in-one/PACKAGE_README.md" "$stage/README-ALL-IN-ONE.md"
  if [ "$os" = windows ]; then
    (cd "$stage" && zip -q -r "$RELEASE/ai-relay-all-in-one_${VERSION}_${os}_${arch}.zip" .)
  else
    (cd "$stage" && tar -czf "$RELEASE/ai-relay-all-in-one_${VERSION}_${os}_${arch}.tar.gz" .)
  fi
}

build_target linux amd64
build_target linux arm64
build_target darwin amd64
build_target darwin arm64
build_target windows amd64
build_target windows arm64
build_target android arm64

cp "$ROOT/packaging/all-in-one/install-unix.sh" "$RELEASE/install-unix.sh"
cp "$ROOT/packaging/all-in-one/install-windows.ps1" "$RELEASE/install-windows.ps1"
cp "$ROOT/docs/ALL_IN_ONE_INSTALLER.md" "$RELEASE/ALL_IN_ONE_INSTALLER.md"
# Release files must remain distributable even when this script is run under a
# restrictive umask.  Installer-created credentials/configuration keep their
# own 0600/0700 policy in the installers and are not affected here.
chmod 0644 "$RELEASE"/ai-relay-all-in-one_* "$RELEASE/install-windows.ps1" "$RELEASE/ALL_IN_ONE_INSTALLER.md"
chmod 0755 "$RELEASE/install-unix.sh"
(cd "$RELEASE" && sha256sum ai-relay-all-in-one_* install-unix.sh install-windows.ps1 ALL_IN_ONE_INSTALLER.md > SHA256SUMS)
chmod 0644 "$RELEASE/SHA256SUMS"
echo "Built all-in-one release: $RELEASE"
cat "$RELEASE/SHA256SUMS"
