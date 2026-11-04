#!/bin/sh
set -eu

GO_BIN="${GO_BIN:-go}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_ID="${ARPL_BUILD_ID:-$(date -u +%Y%m%d-%H%M%S)}"
OUT="$ROOT/dist/arpl-candidate-$BUILD_ID"
mkdir -p "$OUT"

build() {
  os=$1
  arch=$2
  suffix=""
  [ "$os" = windows ] && suffix=.exe
  name="ai-relay-arpl_${BUILD_ID}_${os}_${arch}${suffix}"
  echo "building $name"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 "$GO_BIN" build -buildvcs=false -trimpath -ldflags "-s -w -X main.buildID=$BUILD_ID" -o "$OUT/$name" ./cmd/ai-relay-arpl
}

build_android_arm64() {
  api="${ANDROID_API:-26}"
  ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
  if [ -z "$ndk" ]; then
    sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/android-sdk}}"
    if [ -d "$sdk/ndk" ]; then
      ndk=$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -1)
    fi
  fi
  [ -n "$ndk" ] && [ -d "$ndk" ] || { echo "Android NDK not found" >&2; exit 1; }
  cc=$(find "$ndk/toolchains/llvm/prebuilt" -type f -path "*/bin/aarch64-linux-android${api}-clang" | head -1)
  [ -n "$cc" ] || { echo "Android NDK clang for API $api not found" >&2; exit 1; }
  name="ai-relay-arpl_${BUILD_ID}_android_arm64"
  echo "building $name with NDK/Bionic"
  GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC="$cc" "$GO_BIN" build -buildvcs=false -trimpath -ldflags "-s -w -X main.buildID=$BUILD_ID" -o "$OUT/$name" ./cmd/ai-relay-arpl
}

build linux amd64
build linux arm64
build windows amd64
build windows arm64
build darwin amd64
build darwin arm64
build_android_arm64

(cd "$OUT" && sha256sum * > SHA256SUMS)
echo "candidate=$OUT"
