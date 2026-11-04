#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=${1:-${AI_RELAY_VERSION:-2.1.2}}
OUT_DIR=${2:-"$ROOT/dist/android-companion-v$VERSION"}
APP="$ROOT/deploy/android"
JNI_DIR="$APP/app/build/generated/jniLibs/arm64-v8a"

GO_BIN=${GO_BIN:-$(command -v go || true)}
[ -n "$GO_BIN" ] || { echo "go is required" >&2; exit 2; }

GRADLE_BIN=${GRADLE_BIN:-}
if [ -z "$GRADLE_BIN" ]; then
  if [ -x "$APP/gradlew" ]; then
    GRADLE_BIN="$APP/gradlew"
  else
    GRADLE_BIN=$(command -v gradle || true)
  fi
fi
[ -n "$GRADLE_BIN" ] || { echo "Gradle is required to build the Android companion APK" >&2; exit 2; }
command -v java >/dev/null 2>&1 || { echo "Java 17+ is required to build the Android companion APK" >&2; exit 2; }

rm -rf "$JNI_DIR"
mkdir -p "$JNI_DIR" "$OUT_DIR"

build_native() {
  command=$1
  output=$2
  env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=android GOARCH=arm64     "$GO_BIN" build -buildvcs=false -trimpath -ldflags='-s -w' -o "$output" "$ROOT/cmd/$command"
  chmod 0755 "$output"
}

build_native ai-relay-arpl "$JNI_DIR/libai_relay_arpl.so"
build_native ai-relay-agent "$JNI_DIR/libai_relay_agent.so"

if command -v file >/dev/null 2>&1; then
  file "$JNI_DIR/libai_relay_arpl.so" "$JNI_DIR/libai_relay_agent.so"
fi

if [ -x "$APP/gradlew" ] && [ "$GRADLE_BIN" = "$APP/gradlew" ]; then
  "$GRADLE_BIN" -p "$APP" :app:assembleDebug -PaiRelayVersion="$VERSION"
else
  "$GRADLE_BIN" -p "$APP" :app:assembleDebug -PaiRelayVersion="$VERSION"
fi

APK=$(find "$APP/app/build/outputs/apk/debug" -maxdepth 1 -type f -name '*.apk' -print -quit 2>/dev/null || true)
[ -n "$APK" ] && [ -f "$APK" ] || { echo "Android APK was not produced" >&2; exit 1; }

DEST="$OUT_DIR/AI-Relay-ARPL-Companion_${VERSION}_android_arm64_debug.apk"
cp "$APK" "$DEST"
chmod 0644 "$DEST"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$OUT_DIR" && sha256sum "$(basename "$DEST")" > SHA256SUMS)
else
  (cd "$OUT_DIR" && shasum -a 256 "$(basename "$DEST")" > SHA256SUMS)
fi
chmod 0644 "$OUT_DIR/SHA256SUMS"

echo "Built Android companion: $DEST"
cat "$OUT_DIR/SHA256SUMS"
