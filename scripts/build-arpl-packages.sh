#!/bin/sh
set -eu
VERSION="${1:-0.2.0}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
GO="${GO:-$HOME/bin/go}"
OUT="$ROOT/dist/arpl-v$VERSION"
STAGE="$OUT/.stage"
rm -rf "$OUT"
mkdir -p "$OUT" "$STAGE"

build_unix() {
  os="$1"; arch="$2"
  dir="$STAGE/${os}_${arch}"
  mkdir -p "$dir"
  env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$GO" build -buildvcs=false -trimpath -ldflags="-s -w" -o "$dir/ai-relay-arpl" "$ROOT/cmd/ai-relay-arpl"
  cp "$ROOT/docs/ARPL.md" "$dir/README-ARPL.md"
  (cd "$dir" && tar -czf "$OUT/ai-relay-arpl_${VERSION}_${os}_${arch}.tar.gz" ai-relay-arpl README-ARPL.md)
}

build_windows() {
  arch="$1"
  dir="$STAGE/windows_${arch}"
  mkdir -p "$dir"
  env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=windows GOARCH="$arch" "$GO" build -buildvcs=false -trimpath -ldflags="-s -w" -o "$dir/ai-relay-arpl.exe" "$ROOT/cmd/ai-relay-arpl"
  cp "$ROOT/docs/ARPL.md" "$dir/README-ARPL.md"
  (cd "$dir" && zip -q "$OUT/ai-relay-arpl_${VERSION}_windows_${arch}.zip" ai-relay-arpl.exe README-ARPL.md)
}

build_unix linux amd64
build_unix linux arm64
build_windows amd64
build_windows arm64
build_unix android arm64

src="$STAGE/source/ai-relay-arpl-$VERSION"
mkdir -p "$src/cmd" "$src/internal" "$src/docs"
cp "$ROOT/go.mod" "$src/go.mod"
[ -f "$ROOT/go.sum" ] && cp "$ROOT/go.sum" "$src/go.sum" || true
cp -R "$ROOT/cmd/ai-relay-arpl" "$src/cmd/"
cp -R "$ROOT/internal/arpl" "$src/internal/"
cp "$ROOT/docs/ARPL.md" "$src/docs/"
(cd "$STAGE/source" && tar -czf "$OUT/ai-relay-arpl_${VERSION}_source.tar.gz" "ai-relay-arpl-$VERSION")

cp "$ROOT/packaging/arpl/install.sh" "$OUT/install.sh"
cp "$ROOT/packaging/arpl/install.ps1" "$OUT/install.ps1"
cp "$ROOT/packaging/arpl/install-linux.sh" "$OUT/install-linux.sh"
cp "$ROOT/packaging/arpl/install-macos.sh" "$OUT/install-macos.sh"
cp "$ROOT/packaging/arpl/install-termux.sh" "$OUT/install-termux.sh"
cp "$ROOT/packaging/homebrew/install-homebrew.sh" "$OUT/install-homebrew.sh"
chmod +x "$OUT/install.sh" "$OUT/install-linux.sh" "$OUT/install-macos.sh" "$OUT/install-termux.sh" "$OUT/install-homebrew.sh"

(
  cd "$OUT"
  rm -f SHA256SUMS
  for f in ai-relay-arpl_* install.sh install.ps1 install-linux.sh install-macos.sh install-termux.sh install-homebrew.sh; do
    [ -f "$f" ] && sha256sum "$f"
  done > SHA256SUMS
)
rm -rf "$STAGE"
echo "Built ARPL release bundle: $OUT"
cat "$OUT/SHA256SUMS"
