#!/bin/sh
set -eu
GO=${GO:-go}; out=${1:-dist}; mkdir -p "$out"
for spec in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do os=${spec%/*}; arch=${spec#*/}; ext=; [ "$os" = windows ] && ext=.exe; GOOS=$os GOARCH=$arch "$GO" build -trimpath -ldflags='-s -w' -o "$out/ai-relay-gateway-$os-$arch$ext" ./cmd/ai-relay-gateway; GOOS=$os GOARCH=$arch "$GO" build -trimpath -ldflags='-s -w' -o "$out/ai-relay-agent-$os-$arch$ext" ./cmd/ai-relay-agent; done
