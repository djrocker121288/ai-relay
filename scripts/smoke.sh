#!/bin/sh
set -eu
GO=${GO:-go}; tmp=$(mktemp -d); pid=; trap '[ -z "${pid:-}" ] || kill "$pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
printf '%s' smoke >"$tmp/mcp.token"; chmod 600 "$tmp/mcp.token"
printf '%s' smoke-admin >"$tmp/admin.token"; chmod 600 "$tmp/admin.token"
"$GO" build -o "$tmp/ai-relay-gateway" ./cmd/ai-relay-gateway
AI_RELAY_MCP_TOKEN_FILE="$tmp/mcp.token" AI_RELAY_MCP_ADMIN_TOKEN_FILE="$tmp/admin.token" "$tmp/ai-relay-gateway" -listen 127.0.0.1:18743 -state "$tmp/state" >"$tmp/gateway.log" 2>&1 & pid=$!; for i in 1 2 3 4 5 6 7 8 9 10; do
  curl -fsS http://127.0.0.1:18743/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:18743/healthz >/dev/null
curl -fsS http://127.0.0.1:18743/healthz | grep -q '"ok":true'
curl -fsS -H 'Authorization: Bearer smoke' -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' http://127.0.0.1:18743/mcp | grep -q 'devices.list'
echo 'AI Relay local gateway/MCP smoke: PASS'
