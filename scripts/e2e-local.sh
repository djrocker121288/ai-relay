#!/bin/sh
set -eu
T=$(mktemp -d)
AGENT=
GO=${GO:-go}
printf '%s' local-test >"$T/mcp.token"; chmod 600 "$T/mcp.token"
printf '%s' local-admin >"$T/admin.token"; chmod 600 "$T/admin.token"
"$GO" build -o "$T/ai-relay-gateway" ./cmd/ai-relay-gateway
"$GO" build -o "$T/ai-relay-agent" ./cmd/ai-relay-agent
AI_RELAY_MCP_TOKEN_FILE="$T/mcp.token" AI_RELAY_MCP_ADMIN_TOKEN_FILE="$T/admin.token" "$T/ai-relay-gateway" -listen 127.0.0.1:18744 -state "$T/state" >"$T/gw.log" 2>&1 & GW=$!
trap 'kill "$GW" ${AGENT:-} 2>/dev/null || true; rm -rf "$T"' EXIT
for i in 1 2 3 4 5 6 7 8 9 10; do
  curl -fsS http://127.0.0.1:18744/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:18744/healthz >/dev/null
TOKEN=$(curl -fsS -X PUT -H "Authorization: Bearer local-admin" http://127.0.0.1:18744/v1/enroll | jq -r .token)
printf '%s' "$TOKEN" >"$T/enroll.token"; chmod 600 "$T/enroll.token"
"$T/ai-relay-agent" -gateway http://127.0.0.1:18744 -credential-file "$T/agent.cred" -enroll-token-file "$T/enroll.token" >"$T/agent.log" 2>&1 & AGENT=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -s "$T/agent.cred" ] && break; sleep 1; done
ID=$(jq -r .device_id "$T/agent.cred")
curl -fsS -H 'Authorization: Bearer local-test' -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"agent.exec\",\"arguments\":{\"device_id\":\"$ID\",\"command\":\"printf\",\"args\":[\"ai-relay-e2e\\n\"]}}}" http://127.0.0.1:18744/mcp >"$T/call.json"
JOB=$(jq -r '.result.id' "$T/call.json")
for i in 1 2 3 4 5 6 7 8 9 10; do
  J=$(curl -fsS -H 'Authorization: Bearer local-test' http://127.0.0.1:18744/v1/jobs/$JOB)
  if printf '%s' "$J" | jq -e '.state == "completed"' >/dev/null; then printf '%s\n' "$J"; exit 0; fi
  sleep 1
done
sed -n '1,120p' "$T/gw.log"; sed -n '1,120p' "$T/agent.log"; exit 1
