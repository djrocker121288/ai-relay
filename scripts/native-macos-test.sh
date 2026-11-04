#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin_dir="$root/dist"
if [ ! -x "$bin_dir/ai-relay-gateway-darwin-amd64" ] && [ ! -x "$bin_dir/ai-relay-gateway-darwin-arm64" ]; then bin_dir="$PWD"; fi
work=${AI_RELAY_NATIVE_TEST_DIR:-"$PWD/ai-relay-macos-native-test"}
mkdir -p "$work"
cd "$work"

arch=$(uname -m)
case "$arch" in
  arm64) suffix=arm64 ;;
  x86_64) suffix=amd64 ;;
  *) echo "unsupported macOS architecture: $arch" >&2; exit 2 ;;
esac

for required in "ai-relay-gateway-darwin-$suffix" "ai-relay-agent-darwin-$suffix"; do
  test -x "$bin_dir/$required" || { echo "missing executable: $bin_dir/$required" >&2; exit 1; }
done

printf '%s' native-macos-test > mcp.token
printf '%s' native-macos-admin > admin.token
chmod 600 mcp.token admin.token
AI_RELAY_MCP_TOKEN_FILE="$PWD/mcp.token" \
AI_RELAY_MCP_ADMIN_TOKEN_FILE="$PWD/admin.token" \
  "$bin_dir/ai-relay-gateway-darwin-$suffix" -listen 127.0.0.1:18743 -state "$PWD/state" >gateway.log 2>&1 &
gateway_pid=$!
agent_pid=
cleanup() { kill "$gateway_pid" ${agent_pid:-} 2>/dev/null || true; }
trap cleanup EXIT INT TERM

for i in 1 2 3 4 5 6 7 8 9 10; do
  curl -fsS http://127.0.0.1:18743/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:18743/healthz >/dev/null
token=$(curl -fsS -X PUT -H 'Authorization: Bearer native-macos-admin' http://127.0.0.1:18743/v1/enroll | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
printf '%s' "$token" > enroll.token
chmod 600 enroll.token
"$bin_dir/ai-relay-agent-darwin-$suffix" -gateway http://127.0.0.1:18743 -credential-file "$PWD/agent.cred" -enroll-token-file "$PWD/enroll.token" >agent.log 2>&1 &
agent_pid=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
  test -s agent.cred && break
  sleep 1
done
test -s agent.cred
test "$(stat -f '%Lp' agent.cred)" = 600
device_id=$(python3 -c 'import json; print(json.load(open("agent.cred"))["device_id"])')
curl -fsS -H 'Authorization: Bearer native-macos-test' -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"agent.exec\",\"arguments\":{\"device_id\":\"$device_id\",\"command\":\"printf\",\"args\":[\"native-macos-ok\\n\"]}}}" \
  http://127.0.0.1:18743/mcp >call.json
job_id=$(python3 -c 'import json; print(json.load(open("call.json"))["result"]["id"])')
completed=false
for i in 1 2 3 4 5 6 7 8 9 10; do
  curl -fsS -H 'Authorization: Bearer native-macos-test' "http://127.0.0.1:18743/v1/jobs/$job_id" >job.json
  if python3 -c 'import json; j=json.load(open("job.json")); assert j["state"]=="completed" and j["exit"]==0 and j["stdout"]=="native-macos-ok\n"' 2>/dev/null; then completed=true; break; fi
  sleep 1
done
$completed || { echo 'durable command did not complete correctly' >&2; exit 1; }

"$bin_dir/ai-relay-agent-darwin-$suffix" -telemetry-status -telemetry-file "$PWD/telemetry.json" >/dev/null
"$bin_dir/ai-relay-agent-darwin-$suffix" -telemetry-off -telemetry-file "$PWD/telemetry.json" >/dev/null
"$bin_dir/ai-relay-agent-darwin-$suffix" -report-preview >/dev/null

if grep -Eiq 'error|fatal|permission denied' gateway.log agent.log; then echo 'startup error found' >&2; exit 1; fi
echo 'native macOS functional gate: PASS'
echo 'Persistence is verified separately; native GUI helpers are not implemented.'
