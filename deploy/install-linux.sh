#!/bin/sh
set -eu
prefix=${AI_RELAY_PREFIX:-/usr/local/bin}
state=${AI_RELAY_STATE:-/var/lib/ai-relay}
install -d -m 700 "$state" /etc/ai-relay
chmod 700 /etc/ai-relay
printf '%s\n' "Create /etc/ai-relay/gateway.env with AI_RELAY_MCP_TOKEN_FILE and AI_RELAY_MCP_ADMIN_TOKEN_FILE, each pointing to 0600 files."
install -m 755 ai-relay-gateway ai-relay-agent "$prefix/"
install -m 644 deploy/systemd/ai-relay-gateway.service deploy/systemd/ai-relay-agent.service /etc/systemd/system/
printf '%s\n' "Installed binaries and units. Create /etc/ai-relay/agent.env (0600), enroll once, then enable units."
printf '%s\n' "Emergency disable: systemctl disable --now ai-relay-agent; touch /etc/ai-relay/disabled"
