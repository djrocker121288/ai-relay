#!/bin/sh
set -eu

# AI Relay + ARPL all-in-one installer.  This is deliberately a staging-first
# installer: activation is opt-in, and an unconfigured agent is never called
# connected.

VERSION="${AI_RELAY_VERSION:-2.0.0}"
SOURCE_DIR="${AI_RELAY_SOURCE_DIR:-}"
BASE_URL="${AI_RELAY_BASE_URL:-}"
PREFIX="${AI_RELAY_PREFIX:-$HOME/.local/ai-relay}"
CONFIG_DIR="${AI_RELAY_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/ai-relay}"
STATE_DIR="${AI_RELAY_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/ai-relay}"
ROLE="${AI_RELAY_ROLE:-endpoint}"
GATEWAY="${AI_RELAY_GATEWAY:-http://127.0.0.1:8743}"
CREDENTIAL_FILE="${AI_RELAY_CREDENTIAL_FILE:-}"
ENROLL_TOKEN_FILE="${AI_RELAY_ENROLL_TOKEN_FILE:-}"
ARPL_ENROLLMENT_PAYLOAD_FILE="${ARPL_ENROLLMENT_PAYLOAD_FILE:-}"
PEER_NAME="${AI_RELAY_PEER_NAME:-enrolled-peer}"
ACTIVATE="${AI_RELAY_ACTIVATE:-0}"
ACTION="install"
gateway_explicit=0

usage() {
  cat <<'EOF'
Usage: install-unix.sh [options]

Stages one AI Relay + ARPL package on Linux, macOS, or Android/Termux.
Options:
  --source-dir DIR       local release directory (default: script directory)
  --base-url URL         release URL instead of a local directory
  --version VERSION      release version (default: 2.0.0)
  --role endpoint|full   endpoint installs agent+ARPL; full/server also stages gateway
  --prefix DIR           installed binaries and generated service scaffolding
  --config-dir DIR       AI Relay config directory; must end in /ai-relay
  --state-dir DIR        gateway/runtime state directory
  --gateway URL          agent gateway URL (HTTPS required for remote gateways)
  --credential-file FILE existing protected AI Relay credential to copy
  --enroll-token-file FILE one-use token file; requires --gateway
  --enrollment-payload-file FILE optional ARPL enrollment payload file
  --peer-name NAME       optional ARPL enrollment peer name
  --activate             opt in to native persistence activation
  --status | --doctor    inspect the staged installation
  --repair               rerender ARPL persistence scaffolding
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-dir) SOURCE_DIR="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --role) ROLE="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --config-dir) CONFIG_DIR="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --gateway) GATEWAY="$2"; gateway_explicit=1; shift 2 ;;
    --credential-file) CREDENTIAL_FILE="$2"; shift 2 ;;
    --enroll-token-file) ENROLL_TOKEN_FILE="$2"; shift 2 ;;
    --enrollment-payload-file) ARPL_ENROLLMENT_PAYLOAD_FILE="$2"; shift 2 ;;
    --peer-name) PEER_NAME="$2"; shift 2 ;;
    --activate) ACTIVATE=1; shift ;;
    --status) ACTION=status; shift ;;
    --doctor) ACTION=doctor; shift ;;
    --repair) ACTION=repair; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$ROLE" in
  endpoint|full|server) [ "$ROLE" = server ] && ROLE=full ;;
  *) echo "Role must be endpoint, full, or server." >&2; exit 2 ;;
esac

os_name=$(uname -s | tr '[:upper:]' '[:lower:]')
arch_name=$(uname -m)
case "$arch_name" in
  x86_64|amd64) arch_name=amd64 ;;
  arm64|aarch64) arch_name=arm64 ;;
  *) echo "Unsupported architecture: $arch_name" >&2; exit 1 ;;
esac
if [ -n "${ANDROID_ROOT:-}" ] || [ -n "${ANDROID_DATA:-}" ] || [ -n "${TERMUX_VERSION:-}" ]; then
  os_name=android
elif [ "$os_name" = darwin ]; then
  os_name=darwin
elif [ "$os_name" = linux ]; then
  os_name=linux
else
  echo "Unsupported OS: $os_name" >&2
  exit 1
fi
if [ "$os_name" = android ] && [ "$arch_name" != arm64 ]; then
  echo "Android/Termux all-in-one package supports arm64 only." >&2
  exit 1
fi
if [ "$os_name" = android ] && [ "$ROLE" = full ]; then
  echo "The Android/Termux package intentionally omits the gateway; use role endpoint." >&2
  exit 2
fi

BIN_DIR="$PREFIX/bin"
ARPL_DIR="$CONFIG_DIR/arpl"
SERVICES_DIR="$PREFIX/share/ai-relay/arpl"
ARPL="$BIN_DIR/ai-relay-arpl"
AGENT="$BIN_DIR/ai-relay-agent"
GATEWAY_BIN="$BIN_DIR/ai-relay-gateway"
TARGET_CREDENTIAL="$CONFIG_DIR/agent.cred"
SETTINGS="$ARPL_DIR/settings.json"
IDENTITY="$ARPL_DIR/identity.json"

report_status() {
  echo "AI Relay + ARPL all-in-one status"
  echo "platform: $os_name/$arch_name"
  echo "prefix: $PREFIX"
  echo "config: $CONFIG_DIR"
  if [ -x "$AGENT" ]; then echo "agent: staged"; else echo "agent: missing"; fi
  if [ -f "$TARGET_CREDENTIAL" ]; then
    echo "agent enrollment: credential configured; connectivity not tested"
  else
    echo "agent enrollment: ENROLLMENT REQUIRED (staged; agent is not connected)"
  fi
  if [ "$ROLE" = full ] && [ -x "$GATEWAY_BIN" ]; then
    echo "gateway: staged; loopback activation is operator-controlled"
  else
    echo "gateway: not installed for endpoint role"
  fi
  if [ -x "$ARPL" ] && [ -f "$SETTINGS" ]; then
    "$ARPL" status -key-file "$IDENTITY" 2>/dev/null || true
  else
    echo "ARPL: not initialized"
  fi
}

if [ "$ACTION" = status ] || [ "$ACTION" = doctor ]; then
  report_status
  if [ "$ACTION" = doctor ] && [ -x "$ARPL" ] && [ -f "$SETTINGS" ]; then
    "$ARPL" doctor --settings-file "$SETTINGS" || true
  fi
  exit 0
fi

case "$CONFIG_DIR" in
  */ai-relay) ;;
  *) echo "--config-dir must name an ai-relay directory (for example /tmp/home/.config/ai-relay)." >&2; exit 2 ;;
esac

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -z "$SOURCE_DIR" ]; then SOURCE_DIR="$here"; fi
pkg="ai-relay-all-in-one_${VERSION}_${os_name}_${arch_name}"
case "$os_name" in windows) pkg="$pkg.zip" ;; *) pkg="$pkg.tar.gz" ;; esac
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ai-relay-aio.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

if [ -n "$BASE_URL" ]; then
  command -v curl >/dev/null 2>&1 || { echo "curl is required for --base-url." >&2; exit 1; }
  curl -fsSL --retry 3 "$BASE_URL/$pkg" -o "$tmp/$pkg"
  curl -fsSL --retry 3 "$BASE_URL/SHA256SUMS" -o "$tmp/SHA256SUMS"
else
  [ -f "$SOURCE_DIR/$pkg" ] || { echo "Package not found: $SOURCE_DIR/$pkg" >&2; exit 1; }
  [ -f "$SOURCE_DIR/SHA256SUMS" ] || { echo "SHA256SUMS not found in $SOURCE_DIR" >&2; exit 1; }
  cp "$SOURCE_DIR/$pkg" "$tmp/$pkg"
  cp "$SOURCE_DIR/SHA256SUMS" "$tmp/SHA256SUMS"
fi
expected=$(awk -v f="$pkg" '$2 == f { print $1; exit }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || { echo "Release checksum missing for $pkg" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$pkg" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$pkg" | awk '{print $1}')
else
  echo "sha256sum or shasum is required for release verification." >&2
  exit 1
fi
[ "$expected" = "$actual" ] || { echo "SHA-256 verification failed for $pkg" >&2; exit 1; }

mkdir -p "$tmp/unpack"
case "$pkg" in
  *.tar.gz) tar -xzf "$tmp/$pkg" -C "$tmp/unpack" ;;
  *) echo "Unexpected Unix package format: $pkg" >&2; exit 1 ;;
esac
stage="$tmp/unpack"
for required in ai-relay-arpl ai-relay-agent; do
  [ -f "$stage/bin/$required" ] || { echo "Package is missing $required" >&2; exit 1; }
done
if [ "$ROLE" = full ]; then
  [ -f "$stage/bin/ai-relay-gateway" ] || { echo "Package is missing gateway" >&2; exit 1; }
fi

umask 077
mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$ARPL_DIR" "$STATE_DIR" "$SERVICES_DIR"
cp "$stage/bin/ai-relay-arpl" "$ARPL"; chmod 0755 "$ARPL"
cp "$stage/bin/ai-relay-agent" "$AGENT"; chmod 0755 "$AGENT"
if [ "$ROLE" = full ]; then cp "$stage/bin/ai-relay-gateway" "$GATEWAY_BIN"; chmod 0755 "$GATEWAY_BIN"; fi

if [ -n "$CREDENTIAL_FILE" ]; then
  [ -f "$CREDENTIAL_FILE" ] && [ ! -L "$CREDENTIAL_FILE" ] || { echo "Credential must be a regular, non-symlink file." >&2; exit 1; }
  mode=$(stat -c '%a' "$CREDENTIAL_FILE" 2>/dev/null || stat -f '%Lp' "$CREDENTIAL_FILE")
  case "$mode" in *00) ;; *) echo "Credential file must grant no group/other permissions." >&2; exit 1 ;; esac
  cp "$CREDENTIAL_FILE" "$TARGET_CREDENTIAL"; chmod 0600 "$TARGET_CREDENTIAL"
fi
if [ -f "$TARGET_CREDENTIAL" ]; then
  [ ! -L "$TARGET_CREDENTIAL" ] || { echo "Installed credential cannot be a symlink." >&2; exit 1; }
  mode=$(stat -c '%a' "$TARGET_CREDENTIAL" 2>/dev/null || stat -f '%Lp' "$TARGET_CREDENTIAL")
  case "$mode" in *00) ;; *) echo "Installed credential permissions are too broad." >&2; exit 1 ;; esac
fi

if [ ! -f "$IDENTITY" ]; then "$ARPL" key rotate -key-file "$IDENTITY" >/dev/null; fi
if [ ! -f "$SETTINGS" ]; then
  XDG_CONFIG_HOME=$(dirname "$CONFIG_DIR") "$ARPL" settings init --file "$SETTINGS" >/dev/null
fi

if [ -n "$ENROLL_TOKEN_FILE" ] && [ ! -f "$TARGET_CREDENTIAL" ]; then
  [ "$gateway_explicit" = 1 ] || [ -n "${AI_RELAY_GATEWAY:-}" ] || { echo "A gateway URL is required with --enroll-token-file." >&2; exit 2; }
  [ -f "$ENROLL_TOKEN_FILE" ] && [ ! -L "$ENROLL_TOKEN_FILE" ] || { echo "Enrollment token must be a regular, non-symlink file." >&2; exit 1; }
  mode=$(stat -c '%a' "$ENROLL_TOKEN_FILE" 2>/dev/null || stat -f '%Lp' "$ENROLL_TOKEN_FILE")
  case "$mode" in *00) ;; *) echo "Enrollment token permissions are too broad." >&2; exit 1 ;; esac
  "$AGENT" -gateway "$GATEWAY" -credential-file "$TARGET_CREDENTIAL" -enroll-token-file "$ENROLL_TOKEN_FILE" -enroll-only
fi

if [ -n "$ARPL_ENROLLMENT_PAYLOAD_FILE" ]; then
  [ -f "$ARPL_ENROLLMENT_PAYLOAD_FILE" ] && [ ! -L "$ARPL_ENROLLMENT_PAYLOAD_FILE" ] || { echo "ARPL enrollment payload must be a regular, non-symlink file." >&2; exit 1; }
  "$ARPL" enroll consume --payload-file "$ARPL_ENROLLMENT_PAYLOAD_FILE" --settings-file "$SETTINGS" --name "$PEER_NAME" --key-file "$IDENTITY"
fi

if [ "$ROLE" = full ] && [ ! -f "$CONFIG_DIR/gateway.env" ]; then
  umask 077
  printf '%s\n' '# AI Relay gateway environment. Add protected token-file paths when configuring MCP.' >"$CONFIG_DIR/gateway.env"
  chmod 0600 "$CONFIG_DIR/gateway.env"
fi

# ARPL owns its settings schema and persistence rendering.  Always render the
# private scaffold first.  Explicit desktop activation then asks ARPL to apply
# its settings in native mode, which owns systemd/cron/launchd activation.
ARPL_SERVICE_ACTIVATE=0 "$ARPL" settings apply --file "$SETTINGS" --platform "$os_name" --output-dir "$SERVICES_DIR" >/dev/null

if [ "$ACTIVATE" = 1 ] && [ "$os_name" != android ]; then
  # No output directory means native ARPL activation.  Do not duplicate ARPL's
  # service-manager or cron logic in this installer.
  "$ARPL" settings apply --file "$SETTINGS" --platform "$os_name" >/dev/null
fi

if [ "$ROLE" = full ]; then
  if [ "$os_name" = linux ]; then
    cat >"$SERVICES_DIR/ai-relay-gateway.service" <<EOF
[Unit]
Description=AI Relay Gateway (all-in-one user service)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$GATEWAY_BIN -listen 127.0.0.1:8743 -state $STATE_DIR/gateway
EnvironmentFile=-$CONFIG_DIR/gateway.env
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
EOF
  elif [ "$os_name" = darwin ]; then
    esc_prefix=$(printf '%s' "$PREFIX" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    esc_gateway=$(printf '%s' "$GATEWAY_BIN" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    esc_state=$(printf '%s' "$STATE_DIR/gateway" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    cat >"$SERVICES_DIR/com.ai-relay.gateway.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.ai-relay.gateway</string><key>ProgramArguments</key><array><string>$esc_gateway</string><string>-listen</string><string>127.0.0.1:8743</string><string>-state</string><string>$esc_state</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>
EOF
    chmod 0600 "$SERVICES_DIR/com.ai-relay.gateway.plist"
  fi
fi

if [ "$ACTIVATE" = 1 ]; then
  case "$os_name" in
    linux)
      if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
        native="$HOME/.config/systemd/user"; mkdir -p "$native"
        cp "$SERVICES_DIR/ai-relay-gateway.service" "$native/" 2>/dev/null || true
        if [ "$ROLE" = full ]; then systemctl --user daemon-reload; systemctl --user enable --now ai-relay-gateway.service; fi
        if [ -f "$TARGET_CREDENTIAL" ]; then
          cat >"$native/ai-relay-agent.service" <<EOF
[Unit]
Description=AI Relay outbound agent (all-in-one user service)
After=network-online.target

[Service]
ExecStart=$AGENT -gateway $GATEWAY -credential-file $TARGET_CREDENTIAL
Restart=always
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=default.target
EOF
          systemctl --user daemon-reload; systemctl --user enable --now ai-relay-agent.service
        else
          echo "ENROLLMENT REQUIRED: agent persistence was staged but not activated."
        fi
      else
        echo "Linux user systemd bus unavailable; ARPL fallback is staged in $SERVICES_DIR. Gateway/agent activation remains staged."
      fi
      ;;
    darwin)
      if command -v launchctl >/dev/null 2>&1; then
        uid=$(id -u); native="$HOME/Library/LaunchAgents"; mkdir -p "$native"
        if [ "$ROLE" = full ]; then cp "$SERVICES_DIR/com.ai-relay.gateway.plist" "$native/"; launchctl bootstrap "gui/$uid" "$native/com.ai-relay.gateway.plist" 2>/dev/null || true; fi
        if [ -f "$TARGET_CREDENTIAL" ]; then
          cat >"$native/com.ai-relay.agent.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.ai-relay.agent</string><key>ProgramArguments</key><array><string>$AGENT</string><string>-gateway</string><string>$GATEWAY</string><string>-credential-file</string><string>$TARGET_CREDENTIAL</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>
EOF
          chmod 0600 "$native/com.ai-relay.agent.plist"; launchctl bootstrap "gui/$uid" "$native/com.ai-relay.agent.plist" 2>/dev/null || true
        else echo "ENROLLMENT REQUIRED: agent LaunchAgent was not activated."; fi
        echo "macOS activation requested; no TCC permissions were changed or bypassed."
      else echo "launchctl unavailable; LaunchAgent files remain staged in $SERVICES_DIR."; fi
      ;;
    android) echo "Termux activation is explicit: use $SERVICES_DIR/arpl-termux-start.sh or Termux:Boot. No gateway is installed." ;;
  esac
fi

echo "Installed AI Relay + ARPL all-in-one $VERSION for $os_name/$arch_name."
echo "Binaries: $BIN_DIR"
echo "ARPL settings: $SETTINGS"
echo "Service scaffolding: $SERVICES_DIR"
if [ -f "$TARGET_CREDENTIAL" ]; then
  echo "Agent enrollment: credential configured; connectivity was not tested."
else
  echo "ENROLLMENT REQUIRED: agent is staged and not connected."
fi
if [ "$os_name" = android ]; then
  if [ -d "$HOME/.termux/boot" ] || command -v termux-job-scheduler >/dev/null 2>&1; then echo "Termux:Boot availability: detected."; else echo "Termux:Boot availability: not detected; manual supervisor start is required."; fi
fi
case ":${PATH:-}:" in *":$BIN_DIR:"*) ;; *) echo "Add $BIN_DIR to PATH for ai-relay-arpl and ai-relay-agent." ;; esac
