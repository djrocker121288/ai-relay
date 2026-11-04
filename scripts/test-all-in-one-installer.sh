#!/bin/sh
set -eu

# Source-level safety gate for the activation split.  It deliberately does not
# execute an installer or invoke a service manager.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
UNIX="$ROOT/packaging/all-in-one/install-unix.sh"
WINDOWS="$ROOT/packaging/all-in-one/install-windows.ps1"

grep -F 'ARPL_SERVICE_ACTIVATE=0 "$ARPL" settings apply --file "$SETTINGS" --platform "$os_name" --output-dir "$SERVICES_DIR"' "$UNIX" >/dev/null
grep -F 'if [ "$ACTIVATE" = 1 ] && [ "$os_name" != android ]; then' "$UNIX" >/dev/null
grep -F '"$ARPL" settings apply --file "$SETTINGS" --platform "$os_name" >/dev/null' "$UNIX" >/dev/null
grep -F '"$ARPL" settings apply --file "$SETTINGS" --platform "$os_name" --output-dir' "$UNIX" >/dev/null
grep -F '& $arpl settings apply --file $settings --platform windows --output-dir $servicesDir | Out-Null' "$WINDOWS" >/dev/null
grep -F '& $arpl settings apply --file $settings --platform windows | Out-Null' "$WINDOWS" >/dev/null
grep -F "if (\$Activate) {" "$WINDOWS" >/dev/null

echo "all-in-one installer activation source gate passed"
