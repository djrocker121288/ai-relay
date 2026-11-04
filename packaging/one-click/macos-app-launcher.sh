#!/bin/sh
set -u

contents=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
resources="$contents/Resources"
bootstrap="$resources/ai-relay-installer"
log_dir="$HOME/Library/Logs/AI Relay ARPL Setup"
log_file="$log_dir/setup.log"

if [ ! -x "$bootstrap" ]; then
  message="AI Relay + ARPL bootstrap is missing or not executable."
  if command -v osascript >/dev/null 2>&1 && [ "${AI_RELAY_SETUP_NO_DIALOG:-0}" != 1 ]; then
    /usr/bin/osascript -e 'display dialog "'"$message"'" with title "AI Relay + ARPL Setup" buttons {"OK"} default button "OK" with icon stop'
  else
    echo "$message" >&2
  fi
  exit 1
fi

mkdir -p "$log_dir" || exit 1
chmod 0700 "$log_dir" 2>/dev/null || true

if [ "$#" -eq 0 ]; then
  set -- install --role endpoint
fi

"$bootstrap" "$@" --source-dir "$resources" >"$log_file" 2>&1
rc=$?

if [ "$rc" -eq 0 ]; then
  if grep -q 'ENROLLMENT REQUIRED' "$log_file"; then
    message="AI Relay + ARPL setup completed. Enrollment is still required before the agent can connect. See the setup log for details."
  else
    message="AI Relay + ARPL setup completed successfully. See the setup log for details."
  fi
else
  message="AI Relay + ARPL setup failed with exit code $rc. See the setup log for details."
fi

if [ "${AI_RELAY_SETUP_NO_DIALOG:-0}" = 1 ] || ! command -v osascript >/dev/null 2>&1; then
  cat "$log_file"
  exit "$rc"
fi

/usr/bin/osascript - "$message" "$log_file" <<'APPLESCRIPT'
on run argv
  set setupMessage to item 1 of argv
  set logPath to item 2 of argv
  set resultDialog to display dialog setupMessage with title "AI Relay + ARPL Setup" buttons {"Open Log", "OK"} default button "OK"
  if button returned of resultDialog is "Open Log" then
    tell application "Finder" to open POSIX file logPath
  end if
end run
APPLESCRIPT

exit "$rc"
