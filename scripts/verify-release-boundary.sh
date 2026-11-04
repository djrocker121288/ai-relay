#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
  echo "usage: $0 ARCHIVE [ARCHIVE ...]" >&2
  exit 2
fi

check_listing() {
  listing=$1
  archive=$2
  violations=$(awk -v archive="$archive" '
    function unsafe(path, normalized) {
      normalized = path
      gsub(/\\/, "/", normalized)
      sub(/^\.\//, "", normalized)
      if (normalized ~ /^\// || normalized ~ /(^|\/)\.\.($|\/)/) return 1
      if (normalized ~ /(^|\/)(\.git|\.cache|\.release-[^\/]*|work|state|credentials)(\/|$)/) return 1
      if (normalized ~ /(^|\/)\.env([^\/]*$)/) return 1
      if (tolower(normalized) ~ /(^|\/)[^\/]*(\.pem|\.key|\.token|\.p12|\.pfx)$/) return 1
      return 0
    }
    unsafe($0) {
      print "unsafe archive path in " archive ": " $0
      bad = 1
    }
    END { exit bad }
  ' "$listing") || {
    printf '%s\n' "$violations" >&2
    return 1
  }
}

for archive do
  [ -f "$archive" ] || {
    echo "release archive is not a regular file: $archive" >&2
    exit 1
  }
  case "$archive" in
    *.tar.gz|*.tgz)
      command -v awk >/dev/null 2>&1 || { echo "awk is required" >&2; exit 1; }
      command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
      listing=$(mktemp "${TMPDIR:-/tmp}/ai-relay-release-list.XXXXXX")
      trap 'rm -f "$listing"' EXIT HUP INT TERM
      if ! tar -tzf "$archive" >"$listing"; then
        echo "unable to list release archive: $archive" >&2
        exit 1
      fi
      check_listing "$listing" "$archive"
      ;;
    *.zip)
      command -v awk >/dev/null 2>&1 || { echo "awk is required" >&2; exit 1; }
      command -v unzip >/dev/null 2>&1 || { echo "unzip is required" >&2; exit 1; }
      listing=$(mktemp "${TMPDIR:-/tmp}/ai-relay-release-list.XXXXXX")
      trap 'rm -f "$listing"' EXIT HUP INT TERM
      if ! unzip -Z1 "$archive" >"$listing"; then
        echo "unable to list release archive: $archive" >&2
        exit 1
      fi
      check_listing "$listing" "$archive"
      ;;
    *)
      echo "unsupported release archive type: $archive" >&2
      exit 2
      ;;
  esac
done

echo "Release boundary passed for $# archive(s)."
