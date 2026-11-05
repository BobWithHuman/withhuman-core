#!/usr/bin/env bash
# Gives this device a stable WithHuman client ID and exports it as
# WITHHUMAN_CLIENT_ID from the shell profile, and installs the PreToolUse
# command hook that settings.json runs. Safe to run repeatedly: an existing ID
# is kept, so copied dotfiles never duplicate another device's ID, and the hook
# is replaced with this checkout's.
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# settings.json runs the hook from here.
hook_dir="$HOME/.config/withhuman/hooks"

team=${1:-default}
id_file=${WITHHUMAN_CLIENT_ID_FILE:-"${XDG_CONFIG_HOME:-$HOME/.config}/withhuman/client-id"}
profile=${WITHHUMAN_PROFILE:-"$HOME/.bashrc"}

case $team in
  '' | *[!A-Za-z0-9._-]*)
    printf 'team must match [A-Za-z0-9._-]+: %s\n' "$team" >&2
    exit 1
    ;;
esac

if [ ! -s "$id_file" ]; then
  mkdir -p "$(dirname -- "$id_file")"
  if command -v uuidgen >/dev/null; then
    uuid=$(uuidgen)
  else
    uuid=$(cat /proc/sys/kernel/random/uuid)
  fi
  printf '%s/%s\n' "$team" "$(tr '[:upper:]' '[:lower:]' <<<"$uuid")" >"$id_file"
fi

line="export WITHHUMAN_CLIENT_ID=\$(cat '$id_file')"
touch "$profile"
if ! grep -qxF "$line" "$profile"; then
  printf '\n# WithHuman client ID\n%s\n' "$line" >>"$profile"
fi

mkdir -p "$hook_dir"
install -m 0755 "$script_dir/hooks/pre-tool-use.py" "$hook_dir/pre-tool-use.py"
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
  printf 'warning: the PreToolUse hook needs python3 3.8 or later on PATH\n' >&2
fi

printf 'WITHHUMAN_CLIENT_ID=%s\n' "$(cat "$id_file")"
printf 'PreToolUse hook: %s\n' "$hook_dir/pre-tool-use.py"
printf 'Restart your shell (or run: source %s) before starting Claude Code.\n' "$profile"
