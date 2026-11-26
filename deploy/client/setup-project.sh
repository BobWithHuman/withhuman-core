#!/usr/bin/env bash
# Sets up WithHuman for Claude Code, Codex CLI or Cursor CLI in the current folder (macOS,
# Linux), replacing
# any earlier WithHuman setup. Run it in the folder you start the agent in:
#
#   WITHHUMAN_SERVER=https://withhuman.example.com \
#     curl -fsSL https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.sh | bash -s -- [team]
#
# WITHHUMAN_SERVER is the address of your own engine; WithHuman is self-hosted, so there is no
# default. WITHHUMAN_KEY is the user's key from the security team, when the engine issues keys. WITHHUMAN_AGENT picks the agent: claude (default), codex, cursor, hermes or openclaw (Hermes is
# set up for its profile, HERMES_HOME, and OpenClaw for its state directory,
# OPENCLAW_STATE_DIR, not for the folder). Running it again updates
# the setup; WITHHUMAN_UNINSTALL=1 takes WithHuman out of the folder instead, keeping other hooks.
# From a checkout it uses the checkout's files; otherwise it fetches them from WITHHUMAN_REF
# (default: main), or from WITHHUMAN_BASE_URL (a deploy/client folder served elsewhere, for a
# mirror or a test). See configure.py for what it changes.
set -euo pipefail

team=${1:-default}
ref=${WITHHUMAN_REF:-main}
agent=${WITHHUMAN_AGENT:-claude}
# The files configure.py needs. Claude Code takes only its own hook; every other agent also
# takes the shared bridge, that same hook (its bridge uses it to attach the program files a
# command would run) and its own. Adding an agent is one line here and one entry in
# configure.py's AGENTS.
files="configure.py hooks/pre-tool-use.py"
case "$agent" in
  claude) ;;
  codex) files="$files hooks/withhuman_bridge.py codex/withhuman-hook.py codex/codex_transcript.py" ;;
  cursor) files="$files hooks/withhuman_bridge.py cursor/withhuman-hook.py" ;;
  hermes) files="$files hooks/withhuman_bridge.py hermes/__init__.py hermes/plugin.yaml hermes/withhuman-hook.py" ;;
  # OpenClaw loads a plugin recorded in its own configuration, so its own files are that
  # plugin and what OpenClaw needs to install it.
  openclaw) files="$files hooks/withhuman_bridge.py openclaw/withhuman-hook.py openclaw/index.js openclaw/openclaw.plugin.json openclaw/package.json" ;;
  *) echo "WITHHUMAN_AGENT must be claude, codex, cursor, hermes or openclaw: $agent" >&2; exit 1 ;;
esac

if [ -z "${WITHHUMAN_SERVER:-}" ] && [ -z "${WITHHUMAN_UNINSTALL:-}" ]; then
  cat >&2 <<'USAGE'
WITHHUMAN_SERVER is required: the address of your own WithHuman engine.
  personal Docker host:  http://127.0.0.1:3000
  EKS deployment:        https://<the Ingress host>
USAGE
  exit 1
fi
base=${WITHHUMAN_BASE_URL:-"https://raw.githubusercontent.com/BobWithHuman/withhuman-core/$ref/deploy/client"}
base=${base%/}

python=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 \
    && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
    python=$(command -v "$candidate")
    break
  fi
done
if [ -z "$python" ]; then
  echo 'WithHuman needs Python 3.8 or later (macOS: xcode-select --install, or brew install python)' >&2
  exit 1
fi

here=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  here=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fi
source_dir=""
if [ -n "$here" ]; then
  source_dir=$here
  for file in $files; do
    [ -f "$here/$file" ] || source_dir=""
  done
fi
if [ -z "$source_dir" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  for file in $files; do
    mkdir -p "$tmp/$(dirname "$file")"
    curl -fsSL "$base/$file" -o "$tmp/$file"
  done
  source_dir=$tmp
fi
if [ -n "${WITHHUMAN_UNINSTALL:-}" ]; then
  "$python" "$source_dir/configure.py" --uninstall --agent "$agent" --project "$PWD"
elif [ "$agent" != claude ]; then
  "$python" "$source_dir/configure.py" --agent "$agent" --project "$PWD" --team "$team" --server "$WITHHUMAN_SERVER"
else
  "$python" "$source_dir/configure.py" --project "$PWD" --team "$team" --server "$WITHHUMAN_SERVER"
fi
