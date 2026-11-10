#!/usr/bin/env bash
# Sets up WithHuman on macOS and Linux, replacing any earlier WithHuman setup: Claude Code for
# every project of this user, or Codex CLI in the current folder. Run it in a project folder:
#
#   WITHHUMAN_SERVER=https://withhuman.example.com \
#     curl -fsSL https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.sh | bash -s -- [team]
#
# WITHHUMAN_SERVER is the address of your own engine; WithHuman is self-hosted, so there is no
# default. WITHHUMAN_KEY is the user's key from the security team, when the engine issues keys. WITHHUMAN_AGENT picks the agent: claude (default) or codex. Running it again updates
# the setup; WITHHUMAN_UNINSTALL=1 takes WithHuman out of the folder instead, keeping other hooks.
# From a checkout it uses the checkout's files; otherwise it fetches them from WITHHUMAN_REF
# (default: main), or from WITHHUMAN_BASE_URL (a deploy/client folder served elsewhere, for a
# mirror or a test). See configure.py for what it changes.
set -euo pipefail

team=${1:-default}
ref=${WITHHUMAN_REF:-main}
agent=${WITHHUMAN_AGENT:-claude}
case "$agent" in
  claude|codex) ;;
  *) echo "WITHHUMAN_AGENT must be claude or codex: $agent" >&2; exit 1 ;;
esac
# The files configure.py needs: the Claude Code hook, which the Codex hook also uses to attach
# program files, and the Codex hook with its transcript reader.
files="configure.py checkin.py hooks/pre-tool-use.py"
if [ "$agent" = codex ]; then
  files="$files codex/withhuman-hook.py codex/codex_transcript.py"
fi

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
elif [ "$agent" = codex ]; then
  "$python" "$source_dir/configure.py" --agent codex --project "$PWD" --team "$team" --server "$WITHHUMAN_SERVER"
else
  "$python" "$source_dir/configure.py" --project "$PWD" --team "$team" --server "$WITHHUMAN_SERVER"
fi
