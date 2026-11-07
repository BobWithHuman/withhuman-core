#!/usr/bin/env bash
# Sets up WithHuman for Claude Code in the current folder (macOS, Linux), replacing any earlier
# WithHuman setup. Run it in the folder you start Claude Code in:
#
#   WITHHUMAN_SERVER=https://withhuman.example.com \
#     curl -fsSL https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.sh | bash -s -- [team]
#
# WITHHUMAN_SERVER is the address of your own engine; WithHuman is self-hosted, so there is no
# default. From a checkout it uses the checkout's files; otherwise it fetches them from
# WITHHUMAN_REF (default: main). See configure.py for what it changes.
set -euo pipefail

team=${1:-default}
ref=${WITHHUMAN_REF:-main}

if [ -z "${WITHHUMAN_SERVER:-}" ]; then
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
