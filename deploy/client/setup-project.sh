#!/usr/bin/env bash
# Sets up WithHuman for Claude Code in the current folder (macOS, Linux), replacing any earlier
# WithHuman setup. Run it in the folder you start Claude Code in:
#
#   curl -fsSL https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.sh | bash -s -- [team]
#
# From a checkout it uses the checkout's files; otherwise it fetches them from WITHHUMAN_REF
# (default: main). See configure.py for what it changes.
set -euo pipefail

team=${1:-default}
ref=${WITHHUMAN_REF:-main}
base="https://raw.githubusercontent.com/BobWithHuman/withhuman-core/$ref/deploy/client"

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
if [ -n "$here" ] && [ -f "$here/configure.py" ] && [ -f "$here/hooks/pre-tool-use.py" ]; then
  "$python" "$here/configure.py" --project "$PWD" --team "$team"
else
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/hooks"
  curl -fsSL "$base/configure.py" -o "$tmp/configure.py"
  curl -fsSL "$base/hooks/pre-tool-use.py" -o "$tmp/hooks/pre-tool-use.py"
  "$python" "$tmp/configure.py" --project "$PWD" --team "$team"
fi
