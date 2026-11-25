#!/usr/bin/env python3
"""Dumps one Copilot hook's stdin to a JSONL, then allows the call.

Nothing here judges anything; it exists only to record the exact payload Copilot sends for each
hook of this version. A preToolUse hook that exits 0 with no output lets the call run.
"""
import json, os, sys, time

OUT = os.environ.get("WITHHUMAN_PROBE_OUT") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "capture.jsonl")
event = sys.argv[1] if len(sys.argv) > 1 else "?"
raw = sys.stdin.buffer.read()
try:
    payload = json.loads(raw)
except ValueError:
    payload = {"__unparsed__": raw.decode("utf-8", "replace")}
row = {"_event": event, "_time": time.time(), "payload": payload,
       "_env": {k: v for k, v in os.environ.items() if k.startswith(("COPILOT_", "CLAUDE_"))}}
with open(OUT, "a") as handle:
    handle.write(json.dumps(row, ensure_ascii=False) + "\n")
