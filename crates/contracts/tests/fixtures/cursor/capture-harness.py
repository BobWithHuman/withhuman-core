#!/usr/bin/env python3
"""Dumps one Cursor hook's stdin to capture.jsonl, then answers permissively.

Run as: capture.py <event name>. Nothing here judges anything; it exists only to
record the exact payload Cursor sends for each hook of this version.
"""
import json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
event = sys.argv[1] if len(sys.argv) > 1 else "?"
raw = sys.stdin.buffer.read()
try:
    parsed = json.loads(raw)
except ValueError:
    parsed = {"__unparsed__": raw.decode("utf-8", "replace")}
with open(os.path.join(HERE, "capture.jsonl"), "ab") as file:
    file.write((json.dumps({"_event": event, "_time": time.time(), "payload": parsed},
                           ensure_ascii=False) + "\n").encode("utf-8"))

PERMISSION = {"preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile",
              "beforeTabFileRead", "subagentStart"}
if event in PERMISSION:
    print(json.dumps({"permission": "allow"}))
elif event == "beforeSubmitPrompt":
    print(json.dumps({"continue": True}))
