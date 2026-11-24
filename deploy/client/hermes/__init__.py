"""WithHuman for Hermes Agent: a Hermes plugin that has every tool call judged by the engine.

Hermes calls a plugin's hook callbacks in its own process. This plugin follows what only that
process can tell (the session's directory, the conversation a hook belongs to across context
compressions and delegated subagents, the directory the next `terminal` command runs in), adds it
to the hook's keyword arguments and runs the bridge beside it (`withhuman-hook.py`) with them,
once per hook. The bridge forwards them to the Collector and prints the engine's answer in Claude
Code's form; this plugin answers Hermes in its own:

- `pre_llm_call`: the engine's request for the turn's intent line, as context for the user's
  message.
- `pre_tool_call`: a deny as Hermes' block, whose message the model reads as the tool's result.
  In enforce mode a bridge that fails, times out or cannot run blocks the call too.

Settings: `withhuman.json` beside this file (`{"server": "https://…"}`, written by the setup),
WITHHUMAN_SERVER overriding it; WITHHUMAN_MODE=observe lets every call through.
"""

import itertools
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
BRIDGE = HERE / "withhuman-hook.py"
SETTINGS = HERE / "withhuman.json"
# What the model is told when WithHuman could not judge a call. It says nothing of the engine.
BLOCKED = "WithHuman could not check this call, so it was blocked"
# Seconds a bridge run may take: a little more than the bridge's own deadline, so the bridge
# decides, and well below Hermes' 30 seconds for a plugin callback.
TIMEOUTS = {"pre_tool_call": 15.0, "pre_llm_call": 9.0}
TIMEOUT = 7.0
# Not sent: too large or private, or sent in another form already.
DROPPED = {"conversation_history", "request_messages", "request", "assistant_message", "usage",
           "moa_references", "base_url", "middleware_trace", "side_question_token",
           "review_signals", "telemetry_schema_version"}
FORWARDED = ("on_session_start", "pre_llm_call", "post_api_request", "pre_tool_call",
             "post_tool_call", "on_session_end", "on_session_finalize", "subagent_start",
             "subagent_stop")

_ctx = {}


def settings():
    try:
        found = json.loads(SETTINGS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        found = {}
    found = found if isinstance(found, dict) else {}
    server = os.environ.get("WITHHUMAN_SERVER", "").strip() or found.get("server")
    return server if isinstance(server, str) and server.strip() else None


def enforcing():
    return os.environ.get("WITHHUMAN_MODE", "enforce") != "observe"


class Sessions:
    """Which conversation, subagent and directory each Hermes session stands for.

    Hermes gives a session a new ID when it compresses the context, and only tool hooks carry
    the conversation's first; a delegated subagent runs a session of its own. The engine sees one
    session per conversation, with the subagent as its `agent_id`.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.root = {}      # Hermes session -> engine session
        self.agent = {}     # subagent session -> its agent ID
        self.workdir = {}   # session -> directory its next command runs in
        self.ids = itertools.count(1)

    def identity(self, session, conversation=None):
        """(engine session, agent ID) of a hook of `session`."""
        with self.lock:
            if session not in self.root and session not in self.agent and conversation:
                # A tool hook of a session not seen yet belongs to its conversation. A subagent
                # is announced by subagent_start in this process before it runs, so an unknown
                # session behind another conversation was compressed before this process saw it
                # (a gateway restart): it is that conversation's main agent, still asked for its
                # intent.
                self.root[session] = conversation
            return self.root.get(session, session), self.agent.get(session)

    def delegated(self, parent, child):
        with self.lock:
            self.root[child] = self.root.get(parent, parent)
            self.agent[child] = child

    def compressed(self, old, new):
        with self.lock:
            self.root[new] = self.root.get(old, old)
            if old in self.agent:
                self.agent[new] = self.agent[old]
            if old in self.workdir:
                self.workdir[new] = self.workdir[old]

    def directory(self, session, default):
        with self.lock:
            return self.workdir.get(session, default)

    def moved(self, session, directory):
        with self.lock:
            self.workdir[session] = directory

    def call_id(self):
        return f"withhuman-script-{next(self.ids)}"


SESSIONS = Sessions()


def jsonable(value, depth=0):
    if depth > 8:
        return repr(value)[:200]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): jsonable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v, depth + 1) for v in value]
    if hasattr(value, "model_dump"):
        try:
            return jsonable(value.model_dump(), depth + 1)
        except Exception:  # noqa: BLE001
            pass
    if hasattr(value, "__dict__"):
        return {k: jsonable(v, depth + 1) for k, v in vars(value).items() if not k.startswith("_")}
    return str(value)


def session_cwd():
    try:
        return _ctx["ctx"].session_cwd() or None
    except Exception:  # noqa: BLE001
        return None


def mcp_server(tool_name):
    """The MCP server of a tool Hermes registered as `mcp-<server>`; none for any other."""
    if not isinstance(tool_name, str) or not tool_name.startswith("mcp_"):
        return None
    try:
        from tools.registry import registry
        toolset = registry.get_toolset_for_tool(tool_name) or ""
    except Exception:  # noqa: BLE001
        return None
    return toolset[len("mcp-"):] if toolset.startswith("mcp-") else None


def body_of(hook, kwargs):
    """The hook as the bridge sends it."""
    body = {"hook_event_name": hook}
    body.update({k: jsonable(v) for k, v in kwargs.items() if k not in DROPPED})
    cwd = session_cwd()
    if cwd:
        body["cwd"] = cwd
    if hook in ("subagent_start", "subagent_stop"):
        parent = kwargs.get("parent_session_id") or ""
        engine, _ = SESSIONS.identity(parent)
        body["withhuman_session_id"] = engine
        body["withhuman_agent_id"] = kwargs.get("child_session_id")
        return body
    session = kwargs.get("session_id") or ""
    engine, agent = SESSIONS.identity(session, kwargs.get("conversation_id"))
    if engine:
        body["withhuman_session_id"] = engine
        if agent:
            body["withhuman_agent_id"] = agent
    if hook in ("pre_tool_call", "post_tool_call"):
        if not body.get("tool_call_id"):
            # A call a script made through execute_code: Hermes gives it no ID.
            body["tool_call_id"] = SESSIONS.call_id()
        if body.get("tool_name") == "terminal":
            body["withhuman_workdir"] = SESSIONS.directory(session, cwd)
        server = mcp_server(body.get("tool_name"))
        if server:
            body["withhuman_mcp_server"] = server
    return body


def run_bridge(hook, body):
    """The engine's answer through the bridge, in Claude Code's form; None when it has none.
    Raises when the bridge could not give one."""
    server = settings()
    if not server:
        raise RuntimeError("no WithHuman server set")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    done = subprocess.run(
        [sys.executable or "python", str(BRIDGE), server, hook],
        input=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        capture_output=True, timeout=TIMEOUTS.get(hook, TIMEOUT), creationflags=flags)
    if done.returncode == 2:
        raise RuntimeError("bridge blocked")
    output = done.stdout.strip()
    return json.loads(output) if output else None


def answer(hook, kwargs):
    """Forwards one hook; the bridge's answer, or None when it failed (logged by Hermes)."""
    return run_bridge(hook, body_of(hook, kwargs))


def forward(hook):
    def callback(**kwargs):
        try:
            answer(hook, kwargs)
        except Exception:  # noqa: BLE001
            pass  # Nothing to block here; the bridge keeps its own audit log.
        return None
    callback.__name__ = f"withhuman_{hook}"
    return callback


def on_pre_llm_call(**kwargs):
    try:
        output = (answer("pre_llm_call", kwargs) or {}).get("hookSpecificOutput") or {}
    except Exception:  # noqa: BLE001
        return None
    context = output.get("additionalContext")
    return {"context": context} if isinstance(context, str) and context else None


def on_post_api_request(**kwargs):
    content = (((kwargs.get("response") or {}).get("assistant_message") or {}).get("content"))
    if not content:
        return None  # Only text can hold the turn's intent line.
    return forward("post_api_request")(**kwargs)


def on_pre_tool_call(**kwargs):
    try:
        output = (answer("pre_tool_call", kwargs) or {}).get("hookSpecificOutput") or {}
    except Exception:  # noqa: BLE001
        return {"action": "block", "message": BLOCKED} if enforcing() else None
    if output.get("permissionDecision") in ("deny", "ask"):
        reason = output.get("permissionDecisionReason")
        return {"action": "block", "message": reason if isinstance(reason, str) and reason else BLOCKED}
    return None


def on_post_tool_call(**kwargs):
    if kwargs.get("status") == "blocked":
        return None  # It never ran.
    if kwargs.get("tool_name") == "terminal":
        # A command that changed directory says where it ended; Hermes runs the next one there.
        args = kwargs.get("args") if isinstance(kwargs.get("args"), dict) else {}
        try:
            result = json.loads(kwargs.get("result") or "{}")
        except (TypeError, ValueError):
            result = {}
        if not args.get("workdir") and isinstance(result, dict) and isinstance(result.get("cwd"), str):
            SESSIONS.moved(kwargs.get("session_id") or "", result["cwd"])
    return forward("post_tool_call")(**kwargs)


def on_subagent_start(**kwargs):
    if kwargs.get("parent_session_id") and kwargs.get("child_session_id"):
        SESSIONS.delegated(kwargs["parent_session_id"], kwargs["child_session_id"])
    return forward("subagent_start")(**kwargs)


def on_post_compaction(**kwargs):
    if kwargs.get("old_session_id") and kwargs.get("session_id"):
        SESSIONS.compressed(kwargs["old_session_id"], kwargs["session_id"])


def register(ctx):
    _ctx["ctx"] = ctx
    handlers = {
        "pre_llm_call": on_pre_llm_call,
        "post_api_request": on_post_api_request,
        "pre_tool_call": on_pre_tool_call,
        "post_tool_call": on_post_tool_call,
        "subagent_start": on_subagent_start,
    }
    for hook in FORWARDED:
        ctx.register_hook(hook, handlers.get(hook) or forward(hook))
    ctx.register_hook("post_compaction", on_post_compaction)
