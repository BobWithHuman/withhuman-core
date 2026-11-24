// Dumps one OpenClaw plugin hook to capture.jsonl, then lets the call through.
//
// Install as a plugin of its own and run a session; nothing here judges anything, it exists
// only to record the exact payload OpenClaw sends for each hook of this version:
//
//   openclaw plugins install <this folder>
//   openclaw config set plugins.entries.withhuman-capture.hooks.allowConversationAccess true
//   openclaw chat
//
// The conversation hooks are refused without that config line, so a capture made without it
// holds the tool hooks alone.
//
// One line per hook, in the shape the WithHuman plugin posts to the engine: the hook's own
// event, with the fields of its context that only the context carries (the session, the turn,
// the directory and the call's id). That is what the Collector's OpenClaw route receives, so
// the contract is checked against these lines directly.
//
// Paths and the user name are masked here rather than afterwards, so a capture can be
// committed as it was written.
//
// Two fields are reduced rather than recorded: the system prompt and the message history a
// hook carries (50 KB and a whole transcript on every turn). The WithHuman plugin does not
// send either — the engine judges the turn's prompt and the call, not the agent's own context
// — so what is left is what the engine receives, and their size is kept as evidence that they
// were there.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const OUT = process.env.WH_CAPTURE_OUT || path.join(os.tmpdir(), "capture.jsonl");

// ---- masking -----------------------------------------------------------------------------
// The home directory, the user's name and the workspace are replaced wherever they appear,
// including inside a command's output.

const MASKS = [
  [os.homedir(), "/home/user"],
  [os.userInfo().username, "user"],
];

function mask(value) {
  if (typeof value === "string") {
    let masked = value;
    for (const [from, to] of MASKS) {
      if (from) masked = masked.split(from).join(to);
    }
    return masked;
  }
  if (Array.isArray(value)) return value.map(mask);
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = mask(item);
    return out;
  }
  return value;
}

// ---- what a hook carries -----------------------------------------------------------------
// A plain copy: functions, abort signals and the trace reader are dropped, and a cycle is cut
// rather than followed.

function plain(value, depth = 0, seen = new WeakSet()) {
  if (value === null || value === undefined) return null;
  const type = typeof value;
  if (type === "function" || type === "symbol") return undefined;
  if (type === "bigint") return String(value);
  if (type !== "object") return value;
  if (value instanceof Error) return { error: value.message };
  if (value instanceof Date) return value.toISOString();
  if (seen.has(value) || depth > 8) return undefined;
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map((item) => plain(item, depth + 1, seen)).filter((item) => item !== undefined);
  }
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    const kept = plain(item, depth + 1, seen);
    if (kept !== undefined) out[key] = kept;
  }
  return out;
}

/// The context fields the hook's own event does not carry. The plugin sends these with every
/// event, so they belong in the captured payload.
const FROM_CONTEXT = [
  "sessionId",
  "sessionKey",
  "runId",
  "agentId",
  "workspaceDir",
  "toolCallId",
  "toolName",
  "trigger",
  "requester",
  "modelProviderId",
  "modelId",
  "channel",
  "channelId",
  "senderId",
  "sandboxed",
];

// Every hook this host accepts. An unsupported name is refused at registration, which the
// first line of the capture records.
const HOOKS = [
  "session_start",
  "session_end",
  "before_agent_run",
  "before_prompt_build",
  "before_tool_call",
  "after_tool_call",
  "agent_end",
  "before_agent_reply",
  "before_agent_finalize",
  "message_received",
  "message_sending",
  "subagent_spawned",
  "subagent_ended",
  "skill_changed",
  "before_install",
  "cron_changed",
  "llm_output",
];

/// Fields a hook carries that the plugin does not send: kept as their size alone.
const REDUCED = { systemPrompt: "systemPromptChars", messages: "messageCount" };

function reduce(payload) {
  for (const [field, replacement] of Object.entries(REDUCED)) {
    const value = payload[field];
    if (value === undefined) continue;
    delete payload[field];
    if (typeof value === "string") payload[replacement] = value.length;
    else if (Array.isArray(value)) payload[replacement] = value.length;
  }
  return payload;
}

function record(event, payload) {
  try {
    const line = JSON.stringify({ _event: event, _time: Date.now() / 1000, payload: mask(payload) });
    fs.appendFileSync(OUT, line + "\n", "utf8");
  } catch {
    // A capture must never throw into the Gateway.
  }
}

export default {
  id: "withhuman-capture",
  name: "WithHuman Capture",
  description: "Records the payload of every OpenClaw plugin hook; judges nothing.",
  configSchema: { type: "object", properties: {}, additionalProperties: false },
  register(api) {
    const registered = [];
    const refused = [];
    for (const hook of HOOKS) {
      try {
        api.on(hook, async (event, ctx) => {
          try {
            const payload = plain(event) ?? {};
            for (const field of FROM_CONTEXT) {
              if (payload[field] === undefined && ctx?.[field] !== undefined) {
                const kept = plain(ctx[field]);
                if (kept !== undefined && kept !== null) payload[field] = kept;
              }
            }
            payload.hook_event_name = hook;
            record(hook, reduce(payload));
          } catch (error) {
            record(hook, { __capture_error__: error?.message ?? String(error) });
          }
          // Recording only: nothing is returned, so no call is blocked or changed.
          return undefined;
        });
        registered.push(hook);
      } catch (error) {
        refused.push({ hook, reason: error?.message ?? String(error) });
      }
    }
    record("capture:registered", { registered, refused, out: OUT, node: process.version });
  },
};
