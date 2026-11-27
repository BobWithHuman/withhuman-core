// WithHuman's OpenClaw plugin: the only place a call can be held back.
//
// OpenClaw has two hook systems. Its automation hooks (`openclaw hooks`, a workspace's `hooks/`
// folder) carry no tool event and cannot abort what they observe. Its **plugin** hooks do: a
// plugin registered in the Gateway is handed a call before it runs and blocks it by returning
// `{ block: true, blockReason }`, or puts it to the user with `requireApproval`. Only code
// inside the Gateway can answer one, which is why this file exists.
//
// What it does and does not do:
//
// - Everything a client shares with the other agents' — the device's key, the deadline, the
//   local audit log, and the rule that in enforce mode every failure ends in a decision rather
//   than in a call nobody judged — stays in `withhuman-hook.py` beside this file, which is the
//   same shared bridge Codex's and Cursor's clients run. This file forwards a hook to it and
//   turns its answer into the plugin API's own.
// - The hook's event carries the call; the fields only its context carries (the session, the
//   turn, the directory and the call's id) are added to what is sent, since that is what the
//   engine reads the call's place in the session from.
// - A failure to reach a decision blocks a call rather than letting it through. The bridge
//   answers that way itself; this file blocks as well when the bridge cannot be run at all.
//
// - The engine asks each turn to open its answer with the user intent it inferred, and sends
//   that instruction back with the prompt. Nothing can put it into the turn it came with —
//   OpenClaw builds the prompt before the hook that carries it runs — so it is kept here and
//   put in front of the system context of the turns that follow, the way OpenClaw's own
//   `agent-guidance` plugin adds instructions. The first turn of a Gateway goes without it, and
//   the engine asks that turn for its intent by turning its first call back instead.
//
// The conversation hooks are refused to a plugin that was not allowed them, so a setup without
// `plugins.entries.withhuman.hooks.allowConversationAccess = true` keeps the calls and loses
// the turn around them — the prompt, its intent, and the answer. `configure.py` sets it.

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BRIDGE = path.join(HERE, "withhuman-hook.py");

/// What the agent is told when WithHuman could not judge a call. It reaches the model, not a
/// person, so it says nothing of the engine's inner workings.
const BLOCKED = "WithHuman could not check this call, so it was blocked";

/// The hooks the engine judges or records. `before_tool_call` is the only one whose answer
/// decides a call; the rest are reported and forgotten.
const HOOKS = [
  "session_end",
  "before_agent_run",
  "before_tool_call",
  "after_tool_call",
  "before_agent_finalize",
  "agent_end",
];
const BLOCKING = "before_tool_call";
/// The hook that builds a turn's prompt, and the only one that takes text for the model. It is
/// answered from what the engine last sent, without running the bridge: it fires before the
/// hook that carries the instruction, so this turn's copy could not be waited for anyway.
const PROMPT_BUILD = "before_prompt_build";
/// The hook whose answer carries that instruction.
const PROMPT = "before_agent_run";
/// The hook that carries every message the transcript keeps, the agent's own among them. An
/// agent's message reaches it **before the calls that message announces run**, which makes it
/// the only answer a turn's first call can be judged against: the answer the turn settles on
/// arrives once every call is over. It is synchronous — a handler that returns a promise is
/// ignored and the host says so — so nothing is sent from it; what it carries is kept and sent
/// with the call it announces, which is also what gives that send a session and a turn, since
/// this hook names neither. It is refused to no plugin, so this works in a setup that never
/// allows the conversation.
const ANSWER = "before_message_write";

/// Seconds this plugin waits for the bridge. A judged call waits for the engine, so it gets
/// more; both are above the bridge's own deadlines, so a slow engine ends in the bridge's
/// answer rather than in this timeout.
/// An answer is sent before the call it was made in is judged, so its own wait is short: it
/// decides nothing, and the call is what the user is waiting on.
const DEADLINES = { [BLOCKING]: 15, [ANSWER]: 5 };
const DEFAULT_DEADLINE = 8;

/// How long the user has to answer a call put to them, and the decisions they are offered.
const APPROVAL_TIMEOUT_MS = 120_000;
const APPROVAL_DECISIONS = ["allow-once", "deny"];

/// Fields only a hook's context carries. The event itself holds the call; these say which
/// session and turn it belongs to, which is what the engine puts it on a causal path by.
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
  "sandboxed",
];

/// The instruction the engine last asked a turn to follow, kept for the turns after the one it
/// came with. It is the same text every time, so one copy serves every session; an engine that
/// stops asking for it (intent capture off) clears it rather than leaving a stale one behind.
let standingInstruction = null;

/// Answers kept by the id of a call they announce, until that call arrives. A turn leaves at
/// most one entry per call it makes, and an id the hook never reaches — a call the host
/// dropped — would stay, so the oldest are let go once there are more than a turn could own.
const announced = new Map();
const ANNOUNCED_LIMIT = 64;

/// Keeps what an agent's message said, under the ids of the calls it announces. A message with
/// no words in it (a model that only reasons before calling) leaves nothing to show, and one
/// that announces nothing is the answer that ends the turn, which `before_agent_finalize`
/// already carries.
function remember(message) {
  if (message?.role !== "assistant") return;
  const content = message.content;
  const parts = Array.isArray(content) ? content : [];
  const text = typeof content === "string"
    ? content.trim()
    : parts
        .filter((part) => part?.type === "text" && typeof part.text === "string")
        .map((part) => part.text.trim())
        .filter(Boolean)
        .join("\n\n");
  const calls = parts
    .filter((part) => part?.type === "toolCall" && typeof part.id === "string")
    .map((part) => part.id);
  if (!text || !calls.length) return;
  for (const id of calls) {
    announced.set(id, text);
    if (announced.size > ANNOUNCED_LIMIT) announced.delete(announced.keys().next().value);
  }
}

/// Sends the answer this call was made in, if one was kept, before the call itself is judged.
/// Its own ids are the call's: the hook that carried it named neither session nor turn. The
/// bridge's reply decides nothing, and a failure to report an answer must not hold back a call
/// the engine would have allowed, so nothing here throws.
async function announce(payload, logger) {
  const text = announced.get(payload?.toolCallId);
  if (!text) return;
  // Every call of the same message carries the same answer; the engine keeps it once, and
  // sending it once is enough.
  for (const [id, kept] of announced) {
    if (kept === text) announced.delete(id);
  }
  try {
    await judge(
      ANSWER,
      {
        sessionId: payload.sessionId,
        sessionKey: payload.sessionKey,
        runId: payload.runId,
        agentId: payload.agentId,
        message: { role: "assistant", content: [{ type: "text", text }] },
        hook_event_name: ANSWER,
      },
      logger,
    );
  } catch (error) {
    logger?.warn?.(`WithHuman: the answer this call was made in went unreported (${error?.message ?? error})`);
  }
}

/// The python that runs the bridge. The installer writes the interpreter it found; the
/// environment overrides it for a device where that one moved.
function python() {
  const configured = process.env.WITHHUMAN_PYTHON;
  if (configured) return configured;
  try {
    const beside = fs.readFileSync(path.join(HERE, "python"), "utf8").trim();
    if (beside) return beside;
  } catch {
    // Fall back to the one on the path.
  }
  return process.platform === "win32" ? "python" : "python3";
}

/// A plain copy of what a hook carries: functions, abort signals and readers are dropped, and
/// a cycle is cut rather than followed, so what is sent is always JSON.
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

/// One hook as the bridge receives it: the event, with the fields only the context carries.
function payloadOf(hook, event, ctx) {
  const payload = plain(event) ?? {};
  for (const field of FROM_CONTEXT) {
    if (payload[field] === undefined && ctx?.[field] !== undefined) {
      const kept = plain(ctx[field]);
      if (kept !== undefined && kept !== null) payload[field] = kept;
    }
  }
  payload.hook_event_name = hook;
  return payload;
}

/// Runs the bridge for one hook and reads its answer. The bridge prints nothing for an allow,
/// `{"action": "block"|"ask", "reason": …}` otherwise.
function judge(hook, payload, logger) {
  return new Promise((resolve) => {
    const deadline = (DEADLINES[hook] ?? DEFAULT_DEADLINE) * 1000;
    let child;
    try {
      child = spawn(python(), [BRIDGE, hook], {
        stdio: ["pipe", "pipe", "pipe"],
        env: process.env,
      });
    } catch (error) {
      // The bridge could not be started at all, so nothing judged this call.
      resolve({ action: "unavailable", reason: String(error?.message ?? error) });
      return;
    }
    let out = "";
    let err = "";
    let done = false;
    const finish = (answer) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (err.trim()) logger?.warn?.(`WithHuman bridge: ${err.trim().slice(0, 500)}`);
      resolve(answer);
    };
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already gone.
      }
      finish({ action: "unavailable", reason: "WithHuman did not answer in time" });
    }, deadline);

    child.stdout.on("data", (chunk) => {
      out += chunk;
    });
    child.stderr.on("data", (chunk) => {
      err += chunk;
    });
    child.on("error", (error) =>
      finish({ action: "unavailable", reason: String(error?.message ?? error) }),
    );
    child.on("close", (code) => {
      const text = out.trim();
      // The bridge answers every judged call and exits 0; in observe mode it exits 0 having
      // printed nothing. Any other ending is python itself failing — a module it could not
      // import, a crash, a kill — and nothing judged the call, so it is not let through on the
      // strength of an empty answer.
      if (code !== 0) {
        finish({ action: "unavailable", reason: `WithHuman's bridge exited ${code}` });
        return;
      }
      if (!text) {
        finish({ action: "allow" });
        return;
      }
      try {
        const answer = JSON.parse(text);
        finish(answer && typeof answer === "object" ? answer : { action: "allow" });
      } catch {
        // An answer that does not parse is no judgment.
        finish({ action: "unavailable", reason: "WithHuman's answer could not be read" });
      }
    });

    try {
      child.stdin.end(JSON.stringify(payload));
    } catch (error) {
      finish({ action: "unavailable", reason: String(error?.message ?? error) });
    }
  });
}

/// Whether this device is only watching. In observe mode nothing is ever held back, which is
/// also what the bridge does — it is read here as well, for a failure that stopped the bridge
/// before it could.
function observing() {
  return (process.env.WITHHUMAN_MODE ?? "enforce").trim() === "observe";
}

/// The engine's answer as the plugin API takes it. Only `before_tool_call` can hold a call
/// back; on every other hook an answer is nothing to act on.
function answerOf(hook, answer, logger) {
  if (hook !== BLOCKING) return undefined;
  const reason =
    typeof answer?.reason === "string" && answer.reason ? answer.reason : BLOCKED;
  switch (answer?.action) {
    case "block":
      return { block: true, blockReason: reason };
    case "ask":
      // OpenClaw pauses the call until the user answers and blocks it on a deny or a timeout,
      // so a call the engine wants a person to decide is put to them rather than denied.
      return {
        requireApproval: {
          title: "WithHuman: approve this call?",
          description: reason,
          severity: "warning",
          timeoutMs: APPROVAL_TIMEOUT_MS,
          allowedDecisions: APPROVAL_DECISIONS,
        },
      };
    case "unavailable":
      logger?.warn?.(`WithHuman: ${reason}`);
      // Watching only: the call is let through, as the bridge would have let it through.
      return observing() ? undefined : { block: true, blockReason: BLOCKED };
    default:
      return undefined;
  }
}

export default {
  id: "withhuman",
  name: "WithHuman",
  description:
    "Judges what this agent does against what the user asked for, and holds back a call that " +
    "does not follow from it.",
  configSchema: {
    type: "object",
    properties: {
      server: { type: "string", description: "The WithHuman engine's address" },
    },
    additionalProperties: false,
  },
  register(api) {
    const logger = api?.logger;
    // The engine's address is read by the bridge, from the environment or the file the
    // installer wrote beside it. A plugin's own configuration sets it for a device where
    // neither is in place.
    const configured = api?.pluginConfig?.server;
    if (typeof configured === "string" && configured.trim() && !process.env.WITHHUMAN_SERVER) {
      process.env.WITHHUMAN_SERVER = configured.trim();
    }

    const refused = [];
    // Answered from what the engine last sent. Running the bridge here would cost a turn's
    // prompt a process and tell it nothing new.
    try {
      api.on(PROMPT_BUILD, async () =>
        standingInstruction ? { prependSystemContext: standingInstruction } : undefined,
      );
    } catch (error) {
      refused.push(`${PROMPT_BUILD} (${error?.message ?? error})`);
    }
    // Kept, not sent: the hook is synchronous, so the bridge cannot be reached from it.
    try {
      api.on(ANSWER, (event) => {
        try {
          remember(event?.message);
        } catch (error) {
          logger?.warn?.(`WithHuman: ${error?.message ?? error}`);
        }
        return undefined;
      });
    } catch (error) {
      refused.push(`${ANSWER} (${error?.message ?? error})`);
    }
    for (const hook of HOOKS) {
      try {
        api.on(hook, async (event, ctx) => {
          try {
            const payload = payloadOf(hook, event, ctx);
            // The engine judges a call against what the agent said it was doing, so the answer
            // goes first.
            if (hook === BLOCKING) await announce(payload, logger);
            const answer = await judge(hook, payload, logger);
            if (hook === PROMPT) {
              const text = answer?.action === "context" ? answer.text : null;
              standingInstruction = typeof text === "string" && text.trim() ? text : null;
            }
            return answerOf(hook, answer, logger);
          } catch (error) {
            // Nothing judged this call, so it is held back; an event that decides nothing is
            // only reported.
            logger?.error?.(`WithHuman: ${error?.message ?? error}`);
            return hook === BLOCKING && !observing()
              ? { block: true, blockReason: BLOCKED }
              : undefined;
          }
        });
      } catch (error) {
        refused.push(`${hook} (${error?.message ?? error})`);
      }
    }
    if (refused.length) {
      // A hook this host does not know leaves the engine without that event; the calls are
      // still judged.
      logger?.warn?.(`WithHuman: this OpenClaw does not take ${refused.join(", ")}`);
    }
  },
};
