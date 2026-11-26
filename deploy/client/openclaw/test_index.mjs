// Tests for the OpenClaw plugin: node deploy/client/openclaw/test_index.mjs
//
// The plugin is the only part of the client that runs inside the Gateway, so it is the only
// part node has to check. Each test registers it against a stand-in plugin API and a stand-in
// bridge — a script put where `withhuman-hook.py` goes, printing what the real bridge would —
// and checks the answer the plugin gives the hook.
//
// What matters here is that a call is held back whenever nothing judged it: a bridge that
// cannot run, one that takes too long, one that exits 2 and one whose answer does not parse
// must all end in a block, since OpenClaw runs a call its hook does not object to.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const HERE = path.dirname(new URL(import.meta.url).pathname);
const BLOCKED = "WithHuman could not check this call, so it was blocked";

/// A copy of the plugin with a stand-in bridge beside it, loaded fresh so each test gets its
/// own. `script` is the python the bridge is replaced by.
async function withBridge(script) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "wh-plugin-"));
  fs.copyFileSync(path.join(HERE, "index.js"), path.join(directory, "index.js"));
  fs.writeFileSync(path.join(directory, "withhuman-hook.py"), script, "utf8");
  const module = await import(path.join(directory, "index.js") + `?t=${Math.random()}`);
  return { plugin: module.default, directory };
}

/// The hooks a plugin registered, by name.
function registered(plugin, pluginConfig = {}) {
  const hooks = new Map();
  const warnings = [];
  plugin.register({
    pluginConfig,
    logger: { warn: (text) => warnings.push(text), error: (text) => warnings.push(text) },
    on: (name, handler) => hooks.set(name, handler),
  });
  return { hooks, warnings };
}

const CALL = {
  toolName: "exec",
  params: { command: "ls -la", workdir: "/work" },
  toolCallId: "call_1|fc_1",
};
const CONTEXT = { sessionId: "s-1", sessionKey: "agent:main:main", runId: "r-1", agentId: "main" };

/// A stand-in bridge that prints `answer` and exits 0.
const prints = (answer) =>
  `import sys\nsys.stdout.write(${JSON.stringify(JSON.stringify(answer))})\n`;

const tests = {
  async "registers the hooks the engine judges or records"() {
    const { plugin } = await withBridge(prints({ action: "allow" }));
    const { hooks } = registered(plugin);
    assert.deepEqual(
      [...hooks.keys()].sort(),
      [
        "after_tool_call",
        "agent_end",
        "before_agent_finalize",
        "before_agent_run",
        "before_prompt_build",
        "before_tool_call",
        "session_end",
      ],
    );
  },

  async "a block reaches OpenClaw as a block with the engine's reason"() {
    const { plugin } = await withBridge(prints({ action: "block", reason: "touches the hooks" }));
    const { hooks } = registered(plugin);
    const answer = await hooks.get("before_tool_call")(CALL, CONTEXT);
    assert.deepEqual(answer, { block: true, blockReason: "touches the hooks" });
  },

  async "a review is put to the user rather than denied"() {
    const { plugin } = await withBridge(prints({ action: "ask", reason: "nobody asked for this" }));
    const { hooks } = registered(plugin);
    const answer = await hooks.get("before_tool_call")(CALL, CONTEXT);
    assert.equal(answer.block, undefined);
    assert.equal(answer.requireApproval.description, "nobody asked for this");
    assert.deepEqual(answer.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  },

  async "an allow is nothing at all"() {
    const { plugin } = await withBridge("import sys\n");
    const { hooks } = registered(plugin);
    assert.equal(await hooks.get("before_tool_call")(CALL, CONTEXT), undefined);
  },

  async "a bridge that cannot run blocks the call"() {
    // Python itself failing — a module it could not import, a crash, a kill — ends with
    // nothing printed. An empty answer from a bridge that did not exit cleanly is no allow.
    const { plugin } = await withBridge("import sys\nraise SystemExit(1)\n");
    const { hooks } = registered(plugin);
    const answer = await hooks.get("before_tool_call")(CALL, CONTEXT);
    assert.deepEqual(answer, { block: true, blockReason: BLOCKED });
  },

  async "watching only, nothing is held back"() {
    const { plugin } = await withBridge("import sys\nraise SystemExit(1)\n");
    const { hooks } = registered(plugin);
    process.env.WITHHUMAN_MODE = "observe";
    try {
      assert.equal(await hooks.get("before_tool_call")(CALL, CONTEXT), undefined);
    } finally {
      delete process.env.WITHHUMAN_MODE;
    }
  },

  async "a bridge that could not write its decision blocks the call"() {
    const { plugin } = await withBridge("import sys\nraise SystemExit(2)\n");
    const { hooks } = registered(plugin);
    const answer = await hooks.get("before_tool_call")(CALL, CONTEXT);
    assert.deepEqual(answer, { block: true, blockReason: BLOCKED });
  },

  async "an answer that does not parse blocks the call"() {
    const { plugin } = await withBridge("import sys\nsys.stdout.write('not json')\n");
    const { hooks } = registered(plugin);
    const answer = await hooks.get("before_tool_call")(CALL, CONTEXT);
    assert.deepEqual(answer, { block: true, blockReason: BLOCKED });
  },

  async "an event that decides nothing is never blocked"() {
    const { plugin } = await withBridge("import sys\nsys.stdout.write('not json')\n");
    const { hooks } = registered(plugin);
    assert.equal(await hooks.get("after_tool_call")({ toolName: "exec" }, CONTEXT), undefined);
    assert.equal(await hooks.get("agent_end")({ success: true }, CONTEXT), undefined);
  },

  async "the hook's context reaches the bridge with its event"() {
    // The event carries the call; only the context says which session and turn it is of.
    const script = [
      "import json, sys",
      "payload = json.load(sys.stdin)",
      "sys.stdout.write(json.dumps({'action': 'block', 'reason': json.dumps(payload, sort_keys=True)}))",
      "",
    ].join("\n");
    const { plugin } = await withBridge(script);
    const { hooks } = registered(plugin);
    const answer = await hooks.get("before_tool_call")(CALL, {
      ...CONTEXT,
      workspaceDir: "/work",
      abortSignal: new AbortController().signal,
      trace: () => {},
    });
    const sent = JSON.parse(answer.blockReason);
    assert.equal(sent.sessionId, "s-1");
    assert.equal(sent.runId, "r-1");
    assert.equal(sent.workspaceDir, "/work");
    assert.equal(sent.toolName, "exec");
    assert.equal(sent.hook_event_name, "before_tool_call");
    // What cannot be sent as JSON is left out rather than breaking the call.
    assert.equal("trace" in sent, false);
    assert.equal("abortSignal" in sent, false);
  },

  async "a hook this host does not take is reported, not thrown"() {
    const { plugin } = await withBridge(prints({ action: "allow" }));
    const warnings = [];
    plugin.register({
      pluginConfig: {},
      logger: { warn: (text) => warnings.push(text), error: (text) => warnings.push(text) },
      on: (name) => {
        if (name === "agent_end") throw new Error("unknown typed hook");
      },
    });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /agent_end/);
  },

  async "the turn's instruction is kept and put in front of the next turn's prompt"() {
    // The engine sends it back with the prompt, after OpenClaw has already built that prompt.
    // The text is the same every turn, so the turns after get it.
    const script = [
      "import json, sys",
      "json.load(sys.stdin)",
      "sys.stdout.write(json.dumps({'action': 'context', 'text': '[의도] 줄을 먼저 쓸 것'}))",
      "",
    ].join("\n");
    const { plugin } = await withBridge(script);
    const { hooks } = registered(plugin);

    // Nothing has been sent yet: the first turn of a Gateway goes without it.
    assert.equal(await hooks.get("before_prompt_build")({}, CONTEXT), undefined);

    await hooks.get("before_agent_run")({ prompt: "fix the build" }, CONTEXT);
    assert.deepEqual(await hooks.get("before_prompt_build")({}, CONTEXT), {
      prependSystemContext: "[의도] 줄을 먼저 쓸 것",
    });
  },

  async "an engine that stops asking for an intent clears the instruction"() {
    const empty = [
      "import json, sys",
      "json.load(sys.stdin)",
      "sys.stdout.write(json.dumps({'action': 'context', 'text': ''}))",
      "",
    ].join("\n");
    const { plugin } = await withBridge(empty);
    const { hooks } = registered(plugin);
    await hooks.get("before_agent_run")({ prompt: "p" }, CONTEXT);
    // A stale instruction would keep asking for a line the engine no longer reads.
    assert.equal(await hooks.get("before_prompt_build")({}, CONTEXT), undefined);
  },

  async "building a prompt never runs the bridge"() {
    // The bridge here fails outright; answering the prompt build from what is kept must not
    // depend on it, and must not block a turn.
    const { plugin } = await withBridge("import sys\nraise SystemExit(1)\n");
    const { hooks } = registered(plugin);
    assert.equal(await hooks.get("before_prompt_build")({}, CONTEXT), undefined);
  },

  async "the configured address reaches the bridge"() {
    const script = [
      "import json, os, sys",
      "sys.stdout.write(json.dumps({'action': 'block', 'reason': os.environ.get('WITHHUMAN_SERVER', '')}))",
      "",
    ].join("\n");
    const { plugin } = await withBridge(script);
    delete process.env.WITHHUMAN_SERVER;
    const { hooks } = registered(plugin, { server: "http://127.0.0.1:3000" });
    const answer = await hooks.get("before_tool_call")(CALL, CONTEXT);
    assert.equal(answer.blockReason, "http://127.0.0.1:3000");
    delete process.env.WITHHUMAN_SERVER;
  },
};

let failed = 0;
process.env.WITHHUMAN_PYTHON = process.env.WITHHUMAN_PYTHON || "python3";
for (const [name, test] of Object.entries(tests)) {
  try {
    await test();
    console.log(`ok   ${name}`);
  } catch (error) {
    failed += 1;
    console.log(`FAIL ${name}\n     ${error?.message ?? error}`);
  }
}
console.log(`\n${Object.keys(tests).length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
