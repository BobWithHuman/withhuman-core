# OpenClaw

OpenClaw runs every session of a state directory in one Gateway, which loads plugins recorded in
that directory's configuration and never from a folder, so WithHuman is set up for the device
rather than a project. With the same installers, choosing OpenClaw
(`WITHHUMAN_AGENT=openclaw`), or from a checkout:

```sh
python3 deploy/client/configure.py --agent openclaw --server http://127.0.0.1:3000
```

**Stop OpenClaw first.** Its Gateway owns the configuration and refuses a change to it while it
runs — including an embedded one, which `openclaw chat` starts — and the setup cannot finish
without that change. Unlike Hermes', the plugin is not copied into place here: `openclaw` keeps a
registry of what is installed, so the files are staged in `~/.openclaw/withhuman-setup/` and its
own CLI installs them from there, enables them, and is told the engine's address and
`hooks.allowConversationAccess`. Then start OpenClaw again: a plugin is loaded when the Gateway
starts, so until then the device is not protected. Another state directory
(`OPENCLAW_STATE_DIR`, which `--dev` and a named profile set) is set up on its own.

Seven hooks are registered: `before_tool_call` judges calls; `after_tool_call`,
`before_agent_run`, `before_agent_finalize`, `agent_end` and `session_end` record what happened;
and `before_prompt_build` is where the turn's instruction goes in. That one is answered from what
the engine last sent, without running the bridge.

**`allowConversationAccess` is not optional.** OpenClaw refuses a plugin the hooks that carry a
turn — the prompt, the answer and the turn's end — unless
`plugins.entries.withhuman.hooks.allowConversationAccess` is `true`. Without it the calls are
still judged, but against nothing: no prompt, no `[의도]` line, no causal path. The installer sets
it; taking it away leaves the device at `record` level.

OpenClaw can **ask** rather than only block. Its `before_tool_call` takes `requireApproval`, which
pauses the call until the user answers and blocks it on a deny or a timeout, so a call that needs
the user's confirmation (REVIEW) is put to them. That is also why a call hard to undo that the
engine could not judge is put to them instead of being blocked outright.

Four things about OpenClaw are worth knowing before you change this setup, all found by running
the real client:

- **Only its plugin hooks can hold a call back.** OpenClaw's other hook system — the automation
  hooks of `openclaw hooks`, in a workspace's `hooks/` folder — carries no tool event at all and
  cannot abort what it observes. That is why the client is a plugin.
- **A call may run another call.** `dispatch_action` names an action and the action arrives a
  second time as a call of its own. Blocking the dispatch keeps the action from running at all,
  while what blocking the dispatched call does is not known, so the dispatch is the one judged and
  the second call is passed over. An MCP call arrives this way too, which is why the hook enforces
  MCP rather than leaving it to AgentGateway.
- **The tool hooks name no directory.** Only the turn's hooks carry `workspaceDir`, so the bridge
  remembers it from the turn and fills it in; a shell call's own `workdir` is preferred when it has
  one.
- **The bridge's state is OpenClaw's, not the plugin's.** OpenClaw builds a package of a plugin
  when it installs one, and what the Gateway loads may be a copy of it; state beside the plugin
  file followed that copy and was lost with it, which left no audit log at all. It lives in
  `~/.openclaw/withhuman-state/` instead, which `OPENCLAW_STATE_DIR` moves with a profile and the
  engine protects as it does the rest of OpenClaw's configuration.

The standing instruction that asks each turn for its `[의도]` line reaches the model one turn late,
and that is as early as OpenClaw allows. The engine sends it back with the prompt, and OpenClaw
builds the prompt before the hook carrying it runs, so the plugin keeps the instruction — it is
the same text every turn — and puts it in front of the system context of the turns after, the way
OpenClaw's own `agent-guidance` plugin adds instructions. The first turn of a Gateway goes without
it: the engine asks that turn for its intent by turning its first call back, which the model reads
and retries, so that one turn costs an extra call attempt.

**OpenClaw has more tools than this adapter has counterparts for.** The ones a session actually
reaches are translated — `exec`, `read`, `write`, `edit`, `ls`, `apply_patch`, `web_search` and the
tool a `dispatch_action` names. The rest keep their own name, are marked `openclaw_untranslated` on
the event, and are placed by the words in that name, which for most of OpenClaw's says nothing:
`process` is not `execute`, `canvas` is not a verb. Such a call is still judged on whether it
serves what the user asked, but no rule for the kind of thing it does applies to it.
`services/decision/tests/check_openclaw.rs` holds the list as it stands. This was checked rather
than assumed: a model asked for `plugins`, `openclaw`, `terminal`, `code_execution` or `secrets`
looked for each, found none — they are behind plugins or capabilities a default OpenClaw does not
enable — and reached for the shell instead, where the safeguard rules already apply. An operator
who turns those on should classify them with `WITHHUMAN_TOOL_CATEGORIES`, the `tool_name,category`
table the decision service reads before judging a tool by its name (`.env.example`).

Known differences from Claude Code: a blocked call's reason reaches the model, not the person. The
model relays it in its own words, and the local audit log
(`~/.openclaw/withhuman-state/audit.jsonl`) holds what was decided; OpenClaw's plugin hooks have
no surface for showing a person text, which is why its own 1Password plugin — a security plugin
with an approval policy and an audit history — does the same. A REVIEW is the exception: its reason
is the approval's description, which the person reads. The reminder the engine adds to a tool
result while a turn has stated no intent has nowhere to go either, since `after_tool_call` only
reports. `session_start` and `session_end` did not fire in any recorded session, so the client
opens a session itself. Subagents and changes to what the agent can do (`skill_changed`,
`before_install`, `cron_changed`) are accepted and passed over: a default OpenClaw does not
reach them either. A model asked to spawn a subagent searched for `subagents` and
`sessions_spawn` and found neither, and the one of those tools it did reach
(`skill_workshop`, through a `dispatch_action`) only listed what was there. They are
translated when a session that fires them can be recorded. OpenClaw's tool surface is
not fixed — `tool_search` lets the model look tools up mid-turn — so what an agent can call cannot
be read off a session's start. Verified on Linux with OpenClaw 2026.11.7; macOS and Windows are not
verified yet.
