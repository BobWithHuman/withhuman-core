# Cursor CLI

Set up a Cursor CLI project with the same one-line installers, choosing Cursor. In the folder you
start `cursor-agent` in, on macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.sh \
  | WITHHUMAN_SERVER=http://127.0.0.1:3000 WITHHUMAN_AGENT=cursor bash
```

or on Windows PowerShell:

```powershell
$env:WITHHUMAN_SERVER = "http://127.0.0.1:3000"; $env:WITHHUMAN_AGENT = "cursor"
irm https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.ps1 | iex
```

This installs the bridge into `<project>/.cursor/hooks/`, adds its entries to
`<project>/.cursor/hooks.json` (other hooks are kept) and checks that the installed bridge reaches
the engine; the user's `~/.cursor` is left alone, and no engine secret goes on the device. Then run
`cursor-agent` in the project and trust the workspace when it asks: Cursor runs no project hook
until you do, so until then the project is not protected. From a checkout,
`python3 deploy/client/configure.py --agent cursor --server <engine>` does the same.

Ten hooks are registered: `preToolUse` and `beforeMCPExecution` judge calls; `postToolUse`,
`postToolUseFailure`, `sessionStart`, `sessionEnd`, `beforeSubmitPrompt`, `afterAgentResponse` and
`stop` record what happened; `beforeReadFile` carries a file's text to the result Cursor leaves it
out of. `beforeShellExecution` and `beforeReadFile`'s own decision are deliberately unused:
`preToolUse` already covers every tool, and judging the same call twice would record it twice.

Cursor cannot show a confirmation prompt from a hook, so a call that needs the user's confirmation
(REVIEW) is blocked, as with Codex.

Two things about Cursor's hooks are worth knowing before you change this setup, both found by
running the real client:

- **The engine's address is never in a hook command.** Cursor 2026.11.22 runs *no hook of the
  file* whose command holds an `http://` address — not that one hook, the whole file, and without
  a word in any log, so every call would go unjudged. The setup writes the address to
  `.cursor/hooks/server` beside the bridge instead, and a test holds the command to that.
- **An allowed call says so.** A hook registered with `failClosed` that answers with nothing is a
  failed hook to Cursor, which blocks the call; so the bridge answers `{"permission":"allow"}`
  rather than staying silent, as it does for Claude Code and Codex. `failClosed` itself is set on
  the two judging hooks only — Cursor otherwise lets a call through when a hook crashes or times
  out, which would lift the control exactly when it is needed.

Known differences from Claude Code: the `[의도]` line stays visible on screen (Cursor shows the
answer before the hook runs). A `cursor-agent -p` run fires no `beforeSubmitPrompt`,
`afterAgentResponse` or `stop`, so such a session reaches the engine without a prompt or an intent
line — run it in `record` or `shadow` mode. A file read's text comes from `beforeReadFile`; a
`Grep` answers with neither its matches nor their text, so a grep's content is not judged.
Configuration changes made outside the agent are not recorded (Cursor has no ConfigChange hook).
Cursor Tab's own file access is outside this protection, and Cloud Agents support a different set
of hooks. Verified on macOS with Cursor CLI 2026.11.22; Windows is not verified yet.
