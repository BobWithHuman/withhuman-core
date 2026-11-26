# Codex CLI

Set up a Codex CLI project with the same one-line installers, choosing Codex. In the folder you
start `codex` in, on Windows PowerShell:

```powershell
$env:WITHHUMAN_SERVER = "http://127.0.0.1:3000"; $env:WITHHUMAN_AGENT = "codex"
irm https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.ps1 | iex
```

or on macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.sh \
  | WITHHUMAN_SERVER=http://127.0.0.1:3000 WITHHUMAN_AGENT=codex bash
```

This installs the hook into `<project>/.codex/hooks/`, adds its entries to
`<project>/.codex/hooks.json` (other hooks are kept) and checks that the installed hook reaches
the engine; the user's `~/.codex` is left alone, and no engine secret goes on the device. Then
run `codex` in the project, open `/hooks` and trust the WithHuman hooks. Codex skips project
hooks until they are trusted, and again after `hooks.json` changes, so the project is not
protected until you do. Running the installer again updates the setup; with
`WITHHUMAN_UNINSTALL=1` it takes WithHuman out of the project instead. From a checkout,
`python3 deploy/client/configure.py --agent codex --server <engine>` does the same.

Codex cannot show a confirmation prompt, so a call that needs the user's confirmation (REVIEW)
is blocked. Approving it in the conversation does not help: the same call is reviewed and
blocked again. Make such a change yourself, or ask for a different change.

The personal Compose stack starts with the engine's `WITHHUMAN_MODE=shadow`, which records
verdicts but blocks nothing; set `WITHHUMAN_MODE=enforce` in `.env` for blocking. That engine
setting (`record`, `shadow`, `enforce`) is separate from the hook's own `WITHHUMAN_MODE`
(`enforce`, `observe`) in the environment Codex runs in.

The hook sends Codex's events to the Collector's `/v1/hooks/codex/{event}` route, which turns
them into the Claude Code hook requests the engine already judges. MCP calls are enforced by the
hook rather than by AgentGateway. When the engine cannot be reached or does not answer in time,
the hook blocks the call (the hook's `WITHHUMAN_MODE=observe` lets it through).

Known differences from Claude Code: the `[의도]` line Codex writes stays visible on screen, and
configuration changes made outside the agent are not recorded (Codex has no ConfigChange hook).
Simple literal single-file shell writes are checked as Write, and appends as Edit. Partial or
computed edits, multi-file commands and wildcard paths remain shell calls.
Unknown or ambiguous shell working directories block the call. Delivery failures block protected
calls; if the engine cannot confirm an event, start a new session after restoring the service.
Native web operations without hooks are recorded afterward, using only transcript content.
Subsequent input into an already-open shell and a hook that cannot start or is not trusted are
outside this protection. `observe` records activity without enforcing protection.
Verified on Windows with Codex CLI 0.154 and 0.167; macOS is not verified yet.
