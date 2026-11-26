# Hermes Agent

Hermes runs every session of a profile in one gateway, which loads plugins from the profile only,
so WithHuman is set up for the profile rather than a folder. With the same installers, choosing
Hermes (`$env:WITHHUMAN_AGENT = "hermes"`, or `WITHHUMAN_AGENT=hermes` for `setup-project.sh`),
or from a checkout:

```sh
python3 deploy/client/configure.py --agent hermes --server http://127.0.0.1:3000
```

This installs the WithHuman plugin into `$HERMES_HOME/plugins/withhuman/` (when `HERMES_HOME` is
unset, Hermes' own default: `%LOCALAPPDATA%\hermes` on Windows, where the desktop app keeps it, and
`~/.hermes` elsewhere), keeps the engine's address beside it, enables it with
`hermes plugins enable withhuman` and checks that its bridge reaches the engine. Restart Hermes
(`hermes gateway restart`) for it to load; it then applies to every session of that profile,
whichever folder or messaging platform it runs in. `--uninstall` takes it out again.

The plugin forwards Hermes' hooks to `/v1/hooks/hermes/{hook}`: the turn's prompt
(`pre_llm_call`, whose answer asks for the `[의도]` line), each model response before the tools it
asked for run (`post_api_request`), every call (`pre_tool_call`, including calls a script makes
through `execute_code` and deferred tools reached through `tool_call`) and its result. It follows
what only Hermes' process can tell: the session's directory and the one a `cd` leaves for the
next command, the conversation across context compressions, and delegated subagents, whose calls
are judged in the delegating session under their own agent ID. A REVIEW is blocked, as for
Codex: Hermes' own approval prompt is skipped by `--yolo` and `approvals.mode: off`. When the
engine cannot be reached or answer in time, the call is blocked (`WITHHUMAN_MODE=observe` lets it
through). The `[의도]` line stays visible, and configuration changes are not recorded. Verified on
Windows with Hermes Agent 0.23.3.
