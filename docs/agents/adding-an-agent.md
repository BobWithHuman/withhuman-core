# Adding another agent

Claude Code's hook contract is the engine's own form: its hooks reach `/v1/hooks/<Event>`
unchanged, and every other agent is translated into them, so the normalization, graph and
judgment behind them are the same code for every agent. Adding one is three pieces, each with
its own seam and nothing else to change:

| Piece | Where | What it is |
|---|---|---|
| Hook input | `crates/contracts/src/<kind>.rs` | the agent's own hook JSON, with a fixture per event under `crates/contracts/tests/fixtures/<kind>/` — recorded from the real client, not read off its documentation |
| Translation | `services/collector/src/<kind>.rs` | `impl Agent` (see `agent.rs`): each hook as the Claude Code request doing the same thing, and the few answers its client reads differently. Name it in `agent::REGISTRY` and it has its route, `/v1/hooks/<kind>/{event}` |
| Client bridge | `deploy/client/<kind>/` | a `withhuman_bridge.Bridge` subclass: what only the client can see (its transcript, the directory a command runs in, the program files a command would run). Its installer is one `AgentSetup` in `deploy/client/configure.py` |

The engine's rules are written against Claude Code's tools, so a tool is translated to the
Claude Code tool doing the same thing rather than to a name of its own: Codex's shell calls
become `Bash` (or `PowerShell`), its one-file patches `Write`, `Edit` or `MultiEdit`, its web
operations `WebSearch` or `WebFetch`; Cursor's `Shell` becomes `Bash`, and its `Grep` keeps its
pattern under the name the rules read it by.

How much of an agent the hooks reach decides how much work its bridge is, and the two supported
agents sit at opposite ends: Cursor's hooks carry the prompt, the model's answer, the directory a
command runs in and a call's exit code, so its bridge is one 230-line file; Codex's carry none of
those, so its bridge reads the session transcript in 560 lines more. Record what the client
actually sends before writing either. What decides how much protection an agent can get is how
much its hooks tell: the engine needs the turn's intent before the first call of that turn, a
call's input before it runs, its result afterwards, and a way to answer with a block. An agent
whose hooks cannot carry the intent line can still be run in `record` or `shadow` mode.
