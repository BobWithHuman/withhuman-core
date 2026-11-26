# WithHuman

**Stops the tool calls your coding agent didn't get from you.**

A coding agent reads READMEs, issues, web pages and MCP results while it works. Any of them can
carry an instruction. WithHuman traces every tool call back to where it came from — your request,
or text the agent read — and holds back the ones you never asked for.

<!-- demo: docs/assets/demo.gif — agent reads a poisoned file → tries a call → blocked → cause graph -->

## What it does

- **Traces each call to its cause.** Before a tool call runs, the engine finds what led to it:
  the request you typed, or a paragraph in a file, page or tool result.
- **Blocks or asks.** A call that follows from text you didn't write is denied, or put to you
  where the agent can ask.
- **Keeps the whole session as a graph.** Every prompt, call, result and verdict, with the path
  from a blocked call back to the text that told it.
- **Fails closed.** When the engine can't be reached or can't judge in time, the call is denied.

## Supported agents

| Agent | Setup | Notes |
|---|---|---|
| Claude Code | per user, per project, or managed for the whole device | the engine's reference agent; asks you before a held call |
| Codex CLI | per project | verified on Windows |
| Cursor CLI | per project | verified on macOS |
| Hermes Agent | per profile | verified on Windows |
| OpenClaw | per device | verified on Linux; asks you before a held call |

Each agent's hooks reach a different amount of the session. What that changes is in
[docs/agents](docs/agents).

## Quickstart

Docker 24+ with Compose 2.20+ and Python 3.

```sh
git clone https://github.com/BobWithHuman/withhuman-core.git
cd withhuman-core
cp .env.example .env
```

Edit `.env`:

| Variable | Set to |
|---|---|
| `POSTGRES_PASSWORD` | a long random password (URL-safe characters) |
| `JEV_API_KEY` | your key for Jev, the model that answers the engine's questions |
| `WITHHUMAN_MODE` | `enforce` to block; the default `shadow` judges and records but blocks nothing |
| `GATEWAY_BIND` | `127.0.0.1`, so the engine listens on this machine only |

Start the engine and set Claude Code up for every folder you work in:

```sh
docker compose up --detach --wait
python3 deploy/client/configure.py --scope user --team personal --server http://127.0.0.1:3000
```

Start a new Claude Code session. Its tool calls now go through WithHuman. To take it out again:

```sh
python3 deploy/client/configure.py --scope user --uninstall
```

Other agents: [Codex CLI](docs/agents/codex.md) · [Cursor CLI](docs/agents/cursor.md) ·
[Hermes Agent](docs/agents/hermes.md) · [OpenClaw](docs/agents/openclaw.md)

## What leaves your machine

- **Hooks → your engine.** The agent's hooks send each prompt, call and result to the engine you
  run (`--server`). Sessions are stored in its PostgreSQL.
- **Engine → Jev.** To judge a call, the Decision service sends Jev the text it needs: the
  request, the call, and the text the agent read before it. The endpoint is `JEV_URL`
  (`https://api.typesafe.ai` by default).
- Nothing else is sent anywhere.

## Limits

- WithHuman sees what the agent's hooks report. A program the agent starts that then acts on
  its own, or an agent running without the hooks, is outside it.
- Codex, Cursor and Hermes can't show a confirmation prompt from a hook, so a call that needs
  your confirmation is blocked there.
- It judges where a call came from, not whether its code is safe. Pair it with your usual
  sandboxing and review.

## Documentation

| | |
|---|---|
| [Deployment](docs/deployment.md) | Docker, PostgreSQL, upgrading from Neo4j, Claude Code setup options, maintenance |
| [Judging](docs/judging.md) | grades, failure handling, rules-only mode |
| [Administration](docs/administration.md) | per-user keys, kill switch, device inventory, triage, the security team's viewer |
| [Devices from Wazuh](docs/wazuh.md) | matching registered devices with an EDR's device list |
| [Adding another agent](docs/agents/adding-an-agent.md) | the three pieces an adapter needs |
| [Infrastructure](infra/README.md) | the shared cluster profile |

## License

[MIT](LICENSE)
