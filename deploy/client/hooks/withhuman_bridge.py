#!/usr/bin/env python3
"""What every WithHuman client bridge shares.

A bridge forwards one coding agent's hooks to the Collector's agent route
(`/v1/hooks/<kind>/<event>`), which translates them into the Claude Code hooks the engine
already judges, and prints the engine's answer in the form that agent reads. Claude Code needs
no bridge: its hooks are the form every other agent is translated into, so it posts to the
engine itself (`deploy/client/settings.json`) and runs only `pre-tool-use.py`.

What lives here is the same for every agent: reading the device's client ID and the user's key,
the HTTP call and its deadline, the durable outbox that delivers derived events exactly once,
the session state file and its lock, the local audit log, and the rule that in enforce mode
every failure ends in a decision rather than in a call nobody judged.

Adding an agent: subclass `Bridge` in `deploy/client/<kind>/`, give it `kind`, `name` and the
events whose answer can block a call, and write `run` — it sends what the agent's hooks say,
plus whatever only the client can see (its transcript, the directory a command runs in, the
program files a command would run). Override `output` and `deny` when the agent reads a shape
of its own; the default is Claude Code's, which Codex reads too. `main` does the rest.

Python 3.8 or later, standard library only; Windows and macOS.
"""

import hashlib
import importlib.util
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

# What an agent is told when WithHuman could not judge a call. It reaches the model, not a
# person, so it says nothing of the engine's inner workings.
BLOCKED = "WithHuman could not check this call, so it was blocked"


class BridgeError(Exception):
    """Something kept the event from being judged."""


# ---- what the device and the user are ----


def setting(name, file):
    """The environment variable `name`, else the setup's file of that name."""
    value = os.environ.get(name, "").strip()
    if value:
        return value
    try:
        path = os.path.join(os.path.expanduser("~"), ".config", "withhuman", file)
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def client_id():
    return setting("WITHHUMAN_CLIENT_ID", "client-id")


def key():
    """The user's WithHuman key, sent as `Authorization: Bearer`."""
    return setting("WITHHUMAN_KEY", "key")


def load_programs():
    """`programs()` of the Claude Code PreToolUse hook beside this one, reused as it is: the
    program files a shell command may run, read just before the call."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "pre-tool-use.py")
    if not os.path.isfile(path):
        path = os.path.join(here, "..", "hooks", "pre-tool-use.py")
    spec = importlib.util.spec_from_file_location("withhuman_pre_tool_use", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.programs


# ---- the engine ----


class Collector:
    def __init__(self, server, kind, deadline, headers):
        self.server = server.rstrip("/")
        self.kind = kind
        self.deadline = deadline
        self.headers = headers

    def post(self, event, body, delivery_id=None):
        """The Collector's answer to `body` on this agent's route: its parsed JSON, or None when
        empty. Raises BridgeError for anything but a 200 in time."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0.05:
            raise BridgeError("no time left")
        request = urllib.request.Request(
            f"{self.server}/v1/hooks/{self.kind}/{event}",
            data=json.dumps(body).encode("utf-8"),
            headers={**self.headers,
                     **({"x-withhuman-event": delivery_id} if delivery_id else {})},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=remaining) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            raise BridgeError(f"Collector answered {error.code}") from error
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise BridgeError(f"Collector unreachable: {error}") from error
        if status != 200:
            raise BridgeError(f"Collector answered {status}")
        if not raw.strip():
            return None
        try:
            answer = json.loads(raw)
        except ValueError as error:
            raise BridgeError("Collector answer is not JSON") from error
        if not isinstance(answer, dict):
            raise BridgeError("Collector answer is not an object")
        return answer


# ---- a transcript the agent appends to ----


class TranscriptError(Exception):
    """The transcript could not be read."""


def read_records(path, offset):
    """The JSON records of the complete lines after byte `offset`, and the offset after them.

    Several agents keep the session as a JSONL file they append to, and a bridge reads it for
    what the agent's hooks leave out. A line the agent is still writing (no newline yet) is
    left for the next read. Invalid complete records and a truncated transcript cannot advance
    the confirmed cursor.
    """
    if not path:
        raise TranscriptError("no transcript path")
    try:
        with open(path, "rb") as file:
            size = os.fstat(file.fileno()).st_size
            if offset > size:
                raise TranscriptError("transcript was truncated; start a new session")
            file.seek(offset)
            data = file.read()
    except OSError as error:
        raise TranscriptError(str(error)) from error
    end = data.rfind(b"\n") + 1
    records = []
    for line in data[:end].split(b"\n"):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError as error:
            raise TranscriptError("invalid transcript record") from error
        if not isinstance(record, dict):
            raise TranscriptError("transcript record is not an object")
        records.append(record)
    return records, offset + end


def file_size(path):
    try:
        return os.path.getsize(path)
    except (OSError, TypeError):
        return 0


# ---- what the hook remembers between its runs ----


class State:
    """What a bridge remembers of one session between its runs, kept in a JSON file.

    An agent that needs more of its own adds it to `DEFAULTS`; `outbox` and `resync_required`
    are every bridge's, and `drain` is the only code that changes them.
    """

    #: Kept by every bridge: the events delivered but not yet acknowledged, and whether the
    #: engine's state and this file have parted ways.
    BASE_DEFAULTS = {"outbox": None, "resync_required": False}
    #: The agent's own, merged over the above.
    DEFAULTS = {}
    #: How long a run waits for a state file another run of this hook holds.
    lock_wait = 3.0
    #: The state file's extension. An agent that reads every `.json` file under the folder this
    #: state sits in, as its own configuration, gets another one.
    SUFFIX = ".json"

    def __init__(self, directory, session_id):
        key_of = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
        self.path = os.path.join(directory, key_of + self.SUFFIX)
        #: Where an earlier version of the bridge kept this session's state.
        self.legacy_path = os.path.join(directory, key_of + ".json")
        self.lock_path = self.path + ".lock"
        self.locked = False
        self.state = {**State.BASE_DEFAULTS, **self.DEFAULTS}

    def __enter__(self):
        """Takes the session's lock, waiting while a parallel hook holds it. Without the lock
        the session is still read but its state is not changed."""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        deadline = time.monotonic() + self.lock_wait
        while True:
            try:
                os.close(os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                self.locked = True
                break
            except FileExistsError:
                # Never steal a lock from a live or interrupted hook. Its delivery may have
                # reached the engine; a new session is the safe recovery path.
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
        if self.locked and self.path != self.legacy_path and not os.path.exists(self.path):
            # Carried over from where an earlier bridge kept it, so its outbox is not lost and
            # the old file stops being read as something else.
            try:
                os.replace(self.legacy_path, self.path)
            except FileNotFoundError:
                pass
            except OSError:
                # `__exit__` does not run when `__enter__` raises: without this the lock would
                # outlive the run and turn back every later call of the session.
                self.__exit__(None, None, None)
                raise
        try:
            with open(self.path, encoding="utf-8") as file:
                loaded = json.load(file)
            if isinstance(loaded, dict):
                self.state.update(loaded)
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            self.state["resync_required"] = True
        return self

    def save(self):
        if not self.locked:
            return
        temporary = self.path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump(self.state, file)
        os.replace(temporary, self.path)

    def __exit__(self, *_):
        if self.locked:
            try:
                os.remove(self.lock_path)
            except OSError:
                pass
            self.locked = False


def drain(session, collector, validate):
    """Commit the candidate cursor only after every event has an engine receipt.

    Retrying the exact durable ID retrieves a cached success after a lost reply. A pending
    server receipt returns 409 and requires a new session; it is never applied twice.
    `validate(event, answer)` reads the answer as the agent does, so a decision that does not
    parse is not acknowledged, replayed answers included.
    """
    transaction = session.state.get("outbox")
    if not transaction:
        return None
    while transaction["index"] < len(transaction["events"]):
        entry = transaction["events"][transaction["index"]]
        try:
            answer = collector.post(entry["event"], entry["body"], entry["id"])
            validate(entry["event"], answer)
        except BridgeError as error:
            if "Collector answered" in str(error) or "answer is not" in str(error):
                session.state["resync_required"] = True
            session.save()
            raise
        transaction["answer"] = answer
        transaction["index"] += 1
        session.save()
    answer = transaction.get("answer")
    session.state = transaction["next_state"]
    session.state["outbox"] = None
    session.save()
    return answer


def deliver(session, collector, events, next_state, validate):
    """Sends `events` under durable IDs, then makes `next_state` the session's."""
    if not events:
        session.state = next_state
        session.save()
        return None
    session.state["outbox"] = {"index": 0, "events": [
        {"event": name, "body": body, "id": hashlib.sha256(uuid.uuid4().bytes).hexdigest()}
        for name, body in events], "next_state": next_state}
    session.save()
    return drain(session, collector, validate)


# ---- one agent's bridge ----


class Bridge:
    """One coding agent's hooks, as WithHuman forwards them.

    `kind` is the agent's route segment and `name` what messages call it. `deadlines` keeps the
    whole run below the hook timeouts the installer writes, so a slow engine ends in this
    hook's own decision rather than in the agent's timeout, which would let the call run.
    """

    kind = ""
    name = ""
    #: Seconds for the whole run, by event.
    deadlines = {}
    default_deadline = 4.0
    #: Events whose answer can block a call. Every failure on one of these ends in a deny.
    blocking_events = ("PreToolUse",)
    #: The event `--check` probes the engine with. Agents name their hooks differently, and a
    #: name the engine does not know answers 404, which the check would read as no route at all.
    probe_event = "PreToolUse"
    #: Where the engine's address is kept when the agent cannot carry it on the command line.
    #: Cursor 2026.11.22 runs no hook of a file whose command holds an `http://` address, so its
    #: installer writes the address here instead and the command names the event alone.
    server_file = "server"
    #: Where the session state, the outbox and the audit log are kept.
    state_directory = None

    # ---- what reaches the engine ----

    def headers(self):
        found = {"Content-Type": "application/json"}
        if client_id():
            found["x-withhuman-client"] = client_id()
        if key():
            found["Authorization"] = f"Bearer {key()}"
        if os.environ.get("WITHHUMAN_REPO"):
            found["x-withhuman-repo"] = os.environ["WITHHUMAN_REPO"]
        found.update(self.extra_headers())
        return found

    def extra_headers(self):
        """Headers only this agent sends; the engine binds a delivery receipt to them too."""
        return {}

    def server(self):
        """The engine's address: WITHHUMAN_SERVER, else the file the setup wrote beside this
        hook. Used when the agent's command carries the event alone."""
        value = os.environ.get("WITHHUMAN_SERVER", "").strip()
        if value:
            return value
        beside = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), self.server_file)
        try:
            with open(beside, encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            raise BridgeError(
                f"no WithHuman server: set WITHHUMAN_SERVER or run the setup again ({beside})")

    def collector(self, server, event_name):
        deadline = time.monotonic() + float(
            os.environ.get("WITHHUMAN_HOOK_TIMEOUT")
            or self.deadlines.get(event_name, self.default_deadline))
        return Collector(server, self.kind, deadline, self.headers())

    # ---- what reaches the agent ----

    def deny(self, reason):
        """Blocking a call, in the shape this agent reads."""
        return json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }).encode("utf-8")

    def output(self, event, answer):
        """The engine's answer as the agent reads it. An agent that cannot ask the user blocks
        a call on anything but an allow."""
        output = (answer or {}).get("hookSpecificOutput")
        if event in self.blocking_events:
            if output is None:
                if answer is not None:
                    raise BridgeError("Collector answer has no decision")
                return None
            if not isinstance(output, dict):
                raise BridgeError("Collector answer has no decision")
            if output.get("permissionDecision") == "allow":
                return None
            reason = output.get("permissionDecisionReason")
            return self.deny(reason if isinstance(reason, str) and reason else BLOCKED)
        if isinstance(output, dict) and isinstance(output.get("additionalContext"), str):
            return self.context(event, output["additionalContext"])
        return None

    def context(self, event, text):
        """Text the engine puts in front of the model, in the shape this agent reads. This is
        how the turn's intent is asked for, so an agent that ignores the shape never states an
        intent and every first Call of a turn is turned back."""
        return json.dumps({
            "hookSpecificOutput": {"hookEventName": event, "additionalContext": text},
        }).encode("utf-8")

    # ---- the agent's own part ----

    def run(self, collector, event_name, payload):
        """The engine's answer to this hook: what the agent's event says, with what only the
        client can see. `payload` is the hook's stdin, as bytes."""
        raise NotImplementedError

    def self_test(self):
        """Whatever this bridge needs on the device, checked before the engine is."""

    # ---- running ----

    def drain(self, session, collector):
        """Sends what an earlier run left undelivered; see [`drain`]."""
        return drain(session, collector, self.output)

    def deliver(self, session, collector, events, next_state):
        """Sends events the client derived, then advances the session; see [`deliver`]."""
        return deliver(session, collector, events, next_state, self.output)

    def audit(self, event_name, payload, output, error=None):
        """Local evidence also exists when the Collector is stopped and cannot store a DENY."""
        try:
            event = json.loads(payload)
            result = json.loads(output) if output else {}
            decision = self.decision_of(result)
            session_id, tool_use_id = self.ids_of(event)
            row = {"time": time.time(), "session_id": session_id,
                   "event": event_name, "tool_use_id": tool_use_id,
                   "decision": decision or (
                       "allow" if event_name in self.blocking_events else None),
                   "source": "bridge_error" if error else "collector",
                   "error": str(error)[:300] if error else None}
            os.makedirs(self.state_directory, exist_ok=True)
            with open(os.path.join(self.state_directory, "audit.jsonl"), "ab") as file:
                file.write((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8"))
        except Exception:
            pass  # Logging cannot change the decision already made.

    def decision_of(self, answer):
        """The decision this bridge's own output carries, for the local audit log. An agent that
        answers in a shape of its own reads it differently — recording a deny as an allow would
        make the only local evidence say the opposite of what happened."""
        return (answer or {}).get("hookSpecificOutput", {}).get("permissionDecision")

    def ids_of(self, event):
        """The session and the call an event is of, for the local audit log. An agent that
        names them its own way reads them differently — a row naming neither cannot be matched
        to what the engine recorded, which is the whole point of keeping one."""
        return event.get("session_id"), event.get("tool_use_id")

    def check(self, server):
        """Checks the hook can run here and that the engine knows this agent.

        An empty event is sent to the route the hook uses: the Collector rejects it as invalid
        (400) without recording anything. That answer proves the gateway passes the route on and
        the engine has an adapter for this agent; `/healthz` would prove neither, and some
        gateways do not route it.
        """
        self.self_test()
        os.makedirs(self.state_directory, exist_ok=True)
        request = urllib.request.Request(
            f"{server.rstrip('/')}/v1/hooks/{self.kind}/{self.probe_event}", data=b"{}",
            headers=self.headers(), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status, body = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read()
        try:
            answer = json.loads(body or b"{}")
        except ValueError:
            answer = {}
        accepted = ("invalid_json", "invalid_hook", f"invalid_{self.kind}_hook")
        if status == 400 and isinstance(answer, dict) and answer.get("error") in accepted:
            print(f"WithHuman {self.name} hook OK: Python {sys.version.split()[0]}, "
                  f"engine {server} reachable with {self.name} support")
            return 0
        if status == 404:
            raise BridgeError(f"{server} has no {self.name} route: update the engine to a "
                              f"version with {self.name} support")
        # The engine turns a call back before reading it when the key is missing, wrong or
        # revoked.
        refused = (answer.get("hookSpecificOutput") or {}) if isinstance(answer, dict) else {}
        if status == 200 and refused.get("permissionDecision") == "deny":
            raise BridgeError(f"{server} refused this device's WithHuman key: "
                              f"{refused.get('permissionDecisionReason')}")
        raise BridgeError(f"{server} answered {status} to the {self.name} route")

    def main(self, argv=None, payload=None):
        """One hook run, from the agent's arguments and stdin to its decision.

        In enforce mode every failure on a blocking event (engine unreachable or slow, a
        non-200 answer, an answer or input that does not parse, any exception) ends in a deny,
        and in exit 2 if even that cannot be written: an agent runs the call when its hook
        fails, times out, exits 1 or answers `ask`. Other events have nothing to block and only
        report the failure on stderr. WITHHUMAN_MODE=observe lets everything through.
        """
        argv = sys.argv if argv is None else argv
        if len(argv) >= 2 and argv[1] == "--check":
            try:
                return self.check(argv[2] if len(argv) > 2 else self.server())
            except Exception as error:  # noqa: BLE001
                print(f"WithHuman {self.name} hook check failed: {error}", file=sys.stderr)
                return 1
        # `<server> <event>`, or `<event>` alone when the address is kept beside the hook.
        server, event_name = (argv[1], argv[2]) if len(argv) == 3 else (None, None)
        if len(argv) == 2:
            event_name = argv[1]
        blocking = (event_name in self.blocking_events
                    and os.environ.get("WITHHUMAN_MODE", "enforce") != "observe")
        payload = sys.stdin.buffer.read() if payload is None else payload
        failure = None
        try:
            if event_name is None:
                raise BridgeError(
                    f"usage: {os.path.basename(argv[0])} [<WithHuman server>] <hook event>")
            answer = self.run(
                self.collector(server or self.server(), event_name), event_name, payload)
            output = self.output(event_name, answer)
        except BaseException as error:  # noqa: BLE001  (every failure must end in a decision)
            print(f"WithHuman: {error}", file=sys.stderr)
            failure = error
            if not blocking:
                self.audit(event_name, payload, None, error)
                return 0
            output = self.deny(BLOCKED)
        self.audit(event_name, payload, output, failure)
        try:
            if output:
                sys.stdout.buffer.write(output)
                sys.stdout.buffer.flush()
        except BaseException:  # noqa: BLE001
            # A deny that cannot be written still blocks: an agent blocks on exit 2.
            return 2 if blocking else 0
        return 0


def run_bridge(bridge):
    """A bridge's entry point: `sys.exit(run_bridge(MyBridge()))`."""
    try:
        return bridge.main()
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001
        return 2
