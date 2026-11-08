"""Tests for the graph viewer's PostgreSQL reads and session delete, on synthetic rows.

    GRAPH_VIEWER_TEST_DATABASE_URL=postgres://... python3 tools/graph-viewer/test_server.py

The database named there is wiped: its public schema is dropped and recreated from the
engine's schema. Without the variable the tests are skipped.
"""

import json
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import os  # noqa: E402

URL = os.environ.get("GRAPH_VIEWER_TEST_DATABASE_URL")
SCHEMA = HERE.parents[1] / "crates/common/sql/postgres_schema.sql"
S = "session-a"
OLD = 1_700_000_000_000

if URL:
    os.environ["DATABASE_URL"] = URL
    import psycopg

    import server


def insert(db, table, **row):
    columns = ", ".join(f'"{key}"' for key in row)
    db.execute(f"INSERT INTO {table} ({columns}) VALUES ({', '.join(['%s'] * len(row))})", list(row.values()))


def event(db, session, order, observed_at, meta=None, codex=None):
    body = {"session_id": session, "order": order, "meta": meta or {"agent_kind": None}}
    if codex is not None:
        body["codex_payload"] = codex
    insert(db, "event_commits", session_id=session, order=order, version=order, event_name="E",
           observed_at=observed_at, event_json=json.dumps(body), has_node=True)


def node(db, session, seq, kind, **columns):
    insert(db, "nodes", session_id=session, seq=seq, kind=kind, event_name=columns.pop("event_name", "E"),
           order=seq, observed_at=columns.pop("observed_at", OLD + seq), **columns)


@unittest.skipUnless(URL, "GRAPH_VIEWER_TEST_DATABASE_URL is not set")
class ViewerTest(unittest.TestCase):
    def setUp(self):
        with psycopg.connect(URL, autocommit=True) as db:
            db.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            db.execute(SCHEMA.read_text(encoding="utf-8"))
            insert(db, "sessions", session_id=S, version=7, created_at=OLD)
            node(db, S, 1, "Request", subgraph=0, cwd="/w/project", client_id="cond/case",
                 payload_json=json.dumps({"prompt": "fix the bug"}))
            node(db, S, 2, "Intent", subgraph=0, intent="first", next_seq=1, next_via="request")
            node(db, S, 3, "Call", subgraph=1, tool_use_id="t1", next_seq=2, next_via="order",
                 decision="DENY", decision_rule="intent::mismatch", intent_score=1.0,
                 parents=["s0", "s1"], trace_json=json.dumps({"link": "request", "deviation": {"score": 0.5}}),
                 payload_json=json.dumps({"tool_name": "Write", "tool_input": {
                     "file_path": "a.py", "content": "# REPOGUARD_BACKDOOR_MARKER\n"}}))
            node(db, S, 4, "Segment", subgraph=1, tool_use_id="t1", next_seq=3, next_via="call",
                 payload_json="x" * (server.PREVIEW_CHARS + 10))
            node(db, S, 5, "Call", subgraph=1, tool_use_id="t2", decision="ALLOW", trace_error="boom")
            node(db, S, 6, "Intent", subgraph=2, intent="latest")
            insert(db, "subgraphs", session_id=S, number=0)
            insert(db, "subgraphs", session_id=S, number=1, parent="s0", parents=["s0"],
                   parent_call_seq=3, parent_call_order=3)
            insert(db, "subgraphs", session_id=S, number=9)
            insert(db, "paragraphs", session_id=S, seq=4, index=1, hash="h1", text="second", hidden=False)
            insert(db, "paragraphs", session_id=S, seq=4, index=0, hash="h0", text="hidden one",
                   hidden=True, hidden_rules=["html_comment"], instructs=0.9)
            insert(db, "cause_edges", session_id=S, call_seq=5, target_seq=4, target_index=0,
                   probability=0.75, rank=1, parent="s1")
            insert(db, "cause_edges", session_id=S, call_seq=3, target_seq=1, probability=1.0, rank=1)
            insert(db, "tokens", session_id=S, key_kind="email", key="k", slot="user", node_seq=1,
                   node_order=1, decoded="a@b.lab", category="contact")
            insert(db, "token_mentions", session_id=S, node_seq=1, key_kind="email", key="k", slot="user")
            insert(db, "files", repository="r", path="a.py")
            insert(db, "file_refs", session_id=S, node_seq=3, repository="r", path="a.py")
            for order in range(1, 7):
                event(db, S, order, OLD + order)
            # A Codex session, active just now, and one the list skips.
            now = int(time.time() * 1000)
            insert(db, "sessions", session_id="codex-1", version=1, created_at=OLD + 100)
            node(db, "codex-1", 1, "Call", tool_use_id="c1", observed_at=now,
                 payload_json=json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}))
            event(db, "codex-1", 1, now, meta={"agent_kind": "codex"},
                  codex={"tool_name": "exec_command", "tool_input": {"cmd": "ls"}})
            insert(db, "sessions", session_id="uncreated", version=0)
        self.tearDown()

    def tearDown(self):
        while not server._connections.empty():
            server._connections.get().close()

    def test_graph_rebuilds_properties_and_edges(self):
        graph = server.graph(S)
        nodes = {n["props"]["seq"]: n for n in graph["nodes"]}
        self.assertEqual([n["props"]["seq"] for n in graph["nodes"]], [1, 2, 3, 4, 5, 6])
        call = nodes[3]["props"]
        self.assertEqual(nodes[3]["kind"], "Call")
        self.assertNotIn("kind", call)
        self.assertNotIn("next_seq", call)
        self.assertNotIn("agent_id", call)  # null columns are absent, as in properties()
        self.assertIsInstance(call["intent_score"], float)
        self.assertEqual(json.dumps(call["intent_score"]), "1.0")
        self.assertEqual(call["parents"], ["s0", "s1"])
        self.assertEqual(nodes[3]["summary"], {"tool_name": "Write", "brief": "a.py"})
        self.assertTrue(nodes[4]["props"]["payload_json"].endswith("…"))
        edges = sorted(graph["edges"], key=lambda e: (e["source"], e["target"], e["type"]))
        self.assertEqual(edges, [
            {"source": 1, "target": 2, "type": "NEXT", "paragraph": None,
             "props": {"via": "request", "edge_id": f"{S}:1:2", "probability": 1.0}},
            {"source": 2, "target": 3, "type": "NEXT", "paragraph": None,
             "props": {"via": "order", "edge_id": f"{S}:2:3", "probability": 1.0}},
            {"source": 3, "target": 1, "type": "NEXT", "paragraph": None,
             "props": {"kind": "cause", "call_seq": 3, "probability": 1.0, "rank": 1}},
            {"source": 3, "target": 4, "type": "NEXT", "paragraph": None,
             "props": {"via": "call", "edge_id": f"{S}:3:4", "probability": 1.0}},
            {"source": 4, "target": 3, "type": "RESULT_OF", "paragraph": None, "props": {}},
            {"source": 5, "target": 4, "type": "NEXT", "paragraph": 0,
             "props": {"kind": "cause", "call_seq": 5, "probability": 0.75, "rank": 1, "parent": "s1"}},
        ])
        groups = {g["props"]["number"]: g for g in graph["subgraphs"]}
        self.assertEqual(sorted(groups[1]["members"]), [3, 4, 5])
        self.assertEqual(groups[1]["props"], {"session_id": S, "number": 1, "parent": "s0", "parents": ["s0"],
                                              "parent_call_seq": 3, "parent_call_order": 3})
        self.assertEqual(groups[9], {"props": {"session_id": S, "number": 9}, "members": []})
        self.assertEqual(server.graph("no-such-session"), {"nodes": [], "subgraphs": [], "edges": []})

    def test_node_detail(self):
        detail = server.node(S, 4)
        self.assertEqual(detail["kind"], "Segment")
        self.assertEqual(detail["props"]["payload_json"], "x" * (server.PREVIEW_CHARS + 10))
        self.assertEqual(detail["paragraphs"], [
            {"index": 0, "hidden": True, "hidden_rules": ["html_comment"], "text": "hidden one",
             "source": None, "instructs": 0.9},
            {"index": 1, "hidden": False, "hidden_rules": None, "text": "second", "source": None,
             "instructs": None},
        ])
        self.assertEqual(detail["tokens"], [])
        self.assertNotIn("codex_payload", detail)
        self.assertEqual(server.node(S, 1)["tokens"],
                         [{"kind": "email", "category": "contact", "slot": "user", "decoded": "a@b.lab"}])
        self.assertIsNone(server.node(S, 99))
        self.assertEqual(server.node("codex-1", 1)["codex_payload"],
                         {"tool_name": "exec_command", "tool_input": {"cmd": "ls"}})

    def test_sessions(self):
        rows = server.sessions()
        self.assertEqual([r["id"] for r in rows], ["codex-1", S])
        self.assertEqual(rows[1], {
            "id": S, "version": 7, "created_at": OLD, "nodes": 6, "calls": 2, "denied": 1, "reviewed": 0,
            "allowed": 1, "failed": 1, "intent": "latest", "cwd": "/w/project", "client": "cond/case",
            "last_at": OLD + 6, "prompt": "fix the bug",
        })
        self.assertEqual(rows[0]["agent_kind"], "codex")
        self.assertEqual([r["id"] for r in server.sessions(limit=1)], ["codex-1"])

    def test_calls(self):
        found = server.calls([S, "missing"])
        self.assertEqual(found["missing"], [])
        self.assertEqual([(c["seq"], c["ran"], c["attack"], c["decision"]) for c in found[S]],
                         [(3, True, True, "DENY"), (5, False, False, "ALLOW")])
        self.assertEqual(found[S][0]["score"], 0.5)
        self.assertEqual(found[S][1]["error"], "boom")

    def test_delete_session(self):
        self.assertEqual(server.delete_session("missing")[0], 404)
        status, body = server.delete_session("codex-1")
        self.assertEqual(status, 409, body)
        self.assertEqual(server.sessions(limit=5)[0]["id"], "codex-1")
        # session 1 + event commits 6 + nodes 6 + subgraphs 3 + paragraphs 2 + tokens 1
        self.assertEqual(server.delete_session(S), (200, {"deleted": 19}))
        with psycopg.connect(URL) as db:
            for table in server.SESSION_TABLES + server.EDGE_TABLES:
                left = db.execute(f"SELECT count(*) FROM {table} WHERE session_id = %s", (S,)).fetchone()[0]
                self.assertEqual(left, 0, table)
            self.assertEqual(db.execute("SELECT count(*) FROM files").fetchone()[0], 1)

    def test_http(self):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_port}"
        try:
            with urllib.request.urlopen(f"{base}/api/node?session={S}&seq=99") as response:
                self.assertEqual(response.read(), b"null")
            request = urllib.request.Request(f"{base}/api/session?session=codex-1", method="DELETE")
            with self.assertRaises(urllib.error.HTTPError) as refused:
                urllib.request.urlopen(request)
            self.assertEqual(refused.exception.code, 409)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_connection_error_hides_settings(self):
        self.assertEqual(server.message(psycopg.OperationalError("password=secret")),
                         "데이터베이스에 연결하지 못했습니다.")


if __name__ == "__main__":
    unittest.main()
