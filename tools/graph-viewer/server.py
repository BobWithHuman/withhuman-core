#!/usr/bin/env python3
"""SubGraph timeline viewer for the WithHuman execution graph.

Serves index.html and a read-only JSON API over Neo4j's HTTP query endpoint. It listens on
127.0.0.1 only; forward the port to open it from another machine.

    NEO4J_PASSWORD=... python3 tools/graph-viewer/server.py   # http://127.0.0.1:7480
"""

import base64
import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

NEO4J_URL = os.environ.get("NEO4J_URL", "http://127.0.0.1:7474").rstrip("/")
NEO4J_DATABASE = os.environ.get("NEO4J_DATABASE", "neo4j")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "withhuman-e2e")
ADDRESS = os.environ.get("VIEWER_ADDR", "127.0.0.1")
PORT = int(os.environ.get("VIEWER_PORT", "7480"))

INDEX = Path(__file__).with_name("index.html")
# Tool outputs can hold whole files; the graph carries a preview and the node panel the rest.
PREVIEW_CHARS = 4000

SESSIONS = """
MATCH (s:Session) WHERE s.created_at IS NOT NULL
RETURN s.session_id AS id, s.version AS version, s.created_at AS created_at,
       COUNT { (s)-[:CONTAINS]->() } AS nodes
ORDER BY s.created_at DESC LIMIT 200
"""

NODES = """
MATCH (:Session {session_id: $session})-[:CONTAINS]->(n)
RETURN labels(n)[0] AS kind, properties(n) AS props
ORDER BY n.order
"""

SUBGRAPHS = """
MATCH (g:SubGraph {session_id: $session})
RETURN properties(g) AS props, COLLECT { MATCH (g)-[:MEMBER]->(m) RETURN m.seq } AS members
ORDER BY g.number
"""

EDGES = """
MATCH (:Session {session_id: $session})-[:CONTAINS]->(a)-[r:NEXT|RESULT_OF]->(b)
RETURN a.seq AS source, b.seq AS target, type(r) AS type, properties(r) AS props
"""

NODE = """
MATCH (:Session {session_id: $session})-[:CONTAINS]->(n {seq: $seq})
RETURN labels(n)[0] AS kind, properties(n) AS props,
  COLLECT { MATCH (n)-[:CONTAINS_PARAGRAPH]->(p:Paragraph)
            RETURN {index: p.index, hidden: p.hidden, hidden_rules: p.hidden_rules,
                    text: p.text, source: p.source, instructs: p.instructs}
            ORDER BY p.index } AS paragraphs,
  COLLECT { MATCH (n)-[m:MENTIONS_TOKEN]->(t:Token)
            RETURN {kind: t.key_kind, category: t.category, slot: m.slot, decoded: t.decoded} }
    AS tokens
"""


def cypher(statement, **parameters):
    request = urllib.request.Request(
        f"{NEO4J_URL}/db/{NEO4J_DATABASE}/query/v2",
        data=json.dumps(
            {"statement": statement, "parameters": parameters, "accessMode": "READ"}
        ).encode(),
        headers={
            "content-type": "application/json",
            "authorization": "Basic "
            + base64.b64encode(f"{NEO4J_USER}:{NEO4J_PASSWORD}".encode()).decode(),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.load(response)
    except urllib.error.HTTPError as error:
        body = json.load(error)
    if body.get("errors"):
        raise RuntimeError("; ".join(e.get("message", "") for e in body["errors"]))
    data = body["data"]
    return [dict(zip(data["fields"], row)) for row in data["values"]]


def preview(props):
    return {
        key: value[:PREVIEW_CHARS] + "…" if isinstance(value, str) and len(value) > PREVIEW_CHARS else value
        for key, value in props.items()
    }


def summary(props):
    """The fields a node's caption needs, read before its payload is cut short."""
    try:
        payload = json.loads(props.get("payload_json") or "{}")
    except ValueError:
        payload = {}
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    brief = next(
        (tool_input[key] for key in ("command", "file_path", "action", "query", "url", "pattern", "skill")
         if isinstance(tool_input.get(key), str)),
        "",
    )
    fields = {
        "tool_name": payload.get("tool_name") or props.get("tool_name"),
        "brief": brief,
        "prompt": payload.get("prompt"),
        "intent": payload.get("intent"),
        "text": payload.get("text"),
        "error": payload.get("error"),
        "file_path": payload.get("file_path") or props.get("file_path"),
        "agent_type": payload.get("agent_type") or props.get("agent_type"),
    }
    return {key: value[:200] for key, value in fields.items() if isinstance(value, str) and value}


def graph(session):
    return {
        "nodes": [
            {**row, "summary": summary(row["props"]), "props": preview(row["props"])}
            for row in cypher(NODES, session=session)
        ],
        "subgraphs": cypher(SUBGRAPHS, session=session),
        "edges": cypher(EDGES, session=session),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        query = {key: values[0] for key, values in parse_qs(url.query).items()}
        try:
            if url.path == "/":
                self.send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/api/sessions":
                self.json(cypher(SESSIONS))
            elif url.path == "/api/graph":
                self.json(graph(query["session"]))
            elif url.path == "/api/node":
                rows = cypher(NODE, session=query["session"], seq=int(query["seq"]))
                self.json(rows[0] if rows else None)
            else:
                self.send(404, b"not found", "text/plain")
        except Exception as error:  # noqa: BLE001 - the page shows the message
            self.json({"error": str(error)}, status=500)

    def json(self, value, status=200):
        self.send(status, json.dumps(value, ensure_ascii=False).encode(), "application/json")

    def send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    print(f"graph viewer on http://{ADDRESS}:{PORT}", flush=True)
    ThreadingHTTPServer((ADDRESS, PORT), Handler).serve_forever()
