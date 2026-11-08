#!/usr/bin/env python3
"""Export the legacy graph, import into an empty PostgreSQL DB, or verify a stopped DB."""

import argparse
import base64
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen


SCHEMA = Path(__file__).resolve().parents[3] / "crates/common/sql/postgres_schema.sql"
LABEL_TABLE = {
    "Session": "sessions",
    "EventCommit": "event_commits",
    "SubGraph": "subgraphs",
    "Paragraph": "paragraphs",
    "Token": "tokens",
    "File": "files",
    "PendingParagraphEnrichment": "pending_paragraph_enrichments",
    "PendingRequestContinuation": "pending_request_continuations",
}
NODE_KINDS = {
    "Request", "Intent", "Message", "Call", "Segment", "Error", "ToolBatch",
    "SubagentStart", "SubagentStop", "ConfigChange", "ToolDescriptions",
}
TABLES = tuple(LABEL_TABLE.values()) + ("nodes", "file_refs", "token_mentions", "cause_edges")
DERIVED = {
    "CONTAINS", "COMMITTED", "CREATED", "MEMBER", "CONTAINS_PARAGRAPH", "AGENT_SEQUENCE", "RESULT_OF",
}
BATCH_SIZE = 10


class MigrationError(Exception):
    """An error safe to print without exposing any graph contents."""


def require(condition, message):
    if not condition:
        raise MigrationError(message)


class Source:
    def __init__(self):
        url = os.environ.get("NEO4J_URL", "http://127.0.0.1:7474").rstrip("/")
        database = quote(os.environ.get("NEO4J_DATABASE", "neo4j"), safe="")
        self.endpoint = f"{url}/db/{database}/query/v2"
        user = os.environ.get("NEO4J_USER", "neo4j")
        password = os.environ.get("NEO4J_PASSWORD")
        require(password, "NEO4J_PASSWORD is required for the read-only export")
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Content-Type": "application/json", "Authorization": f"Basic {auth}"}

    def query(self, statement, **parameters):
        request = Request(
            self.endpoint,
            data=json.dumps(
                {"statement": statement, "parameters": parameters, "accessMode": "READ"}
            ).encode(),
            headers=self.headers,
        )
        with urlopen(request, timeout=120) as response:
            body = json.load(response)
        require(not body.get("errors"), "Neo4j rejected a read-only export query")
        return body["data"]["values"]


def project_batch(source, ids):
    rows = {}
    sessions = {}
    groups = {}
    nodes = {}
    agents = defaultdict(list)
    calls = defaultdict(list)
    derived = Counter()
    actual = Counter()
    links = []
    for node_id, labels, props in source.query(
        "MATCH (n) WHERE n.session_id IN $ids RETURN elementId(n), labels(n), properties(n)",
        ids=ids,
    ):
        require(len(labels) == 1, "Encountered a node without a single supported label")
        label = labels[0]
        table = LABEL_TABLE.get(label)
        props.pop("commit_lock", None)
        if label in NODE_KINDS:
            table = "nodes"
            props["kind"] = label
            sid = props["session_id"]
            nodes[sid, props["seq"]] = node_id
            if props.get("agent_id") is not None and props.get("sequence") is not None:
                agents[sid, props["agent_id"], props["sequence"]].append(node_id)
            if label == "Call" and props.get("tool_use_id") is not None:
                calls[sid, props["tool_use_id"]].append(node_id)
        require(table is not None and table != "files", "Encountered an unsupported session node")
        rows[node_id] = table, props
        if table == "sessions":
            sessions[props["session_id"]] = node_id
        if table == "subgraphs":
            groups[props["session_id"], props["number"]] = node_id

    for node_id, (table, props) in rows.items():
        sid = props["session_id"]
        if table == "event_commits":
            derived["COMMITTED", sessions[sid], node_id] += 1
            node = nodes.get((sid, props["version"]))
            if "has_node" not in props:
                props["has_node"] = node is not None
            require(props["has_node"] == (node is not None), "EventCommit has_node disagrees with its node")
            if node is not None:
                require(rows[node][1]["order"] == props["order"], "EventCommit order differs from its node")
                derived["CREATED", node_id, node] += 1
        elif table == "paragraphs":
            derived["CONTAINS_PARAGRAPH", nodes[sid, props["seq"]], node_id] += 1
        elif table == "nodes":
            derived["CONTAINS", sessions[sid], node_id] += 1
            if props.get("subgraph") is not None:
                derived["MEMBER", groups[sid, props["subgraph"]], node_id] += 1
            if props.get("agent_id") is not None and props.get("sequence") is not None:
                for following in agents[sid, props["agent_id"], props["sequence"] + 1]:
                    derived["AGENT_SEQUENCE", node_id, following] += 1
            if props["kind"] in ("Segment", "Error") and props.get("tool_use_id") is not None:
                for call in calls[sid, props["tool_use_id"]]:
                    derived["RESULT_OF", node_id, call] += 1

    for origin, kind, dest, dest_labels, file_props, edge in source.query(
        """MATCH (a)-[r]->(b) WHERE a.session_id IN $ids
           RETURN elementId(a), type(r), elementId(b), labels(b),
                  CASE WHEN b:File THEN properties(b) END, properties(r)""",
        ids=ids,
    ):
        origin_table, a = rows[origin]
        sid = a["session_id"]
        if dest_labels == ["File"]:
            require(kind == "REFERENCES_FILE" and origin_table == "nodes" and not edge,
                    "Unsupported edge to a shared File")
            links.append(("file_refs", {
                "session_id": sid, "node_seq": a["seq"],
                "repository": file_props["repository"], "path": file_props["path"],
            }))
            continue
        require(dest in rows, "Encountered an edge between different sessions")
        dest_table, b = rows[dest]
        require(b["session_id"] == sid, "Encountered an edge between different sessions")
        if kind in DERIVED:
            require(not edge, "A derived relationship has extra properties")
            actual[kind, origin, dest] += 1
        elif kind == "NEXT" and edge.get("kind") == "cause":
            require(origin_table == "nodes" and a["kind"] == "Call" and
                    dest_table in ("nodes", "paragraphs") and edge.get("call_seq") == a["seq"] and
                    set(edge) <= {"kind", "call_seq", "probability", "rank", "parent"},
                    "Unsupported cause relationship")
            links.append(("cause_edges", {
                "session_id": sid, "call_seq": a["seq"], "target_seq": b["seq"],
                "target_index": b["index"] if dest_table == "paragraphs" else -1,
                **{key: edge.get(key) for key in ("probability", "rank", "parent")},
            }))
        elif kind == "NEXT":
            require(origin_table == dest_table == "nodes" and "next_seq" not in b and
                    set(edge) <= {"via", "edge_id", "probability"} and
                    edge.get("edge_id", f"{sid}:{a['seq']}:{b['seq']}") == f"{sid}:{a['seq']}:{b['seq']}" and
                    edge.get("probability", 1.0) == 1.0,
                    "Unsupported structural NEXT relationship")
            b.update(next_seq=a["seq"], next_via=edge["via"])
        elif kind == "MENTIONS_TOKEN":
            require(origin_table == "nodes" and dest_table == "tokens" and edge == {"slot": b["slot"]},
                    "Unsupported token mention relationship")
            links.append(("token_mentions", {
                "session_id": sid, "node_seq": a["seq"],
                **{key: b[key] for key in ("key_kind", "key", "slot")},
            }))
        else:
            raise MigrationError("Encountered an unsupported relationship")
    require(actual == derived, "Relationships implied by the PostgreSQL schema differ from the source")
    yield from rows.values()
    yield from links


def export_graph(source, output):
    require(
        source.query("MATCH (n) WHERE n.session_id IS NULL AND NOT n:File RETURN count(n)") == [[0]]
        and source.query("MATCH (:File)-[r]->() RETURN count(r)") == [[0]],
        "Encountered unowned nodes or outgoing edges from shared Files",
    )
    ids = [sid for sid, in source.query(
        "MATCH (n) WHERE n.session_id IS NOT NULL RETURN DISTINCT n.session_id ORDER BY n.session_id"
    )]
    require(ids, "The source has no sessions")
    digest = hashlib.sha256()
    counts = dict.fromkeys(TABLES, 0)
    output.write(b'{"format": 1}\n')

    def write_row(table, record):
        line = json.dumps([table, record], ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
        output.write(line)
        digest.update(line)
        counts[table] += 1

    for offset in range(0, len(ids), BATCH_SIZE):
        for table, props in project_batch(source, ids[offset:offset + BATCH_SIZE]):
            write_row(table, props)
    for props, in source.query("MATCH (f:File) RETURN properties(f) ORDER BY f.repository, f.path"):
        write_row("files", props)
    output.write(json.dumps({"counts": counts, "sha256": digest.hexdigest()}).encode("utf-8") + b"\n")
    return counts


def for_postgres(value):
    """A snapshot value as PostgreSQL can store it. Neo4j kept U+0000 (hidden-text attacks carry
    it on purpose), but PostgreSQL text and jsonb cannot; the engine stores U+FFFD in its place,
    and so does the import. The snapshot itself and its checksum keep the original."""
    if isinstance(value, str):
        return value.replace("\x00", "\ufffd")
    if isinstance(value, list):
        return [for_postgres(item) for item in value]
    return value


def stage_snapshot(db, snapshot, sql):
    digest = hashlib.sha256()
    counts = dict.fromkeys(TABLES, 0)
    replaced = 0
    columns = defaultdict(set)
    buffers = defaultdict(list)
    for table in TABLES:
        db.execute(sql.SQL("CREATE TEMP TABLE {} (LIKE public.{} INCLUDING ALL) ON COMMIT DROP").format(
            sql.Identifier(table), sql.Identifier(table),
        ))
    for table, column in db.execute(
        "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'"
    ):
        columns[table].add(column)

    def flush(table):
        name = sql.Identifier(table)
        db.execute(sql.SQL(
            "INSERT INTO pg_temp.{} SELECT * FROM jsonb_populate_recordset(NULL::public.{}, %s::jsonb)"
        ).format(name, name), (json.dumps(buffers.pop(table), ensure_ascii=False),))

    require(json.loads(snapshot.readline()) == {"format": 1}, "Unsupported snapshot format")
    for line in snapshot:
        row = json.loads(line)
        if isinstance(row, dict):
            require(row == {"counts": counts, "sha256": digest.hexdigest()} and not snapshot.read(1),
                    "Snapshot checksum or row counts do not match")
            break
        table, record = row
        require(table in TABLES and isinstance(record, dict) and set(record) <= columns[table],
                "Snapshot contains a property without a PostgreSQL column")
        digest.update(line)
        counts[table] += 1
        stored = {key: for_postgres(value) for key, value in record.items()}
        replaced += stored != record
        buffers[table].append(stored)
        if len(buffers[table]) == 250:
            flush(table)
    else:
        raise MigrationError("Snapshot is incomplete")
    for table in list(buffers):
        flush(table)
    require(counts["sessions"] > 0, "Snapshot has no session rows")
    return counts, replaced


def copy_or_verify(db, snapshot, sql, copy):
    # All commands run in the caller's transaction. A failure rolls back even the schema setup.
    db.execute("SELECT pg_advisory_xact_lock(%s::bigint)", (0x574954484855,))
    if copy:
        db.execute(SCHEMA.read_text(encoding="utf-8"))
    db.execute(sql.SQL("LOCK TABLE {} IN SHARE ROW EXCLUSIVE MODE").format(
        sql.SQL(", ").join(sql.Identifier("public", table) for table in TABLES),
    ))
    counts, replaced = stage_snapshot(db, snapshot, sql)
    for table in TABLES:
        name = sql.Identifier(table)
        if copy:
            populated = db.execute(sql.SQL("SELECT EXISTS (SELECT 1 FROM public.{})").format(name)).fetchone()[0]
            require(not populated, "PostgreSQL already contains graph data; use a fresh target or verify")
            db.execute(sql.SQL("INSERT INTO public.{} SELECT * FROM pg_temp.{}").format(name, name))
        mismatch = db.execute(sql.SQL("""
            SELECT EXISTS (
                (SELECT * FROM public.{0} EXCEPT ALL SELECT * FROM pg_temp.{0})
                UNION ALL
                (SELECT * FROM pg_temp.{0} EXCEPT ALL SELECT * FROM public.{0})
            )
        """).format(name)).fetchone()[0]
        require(not mismatch, f"Full-row verification failed for {table}")
    return counts, replaced


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("export", "import", "verify"))
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "export":
            source = Source()
            fd = os.open(args.snapshot, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as output:
                counts = export_graph(source, output)
            replaced = 0
        else:
            import psycopg
            from psycopg import sql

            database_url = os.environ.get("DATABASE_URL")
            require(database_url, "DATABASE_URL is required")
            with args.snapshot.open("rb") as snapshot, psycopg.connect(database_url, connect_timeout=10) as db:
                counts, replaced = copy_or_verify(db, snapshot, sql, copy=args.command == "import")
    except MigrationError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception as error:
        # Database errors may contain credentials or entire rows.
        print(f"Migration failed ({type(error).__name__}). Check the connection, snapshot and schema.",
              file=sys.stderr)
        return 1
    result = {"command": args.command, "rows": counts}
    if replaced:
        # Rows stored with U+FFFD for U+0000 (see for_postgres).
        result["rows_with_nul_replaced"] = replaced
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
