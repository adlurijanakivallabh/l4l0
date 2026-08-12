"""Durable graph + solver + audit state for run resume (b-items D6/D2).

A scan can crash (network flap, host reboot, budget timeout) and resume without
losing confirmed findings, exploration state, or the Coordinator loop's position
— the precondition for long evaluation runs (VAmPI / Juice Shop / crAPI gates)
surviving interruptions. This is the (b) "durable resume" item from the
comprehensive reference audit, plus the RECOVER-phase (D2) gap, bundled as one
run-resilience task.

# DECISION BLOCK (D1-D4)

# D1. What is persisted, what is not.
#     PERSISTED: the full structural layer (endpoints / parameters / objects /
#     identities / sessions / hosts / services + all edges with status, evidence,
#     and attributes — technology, detected_version, access_restricted,
#     owner_identity_ref, instance_key, inferred_sink_type, can_call status +
#     evidence, finding status / oracle_used / evidence_ref / metadata), plus
#     ChainSolver state (per-path_id budgets + _spawned_by_path sets) plus the
#     audit tail.
#     NEVER PERSISTED: token VALUES (TokenStore holds them in memory only — the
#     graph carries token_ref handles, and the dump must never contain a token
#     value; asserted in the tests), FireResult bodies/handles (fire_refs are
#     session-scoped and meaningless across a restart), verdict handles.
#     Format: JSON file, deterministic (sorted keys), atomic write (temp file +
#     os.replace). Path from --state on CLI / state_path on scan_target.
#
# # D2. Resume semantics — idempotent, continue-not-replay.
#     load_graph() rebuilds the ReachabilityGraph exactly (dump → load → dump
#     must be byte-identical). scan_target(resume_path=...) loads graph + solver
#     state, then the Coordinator loop continues: query_graph skips (identity,
#     endpoint) pairs with an existing can_call verdict (already the store's
#     behavior), score_and_select picks fresh candidates, budget continues from
#     the persisted remaining count, spawned_identity_nodes restored so §4
#     scoring keeps weighting chain hops. A confirmed finding already in the
#     graph is a fact — loaded as-is (it was confirmed by run_oracle before
#     persistence), never re-confirmed, never re-fired.
#
# # D3. RECOVER-phase integration (the D2 audit item).
#     On resume, re-surface unexplored pairs for any confirmed finding whose
#     derived edges were not yet explored before the crash: scan persisted
#     findings, for each with a derived_credential edge whose spawned identity is
#     absent from _spawned_by_path, call ChainSolver.recover_derived() to re-query
#     unexplored (identity, endpoint) pairs (advance-lite — the persisted
#     Session/Identity node and derived_credential edge are NOT re-written).
#     ALSO: endpoints that ERRORED (transport, not inconclusive) before the crash
#     get re-queried — an errored fire writes NO can_call verdict, so the edge is
#     still unexplored and the normal loop retries it; an inconclusive edge stays
#     skipped (it carried a real negative verdict). This is the honest
#     "recover what was interrupted, don't replay what was decided" rule.
#
# # D4. Safety — no re-confirmation, no secrets, no scope change.
#     Scope allowlist + read-only-first unchanged (resume uses the same
#     EnforcerScopeWrapper + RequestFirer gates). Six families held. persistence
#     imports no validator, no TokenStore; token VALUES never cross the JSON
#     boundary (only token_ref handles, which the graph already carries).
# ---------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from reachagent.execution.audit import AuditEntry, AuditLog
from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.edges import StructuralEdge
from reachagent.graph.nodes import (
    AuthState,
    Endpoint,
    ExecutionContext,
    Finding,
    FindingStatus,
    Host,
    Identity,
    InternalResource,
    Object,
    Parameter,
    Protocol,
    Provenance,
    Service,
    Session,
    SinkType,
)
from reachagent.graph.store import (
    _DATA,
    _KIND,
    ReachabilityGraph,
)

_VERSION = 1


class PersistenceError(RuntimeError):
    """Raised on a malformed or unknown state file — never silently dropped state."""


# kind → dataclass type, for exact reconstruction (unknown kind → error, D1).
_NODE_CLASSES: dict[str, type] = {
    "endpoint": Endpoint,
    "parameter": Parameter,
    "object": Object,
    "identity": Identity,
    "session": Session,
    "host": Host,
    "service": Service,
    "internal_resource": InternalResource,
    "execution_context": ExecutionContext,
    "finding": Finding,
}

# kind → {field: enum type} for StrEnum fields, re-coerced on load (JSON gives
# the plain string; the dataclass needs the enum member).
_ENUM_FIELDS: dict[str, dict[str, type[StrEnum]]] = {
    "identity": {"auth_state": AuthState, "provenance": Provenance},
    "endpoint": {"protocol": Protocol},
    "parameter": {"inferred_sink_type": SinkType},
    "finding": {"status": FindingStatus},
}


def _serialize_edges(graph: ReachabilityGraph) -> list[dict[str, object]]:
    """All edges as sorted (src, dst, key, attrs) records.

    StrEnum attrs (can_call ``status``) serialize as their string value via JSON;
    determinism comes from sorting by (src, dst, key) and the single-edge-per-pair
    can_call slot. ``attrs`` are stored raw — the only edge carrying attrs is
    ``can_call`` (status + evidence).
    """
    out: list[dict[str, object]] = []
    for src, dst, key, attrs in graph._g.edges(keys=True, data=True):  # noqa: SLF001 — raw store access, same package
        out.append({"src": src, "dst": dst, "key": key, "attrs": dict(attrs)})
    out.sort(key=lambda e: (str(e["src"]), str(e["dst"]), str(e["key"])))
    return out


def dump_graph(
    graph: ReachabilityGraph, solver: ChainSolver, audit: AuditLog, path: str | Path
) -> None:
    """Deterministic, atomic JSON dump of graph + solver + audit tail (D1).

    Nodes are sorted by id, edges by (src, dst, key), nested keys sorted by
    ``json.dumps(sort_keys=True)``, and the write is a temp file + ``os.replace``
    so a crash mid-write never leaves a partial state file. Never serializes a
    token value: the graph carries only ``token_ref`` handles.
    """
    nodes: list[dict[str, object]] = []
    for node_id in sorted(graph._g.nodes):  # noqa: SLF001 — raw store access, same package
        data = graph._g.nodes[node_id]
        kind = data.get(_KIND)
        if kind is None:
            raise PersistenceError(f"node {node_id!r} has no kind — cannot persist")
        nodes.append({"id": node_id, "kind": kind, "fields": asdict(data[_DATA])})

    payload: dict[str, object] = {
        "version": _VERSION,
        "graph": {
            "nodes": nodes,
            "edges": _serialize_edges(graph),
        },
        "solver": solver.snapshot(),
        "audit": [
            {
                "timestamp": e.timestamp.isoformat(),
                "identity": e.identity,
                "method": e.method,
                "target": e.target,
                "outcome": e.outcome,
            }
            for e in audit.entries
        ],
    }

    text = json.dumps(payload, sort_keys=True, indent=2) + "\n"
    target = Path(path)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent) if target.parent != Path("") else ".",
        prefix=target.name,
        suffix=".tmp",
    )  # noqa: S108 — mkstemp in the target dir, not hardcoded /tmp
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def load_graph(path: str | Path) -> tuple[ReachabilityGraph, ChainSolver, AuditLog]:
    """Rebuild graph + solver + audit exactly (D2) — dump → load → dump identical.

    Unknown node kinds raise :class:`PersistenceError` (never silently dropped).
    The solver is restored from its persisted ledgers; the audit tail is seeded
    with its original timestamps.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("version") != _VERSION:
        raise PersistenceError(f"state file version {data.get('version')!r} != expected {_VERSION}")

    g = ReachabilityGraph()
    graph_rec = data.get("graph")
    if not isinstance(graph_rec, dict):
        raise PersistenceError("state file missing 'graph'")
    for rec in graph_rec.get("nodes", []):
        kind = rec.get("kind")
        cls = _NODE_CLASSES.get(kind)
        if cls is None:
            raise PersistenceError(f"unknown node kind {kind!r} — refusing to drop it")
        fields = dict(rec.get("fields", {}))
        for field_name, enum_cls in _ENUM_FIELDS.get(kind, {}).items():
            value = fields.get(field_name)
            if value is not None:
                fields[field_name] = enum_cls(value)
        g._g.add_node(str(rec["id"]), **{_KIND: kind, _DATA: cls(**fields)})  # noqa: SLF001
    for rec in graph_rec.get("edges", []):
        attrs = dict(rec.get("attrs", {}))
        if rec.get("key") == StructuralEdge.CAN_CALL and attrs.get("status") is not None:
            attrs["status"] = FindingStatus(str(attrs["status"]))
        g._g.add_edge(str(rec["src"]), str(rec["dst"]), key=str(rec["key"]), **attrs)  # noqa: SLF001

    solver = ChainSolver(g)
    solver.restore(data.get("solver", {}))

    audit_log = AuditLog()
    parsed_entries: list[AuditEntry] = []
    for rec in data.get("audit", []):
        parsed_entries.append(
            AuditEntry(
                timestamp=datetime.fromisoformat(str(rec.get("timestamp", ""))),
                identity=str(rec.get("identity", "")),
                method=str(rec.get("method", "")),
                target=str(rec.get("target", "")),
                outcome=str(rec.get("outcome", "")),
            )
        )
    with audit_log._lock:  # noqa: SLF001 — seeding the append-only log; same package
        audit_log._entries.extend(parsed_entries)  # noqa: SLF001
    return g, solver, audit_log
