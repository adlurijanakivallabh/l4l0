"""Store-contract parity suite: NetworkX vs. Neo4j-MCP backend (plan §12, §13; Task 3).

Asserts the Task 3 DoD invariants:

  1. **One contract, two backends.** The same test bodies run against both
     :class:`ReachabilityGraph` (NetworkX, the default) and
     :class:`Neo4jGraphStore` (driven through the ``neo4j-cypher`` MCP tool), via
     a parametrized ``backend`` fixture. Every query type — node kinds,
     ``can_call``, ``owns``, ``findings``, and ``enables``/``derived_credential``
     traversal — returns matching results on both.
  2. **Multi-hop traversal is one Cypher path query.** The Neo4j backend's
     ``chain_paths`` uses a single variable-length pattern, not client-side hop
     reassembly (asserted structurally against its source), and its output equals
     the NetworkX reference on the same graph.
  3. **No bolt driver.** All Neo4j I/O goes through the MCP tool — there is no
     ``import neo4j`` anywhere in ``src/reachagent`` (AST/text scan).
  4. **Secrets never enter the graph on either backend.** A ``Session`` node
     carries only its ``token_ref`` handle; neither backend stores a token value.
  5. **Parity, not cutover.** NetworkX stays the default; the Neo4j backend is
     opt-in via an injected executor.

The Neo4j-backed parametrization is gated on a live bolt endpoint *and* a
``NEO4J_PASSWORD`` in the environment (the MCP server needs it to connect), so
the suite runs green on a machine without Neo4j while remaining the reproducible
parity check when it is up — the credential is passed via env at run time, never
hardcoded (same discipline as the live crAPI gate).
"""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from typing import Protocol

import pytest

from reachagent.graph.cypher_executor import MCPCypherExecutor
from reachagent.graph.neo4j_store import Neo4jGraphStore
from reachagent.graph.nodes import (
    AuthState,
    Endpoint,
    Finding,
    FindingStatus,
    Identity,
    Object,
    Parameter,
    Provenance,
    Session,
)
from reachagent.graph.store import (
    ReachabilityGraph,
)

# -- backend fixtures ------------------------------------------------------


class _Backend(Protocol):
    """What a contract test needs from either backend."""

    name: str

    def make(self) -> object: ...
    def session_props(self, store: object, node_id: str) -> dict[str, object]: ...
    def close(self) -> None: ...


class _NetworkXBackend:
    name = "networkx"

    def make(self) -> ReachabilityGraph:
        return ReachabilityGraph()

    def session_props(self, store: object, node_id: str) -> dict[str, object]:
        assert isinstance(store, ReachabilityGraph)
        session = dict(store.sessions())[node_id]
        return dict(vars(session))

    def close(self) -> None:
        pass


class _Neo4jBackend:
    name = "neo4j"

    def __init__(self) -> None:
        self._ex = MCPCypherExecutor()
        self._ex.__enter__()

    def make(self) -> Neo4jGraphStore:
        store = Neo4jGraphStore(self._ex)
        store.wipe()  # isolate every test on a clean database
        return store

    def session_props(self, store: object, node_id: str) -> dict[str, object]:
        rows = self._ex.read("MATCH (n:Node {id: $id}) RETURN properties(n) AS p", {"id": node_id})
        props = dict(rows[0]["p"]) if rows else {}
        props.pop("id", None)
        props.pop("kind", None)
        return props

    def close(self) -> None:
        self._ex.__exit__(None, None, None)


def _bolt_up(host: str = "localhost", port: int = 7687) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


_NEO4J_AVAILABLE = _bolt_up() and bool(os.environ.get("NEO4J_PASSWORD"))
_NEO4J_SKIP = pytest.param(
    _Neo4jBackend,
    marks=pytest.mark.skipif(
        not _NEO4J_AVAILABLE,
        reason="live Neo4j not reachable or NEO4J_PASSWORD unset — start neo4j to run",
    ),
    id="neo4j",
)


@pytest.fixture(params=[pytest.param(_NetworkXBackend, id="networkx"), _NEO4J_SKIP])
def backend(request: pytest.FixtureRequest) -> Iterator[_Backend]:
    backend_obj: _Backend = request.param()
    try:
        yield backend_obj
    finally:
        backend_obj.close()


# -- shared graph builder --------------------------------------------------


def _build_sample(store: object) -> dict[str, str]:
    """Populate ``store`` with one of every node/edge kind via shared writer methods.

    A small but complete BOLA-style graph: two identities, an endpoint returning
    two per-instance objects each owned by a different identity, empirical
    can_call verdicts, and a confirmed finding that chains (enables +
    derived_credential) into a spawned session. Uses only methods both backends
    implement, so the same builder drives both.
    """
    ep = store.add_endpoint(Endpoint(method="GET", path="/api/vehicle/{id}/location"))  # type: ignore[attr-defined]
    store.add_parameter(ep, Parameter(name="id", location="path"))  # type: ignore[attr-defined]

    id_a = store.add_identity("owner_a", Identity("user", AuthState.USER, Provenance.SEEDED))  # type: ignore[attr-defined]
    id_b = store.add_identity("owner_b", Identity("user", AuthState.USER, Provenance.SEEDED))  # type: ignore[attr-defined]

    obj_a = store.add_object(Object(type="vehicle", instance_key="uuid-a"))  # type: ignore[attr-defined]
    obj_b = store.add_object(Object(type="vehicle", instance_key="uuid-b"))  # type: ignore[attr-defined]
    store.add_returns(ep, obj_a)  # type: ignore[attr-defined]
    store.add_returns(ep, obj_b)  # type: ignore[attr-defined]
    store.set_owns(id_a, obj_a)  # type: ignore[attr-defined]
    store.set_owns(id_b, obj_b)  # type: ignore[attr-defined]

    store.set_can_call(id_a, ep, FindingStatus.CONFIRMED_ALLOWED, evidence="200")  # type: ignore[attr-defined]
    store.set_can_call(id_b, ep, FindingStatus.CONFIRMED_VIOLATION, evidence="200 cross-user")  # type: ignore[attr-defined]

    f1 = store.add_finding(  # type: ignore[attr-defined]
        Finding(
            vuln_class="bola",
            severity="high",
            oracle_used="differential",
            evidence_ref="bola/vehicle-location",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    f2 = store.add_finding(  # type: ignore[attr-defined]
        Finding(
            vuln_class="info_leak",
            severity="medium",
            oracle_used="differential",
            evidence_ref="leak/mechanic-report",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    spawned = store.add_session(Session(token_ref="tok-derived", identity_ref="owner_b"))  # type: ignore[attr-defined]
    store.add_enables(f1, f2)  # type: ignore[attr-defined]
    store.add_derived_credential(f2, spawned)  # type: ignore[attr-defined]

    return {
        "ep": ep,
        "id_a": id_a,
        "id_b": id_b,
        "obj_a": obj_a,
        "obj_b": obj_b,
        "f1": f1,
        "f2": f2,
        "spawned": spawned,
    }


def _ids(pairs_or_ids: object) -> list[str]:
    """Normalize a node query to a sorted id list (NetworkX yields pairs; Neo4j ids)."""
    assert isinstance(pairs_or_ids, list)
    return sorted(p[0] if isinstance(p, tuple) else p for p in pairs_or_ids)


# -- Invariant 1: same contract holds on each backend ---------------------


def test_node_kinds_round_trip(backend: _Backend) -> None:
    store = backend.make()
    ids = _build_sample(store)

    assert _ids(store.endpoints()) == [ids["ep"]]  # type: ignore[attr-defined]
    assert _ids(store.objects()) == sorted([ids["obj_a"], ids["obj_b"]])  # type: ignore[attr-defined]
    assert _ids(store.identities()) == sorted([ids["id_a"], ids["id_b"]])  # type: ignore[attr-defined]
    assert _ids(store.sessions()) == [ids["spawned"]]  # type: ignore[attr-defined]
    assert _ids(store.findings()) == sorted([ids["f1"], ids["f2"]])  # type: ignore[attr-defined]


def test_can_call_round_trips(backend: _Backend) -> None:
    store = backend.make()
    ids = _build_sample(store)

    assert store.can_call_status(ids["id_a"], ids["ep"]) is FindingStatus.CONFIRMED_ALLOWED  # type: ignore[attr-defined]
    assert store.can_call_status(ids["id_b"], ids["ep"]) is FindingStatus.CONFIRMED_VIOLATION  # type: ignore[attr-defined]
    edges = sorted(store.can_call_edges())  # type: ignore[attr-defined]
    assert edges == sorted(
        [
            (ids["id_a"], ids["ep"], FindingStatus.CONFIRMED_ALLOWED),
            (ids["id_b"], ids["ep"], FindingStatus.CONFIRMED_VIOLATION),
        ]
    )


def test_can_call_reprobe_overwrites_not_stacks(backend: _Backend) -> None:
    store = backend.make()
    ids = _build_sample(store)
    store.set_can_call(ids["id_a"], ids["ep"], FindingStatus.CONFIRMED_DENIED, evidence="403")  # type: ignore[attr-defined]

    assert store.can_call_status(ids["id_a"], ids["ep"]) is FindingStatus.CONFIRMED_DENIED  # type: ignore[attr-defined]
    a_edges = [e for e in store.can_call_edges() if e[0] == ids["id_a"]]  # type: ignore[attr-defined]
    assert len(a_edges) == 1  # a single verdict per (identity, endpoint), not stacked


def test_owns_round_trips(backend: _Backend) -> None:
    store = backend.make()
    ids = _build_sample(store)

    assert sorted(store.owns_edges()) == sorted(  # type: ignore[attr-defined]
        [(ids["id_a"], ids["obj_a"]), (ids["id_b"], ids["obj_b"])]
    )
    assert store.owner_of(ids["obj_a"]) == ids["id_a"]  # type: ignore[attr-defined]
    assert store.owner_of(ids["obj_b"]) == ids["id_b"]  # type: ignore[attr-defined]


def test_findings_and_finding_gate(backend: _Backend) -> None:
    store = backend.make()
    _build_sample(store)

    # The store physically refuses a non-confirmed_violation finding on both backends.
    with pytest.raises(ValueError, match="confirmed_violation"):
        store.add_finding(  # type: ignore[attr-defined]
            Finding(
                vuln_class="x",
                severity="low",
                oracle_used="",
                evidence_ref="never",
                status=FindingStatus.INCONCLUSIVE,
            )
        )


def test_enables_requires_committed_findings(backend: _Backend) -> None:
    store = backend.make()
    ids = _build_sample(store)
    # An endpoint id is not a Finding — the chain edge refuses it on both backends.
    with pytest.raises(ValueError, match="not a committed Finding"):
        store.add_enables(ids["f1"], ids["ep"])  # type: ignore[attr-defined]


def test_chain_traversal_round_trips(backend: _Backend) -> None:
    store = backend.make()
    ids = _build_sample(store)

    # f1 -enables-> f2 -derived_credential-> spawned : one maximal chain.
    paths = store.chain_paths(ids["f1"])  # type: ignore[attr-defined]
    assert paths == [(ids["f1"], ids["f2"], ids["spawned"])]
    # enables / derived_credential edge queries agree too.
    assert store.enables_edges() == [(ids["f1"], ids["f2"])]  # type: ignore[attr-defined]
    assert store.derived_credential_edges() == [(ids["f2"], ids["spawned"])]  # type: ignore[attr-defined]


# -- Invariant 4: secrets never enter the graph on either backend ---------


def test_session_node_carries_only_a_token_ref(backend: _Backend) -> None:
    store = backend.make()
    ids = _build_sample(store)

    props = backend.session_props(store, ids["spawned"])
    assert props.get("token_ref") == "tok-derived"
    # No property holds a raw token value — only the secret-free handle set.
    assert "token" not in props
    assert set(props) <= {"token_ref", "identity_ref", "live"}


# -- Invariant 1 (direct): the two backends return matching results -------


@pytest.mark.skipif(
    not _NEO4J_AVAILABLE,
    reason="live Neo4j not reachable or NEO4J_PASSWORD unset — start neo4j + set the env to run",
)
def test_both_backends_return_matching_results() -> None:
    """Build the identical graph in each backend; every query type must agree."""
    nx_store = ReachabilityGraph()
    nx_ids = _build_sample(nx_store)
    with MCPCypherExecutor() as ex:
        neo = Neo4jGraphStore(ex)
        neo.wipe()
        neo_ids = _build_sample(neo)

        # Same deterministic ids from the shared *_id helpers on both backends.
        assert nx_ids == neo_ids

        assert _ids(nx_store.endpoints()) == _ids(neo.endpoints())
        assert _ids(nx_store.objects()) == _ids(neo.objects())
        assert _ids(nx_store.identities()) == _ids(neo.identities())
        assert _ids(nx_store.sessions()) == _ids(neo.sessions())
        assert _ids(nx_store.findings()) == _ids(neo.findings())

        assert sorted(nx_store.can_call_edges()) == sorted(neo.can_call_edges())
        assert sorted(nx_store.owns_edges()) == sorted(neo.owns_edges())
        assert sorted(nx_store.enables_edges()) == sorted(neo.enables_edges())
        assert sorted(nx_store.derived_credential_edges()) == sorted(neo.derived_credential_edges())

        # The single-Cypher-path traversal equals the NetworkX client-side walk.
        start = nx_ids["f1"]
        assert nx_store.chain_paths(start) == neo.chain_paths(start)
        assert nx_store.owner_of(nx_ids["obj_a"]) == neo.owner_of(neo_ids["obj_a"])


# -- Invariants 2 & 3: single-path Cypher; no bolt driver -----------------


def test_neo4j_traversal_is_a_single_path_query_not_reassembled() -> None:
    import inspect

    from reachagent.graph import neo4j_store

    src = inspect.getsource(neo4j_store.Neo4jGraphStore.chain_paths)
    # A variable-length relationship pattern — one query, not a hop loop.
    assert "*1.." in src
    # Structural: the traversal issues exactly one read and never recurses.
    assert src.count("self._ex.read(") == 1
    assert "chain_paths(" not in src.replace("def chain_paths(", "")


def test_no_bolt_driver_import_anywhere() -> None:
    import ast
    import pathlib

    import reachagent

    src_root = pathlib.Path(reachagent.__file__).parent
    offenders: list[str] = []
    for path in src_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            if any(n == "neo4j" or n.startswith("neo4j.") for n in names):
                offenders.append(str(path.relative_to(src_root)))
    # All Neo4j I/O goes through the MCP tool; the bolt driver is never imported.
    assert offenders == []
