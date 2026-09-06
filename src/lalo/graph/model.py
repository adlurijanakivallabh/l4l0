"""Reachability graph: everything a scan knows, chain solving, crash-safe persistence.

Reference reads for this phase (all five, real source and comparison-doc
detail) converge on one finding: **none of the five references models scan
state as a graph at all.** A reference relational-DB pentest platform uses
Postgres tables (flow/task/subtask + tool-call logs) with no graph structure
between findings; a reference TypeScript platform uses git-committed
content-addressed artifacts plus durable workflow state, again relational/
document-shaped, not a graph; a reference agent's own `report/state.py` (read
directly, along with the `report/writer.py` it calls into) is an in-memory,
loosely-typed dataclass store with ~20 freeform fields per finding. Its
`save_run_data()` is more mixed than a first pass suggested: most artifacts
(the run record, individual vulnerability files, the CSV index) DO go
through an atomic-rename helper (`tempfile.NamedTemporaryFile` +
`Path.replace`) — only the final human-facing report writes directly with no
atomic swap at all. What none of its writes do, atomic or not, is verify the
written bytes before declaring success, and nothing ties the several
per-artifact writes together as one crash-safe unit. This stays a largely
original L4L0 mechanism, built on top of
the `networkx` dependency already adopted in Phase 0 rather than hand-rolled
(reuse over reinvention), specifically because a reachability/attack-chain
model is what a role-bounded, evidence-driven agent needs to reason about
multi-step exploitation paths — something none of the five references'
flatter state models directly represent.

The one piece of real, adoptable mechanism found this phase came from a
different file entirely: a reference's `exact-output-commit.ts` (336 lines,
read in full) for the persistence half — see
:mod:`lalo.core.atomic_io` for the full citation and what was kept versus
dropped from it.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

import networkx as nx

from ..core.atomic_io import atomic_write_verified


class NodeKind(StrEnum):
    ENDPOINT = "endpoint"
    PARAM = "param"
    IDENTITY = "identity"
    SESSION = "session"
    FINDING = "finding"
    EVIDENCE = "evidence"
    FINGERPRINT = "fingerprint"
    SERVICE = "service"
    # A freeform scratch note an agent leaves for itself or another agent -
    # deliberately untyped/unstructured, unlike every other kind above.
    NOTE = "note"


class EdgeKind(StrEnum):
    HAS_PARAM = "has_param"
    AUTHENTICATED_AS = "authenticated_as"
    SUPPORTS = "supports"  # evidence -> finding
    ENABLES = "enables"  # attack-chain edge: one step's outcome enables the next
    EXPOSES = "exposes"  # service -> endpoint
    FINGERPRINTED_AS = "fingerprinted_as"


@dataclass(frozen=True)
class Chain:
    """One multi-step exploit path, as an ordered list of node ids."""

    node_ids: list[str]


class ReachabilityGraph:
    """A directed multigraph of endpoints/params/identities/findings/evidence/etc.

    Implements the ``Isolatable`` seam Phase 6's spawn tools expect: ``snapshot()``
    returns a fully independent deep copy, so a spawned child can mutate its own
    view without a sibling or the parent ever seeing it.
    """

    def __init__(self, graph: nx.MultiDiGraph[str] | None = None) -> None:
        self._g: nx.MultiDiGraph[str] = graph if graph is not None else nx.MultiDiGraph()

    def add_node(self, node_id: str, kind: NodeKind, **attrs: Any) -> None:
        self._g.add_node(node_id, kind=kind.value, **attrs)

    def add_edge(self, src: str, dst: str, kind: EdgeKind, **attrs: Any) -> None:
        self._g.add_edge(src, dst, kind=kind.value, **attrs)

    def has_node(self, node_id: str) -> bool:
        return self._g.has_node(node_id)

    def node(self, node_id: str) -> dict[str, Any]:
        return dict(self._g.nodes[node_id])

    def nodes_of_kind(self, kind: NodeKind) -> list[str]:
        return [n for n, data in self._g.nodes(data=True) if data.get("kind") == kind.value]

    def has_edge_of_kind(self, node_id: str, kind: EdgeKind) -> bool:
        """Whether ``node_id`` touches an edge of ``kind``, in either direction."""
        if not self._g.has_node(node_id):
            return False
        touching = (*self._g.out_edges(node_id, data=True), *self._g.in_edges(node_id, data=True))
        return any(data.get("kind") == kind.value for *_ends, data in touching)

    def connected_via(self, node_id: str, kind: EdgeKind) -> list[str]:
        """Every node connected to ``node_id`` by an edge of ``kind``, in
        either direction — the neighbor's id, not the edge itself. Used by
        confidence scoring to look up what a declared chain link actually
        connects to, not just whether one exists."""
        if not self._g.has_node(node_id):
            return []
        neighbors: list[str] = []
        for _u, v, data in self._g.out_edges(node_id, data=True):
            if data.get("kind") == kind.value:
                neighbors.append(v)
        for u, _v, data in self._g.in_edges(node_id, data=True):
            if data.get("kind") == kind.value:
                neighbors.append(u)
        return neighbors

    def __len__(self) -> int:
        return self._g.number_of_nodes()

    def snapshot(self) -> Self:
        """A fully independent deep copy — never hand a child the live graph."""
        return type(self)(copy.deepcopy(self._g))

    def find_chains(
        self, source: str, target: str, *, edge_kind: EdgeKind = EdgeKind.ENABLES
    ) -> list[Chain]:
        """Every simple multi-step path from ``source`` to ``target`` over ``edge_kind`` edges."""
        view: nx.MultiDiGraph[str] = nx.MultiDiGraph(
            (u, v, d) for u, v, d in self._g.edges(data=True) if d.get("kind") == edge_kind.value
        )
        # A node with no edge of this kind is absent from `view` entirely; add every
        # node back so an unreachable source/target returns [], never a KeyError.
        view.add_nodes_from(self._g.nodes)
        # nx.all_simple_paths is a generator: NodeNotFound only raises once iterated,
        # so the list comprehension has to be inside the try, not just the call.
        try:
            paths = list(nx.all_simple_paths(view, source, target))
        except nx.NodeNotFound:
            return []

        chains: list[Chain] = []
        seen: set[tuple[str, ...]] = set()
        for path in paths:
            if len(path) < 2:
                # networkx's own documented special case for source == target:
                # a trivial single-node "path" that traversed no edge at all —
                # never a real chain, regardless of whether any edge exists.
                continue
            key = tuple(path)
            if key in seen:
                # Parallel edges of the same kind between the same node pair
                # (e.g. two agents each recording their own ENABLES edge for
                # the same relationship) make all_simple_paths enumerate the
                # identical node sequence once per edge combination on a
                # MultiDiGraph — one real chain, not one per edge.
                continue
            seen.add(key)
            chains.append(Chain(node_ids=list(path)))
        return chains

    def all_enabling_chains(self) -> list[Chain]:
        """Every maximal :data:`EdgeKind.ENABLES` chain in the graph — from a
        root (no incoming ENABLES edge) to a leaf (no outgoing one).

        Closes a real gap :func:`find_chains` alone left open: that method
        needs an explicit ``(source, target)`` pair, but nothing else in the
        codebase ever picks one — this is the actual entry point a caller
        wanting "every real attack chain right now" uses, built entirely on
        top of the already-tested :func:`find_chains` (dedup of parallel
        edges, the trivial-single-node exclusion, the empty-result-not-a-
        crash guarantee all come along for free).
        """
        view: nx.MultiDiGraph[str] = nx.MultiDiGraph(
            (u, v, d)
            for u, v, d in self._g.edges(data=True)
            if d.get("kind") == EdgeKind.ENABLES.value
        )
        if view.number_of_nodes() == 0:
            return []
        roots = [n for n in view.nodes if view.in_degree(n) == 0]
        leaves = [n for n in view.nodes if view.out_degree(n) == 0]
        chains: list[Chain] = []
        seen: set[tuple[str, ...]] = set()
        for root in roots:
            for leaf in leaves:
                for chain in self.find_chains(root, leaf):
                    key = tuple(chain.node_ids)
                    if key not in seen:
                        seen.add(key)
                        chains.append(chain)
        return chains

    def to_json(self) -> bytes:
        data = nx.node_link_data(self._g, edges="edges")
        return json.dumps(data, sort_keys=True).encode("utf-8")

    @classmethod
    def from_json(cls, blob: bytes) -> Self:
        data = json.loads(blob.decode("utf-8"))
        return cls(nx.node_link_graph(data, directed=True, multigraph=True, edges="edges"))

    def save(self, path: Path) -> None:
        atomic_write_verified(path, self.to_json())

    @classmethod
    def load(cls, path: Path) -> Self:
        return cls.from_json(path.read_bytes())
