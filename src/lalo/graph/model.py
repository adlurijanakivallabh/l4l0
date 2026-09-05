"""Reachability graph: everything a scan knows, chain solving, crash-safe persistence.

Reference reads for this phase (all five, real source and comparison-doc
detail) converge on one finding: **none of the five references models scan
state as a graph at all.** A reference relational-DB pentest platform uses
Postgres tables (flow/task/subtask + tool-call logs) with no graph structure
between findings; a reference TypeScript platform uses git-committed
content-addressed artifacts plus durable workflow state, again relational/
document-shaped, not a graph; a reference agent's own `report/state.py` (read
directly) is an in-memory, loosely-typed dataclass store with ~20 freeform
fields per finding and, critically, **no atomicity guarantee at all** —
`save_run_data()` writes synchronously and unconditionally, no atomic rename,
no byte-verify. This stays a largely original L4L0 mechanism, built on top of
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
            return [Chain(node_ids=list(p)) for p in nx.all_simple_paths(view, source, target)]
        except nx.NodeNotFound:
            return []

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
