"""Chain solver — find multi-step exploit paths over ``ENABLES`` edges.

A chain is a path where each primitive enables reaching the next, ending at a node
of the target type (a finding by default). Feeds the exploitation agents, which
execute the discovered path step by step.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import networkx as nx

from .schema import EdgeType, NodeType
from .store import ReachGraph


@dataclass(frozen=True)
class ChainStep:
    node_id: str
    node_type: str


def find_chains(
    graph: ReachGraph,
    *,
    target_type: NodeType = NodeType.FINDING,
    edge_types: Sequence[EdgeType] = (EdgeType.ENABLES,),
    max_len: int = 8,
) -> list[list[ChainStep]]:
    """Return distinct enabling paths that end at a ``target_type`` node."""
    allowed = {e.value for e in edge_types}
    sub: nx.DiGraph[str] = nx.DiGraph()
    for src, dst, attrs in graph.graph.edges(data=True):
        if attrs.get("type") in allowed:
            sub.add_edge(src, dst)

    targets = [nid for nid, _ in graph.nodes_of_type(target_type) if nid in sub]
    if not targets:
        return []
    sources = [nid for nid in sub.nodes if sub.in_degree(nid) == 0]

    chains: list[list[ChainStep]] = []
    seen: set[tuple[str, ...]] = set()
    for source in sources:
        for target in targets:
            if source == target:
                continue
            for path in nx.all_simple_paths(sub, source, target, cutoff=max_len):
                key = tuple(path)
                if key in seen:
                    continue
                seen.add(key)
                chains.append(
                    [
                        ChainStep(
                            node_id=nid,
                            node_type=str(graph.graph.nodes[nid].get("type", "unknown")),
                        )
                        for nid in path
                    ]
                )
    chains.sort(key=len, reverse=True)
    return chains
