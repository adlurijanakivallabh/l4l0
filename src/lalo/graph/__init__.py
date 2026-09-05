"""The reachability + attack-chain graph.

A NetworkX-backed store of what L4L0 has discovered (endpoints, params,
identities, sessions, services, findings, evidence) and how primitives enable one
another (chain edges). Persisted atomically with byte-verification; the chain
solver searches it for multi-step exploit paths.
"""

from .chain import ChainStep, find_chains
from .persistence import load_graph, save_graph
from .schema import EdgeType, NodeType
from .store import ReachGraph

__all__ = [
    "ChainStep",
    "EdgeType",
    "NodeType",
    "ReachGraph",
    "find_chains",
    "load_graph",
    "save_graph",
]
