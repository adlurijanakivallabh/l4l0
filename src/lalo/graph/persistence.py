"""Graph persistence: atomic write + byte-verify-after-write.

Write to a temp file in the same directory, fsync, ``os.replace`` (atomic), then
re-read and hash-compare — so a truncated/corrupt write is detected, never
silently served. Loading a corrupt file raises rather than returning junk.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import networkx as nx

from ..core.errors import LaloError
from .store import ReachGraph


class PersistenceError(LaloError):
    code = "persistence_error"


def save_graph(graph: ReachGraph, path: str | os.PathLike[str]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = nx.node_link_data(graph.graph, edges="edges")
    payload = json.dumps(data, sort_keys=True).encode("utf-8")

    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except OSError as exc:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise PersistenceError(f"failed writing graph: {exc}") from exc

    written = target.read_bytes()
    if hashlib.sha256(written).digest() != hashlib.sha256(payload).digest():
        raise PersistenceError("byte-verify failed: written graph does not match intended bytes")


def load_graph(path: str | os.PathLike[str]) -> ReachGraph:
    try:
        data = json.loads(Path(path).read_bytes())
        directed = nx.node_link_graph(data, directed=True, multigraph=False, edges="edges")
    except (OSError, json.JSONDecodeError, KeyError, nx.NetworkXError) as exc:
        raise PersistenceError(f"failed loading graph: {exc}") from exc
    return ReachGraph(directed)
