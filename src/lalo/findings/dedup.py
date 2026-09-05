"""Deterministic finding dedup — same class + target + param is the same finding.

A reference agent's own dedup (``report/dedupe.py``, read in full) is an
LLM-judge call comparing full report prose against every existing report —
deliberately not adopted here. Its own system prompt states the real
distinguishing signal in one line: "different endpoints even with same
vulnerability type... different parameters in same endpoint... are NOT
duplicates" — exactly a (class, target, param) identity, just resolved by an
LLM instead of a plain key. L4L0 takes the identity, not the LLM: a
deterministic key is cheaper, has no hallucination surface of its own, and
keeps the one real LLM call in this phase (:mod:`~lalo.findings.review`)
focused on the harder question — is this finding real — rather than on
finding-vs-finding comparison.
"""

from __future__ import annotations

from ..graph.model import NodeKind, ReachabilityGraph


def dedup_key(vuln_class: str, target: str, param: str | None) -> str:
    normalized_param = (param or "").strip().lower()
    return f"{vuln_class.strip().lower()}::{target.strip().lower()}::{normalized_param}"


def find_duplicate(graph: ReachabilityGraph, key: str) -> str | None:
    """The node id of an existing finding with the same dedup key, if any."""
    for node_id in graph.nodes_of_kind(NodeKind.FINDING):
        if graph.node(node_id).get("dedup_key") == key:
            return node_id
    return None
