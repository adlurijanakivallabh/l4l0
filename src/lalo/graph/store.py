"""ReachGraph — the NetworkX-backed reachability + attack-chain store."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from typing import Any, cast

import networkx as nx

from ..models import Evidence, EvidenceKind, Finding, Severity
from .schema import EdgeType, NodeType


def _finding_to_attrs(finding: Finding) -> dict[str, object]:
    return {
        "finding_id": finding.id,
        "title": finding.title,
        "vuln_class": finding.vuln_class,
        "severity": finding.severity.value,
        "target": finding.target,
        "confidence": finding.confidence,
        "confidence_breakdown": dict(finding.confidence_breakdown),
        "poc": finding.poc,
        "evidence": [
            {
                "kind": e.kind.value,
                "summary": e.summary,
                "fire_ref": e.fire_ref,
                "observed": e.observed,
                "metadata": dict(e.metadata),
            }
            for e in finding.evidence
        ],
        "metadata": dict(finding.metadata),
    }


def _finding_from_attrs(attrs: dict[str, object]) -> Finding:
    raw_evidence = cast("list[dict[str, Any]]", attrs.get("evidence", []))
    evidence = [
        Evidence(
            kind=EvidenceKind(str(e["kind"])),
            summary=str(e["summary"]),
            fire_ref=e.get("fire_ref"),
            observed=str(e.get("observed", "")),
            metadata=dict(e.get("metadata", {})),
        )
        for e in raw_evidence
    ]
    breakdown = cast("dict[str, float]", attrs.get("confidence_breakdown", {}))
    metadata = cast("dict[str, object]", attrs.get("metadata", {}))
    return Finding(
        id=str(attrs["finding_id"]),
        title=str(attrs["title"]),
        vuln_class=str(attrs["vuln_class"]),
        severity=Severity(str(attrs["severity"])),
        target=str(attrs["target"]),
        evidence=evidence,
        confidence=cast("float | None", attrs.get("confidence")),
        confidence_breakdown=dict(breakdown),
        poc=cast("str | None", attrs.get("poc")),
        metadata=dict(metadata),
    )


class ReachGraph:
    """Typed convenience wrapper over a directed graph of discovered facts."""

    def __init__(self, graph: nx.DiGraph[str] | None = None) -> None:
        self._g: nx.DiGraph[str] = graph if graph is not None else nx.DiGraph()

    @property
    def graph(self) -> nx.DiGraph[str]:
        return self._g

    def snapshot(self) -> ReachGraph:
        """Return a deep, independent copy — a sub-agent works on this in isolation."""
        return ReachGraph(copy.deepcopy(self._g))

    def _add_node(self, node_id: str, node_type: NodeType, **attrs: object) -> str:
        self._g.add_node(node_id, type=node_type.value, **attrs)
        return node_id

    def link(self, src: str, dst: str, edge_type: EdgeType, **attrs: object) -> None:
        self._g.add_edge(src, dst, type=edge_type.value, **attrs)

    # --- typed node adders -------------------------------------------------
    def add_host(self, host: str) -> str:
        return self._add_node(f"host:{host}", NodeType.HOST, host=host)

    def add_endpoint(self, url: str, method: str = "GET") -> str:
        nid = f"endpoint:{method}:{url}"
        return self._add_node(nid, NodeType.ENDPOINT, url=url, method=method)

    def add_identity(self, name: str, role: str | None = None) -> str:
        return self._add_node(f"identity:{name}", NodeType.IDENTITY, name=name, role=role)

    def add_session(self, identity_name: str, label: str) -> str:
        """Add a session node and mirror it onto its identity by construction.

        No usable session should ever exist without a graph session node — this
        is the single place that guarantees the mirror (see identity/store).
        """
        identity_id = self.add_identity(identity_name)
        session_id = f"session:{identity_name}:{label}"
        self._add_node(session_id, NodeType.SESSION, label=label, identity=identity_name)
        self.link(session_id, identity_id, EdgeType.AUTHENTICATED_AS)
        return session_id

    def add_service(self, host: str, port: int, name: str | None = None) -> str:
        nid = f"service:{host}:{port}"
        return self._add_node(nid, NodeType.SERVICE, host=host, port=port, name=name)

    def add_fingerprint(self, label: str, **metadata: object) -> str:
        nid = f"fingerprint:{label}"
        return self._add_node(nid, NodeType.FINGERPRINT, label=label, **metadata)

    def add_finding(self, finding: Finding) -> str:
        nid = f"finding:{finding.id}"
        self._add_node(nid, NodeType.FINDING, **_finding_to_attrs(finding))
        return nid

    # --- queries -----------------------------------------------------------
    def nodes_of_type(self, node_type: NodeType) -> Iterator[tuple[str, dict[str, object]]]:
        for node_id, attrs in self._g.nodes(data=True):
            if attrs.get("type") == node_type.value:
                yield node_id, attrs

    def findings(self) -> list[Finding]:
        return [_finding_from_attrs(attrs) for _, attrs in self.nodes_of_type(NodeType.FINDING)]

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, attrs in self._g.nodes(data=True):
            node_type = str(attrs.get("type", "unknown"))
            counts[node_type] = counts.get(node_type, 0) + 1
        return counts
