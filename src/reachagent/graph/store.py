"""Reachability graph store (plan §6, §12).

NetworkX-backed in-process store for Phases 1–2. Migrates to Neo4j (via Neo4j
MCP, §13) once finding-relationship chain queries become the bottleneck.

Phase 1 scope: the **structural layer** (§6) — ``Endpoint``/``Parameter``/
``Object`` nodes and ``accepts``/``returns``/``can_call`` edges, written by recon
(the surface mapper) and the execution layer. The finding-relationship layer
(``enables``/``derived_credential``, §8) is written only via ``write_finding``
(§13) and is not implemented here yet.

Node identity is derived deterministically from the node's own fields (see the
``*_id`` helpers), so re-adding the same endpoint/parameter/object is idempotent
— recon can be re-run without duplicating the surface.
"""

from __future__ import annotations

from collections.abc import Iterator

import networkx as nx

from reachagent.graph.edges import StructuralEdge
from reachagent.graph.nodes import (
    Endpoint,
    Finding,
    FindingStatus,
    Identity,
    Object,
    Parameter,
    SinkType,
)

# Node-kind tags stored on every node so a query can filter by type without
# reconstructing the dataclass.
_KIND = "kind"
_DATA = "data"


def endpoint_id(method: str, path: str) -> str:
    """Stable id for an :class:`Endpoint` node (method + path)."""
    return f"endpoint:{method.upper()} {path}"


def parameter_id(endpoint_key: str, location: str, name: str) -> str:
    """Stable id for a :class:`Parameter`, scoped to its owning endpoint."""
    return f"param:{endpoint_key}:{location}:{name}"


def object_id(obj_type: str) -> str:
    """Stable id for an :class:`Object` node (its type)."""
    return f"object:{obj_type}"


def identity_id(name: str) -> str:
    """Stable id for an :class:`Identity` node (its seed name)."""
    return f"identity:{name}"


def finding_id(vuln_class: str, evidence_ref: str) -> str:
    """Stable id for a :class:`Finding` node (class + its evidence handle).

    Keyed by ``evidence_ref`` so re-committing the same confirmed evidence is
    idempotent rather than stacking duplicate findings.
    """
    return f"finding:{vuln_class}:{evidence_ref}"


class ReachabilityGraph:
    """The shared graph — every confirmed finding writes structured facts here (§2).

    Nothing lives only in a report string; the graph is the system of record.
    """

    def __init__(self) -> None:
        # Directed multigraph: parallel typed edges between the same node pair
        # (e.g. an Identity both owns an Object and can_call an Endpoint).
        # Nodes are keyed by string id; attributes carry the §6 node/edge data.
        self._g: nx.MultiDiGraph[str] = nx.MultiDiGraph()

    # -- structural nodes (§6) --------------------------------------------

    def add_endpoint(self, endpoint: Endpoint) -> str:
        """Add (or refresh) an ``Endpoint`` node; returns its stable id."""
        node = endpoint_id(endpoint.method, endpoint.path)
        self._g.add_node(node, **{_KIND: "endpoint", _DATA: endpoint})
        return node

    def add_parameter(self, endpoint_node: str, parameter: Parameter) -> str:
        """Add a ``Parameter`` and the ``accepts`` edge from its endpoint (§6).

        The parameter id is scoped to ``endpoint_node`` so the same parameter
        name on two endpoints stays distinct.
        """
        node = parameter_id(endpoint_node, parameter.location, parameter.name)
        self._g.add_node(node, **{_KIND: "parameter", _DATA: parameter})
        self._g.add_edge(endpoint_node, node, key=StructuralEdge.ACCEPTS)
        return node

    def add_object(self, obj: Object) -> str:
        """Add (or refresh) an ``Object`` node; returns its stable id."""
        node = object_id(obj.type)
        self._g.add_node(node, **{_KIND: "object", _DATA: obj})
        return node

    def add_identity(self, name: str, identity: Identity) -> str:
        """Add (or refresh) an ``Identity`` node keyed by its seed ``name``."""
        node = identity_id(name)
        self._g.add_node(node, **{_KIND: "identity", _DATA: identity})
        return node

    # -- structural edges (§6) --------------------------------------------

    def add_returns(self, endpoint_node: str, object_node: str) -> None:
        """Record that ``endpoint_node`` exposes ``object_node`` (§6)."""
        self._g.add_edge(endpoint_node, object_node, key=StructuralEdge.RETURNS)

    def set_can_call(
        self,
        identity_node: str,
        endpoint_node: str,
        status: FindingStatus,
        *,
        evidence: str,
    ) -> None:
        """Write/replace the empirical ``can_call`` edge for an (identity, endpoint) (§6).

        ``status`` must come from an actual response (the mapper never assumes
        it). ``evidence`` is a short, secret-free provenance string (e.g. the
        observed HTTP status) so the edge is auditable.
        """
        # Single can_call edge per (identity, endpoint): drop any prior verdict
        # before writing the current one, so a re-probe overwrites rather than
        # stacking a second parallel edge.
        if self._g.has_edge(identity_node, endpoint_node, key=StructuralEdge.CAN_CALL):
            self._g.remove_edge(identity_node, endpoint_node, key=StructuralEdge.CAN_CALL)
        self._g.add_edge(
            identity_node,
            endpoint_node,
            key=StructuralEdge.CAN_CALL,
            status=status,
            evidence=evidence,
        )

    # -- queries ----------------------------------------------------------

    def _nodes_of_kind(self, kind: str) -> Iterator[tuple[str, object]]:
        for node, attrs in self._g.nodes(data=True):
            if attrs.get(_KIND) == kind:
                yield node, attrs[_DATA]

    def endpoints(self) -> list[tuple[str, Endpoint]]:
        """All endpoint nodes as ``(id, Endpoint)`` pairs."""
        return [(n, d) for n, d in self._nodes_of_kind("endpoint")]  # type: ignore[misc]

    def parameters_of(self, endpoint_node: str) -> list[tuple[str, Parameter]]:
        """Parameters reachable from ``endpoint_node`` via an ``accepts`` edge."""
        out: list[tuple[str, Parameter]] = []
        for _, target, key in self._g.out_edges(endpoint_node, keys=True):
            if key == StructuralEdge.ACCEPTS:
                out.append((target, self._g.nodes[target][_DATA]))
        return out

    def endpoint(self, endpoint_node: str) -> Endpoint:
        """The ``Endpoint`` dataclass stored at ``endpoint_node``."""
        data: Endpoint = self._g.nodes[endpoint_node][_DATA]
        return data

    def parameter(self, param_node: str) -> Parameter:
        """The ``Parameter`` dataclass stored at ``param_node``."""
        data: Parameter = self._g.nodes[param_node][_DATA]
        return data

    def set_parameter_sink_type(self, param_node: str, sink: SinkType | None) -> None:
        """Set a Parameter's ``inferred_sink_type`` — written by fingerprinting (§9).

        This is the single mutation ``fingerprint_parameter`` makes to the graph;
        it must complete before any attack payload fires downstream (§9), which
        the Explorer's ``fire_request`` enforces by refusing an un-fingerprinted
        parameter.
        """
        self._g.nodes[param_node][_DATA].inferred_sink_type = sink

    def parameter_sink(self, param_node: str) -> SinkType | None:
        """The Parameter's inferred sink, or ``None`` if not yet fingerprinted."""
        sink: SinkType | None = self._g.nodes[param_node][_DATA].inferred_sink_type
        return sink

    def can_call_status(self, identity_node: str, endpoint_node: str) -> FindingStatus | None:
        """The recorded ``can_call`` status for an edge, or ``None`` if unprobed."""
        data = self._g.get_edge_data(identity_node, endpoint_node, key=StructuralEdge.CAN_CALL)
        if data is None:
            return None
        status: FindingStatus = data["status"]
        return status

    def can_call_edges(self) -> list[tuple[str, str, FindingStatus]]:
        """All ``can_call`` edges as ``(identity_id, endpoint_id, status)``."""
        out: list[tuple[str, str, FindingStatus]] = []
        for src, dst, key, data in self._g.edges(keys=True, data=True):
            if key == StructuralEdge.CAN_CALL:
                out.append((src, dst, data["status"]))
        return out

    # -- findings & negative results (§13) --------------------------------

    def add_finding(self, finding: Finding) -> str:
        """Persist a confirmed :class:`Finding` node and return its id (§13).

        Independent last-line guard on the CLAUDE.md non-negotiable: the store
        physically refuses any ``Finding`` whose ``status`` is not
        ``CONFIRMED_VIOLATION``. The Validator's ``write_finding`` is the intended
        caller and already gates on the oracle verdict; this check means even a
        mis-wired caller can't land a non-violation (or defaulted-inconclusive)
        finding in the graph. Idempotent by ``finding_id``.
        """
        if finding.status is not FindingStatus.CONFIRMED_VIOLATION:
            raise ValueError(
                "refusing to persist a Finding without a confirmed_violation status "
                f"(got {finding.status.value!r}) — only a confirmed violation is a finding"
            )
        node = finding_id(finding.vuln_class, finding.evidence_ref)
        self._g.add_node(node, **{_KIND: "finding", _DATA: finding})
        return node

    def findings(self) -> list[tuple[str, Finding]]:
        """All persisted findings as ``(id, Finding)`` pairs."""
        return [(n, d) for n, d in self._nodes_of_kind("finding")]  # type: ignore[misc]

    def mark_edge_inconclusive(
        self, identity_node: str, endpoint_node: str, *, evidence: str
    ) -> None:
        """Write an ``inconclusive`` verdict back onto a ``can_call`` edge (§13).

        Records the negative result so the Coordinator's scoring doesn't re-select
        the same edge for retesting. Reuses the single-edge ``can_call`` slot, so
        an inconclusive verdict overwrites whatever provisional status was there.
        """
        self.set_can_call(
            identity_node, endpoint_node, FindingStatus.INCONCLUSIVE, evidence=evidence
        )

    def node_count(self) -> int:
        """Total node count — cheap coverage check for tests/reporting."""
        return self._g.number_of_nodes()

    def has_node(self, node: str) -> bool:
        """Whether ``node`` exists in the graph."""
        return self._g.has_node(node)
