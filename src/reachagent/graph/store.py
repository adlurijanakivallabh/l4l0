"""Reachability graph store (plan §6, §12).

NetworkX-backed in-process store for Phases 1–2. Migrates to Neo4j (via Neo4j
MCP, §13) once finding-relationship chain queries become the bottleneck.

The **structural layer** (§6) — ``Endpoint``/``Parameter``/``Object`` nodes and
``accepts``/``returns``/``can_call``/``owns`` edges, written by recon (the surface
mapper) and the execution layer.

The **finding-relationship layer** (§6, §8) — the chain mechanism. ``enables``
(``Finding → Finding``) and ``derived_credential`` (``Finding → Session |
Identity``) edges connect confirmed findings into attack paths; a
credential-yielding finding spawns a first-class ``Session``/``Identity`` node the
Coordinator's Chain Solver re-queries from (§8). Finding nodes themselves are
written only through ``write_finding`` (§13) and its ``confirmed_violation`` gate;
the store guards that invariant independently in :meth:`add_finding`.

Node identity is derived deterministically from the node's own fields (see the
``*_id`` helpers), so re-adding the same endpoint/parameter/object/session is
idempotent — recon and the Chain Solver can re-run without duplicating nodes.
Typed edges are keyed on ``(source, target, edge_type)``, so re-adding the same
relationship updates it in place rather than stacking a parallel edge.
"""

from __future__ import annotations

from collections.abc import Iterator

import networkx as nx

from reachagent.graph.edges import FindingEdge, StructuralEdge
from reachagent.graph.nodes import (
    Endpoint,
    Finding,
    FindingStatus,
    Identity,
    Object,
    Parameter,
    Session,
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


def object_id(obj_type: str, instance_key: str | None = None) -> str:
    """Stable id for an :class:`Object` node.

    Keyed by type alone (``object:{type}``) for a type-level object, or by
    type + instance (``object:{type}:{instance_key}``) when the specific instance
    is known — so two instances of the same type (two vehicles) are two distinct
    nodes, which cross-user BOLA needs to anchor "identity B reaches identity A's
    object" on a real instance (§8). A type-only object is the unchanged default,
    so VAmPI and the structural pass are unaffected.
    """
    if instance_key is None:
        return f"object:{obj_type}"
    return f"object:{obj_type}:{instance_key}"


def identity_id(name: str) -> str:
    """Stable id for an :class:`Identity` node (its seed name)."""
    return f"identity:{name}"


def finding_id(vuln_class: str, evidence_ref: str) -> str:
    """Stable id for a :class:`Finding` node (class + its evidence handle).

    Keyed by ``evidence_ref`` so re-committing the same confirmed evidence is
    idempotent rather than stacking duplicate findings.
    """
    return f"finding:{vuln_class}:{evidence_ref}"


def session_id(token_ref: str) -> str:
    """Stable id for a :class:`Session` node (its ``token_ref`` handle).

    Keyed by ``token_ref`` — the secret-free handle the session carries (§10) —
    so a ``derived_credential`` finding that spawns the same session twice is
    idempotent rather than stacking duplicate session nodes.
    """
    return f"session:{token_ref}"


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
        """Add (or refresh) an ``Object`` node; returns its stable id.

        Keyed by ``(type, instance_key)`` (:func:`object_id`): a type-level object
        and a specific instance of that type are distinct nodes, and re-adding the
        same instance is idempotent.
        """
        node = object_id(obj.type, obj.instance_key)
        self._g.add_node(node, **{_KIND: "object", _DATA: obj})
        return node

    def add_identity(self, name: str, identity: Identity) -> str:
        """Add (or refresh) an ``Identity`` node keyed by its seed ``name``."""
        node = identity_id(name)
        self._g.add_node(node, **{_KIND: "identity", _DATA: identity})
        return node

    def add_session(self, session: Session) -> str:
        """Add (or refresh) a ``Session`` node + its ``authenticates_as`` edge (§6).

        Keyed by ``token_ref`` (:func:`session_id`), so re-adding the same session
        is idempotent. The node carries only the ``token_ref`` handle — never the
        token value, which lives solely in the owning identity's isolated store
        (§10). The ``authenticates_as`` edge to ``Identity(session.identity_ref)``
        records which identity the session currently represents; a ``Session`` the
        Chain Solver spawns from a finding (a derived credential, §8) is added the
        same way, so a derived credential is a first-class, queryable node exactly
        like a seeded one.
        """
        node = session_id(session.token_ref)
        self._g.add_node(node, **{_KIND: "session", _DATA: session})
        # Session → Identity: which principal this session acts as (§6).
        self._g.add_edge(
            node,
            identity_id(session.identity_ref),
            key=StructuralEdge.AUTHENTICATES_AS,
        )
        return node

    # -- structural edges (§6) --------------------------------------------

    def add_returns(self, endpoint_node: str, object_node: str) -> None:
        """Record that ``endpoint_node`` exposes ``object_node`` (§6)."""
        self._g.add_edge(endpoint_node, object_node, key=StructuralEdge.RETURNS)

    def set_owns(self, identity_node: str, object_node: str) -> None:
        """Record that ``identity_node`` owns ``object_node`` — app-declared (§6).

        The ``owns`` edge is intended ownership per the app's own roles (§6): the
        cross-user reference point a BOLA diff is posed against ("identity A owns
        object O; does identity B, who does not, still reach the endpoint that
        returns O?"). Phase 1 deferred this edge; it is written here so cross-user
        BOLA can be modelled structurally rather than per-scenario.

        Also stamps ``owner_identity_ref`` onto the ``Object`` node, so the fact
        is readable both as an edge and as an attribute on the object itself. The
        edge is keyed on ``(identity, object, owns)``, so re-declaring the same
        ownership updates in place rather than stacking. Ownership is only ever
        *declared* here from a source that knows it (recon reading the app's own
        response, Task 2) — this method never infers an owner.
        """
        self._g.add_edge(identity_node, object_node, key=StructuralEdge.OWNS)
        # Mirror the fact onto the Object node so a reader holding only the object
        # sees its owner without walking edges. identity_node is the stable id.
        self._g.nodes[object_node][_DATA].owner_identity_ref = identity_node

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

    def objects(self) -> list[tuple[str, Object]]:
        """All object nodes as ``(id, Object)`` pairs — type-level and per-instance alike."""
        return [(n, d) for n, d in self._nodes_of_kind("object")]  # type: ignore[misc]

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

    def identities(self) -> list[tuple[str, Identity]]:
        """All identity nodes as ``(id, Identity)`` pairs — seeded and derived alike.

        A derived identity spawned from a finding (§8) is returned here exactly
        like a seeded one, so the Coordinator can treat it as first-class.
        """
        return [(n, d) for n, d in self._nodes_of_kind("identity")]  # type: ignore[misc]

    def sessions(self) -> list[tuple[str, Session]]:
        """All session nodes as ``(id, Session)`` pairs — seeded and derived alike.

        A ``Session`` the Chain Solver spawns via a ``derived_credential`` edge is
        returned from this normal query just like a seeded one, which is what makes
        a derived credential first-class (§8).
        """
        return [(n, d) for n, d in self._nodes_of_kind("session")]  # type: ignore[misc]

    def owns_edges(self) -> list[tuple[str, str]]:
        """All ``owns`` edges as ``(identity_id, object_id)`` pairs (§6)."""
        return [
            (src, dst) for src, dst, key in self._g.edges(keys=True) if key == StructuralEdge.OWNS
        ]

    def owner_of(self, object_node: str) -> str | None:
        """The identity id that owns ``object_node``, or ``None`` if undeclared (§6).

        Read from the ``Object`` node's ``owner_identity_ref``, which ``set_owns``
        stamps alongside the edge — so a reader holding only the object sees its
        owner without walking edges. ``None`` means ownership was never declared
        (empirical-or-absent, mirroring ``can_call``), not that it is public.
        """
        ref: str | None = self._g.nodes[object_node][_DATA].owner_identity_ref
        return ref

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

    def add_enables(self, from_finding: str, to_finding: str) -> None:
        """Link finding A → finding B: A's output makes B possible — the chain edge (§8).

        The ``enables`` edge is the single mechanism the Chain Solver uses to
        connect confirmed findings into one attack path (§8), so a reconstructed
        chain is a connected run of these edges rather than a report string.
        Both endpoints must be existing ``Finding`` nodes — an ``enables`` edge
        only ever links two confirmations, never a raw candidate — so this raises
        if either id is not a finding already committed via ``write_finding``.
        Keyed on ``(from, to, enables)``, so re-linking the same pair is
        idempotent.
        """
        self._require_finding(from_finding)
        self._require_finding(to_finding)
        self._g.add_edge(from_finding, to_finding, key=FindingEdge.ENABLES)

    def add_derived_credential(self, from_finding: str, spawned_node: str) -> None:
        """Link a finding to the ``Session``/``Identity`` it yields (§8).

        A finding that yields a usable session or credential spawns a first-class
        node the Coordinator treats like a seeded one (§8); this edge records that
        provenance. ``spawned_node`` must already exist (added via ``add_session``
        or ``add_identity``) and ``from_finding`` must be a committed ``Finding``,
        so the edge always connects a real confirmation to a real spawned node.
        Keyed on ``(from, spawned, derived_credential)`` — idempotent on re-add.
        """
        self._require_finding(from_finding)
        if not self._g.has_node(spawned_node):
            raise ValueError(
                f"derived_credential target {spawned_node!r} does not exist; "
                "spawn the Session/Identity node first"
            )
        self._g.add_edge(from_finding, spawned_node, key=FindingEdge.DERIVED_CREDENTIAL)

    def enables_edges(self) -> list[tuple[str, str]]:
        """All ``enables`` edges as ``(from_finding_id, to_finding_id)`` pairs (§8)."""
        return [
            (src, dst) for src, dst, key in self._g.edges(keys=True) if key == FindingEdge.ENABLES
        ]

    def derived_credential_edges(self) -> list[tuple[str, str]]:
        """All ``derived_credential`` edges as ``(finding_id, spawned_node_id)`` (§8)."""
        return [
            (src, dst)
            for src, dst, key in self._g.edges(keys=True)
            if key == FindingEdge.DERIVED_CREDENTIAL
        ]

    def _require_finding(self, node: str) -> None:
        """Raise unless ``node`` is an existing ``Finding`` node.

        Guards the finding-relationship layer: an ``enables``/``derived_credential``
        edge only ever originates from a committed confirmation, never a candidate
        or an arbitrary node id.
        """
        attrs = self._g.nodes.get(node)
        if attrs is None or attrs.get(_KIND) != "finding":
            raise ValueError(f"{node!r} is not a committed Finding node")

    def node_count(self) -> int:
        """Total node count — cheap coverage check for tests/reporting."""
        return self._g.number_of_nodes()

    def has_node(self, node: str) -> bool:
        """Whether ``node`` exists in the graph."""
        return self._g.has_node(node)
