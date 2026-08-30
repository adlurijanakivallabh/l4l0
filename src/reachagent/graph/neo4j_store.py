"""Neo4j-backed reachability store — parity backend via the neo4j-cypher MCP (§12, §13).

A second implementation of the store contract that :class:`ReachabilityGraph`
(NetworkX) also satisfies. This is **parity, not cutover**: NetworkX stays the
default in-process backend for Phases 1–2; this backend exists so the finding-
relationship chain queries (§8) can move to Cypher — where variable-length path
traversal is a single query — once they become the bottleneck (§12).

Every method here emits parameterized Cypher and runs it through an injected
:class:`~reachagent.graph.cypher_executor.CypherExecutor`. Two properties are
load-bearing:

* **No bolt driver.** All Neo4j I/O goes through the MCP tool (CLAUDE.md §13);
  there is no ``import neo4j`` — the executor drives the same ``neo4j-cypher``
  MCP server the agent uses.
* **Secrets never enter the graph.** A ``Session`` node stores only its
  ``token_ref`` handle, exactly as the NetworkX store does (§10). Values are
  passed as query *parameters*, never string-interpolated into Cypher, so the
  stored properties are the same secret-free fields on both backends.

Node identity is the same ``*_id`` string the NetworkX store uses (imported from
``store``), stored as the ``id`` property under a shared ``:Node`` label with a
``kind`` discriminator — so the two backends key nodes identically and a contract
test can assert equal results.
"""

from __future__ import annotations

from reachagent.graph.cypher_executor import CypherExecutor
from reachagent.graph.edges import FindingEdge, StructuralEdge
from reachagent.graph.nodes import (
    Endpoint,
    Finding,
    FindingStatus,
    Identity,
    Object,
    Parameter,
    Session,
)
from reachagent.graph.store import (
    _DEPENDENCY_REF,
    endpoint_id,
    finding_id,
    identity_id,
    object_id,
    parameter_id,
    session_id,
)
from reachagent.oracles import evidence as _evidence

# Shared node label + relationship type used for every node/edge; the specific
# kind and edge semantics live in properties, mirroring the NetworkX store's
# _KIND tag rather than growing a label per node type (§6 — no schema sprawl).
_LABEL = "Node"


class Neo4jGraphStore:
    """The store contract over Neo4j, driven entirely through a Cypher executor.

    Exposes the same node-writer / edge-writer / query methods as
    :class:`ReachabilityGraph`; only the backing store differs.
    """

    def __init__(self, executor: CypherExecutor) -> None:
        self._ex = executor

    # -- schema / lifecycle ----------------------------------------------

    def wipe(self) -> None:
        """Delete every node and relationship — a clean slate for a test run."""
        self._ex.write("MATCH (n) DETACH DELETE n")

    def _merge_node(self, node_id: str, kind: str, props: dict[str, object]) -> str:
        """MERGE a node by id, refreshing its kind + properties. Idempotent."""
        self._ex.write(
            f"MERGE (n:{_LABEL} {{id: $id}}) SET n.kind = $kind, n += $props",
            {"id": node_id, "kind": kind, "props": props},
        )
        return node_id

    def _merge_edge(
        self, src: str, dst: str, edge_type: str, props: dict[str, object] | None = None
    ) -> None:
        """MERGE a typed edge keyed on (src, dst, type). Idempotent; refreshes props."""
        self._ex.write(
            f"MATCH (a:{_LABEL} {{id: $src}}), (b:{_LABEL} {{id: $dst}}) "
            "MERGE (a)-[r:REL {type: $type}]->(b) SET r += $props",
            {"src": src, "dst": dst, "type": edge_type, "props": props or {}},
        )

    # -- structural nodes (§6) -------------------------------------------

    def add_endpoint(self, endpoint: Endpoint) -> str:
        node = endpoint_id(endpoint.method, endpoint.path)
        props: dict[str, object] = {
            "method": endpoint.method,
            "path": endpoint.path,
            "state_changing": endpoint.state_changing,
            "protocol": endpoint.protocol.value,
        }
        for key, value in {
            "content_type": endpoint.content_type,
            "graphql_operation_type": endpoint.graphql_operation_type,
            "technology": endpoint.technology,
            "detected_version": endpoint.detected_version,
            "access_restricted": endpoint.access_restricted,
            "source": endpoint.source,
            "confidence": endpoint.confidence,
            "evidence_ref": endpoint.evidence_ref,
            "request_body": endpoint.request_body,
            "response_content_type": endpoint.response_content_type,
            "response_shape": endpoint.response_shape,
        }.items():
            if value is not None:
                props[key] = value
        if endpoint.request_headers:
            props["request_headers"] = dict(endpoint.request_headers)
        return self._merge_node(
            node,
            "endpoint",
            props,
        )

    def add_parameter(self, endpoint_node: str, parameter: Parameter) -> str:
        node = parameter_id(endpoint_node, parameter.location, parameter.name)
        props: dict[str, object] = {
            "name": parameter.name,
            "location": parameter.location,
            "required": parameter.required,
        }
        for key, value in {
            "serialization": parameter.serialization,
            "example": parameter.example,
            "source": parameter.source,
            "confidence": parameter.confidence,
            "evidence_ref": parameter.evidence_ref,
        }.items():
            if value is not None:
                props[key] = value
        if parameter.inferred_sink_type is not None:
            props["inferred_sink_type"] = parameter.inferred_sink_type.value
        self._merge_node(
            node,
            "parameter",
            props,
        )
        self._merge_edge(endpoint_node, node, StructuralEdge.ACCEPTS)
        return node

    def add_object(self, obj: Object) -> str:
        node = object_id(obj.type, obj.instance_key)
        props: dict[str, object] = {"type": obj.type, "sensitivity_tier": obj.sensitivity_tier}
        if obj.instance_key is not None:
            props["instance_key"] = obj.instance_key
        if obj.owner_identity_ref is not None:
            props["owner_identity_ref"] = obj.owner_identity_ref
        return self._merge_node(node, "object", props)

    def add_identity(self, name: str, identity: Identity) -> str:
        node = identity_id(name)
        return self._merge_node(
            node,
            "identity",
            {
                "role": identity.role,
                "auth_state": identity.auth_state.value,
                "provenance": identity.provenance.value,
            },
        )

    def add_session(self, session: Session) -> str:
        node = session_id(session.token_ref)
        # Only the token_ref handle is stored — never a token value (§10).
        self._merge_node(
            node,
            "session",
            {
                "token_ref": session.token_ref,
                "identity_ref": session.identity_ref,
                "live": session.live,
            },
        )
        self._merge_edge(node, identity_id(session.identity_ref), StructuralEdge.AUTHENTICATES_AS)
        return node

    # -- structural edges (§6) -------------------------------------------

    def add_returns(self, endpoint_node: str, object_node: str) -> None:
        self._merge_edge(endpoint_node, object_node, StructuralEdge.RETURNS)

    def set_owns(self, identity_node: str, object_node: str) -> None:
        self._merge_edge(identity_node, object_node, StructuralEdge.OWNS)
        # Mirror the fact onto the Object node, as the NetworkX store does.
        self._ex.write(
            f"MATCH (o:{_LABEL} {{id: $id}}) SET o.owner_identity_ref = $owner",
            {"id": object_node, "owner": identity_node},
        )

    def set_can_call(
        self,
        identity_node: str,
        endpoint_node: str,
        status: FindingStatus,
        *,
        evidence: str,
    ) -> None:
        # MERGE gives one can_call edge per (identity, endpoint); SET overwrites the
        # verdict, so a re-probe replaces rather than stacks — the NetworkX behavior.
        self._merge_edge(
            identity_node,
            endpoint_node,
            StructuralEdge.CAN_CALL,
            {"status": status.value, "evidence": evidence},
        )

    def add_dependency(
        self,
        producer_endpoint: str,
        consumer_endpoint: str,
        *,
        parameter_node: str,
        source_field: str,
        value_ref: str,
        evidence_ref: str = "",
    ) -> None:
        """Persist the same secret-free producer→consumer dependency as NetworkX."""
        if producer_endpoint == consumer_endpoint:
            raise ValueError("producer and consumer endpoints must be distinct")
        if not isinstance(value_ref, str) or _DEPENDENCY_REF.fullmatch(value_ref) is None:
            raise ValueError("value_ref must be a sha256: hash of the runtime identifier")
        source = str(source_field).strip()
        if not source or len(source) > 128 or any(ord(char) < 32 for char in source):
            raise ValueError("source_field must be a bounded, printable name")
        safe_evidence = _evidence.validate_evidence_ref(evidence_ref)
        self._merge_edge(
            producer_endpoint,
            consumer_endpoint,
            StructuralEdge.DATA_DEPENDENCY,
            {
                "parameter_node": parameter_node,
                "source_field": source,
                "value_ref": value_ref,
                "evidence_ref": safe_evidence,
            },
        )

    def dependency_edges(self) -> list[tuple[str, str]]:
        return self._typed_edges(StructuralEdge.DATA_DEPENDENCY)

    # -- findings & finding-relationship layer (§8, §13) -----------------

    def add_finding(self, finding: Finding) -> str:
        if finding.status is not FindingStatus.CONFIRMED_VIOLATION:
            raise ValueError(
                "refusing to persist a Finding without a confirmed_violation status "
                f"(got {finding.status.value!r}) — only a confirmed violation is a finding"
            )
        node = finding_id(finding.vuln_class, finding.evidence_ref)
        return self._merge_node(
            node,
            "finding",
            {
                "vuln_class": finding.vuln_class,
                "severity": finding.severity,
                "oracle_used": finding.oracle_used,
                "evidence_ref": finding.evidence_ref,
                "status": finding.status.value,
            },
        )

    def add_enables(self, from_finding: str, to_finding: str) -> None:
        self._require_finding(from_finding)
        self._require_finding(to_finding)
        self._merge_edge(from_finding, to_finding, FindingEdge.ENABLES)

    def add_derived_credential(self, from_finding: str, spawned_node: str) -> None:
        self._require_finding(from_finding)
        if not self.has_node(spawned_node):
            raise ValueError(
                f"derived_credential target {spawned_node!r} does not exist; "
                "spawn the Session/Identity node first"
            )
        self._merge_edge(from_finding, spawned_node, FindingEdge.DERIVED_CREDENTIAL)

    def _require_finding(self, node: str) -> None:
        rows = self._ex.read(
            f"MATCH (n:{_LABEL} {{id: $id}}) RETURN n.kind AS kind",
            {"id": node},
        )
        if not rows or rows[0].get("kind") != "finding":
            raise ValueError(f"{node!r} is not a committed Finding node")

    # -- queries ----------------------------------------------------------

    def _nodes_of_kind(self, kind: str) -> list[str]:
        rows = self._ex.read(
            f"MATCH (n:{_LABEL} {{kind: $kind}}) RETURN n.id AS id ORDER BY n.id",
            {"kind": kind},
        )
        return [str(r["id"]) for r in rows]

    def endpoints(self) -> list[str]:
        return self._nodes_of_kind("endpoint")

    def objects(self) -> list[str]:
        return self._nodes_of_kind("object")

    def identities(self) -> list[str]:
        return self._nodes_of_kind("identity")

    def sessions(self) -> list[str]:
        return self._nodes_of_kind("session")

    def findings(self) -> list[str]:
        return self._nodes_of_kind("finding")

    def can_call_status(self, identity_node: str, endpoint_node: str) -> FindingStatus | None:
        rows = self._ex.read(
            f"MATCH (a:{_LABEL} {{id: $src}})-[r:REL {{type: $type}}]->(b:{_LABEL} {{id: $dst}}) "
            "RETURN r.status AS status",
            {"src": identity_node, "dst": endpoint_node, "type": StructuralEdge.CAN_CALL.value},
        )
        if not rows:
            return None
        return FindingStatus(str(rows[0]["status"]))

    def can_call_edges(self) -> list[tuple[str, str, FindingStatus]]:
        rows = self._ex.read(
            f"MATCH (a:{_LABEL})-[r:REL {{type: $type}}]->(b:{_LABEL}) "
            "RETURN a.id AS src, b.id AS dst, r.status AS status ORDER BY a.id, b.id",
            {"type": StructuralEdge.CAN_CALL.value},
        )
        return [(str(r["src"]), str(r["dst"]), FindingStatus(str(r["status"]))) for r in rows]

    def owns_edges(self) -> list[tuple[str, str]]:
        return self._typed_edges(StructuralEdge.OWNS)

    def owner_of(self, object_node: str) -> str | None:
        rows = self._ex.read(
            f"MATCH (o:{_LABEL} {{id: $id}}) RETURN o.owner_identity_ref AS owner",
            {"id": object_node},
        )
        if not rows:
            return None
        owner = rows[0].get("owner")
        return None if owner is None else str(owner)

    def enables_edges(self) -> list[tuple[str, str]]:
        return self._typed_edges(FindingEdge.ENABLES)

    def derived_credential_edges(self) -> list[tuple[str, str]]:
        return self._typed_edges(FindingEdge.DERIVED_CREDENTIAL)

    def _typed_edges(self, edge_type: str) -> list[tuple[str, str]]:
        rows = self._ex.read(
            f"MATCH (a:{_LABEL})-[r:REL {{type: $type}}]->(b:{_LABEL}) "
            "RETURN a.id AS src, b.id AS dst ORDER BY a.id, b.id",
            {"type": str(edge_type)},
        )
        return [(str(r["src"]), str(r["dst"])) for r in rows]

    def chain_paths(self, start: str) -> list[tuple[str, ...]]:
        """Multi-hop attack paths from ``start`` as a *single* Cypher path query (§8).

        The whole point of moving the finding-relationship layer to Neo4j: a
        variable-length pattern (``-[:REL*1..]->`` over the two chain edge types)
        expresses transitive ``enables``/``derived_credential`` traversal in one
        query, rather than reassembling hops client-side. ``NONE(... IN ...)``
        keeps it acyclic; the ``NOT (last)-->()`` filter keeps only maximal paths
        (those ending at a leaf), matching the NetworkX reference exactly. Sorted
        for a stable, backend-independent result.
        """
        rows = self._ex.read(
            f"MATCH path = (s:{_LABEL} {{id: $start}})-[rels:REL*1..]->(leaf:{_LABEL}) "
            "WHERE ALL(r IN rels WHERE r.type IN $chain) "
            "AND NONE(n IN nodes(path) WHERE size([m IN nodes(path) WHERE m = n]) > 1) "
            "AND NOT (leaf)-[:REL {type: $enables}]->() "
            "AND NOT (leaf)-[:REL {type: $derived}]->() "
            "RETURN [n IN nodes(path) | n.id] AS ids",
            {
                "start": start,
                "chain": [FindingEdge.ENABLES.value, FindingEdge.DERIVED_CREDENTIAL.value],
                "enables": FindingEdge.ENABLES.value,
                "derived": FindingEdge.DERIVED_CREDENTIAL.value,
            },
        )
        paths = [tuple(str(i) for i in row["ids"]) for row in rows if isinstance(row["ids"], list)]
        return sorted(paths)

    def node_count(self) -> int:
        rows = self._ex.read(f"MATCH (n:{_LABEL}) RETURN count(n) AS c")
        return int(str(rows[0]["c"])) if rows else 0

    def has_node(self, node: str) -> bool:
        rows = self._ex.read(
            f"MATCH (n:{_LABEL} {{id: $id}}) RETURN count(n) AS c",
            {"id": node},
        )
        return bool(rows) and int(str(rows[0]["c"])) > 0
