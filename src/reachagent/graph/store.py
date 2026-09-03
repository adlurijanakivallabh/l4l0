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

import json
import re
from collections.abc import Iterator
from dataclasses import replace

import networkx as nx

from reachagent.graph.edges import FindingEdge, StructuralEdge
from reachagent.graph.nodes import (
    Endpoint,
    Finding,
    FindingStatus,
    Host,
    Identity,
    Object,
    PackageDependency,
    Parameter,
    Protocol,
    Secret,
    Service,
    Session,
    SinkType,
    SourceFile,
    StaticAdvisory,
)
from reachagent.oracles import evidence as _evidence

# Node-kind tags stored on every node so a query can filter by type without
# reconstructing the dataclass.
_KIND = "kind"
_DATA = "data"
_SECRET_FIELD = re.compile(
    r"(?i)(?:pass(?:word|wd)?|token|bearer|secret|authorization|auth(?:entication)?|cookie|csrf|"
    r"api[_-]?key|access[_-]?token|id[_-]?token)"
)
_DEPENDENCY_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


def _redact_text(value: str | None) -> str | None:
    """Redact sensitive JSON fields before examples enter graph state."""
    if value is None:
        return None
    try:
        parsed: object = json.loads(value)
    except (TypeError, ValueError):
        pattern = re.compile(
            r"(?i)(?P<key>pass(?:word|wd)?|token|bearer|secret|authorization|auth(?:entication)?|cookie|csrf|"
            r"api[_-]?key|access[_-]?token|id[_-]?token)"
            r"\s*[=:]\s*(?P<raw>(?:Bearer\s+)?[^,;\s}]+)"
        )

        def redact_match(match: re.Match[str]) -> str:
            raw = match.group("raw")
            # GraphQL variable/type references are schema, not credentials.
            if raw.startswith("$") or raw.rstrip("!)") in {
                "String",
                "Int",
                "Float",
                "Boolean",
                "ID",
            }:
                return match.group(0)
            return f"{match.group('key')}=<redacted>"

        scrubbed = pattern.sub(redact_match, str(value))
        return re.sub(r"(?i)\bBearer\s+[^\s,;}]+", "Bearer <redacted>", scrubbed)

    def scrub(item: object) -> object:
        if isinstance(item, dict):
            return {
                str(key): "<redacted>" if _SECRET_FIELD.search(str(key)) else scrub(child)
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [scrub(child) for child in item]
        return item

    return json.dumps(scrub(parsed), sort_keys=True)


def _sanitize_endpoint(endpoint: Endpoint) -> Endpoint:
    headers = tuple(
        (str(name), "<redacted>" if _SECRET_FIELD.search(str(name)) else str(value))
        for name, value in endpoint.request_headers
    )
    return replace(
        endpoint, request_headers=headers, request_body=_redact_text(endpoint.request_body)
    )


def _sanitize_parameter(parameter: Parameter) -> Parameter:
    example = "<redacted>" if _SECRET_FIELD.search(parameter.name) else parameter.example
    return replace(parameter, example=example)


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


def host_id(address: str) -> str:
    """Stable id for a transport-tier :class:`Host` node (§6, §9; v1.8).

    Keyed by ``address`` (an IP or hostname), so re-asserting the same host from a
    second recon tool refreshes the one node rather than stacking duplicates — the
    same idempotency discipline as every other node id. A discovered subdomain is
    just a host with a hostname address, so it keys here too (no ``Subdomain`` id).
    """
    return f"host:{address}"


def service_id(host_address: str, port: int, protocol: str) -> str:
    """Stable id for a transport-tier :class:`Service` node, scoped to its host (§6, §9).

    Keyed by ``(host_address, port, protocol)`` so the same port on two hosts stays
    distinct and re-scanning one host is idempotent. A service is meaningless
    without the host that exposes it, so its id is host-scoped by construction.
    """
    return f"service:{host_address}:{protocol.lower()}/{port}"


def source_file_id(path: str, rule_id: str, line: int) -> str:
    """Stable id for a :class:`SourceFile` SAST hit (§6, Build Order 7).

    Keyed by ``(path, rule_id, line)`` — the same rule flagging the same line
    on a re-scan is idempotent rather than stacking duplicates.
    """
    return f"source_file:{path}:{rule_id}:{line}"


def package_dependency_id(ecosystem: str, name: str, version: str) -> str:
    """Stable id for a :class:`PackageDependency` node (§6, Build Order 7).

    Keyed by ``(ecosystem, name, version)`` — the same package/version
    declared in two manifests (or re-scanned) is one node, not two.
    """
    return f"package_dependency:{ecosystem}:{name}:{version}"


def secret_id(path: str, line: int, detector: str) -> str:
    """Stable id for a :class:`Secret` detection (§6, Build Order 7).

    Keyed by ``(path, line, detector)`` — never by the secret's own value,
    which never enters the graph at all (§10).
    """
    return f"secret:{path}:{line}:{detector}"


def static_advisory_id(ecosystem: str, package: str, version: str, cve_id: str) -> str:
    """Stable id for a :class:`StaticAdvisory` known-CVE match (§6, Build Order 7)."""
    return f"static_advisory:{ecosystem}:{package}:{version}:{cve_id}"


def _merge_host(existing: Host, incoming: Host) -> Host:
    """Enrich ``existing`` with ``incoming``'s non-``None`` facts — never shrink (§9).

    Recon facts about a host accumulate across tools/records: a later assertion
    fills gaps and unions the ``technology`` set, but never replaces a known value
    with ``None`` or drops previously-seen technology. ``source`` keeps the first
    asserter and folds in any new one as comma-joined provenance, so a merged host
    stays auditable to every tool that contributed. Pure — returns a new ``Host``.
    """
    return Host(
        address=existing.address,
        hostname=existing.hostname or incoming.hostname,
        source=_merge_csv(existing.source, incoming.source),
        technology=_merge_csv(existing.technology, incoming.technology),
        detected_version=existing.detected_version or incoming.detected_version,
        cname=existing.cname or incoming.cname,
        app_domain=existing.app_domain or incoming.app_domain,
    )


def _merge_csv(existing: str | None, incoming: str | None) -> str | None:
    """Union two optional comma-separated fact strings, order-stable, deduped.

    ``None``/absent on either side is tolerated; the result preserves first-seen
    order so a merged ``technology``/``source`` reads deterministically.
    """
    seen: list[str] = []
    for source in (existing, incoming):
        if not source:
            continue
        for token in (t.strip() for t in source.split(",")):
            if token and token not in seen:
                seen.append(token)
    return ", ".join(seen) or None


def _merge_pairs(
    existing: tuple[tuple[str, str], ...], incoming: tuple[tuple[str, str], ...]
) -> tuple[tuple[str, str], ...]:
    """Union replay headers without losing the first observed value."""
    merged: dict[str, str] = dict(existing)
    for key, value in incoming:
        merged.setdefault(str(key), str(value))
    return tuple(sorted(merged.items()))


def _max_confidence(existing: float | None, incoming: float | None) -> float | None:
    values = [value for value in (existing, incoming) if value is not None]
    return max(values) if values else None


def _merge_endpoint(existing: Endpoint, incoming: Endpoint) -> Endpoint:
    """Enrich an endpoint with later source evidence; facts never shrink."""
    return Endpoint(
        method=existing.method,
        path=existing.path,
        content_type=existing.content_type or incoming.content_type,
        protocol=(incoming.protocol if existing.protocol is Protocol.REST else existing.protocol),
        graphql_operation_type=existing.graphql_operation_type or incoming.graphql_operation_type,
        technology=_merge_csv(existing.technology, incoming.technology),
        detected_version=existing.detected_version or incoming.detected_version,
        access_restricted=existing.access_restricted or incoming.access_restricted,
        state_changing=existing.state_changing or incoming.state_changing,
        source=_merge_csv(existing.source, incoming.source),
        confidence=_max_confidence(existing.confidence, incoming.confidence),
        evidence_ref=_merge_csv(existing.evidence_ref, incoming.evidence_ref),
        request_headers=_merge_pairs(existing.request_headers, incoming.request_headers),
        request_body=existing.request_body or incoming.request_body,
        response_content_type=existing.response_content_type or incoming.response_content_type,
        response_shape=existing.response_shape or incoming.response_shape,
    )


def _merge_parameter(existing: Parameter, incoming: Parameter) -> Parameter:
    """Enrich a parameter with replay/provenance facts without clearing a sink."""
    return Parameter(
        name=existing.name,
        location=existing.location,
        inferred_sink_type=existing.inferred_sink_type or incoming.inferred_sink_type,
        serialization=existing.serialization or incoming.serialization,
        required=existing.required or incoming.required,
        example=existing.example or incoming.example,
        source=_merge_csv(existing.source, incoming.source),
        confidence=_max_confidence(existing.confidence, incoming.confidence),
        evidence_ref=_merge_csv(existing.evidence_ref, incoming.evidence_ref),
    )


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
        endpoint = _sanitize_endpoint(endpoint)
        node = endpoint_id(endpoint.method, endpoint.path)
        existing = self._g.nodes.get(node)
        if existing is not None and existing.get(_KIND) == "endpoint":
            self._g.nodes[node][_DATA] = _merge_endpoint(existing[_DATA], endpoint)
        else:
            self._g.add_node(node, **{_KIND: "endpoint", _DATA: endpoint})
        return node

    def add_parameter(self, endpoint_node: str, parameter: Parameter) -> str:
        """Add a ``Parameter`` and the ``accepts`` edge from its endpoint (§6).

        The parameter id is scoped to ``endpoint_node`` so the same parameter
        name on two endpoints stays distinct.
        """
        parameter = _sanitize_parameter(parameter)
        node = parameter_id(endpoint_node, parameter.location, parameter.name)
        existing = self._g.nodes.get(node)
        if existing is not None and existing.get(_KIND) == "parameter":
            self._g.nodes[node][_DATA] = _merge_parameter(existing[_DATA], parameter)
        else:
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

    # -- transport-tier nodes (§6, §9; v1.8) — recon facts only -----------
    #
    # Host/Service nodes carry NO status: they are never a can_call, never a
    # Finding, never confirmed by an oracle. Only recon-tier fact-emitters write
    # them (§9). Idempotent by their *_id helpers, like every other node.

    def add_host(self, host: Host) -> str:
        """Add (or *merge*) a transport-tier :class:`Host` node; return its id (§6, §9).

        Re-asserting the same address is idempotent and **enriching, not
        clobbering**: a second recon tool (or a second whatweb record) that names
        the same host merges its non-``None`` attributes onto the existing node
        rather than overwriting richer facts with sparser ones. This is the correct
        idempotency for a *fact* store — recon facts accumulate, they never shrink.
        A first ``source`` is preserved (the original asserter); a later differing
        source is folded into a comma-joined provenance so attribution stays honest.
        Stored under ``_DATA`` like every structural node, so ``hosts()`` reads it
        back uniformly.
        """
        node = host_id(host.address)
        existing = self._g.nodes.get(node)
        if existing is not None and existing.get(_KIND) == "host":
            self._g.nodes[node][_DATA] = _merge_host(existing[_DATA], host)
        else:
            self._g.add_node(node, **{_KIND: "host", _DATA: host})
        return node

    def add_service(self, host_node: str, service: Service) -> str:
        """Add a transport-tier :class:`Service` and its ``runs_service`` edge (§6, §9).

        The service is attached to ``host_node`` in the same call — a service is
        meaningless without the host that exposes it, so the node and its
        ``runs_service(Host → Service)`` edge are written together (mirrors how
        ``add_session`` writes its ``authenticates_as`` edge). Idempotent, keyed by
        ``(host_address, port, protocol)``.
        """
        host: Host = self._g.nodes[host_node][_DATA]
        node = service_id(host.address, service.port, service.protocol)
        self._g.add_node(node, **{_KIND: "service", _DATA: service})
        self._g.add_edge(host_node, node, key=StructuralEdge.RUNS_SERVICE)
        return node

    def add_source_file(self, source_file: SourceFile) -> str:
        """Add a static-analysis (SAST) hit; return its stable id (§6, Build Order 7).

        Fact-only, same discipline as :meth:`add_host` — never a finding status,
        never confirmed by an oracle. Idempotent, keyed by ``(path, rule_id, line)``.
        """
        node = source_file_id(source_file.path, source_file.rule_id, source_file.line)
        self._g.add_node(node, **{_KIND: "source_file", _DATA: source_file})
        return node

    def add_package_dependency(self, dependency: PackageDependency) -> str:
        """Add a manifest-declared dependency; return its stable id (§6, Build Order 7).

        Idempotent, keyed by ``(ecosystem, name, version)``.
        """
        node = package_dependency_id(dependency.ecosystem, dependency.name, dependency.version)
        self._g.add_node(node, **{_KIND: "package_dependency", _DATA: dependency})
        return node

    def add_secret(self, secret: Secret) -> str:
        """Add a detected hardcoded-secret location; return its stable id (§6, §10,
        Build Order 7). The secret's own value never enters the graph — only its
        detector type and location. Idempotent, keyed by ``(path, line, detector)``.
        """
        node = secret_id(secret.path, secret.line, secret.detector)
        self._g.add_node(node, **{_KIND: "secret", _DATA: secret})
        return node

    def add_static_advisory(self, advisory: StaticAdvisory) -> str:
        """Add a known-CVE match against a manifest dependency version (§6, Build
        Order 7) — the plan's one narrow, explicit exception to "no Finding without
        a confirmed run_oracle result." Deliberately never touches ``Finding``/
        ``add_finding`` at all: this is a structurally distinct node type, so the
        non-negotiable holds by construction, not by a special case inside the
        Finding path. Idempotent, keyed by ``(ecosystem, package, version, cve_id)``.
        """
        node = static_advisory_id(
            advisory.ecosystem, advisory.package, advisory.version, advisory.cve_id
        )
        self._g.add_node(node, **{_KIND: "static_advisory", _DATA: advisory})
        return node

    def add_resolves_to(self, host_node: str, endpoint_node: str) -> None:
        """Record that ``host_node`` serves ``endpoint_node`` — a transport fact (§6, §9).

        How a recon-discovered path (gobuster/ffuf) or fingerprinted endpoint
        (whatweb) attaches to the ``Host`` that serves it. Facts only — no status.
        """
        self._g.add_edge(host_node, endpoint_node, key=StructuralEdge.RESOLVES_TO)

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
        """Record a producer→consumer identifier dependency without the value.

        The edge carries only the consumer parameter, source field, a one-way
        hash of the runtime identifier, and an opaque evidence reference.  The
        identifier itself stays in the short-lived execution binding store.
        """
        if producer_endpoint == consumer_endpoint:
            raise ValueError("producer and consumer endpoints must be distinct")
        for node, expected in (
            (producer_endpoint, "endpoint"),
            (consumer_endpoint, "endpoint"),
            (parameter_node, "parameter"),
        ):
            attrs = self._g.nodes.get(node)
            if attrs is None or attrs.get(_KIND) != expected:
                raise ValueError(f"{node!r} is not a graph {expected} node")
        if not any(
            target == parameter_node and key == StructuralEdge.ACCEPTS
            for _, target, key in self._g.out_edges(consumer_endpoint, keys=True)
        ):
            raise ValueError(
                f"parameter {parameter_node!r} is not accepted by {consumer_endpoint!r}"
            )
        if not isinstance(value_ref, str) or _DEPENDENCY_REF.fullmatch(value_ref) is None:
            raise ValueError("value_ref must be a sha256: hash of the runtime identifier")
        source = str(source_field).strip()
        if not source or len(source) > 128 or any(ord(char) < 32 for char in source):
            raise ValueError("source_field must be a bounded, printable name")
        safe_evidence = _evidence.validate_evidence_ref(evidence_ref)
        self._g.add_edge(
            producer_endpoint,
            consumer_endpoint,
            key=StructuralEdge.DATA_DEPENDENCY,
            parameter_node=parameter_node,
            source_field=source,
            value_ref=value_ref,
            evidence_ref=safe_evidence,
        )

    def dependency_edges(self) -> list[tuple[str, str]]:
        """All producer→consumer data-dependency edges in stable order."""
        return sorted(
            (src, dst)
            for src, dst, key in self._g.edges(keys=True)
            if key == StructuralEdge.DATA_DEPENDENCY
        )

    def dependency_details(self) -> list[dict[str, str]]:
        """Safe metadata for each producer→consumer dependency edge."""
        rows: list[dict[str, str]] = []
        for src, dst, key, attrs in self._g.edges(keys=True, data=True):
            if key != StructuralEdge.DATA_DEPENDENCY:
                continue
            rows.append(
                {
                    "producer_endpoint": str(src),
                    "consumer_endpoint": str(dst),
                    "parameter_node": str(attrs.get("parameter_node", "")),
                    "source_field": str(attrs.get("source_field", "")),
                    "value_ref": str(attrs.get("value_ref", "")),
                    "evidence_ref": str(attrs.get("evidence_ref", "")),
                }
            )
        return sorted(
            rows,
            key=lambda row: (
                row["producer_endpoint"],
                row["consumer_endpoint"],
                row["parameter_node"],
                row["source_field"],
            ),
        )

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

    def returns_of(self, endpoint_node: str) -> list[tuple[str, Object]]:
        """Object nodes reachable from ``endpoint_node`` via a ``returns`` edge."""
        out: list[tuple[str, Object]] = []
        for _, target, key in self._g.out_edges(endpoint_node, keys=True):
            if key == StructuralEdge.RETURNS:
                out.append((target, self._g.nodes[target][_DATA]))
        return out

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

    # -- transport-tier queries (§6, §9; v1.8) ----------------------------

    def hosts(self) -> list[tuple[str, Host]]:
        """All transport-tier host nodes as ``(id, Host)`` pairs (§9). Facts only."""
        return [(n, d) for n, d in self._nodes_of_kind("host")]  # type: ignore[misc]

    def services(self) -> list[tuple[str, Service]]:
        """All transport-tier service nodes as ``(id, Service)`` pairs (§9). Facts only."""
        return [(n, d) for n, d in self._nodes_of_kind("service")]  # type: ignore[misc]

    # -- white-box static facts (Build Order 7) ----------------------------

    def source_files(self) -> list[tuple[str, SourceFile]]:
        """All SAST-hit nodes as ``(id, SourceFile)`` pairs. Facts only."""
        return [(n, d) for n, d in self._nodes_of_kind("source_file")]  # type: ignore[misc]

    def package_dependencies(self) -> list[tuple[str, PackageDependency]]:
        """All manifest-declared dependency nodes as ``(id, PackageDependency)`` pairs."""
        return [(n, d) for n, d in self._nodes_of_kind("package_dependency")]  # type: ignore[misc]

    def secrets(self) -> list[tuple[str, Secret]]:
        """All detected-secret-location nodes as ``(id, Secret)`` pairs. Never
        carries the secret value itself."""
        return [(n, d) for n, d in self._nodes_of_kind("secret")]  # type: ignore[misc]

    def static_advisories(self) -> list[tuple[str, StaticAdvisory]]:
        """All known-CVE-dependency nodes as ``(id, StaticAdvisory)`` pairs. Never a
        ``Finding`` — see :meth:`add_static_advisory`."""
        return [(n, d) for n, d in self._nodes_of_kind("static_advisory")]  # type: ignore[misc]

    def host(self, host_node: str) -> Host:
        """The :class:`Host` dataclass stored at ``host_node``."""
        data: Host = self._g.nodes[host_node][_DATA]
        return data

    def services_of(self, host_node: str) -> list[tuple[str, Service]]:
        """Services reachable from ``host_node`` via a ``runs_service`` edge (§9)."""
        out: list[tuple[str, Service]] = []
        for _, target, key in self._g.out_edges(host_node, keys=True):
            if key == StructuralEdge.RUNS_SERVICE:
                out.append((target, self._g.nodes[target][_DATA]))
        return out

    def resolves_to_edges(self) -> list[tuple[str, str]]:
        """All ``resolves_to`` edges as ``(host_id, endpoint_id)`` pairs (§9)."""
        return [
            (src, dst)
            for src, dst, key in self._g.edges(keys=True)
            if key == StructuralEdge.RESOLVES_TO
        ]

    def runs_service_edges(self) -> list[tuple[str, str]]:
        """All ``runs_service`` edges as ``(host_id, service_id)`` pairs (§9)."""
        return [
            (src, dst)
            for src, dst, key in self._g.edges(keys=True)
            if key == StructuralEdge.RUNS_SERVICE
        ]

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
        finding.evidence_ref = _evidence.validate_evidence_ref(finding.evidence_ref)
        finding.metadata = _evidence.validate_metadata_dict(finding.metadata)
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

    def chain_paths(self, start: str) -> list[tuple[str, ...]]:
        """Multi-hop attack paths from ``start`` over the finding-relationship layer (§8).

        Follows ``enables`` and ``derived_credential`` edges transitively and
        returns every maximal path — one tuple of node ids per leaf reachable from
        ``start`` (a leaf being a node with no further chain edge). This is the
        reconstructed chain §8's Chain Solver walks: a connected run of edges, not
        a report string. Returned sorted for a stable, backend-independent result
        so the NetworkX and Neo4j stores can be asserted equal.

        This is the reference (client-side DFS) the Neo4j backend must match with a
        *single* variable-length Cypher path query rather than reassembling hops.
        """
        chain = {FindingEdge.ENABLES, FindingEdge.DERIVED_CREDENTIAL}

        def _out(node: str) -> list[str]:
            return [dst for _, dst, key in self._g.out_edges(node, keys=True) if key in chain]

        paths: list[tuple[str, ...]] = []

        def _walk(node: str, trail: tuple[str, ...]) -> None:
            nexts = [n for n in _out(node) if n not in trail]  # cycle-safe
            if not nexts:
                if len(trail) > 1:  # a bare start with no chain edge is not a path
                    paths.append(trail)
                return
            for nxt in nexts:
                _walk(nxt, (*trail, nxt))

        if self._g.has_node(start):
            _walk(start, (start,))
        return sorted(paths)

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
