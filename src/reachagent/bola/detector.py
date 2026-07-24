"""Generic cross-identity BOLA detector (plan §8, §14; Phase 2 Task 8).

Drives the full detection pipeline through the MCP tool boundary — every
fingerprint / fire / run_oracle / write_finding call goes through
``mcp.call_tool`` (the real MCP dispatch boundary), never a direct Python call
into a tool function. Mirrors the Phase 1 harness discipline (Task 9).

For each endpoint in the graph that returns an object with sensitivity_tier ≥ 2
and has a known owner (from recon's ``owns`` edges), the detector:

  1. Fires a baseline GET under the owner identity (read-only, §10).
  2. Fires a probe GET under a non-owner identity.
  3. Runs the cross-identity differential oracle (axis="cross_identity",
     expectation="probe_unauthorized").
  4. On a confirmed violation, writes the finding and links it to the prior
     hop's finding via ``enables`` (Chain Solver, §8).

No crAPI-specific paths, object ids, or identity names appear here — those live
in the surface config and the test fixtures. The detector is generic over any
target whose recon has populated ``owns`` edges.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from itertools import count
from typing import TYPE_CHECKING

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph, finding_id
from reachagent.mcp import server
from reachagent.payloads import PayloadLibrary
from reachagent.tools.explorer_context import ExplorerContext

if TYPE_CHECKING:
    from reachagent.execution.firer import FireResult
    from reachagent.oracles.base import OracleVerdict


@dataclass
class _Shared:
    """Graph + handle registries shared across per-identity MCP sessions."""

    graph: ReachabilityGraph
    fires: dict[str, FireResult] = field(default_factory=dict)
    verdicts: dict[str, OracleVerdict] = field(default_factory=dict)
    fire_seq: count[int] = field(default_factory=count)
    verdict_seq: count[int] = field(default_factory=count)


def _session(
    base_url: str,
    host: str,
    token: str | None,
    shared: _Shared,
    transport: httpx.BaseTransport | None = None,
) -> server._Session:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    client = httpx.Client(headers=headers, timeout=10.0, transport=transport)
    firer = RequestFirer(client, ScopeGuard.from_hosts([host]), AuditLog())
    ctx = ExplorerContext(
        graph=shared.graph,
        firer=firer,
        library=PayloadLibrary.from_file(),
        base_url=base_url,
    )
    return server._Session(
        ctx=ctx,
        _fires=shared.fires,
        _verdicts=shared.verdicts,
        _fire_seq=shared.fire_seq,
        _verdict_seq=shared.verdict_seq,
    )


def _mcp(sess: server._Session) -> object:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("reachagent-bola")
    server.register_tools(mcp, sess)
    return mcp


def _call(mcp: object, name: str, **arguments: object) -> dict[str, object]:
    _content, structured = asyncio.run(mcp.call_tool(name, arguments))  # type: ignore[attr-defined]
    return dict(structured)


def _fire_get(
    mcp: object,
    sess: server._Session,
    identity: str,
    path: str,
    query: dict[str, str] | None = None,
) -> str:
    """Seed endpoint+param, fingerprint, fire GET via MCP; return fire_ref.

    ``query`` names the real query parameter(s) this hop consumes (e.g.
    ``{"report_id": "4"}``). Each is injected by the firer as an actual parameter
    — never baked into ``path`` as a literal ``?k=v`` string, which httpx's
    ``params=`` would then clobber. When ``query`` is empty the endpoint takes no
    consumed identifier, so a benign empty ``probe`` param stands in (the
    fingerprint step the firer requires before any fire).
    """
    items = list((query or {}).items())
    name, value = items[0] if items else ("probe", "")
    ep = sess.graph.add_endpoint(Endpoint(method="GET", path=path))
    param = sess.graph.add_parameter(ep, Parameter(name=name, location="query"))
    _call(mcp, "fingerprint_parameter", identity=identity, endpoint_node=ep, param_node=param)
    fired = _call(
        mcp,
        "fire_request",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        payload=value,
        method="GET",
    )
    return str(fired["fire_ref"])


def _confirm(
    mcp: object,
    *,
    vuln_class: str,
    baseline_ref: str,
    probe_ref: str,
    evidence_ref: str,
    metadata: dict[str, str] | None = None,
) -> bool:
    """Run cross-identity oracle and write finding on violation; return confirmed."""
    verdict = _call(
        mcp,
        "run_oracle",
        evidence={
            "axis": "cross_identity",
            "expectation": "probe_unauthorized",
            "baseline_fire_ref": baseline_ref,
            "probe_fire_ref": probe_ref,
            "json_field": None,
            "baseline_select": None,
            "probe_select": None,
            "evidence_ref": evidence_ref,
        },
    )
    if not verdict.get("is_violation"):
        return False
    _call(
        mcp,
        "write_finding",
        verdict_ref=str(verdict["verdict_ref"]),
        vuln_class=vuln_class,
        metadata=metadata or {},
    )
    return True


@dataclass(frozen=True)
class HopResult:
    """One confirmed BOLA hop: the endpoint path and the finding node id."""

    path: str
    finding_node: str


@dataclass
class DetectionResult:
    """Outcome of a full BOLA detection run over the graph."""

    confirmed_hops: list[HopResult] = field(default_factory=list)
    # enables edges written by the Chain Solver: (from_finding, to_finding)
    chain_edges: list[tuple[str, str]] = field(default_factory=list)
    # per confirmed finding node: how it reaches its object (direct / disclosed /
    # enumerable) — the honest chain precondition, also stamped on the finding.
    preconditions: dict[str, str] = field(default_factory=dict)


_PLACEHOLDER = re.compile(r"\{[^}]+\}")

# An identifier token worth chaining on: a UUID or a long opaque/numeric id.
# Deliberately conservative — short values ("1", "user") produce false links.
_ID_TOKEN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"  # uuid
    r"|[0-9a-zA-Z_-]{12,}"  # long opaque token / slug
    r"|\b\d{4,}\b"  # numeric id (≥4 digits)
)

# A high-entropy, unguessable reference: a UUID or a long opaque token/slug. To
# reach *another* principal's such object cross-user, its id must first be
# *disclosed* somewhere — so a hop consuming one has a genuine upstream producer.
_UNGUESSABLE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    r"|^[0-9a-zA-Z_-]{12,}$"
)

# How a confirmed hop's consumed identifier is obtained — the chain precondition.
_DIRECT = "direct"  # consumes no upstream identifier (a returns-edge read)
_DISCLOSED = "requires_disclosed_identifier"  # unguessable key → must be leaked upstream
_ENUMERABLE = "enumerable_identifier"  # short/sequential key → guessable, no producer needed


def _precondition(consumed: str | None) -> str:
    """Classify how a hop reaches its object — the honest chain precondition.

    Read purely from the *shape* of the consumed identifier, never a target-specific
    field name: ``None`` means the hop reads its object directly; an unguessable key
    (UUID / long opaque token) means the id must be disclosed by an upstream finding
    before a cross-user read is possible (a real two-finding chain); a short numeric
    key means the id is enumerable, so the cross-user read needs no upstream
    producer — recording it as such keeps the chain model honest rather than
    fabricating an ``enables`` edge for a dependency that does not exist.
    """
    if consumed is None:
        return _DIRECT
    return _DISCLOSED if _UNGUESSABLE.match(consumed) else _ENUMERABLE


def _identifiers(body: bytes) -> set[str]:
    """Id-like tokens a response body produces — candidates for a later hop to consume.

    Generic extraction: UUIDs, long opaque tokens, and multi-digit numeric ids.
    No field names or target-specific keys — an identifier is recognised by shape,
    so this works for any target whose objects reference each other by id.
    """
    text = body.decode("utf-8", errors="replace")
    return set(_ID_TOKEN.findall(text))


@dataclass(frozen=True)
class _Candidate:
    """One BOLA probe target: how to fire it, and how to identify its finding.

    ``fire_path`` is the *bare* endpoint path handed to the firer; ``query`` names
    the real query parameter(s) the firer injects (empty for path-only hops).
    ``label`` is the concrete human path (query baked in) — the stable key for the
    finding node, so two instances of the same endpoint stay distinct. ``consumed``
    is the upstream identifier this hop consumes, the precondition anchor.
    """

    fire_path: str
    owner_id: str
    consumed: str | None
    query: dict[str, str]
    label: str


def _candidates(graph: ReachabilityGraph) -> list[_Candidate]:
    """Collect BOLA probe candidates over the graph.

    ``consumed`` is the instance identifier this hop's path consumes — the value
    substituted into a ``{placeholder}`` (strategy 2) or a query parameter
    (strategy 3), or ``None`` for a direct-returns hop (strategy 1) that consumes
    no upstream identifier. It is the precondition anchor: hop B is enabled by hop
    A only when A's response produced the identifier B consumes.

    Considers only GET endpoints returning an object with sensitivity_tier ≥ 2
    that has a known owner. Three strategies, unioned and de-duplicated:

    1. Direct: the endpoint has a ``returns`` edge to an owned object; probe the
       endpoint path verbatim (``consumed=None``).
    2. Path-template substitution: an owned per-instance object whose
       ``instance_key`` can fill a ``{placeholder}`` in a GET path template (e.g. a
       vehicle uuid into ``/identity/api/v2/vehicle/{vehicleId}/location``); the
       substituted key is the ``consumed`` identifier.
    3. Query-parameter substitution: an owned per-instance object read by a GET
       endpoint that returns the *same object type* and declares a query
       parameter (e.g. ``mechanic_report?report_id=<id>``). The instance key is
       carried as a *real* injected query parameter (``query``), never baked into
       the path — the firer injects it, so the path's other query state is not
       clobbered.

    Strategies 2–3 are generic over any target — the id-carrying seam (path
    placeholder or query param) is read from the graph, not from target-specific
    paths or ids.
    """
    out: list[_Candidate] = []
    seen: set[tuple[str, str]] = set()

    def _add(cand: _Candidate) -> None:
        key = (cand.label, cand.owner_id)
        if key not in seen:
            seen.add(key)
            out.append(cand)

    for obj_node, obj in graph.objects():
        if obj.sensitivity_tier < 2:
            continue
        owner_id = graph.owner_of(obj_node)
        if owner_id is None:
            continue
        for ep_node, ep in graph.endpoints():
            if ep.method.upper() != "GET":
                continue
            returns_this_type = any(ro.type == obj.type for _, ro in graph.returns_of(ep_node))
            # Strategy 1: direct returns edge (consumes no upstream identifier).
            for ret_node, _ in graph.returns_of(ep_node):
                if ret_node == obj_node:
                    _add(_Candidate(ep.path, owner_id, None, {}, ep.path))
            # Strategy 2: substitute instance key into a path template.
            if obj.instance_key and _PLACEHOLDER.search(ep.path):
                concrete = _PLACEHOLDER.sub(obj.instance_key, ep.path)
                _add(_Candidate(concrete, owner_id, obj.instance_key, {}, concrete))
            # Strategy 3: inject the instance key as a real query parameter of a GET
            # endpoint that returns the same object type (e.g. ?report_id=<id>).
            if obj.instance_key and returns_this_type:
                for _, param in graph.parameters_of(ep_node):
                    if param.location == "query":
                        label = f"{ep.path}?{param.name}={obj.instance_key}"
                        _add(
                            _Candidate(
                                ep.path,
                                owner_id,
                                obj.instance_key,
                                {param.name: obj.instance_key},
                                label,
                            )
                        )

    return out


def detect(
    graph: ReachabilityGraph,
    base_url: str,
    *,
    owner_tokens: dict[str, str],
    non_owner_tokens: dict[str, str],
    transport: httpx.BaseTransport | None = None,
) -> DetectionResult:
    """Run cross-identity BOLA detection over every sensitivity_tier ≥ 2 endpoint.

    ``owner_tokens`` maps identity_id → bearer token for the resource owner.
    ``non_owner_tokens`` maps identity_id → bearer token for a non-owner probe.
    ``transport`` is an optional httpx transport override for hermetic testing.

    All detection goes through the MCP boundary. The Chain Solver links
    confirmed findings into ``enables`` edges so the reconstructed chain is
    queryable from the graph.

    Read-only-first (§10): only GET endpoints are probed here. State-changing
    endpoints are materialized by recon but never fired by this detector.
    """
    host = httpx.URL(base_url).host or ""
    shared = _Shared(graph=graph)
    solver = ChainSolver(graph)
    result = DetectionResult()

    # Per confirmed hop, the identifiers its owner-baseline response produced and
    # the identifier its own path consumed. An enables edge A→B is written only
    # when B's consumed identifier appears in A's produced set — a real data
    # dependency, never iteration adjacency.
    produced: dict[str, set[str]] = {}
    consumed: dict[str, str | None] = {}

    for cand in _candidates(graph):
        owner_token = owner_tokens.get(cand.owner_id)
        if owner_token is None:
            continue

        # Pick any non-owner that has a token.
        probe_id: str | None = None
        probe_token: str | None = None
        for pid, tok in non_owner_tokens.items():
            if pid != cand.owner_id:
                probe_id = pid
                probe_token = tok
                break
        if probe_id is None or probe_token is None:
            continue

        owner_sess = _session(base_url, host, owner_token, shared, transport)
        probe_sess = _session(base_url, host, probe_token, shared, transport)
        owner_mcp = _mcp(owner_sess)
        probe_mcp = _mcp(probe_sess)

        baseline_ref = _fire_get(owner_mcp, owner_sess, cand.owner_id, cand.fire_path, cand.query)
        probe_ref = _fire_get(probe_mcp, probe_sess, probe_id, cand.fire_path, cand.query)

        evidence_ref = f"bola/{cand.label}"
        precondition = _precondition(cand.consumed)
        confirmed = _confirm(
            _mcp(owner_sess),
            vuln_class="bola",
            baseline_ref=baseline_ref,
            probe_ref=probe_ref,
            evidence_ref=evidence_ref,
            metadata={"chain_precondition": precondition},
        )
        if not confirmed:
            continue

        fn = finding_id("bola", evidence_ref)
        hop = HopResult(path=cand.label, finding_node=fn)
        result.confirmed_hops.append(hop)
        result.preconditions[fn] = precondition

        # Harvest the identifiers this hop's owner-baseline body produced (read
        # server-side from the fire handle — the body never crossed the wire).
        produced[fn] = _identifiers(owner_sess.get_fire(baseline_ref).body)
        consumed[fn] = cand.consumed

    # Second pass — genuine precondition linking, order-independent: link hop A →
    # hop B iff B consumes an identifier A produced (and B did not itself produce
    # it — the dependency must be one-directional). Two independent BOLA instances
    # (each consuming its own owner's key, neither leaking the other's) never
    # satisfy this, so they stay unlinked. This is the documented multi-step
    # chain: hop A's response leaks the identifier hop B's path consumes.
    for to_fn, needed in consumed.items():
        if needed is None:
            continue
        for from_fn, produced_ids in produced.items():
            if from_fn == to_fn:
                continue
            # A→B iff B consumes an identifier A produced, A≠B, and A did not
            # itself consume that identifier. The last clause is what enforces
            # direction and rejects adjacency: a genuine *source* of X (a leak, a
            # direct read) has consumed[A] != X, whereas a co-consumer that merely
            # echoes its own input key (e.g. a location response echoing its
            # carId) has consumed[A] == X and never becomes a spurious producer.
            if needed in produced_ids and consumed.get(from_fn) != needed:
                solver.link(from_fn, to_fn)
                result.chain_edges.append((from_fn, to_fn))

    return result
