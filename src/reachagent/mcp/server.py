"""``reachagent-mcp`` — the Explorer + Validator tools as an MCP server (plan §13).

Phase 1 ships the tool contracts as MCP tools "from the start" so a human can
drive them by hand from Claude Desktop/Code before the autonomous Coordinator
exists (§13, Phase 1 plan). The same contracts the Phase 5 Coordinator will call
are exposed here unchanged — *nothing changes when it takes over* (§13). So this
module adds no logic: it binds runtime collaborators and re-exports the existing
tool functions under their bare §13 signatures.

Three invariants shape the design, and every one is load-bearing:

* **Role boundary (CLAUDE.md non-negotiable, §13).** Only the Explorer subset
  (``fingerprint_parameter``, ``get_payloads``, ``fire_request``,
  ``classify_response``) and the Validator subset (``run_oracle``,
  ``write_finding``, ``mark_inconclusive``) are registered — never a Coordinator
  tool. The Explorer-facing tools have no path to ``write_finding``:
  confirmation stays the Validator's alone. ``tests/phase1/test_mcp_server.py``
  pins the exact registered set.

* **The verdict-construction invariant (Task 6, AST-checked).** ``OracleVerdict``
  is constructed *only* inside ``oracles/differential.py``; a test AST-scans all
  of ``src/reachagent`` to prove it. This module therefore never rebuilds a
  verdict from JSON — if it did, a human could hand ``write_finding`` a
  fabricated "confirmed" verdict and bypass deterministic verification entirely.
  Instead ``run_oracle`` keeps the real verdict server-side and returns an opaque
  ``verdict_ref``; ``write_finding`` commits by that handle. The gate stays where
  the tests put it: behind a genuine oracle run.

* **The JSON boundary.** ``FireResult`` (carries ``httpx.Headers`` + raw
  ``bytes``) and ``OracleVerdict`` (frozen, oracle-minted) don't serialize to a
  JSON schema, and rebuilding them client-side would break the invariant above.
  So in-flight objects pass by *server-side handle*: ``fire_request`` returns a
  ``fire_ref``, ``classify_response`` consumes it. This is exactly how the Phase
  5 Coordinator — itself a JSON tool-caller exchanging refs, not Python objects —
  will chain these calls, which is *why* the contract is stable across the
  handoff rather than in spite of the indirection.

The bound context (firer, payload library, graph, seeded identities, scope) is
built once at startup from environment configuration, mirroring what the
Coordinator will construct per run (``ExplorerContext``, §9, §13).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from itertools import count
from typing import TYPE_CHECKING, Any

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph import nodes as _nodes
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.payloads import (
    PayloadLibrary,
    build_library,
    mint_fire_kit,
    resolve_entry,
)
from reachagent.tools import explorer as _explorer
from reachagent.tools import validator as _validator
from reachagent.tools.explorer_context import ExplorerContext, UploadSpec

_log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from reachagent.execution.firer import FireResult
    from reachagent.oracles.base import OracleVerdict

# Environment configuration (§10, §13). The scope allowlist is deny-by-default and
# mandatory: with no hosts set, every request the firer sees is out of scope, so a
# misconfigured server fires nothing rather than firing somewhere unintended.
_ENV_BASE_URL = "REACHAGENT_TARGET_BASE_URL"
_ENV_SCOPE_HOSTS = "REACHAGENT_SCOPE_HOSTS"
_DEFAULT_BASE_URL = "http://127.0.0.1:5000"


@dataclass
class _Session:
    """Server-side state bridging the stateless MCP calls into the tool objects.

    Holds the one bound :class:`ExplorerContext` (and its graph), plus the two
    handle registries that let non-serializable in-flight objects — a
    :class:`FireResult` and an oracle-minted :class:`OracleVerdict` — be
    referenced across calls without ever crossing the JSON boundary. Handles are
    opaque monotonic strings; a caller can only use one the server previously
    minted, which is also what keeps ``write_finding`` reachable *only* by a
    verdict a real ``run_oracle`` produced.
    """

    ctx: ExplorerContext
    _fires: dict[str, FireResult] = field(default_factory=dict, repr=False)
    _verdicts: dict[str, OracleVerdict] = field(default_factory=dict, repr=False)
    _fire_seq: count[int] = field(default_factory=count, repr=False)
    _verdict_seq: count[int] = field(default_factory=count, repr=False)

    @property
    def graph(self) -> ReachabilityGraph:
        """The reachability graph the bound context reads and writes (§6)."""
        return self.ctx.graph

    def put_fire(self, result: FireResult) -> str:
        """Register a fired-response object and return its opaque handle."""
        ref = f"fire-{next(self._fire_seq)}"
        self._fires[ref] = result
        return ref

    def get_fire(self, ref: str) -> FireResult:
        """Resolve a ``fire_ref`` from ``fire_request`` or raise ``KeyError``."""
        try:
            return self._fires[ref]
        except KeyError as exc:
            raise KeyError(f"unknown fire_ref {ref!r}; call fire_request first") from exc

    def put_verdict(self, verdict: OracleVerdict) -> str:
        """Register an oracle-minted verdict and return its opaque handle."""
        ref = f"verdict-{next(self._verdict_seq)}"
        self._verdicts[ref] = verdict
        return ref

    def get_verdict(self, ref: str) -> OracleVerdict:
        """Resolve a ``verdict_ref`` from ``run_oracle`` or raise ``KeyError``."""
        try:
            return self._verdicts[ref]
        except KeyError as exc:
            raise KeyError(f"unknown verdict_ref {ref!r}; call run_oracle first") from exc


def _build_context(
    *,
    base_url: str | None = None,
    scope_hosts: list[str] | None = None,
) -> ExplorerContext:
    """Build the bound :class:`ExplorerContext` from environment configuration (§10).

    The scope allowlist is deny-by-default: hosts come from
    ``REACHAGENT_SCOPE_HOSTS`` (comma-separated) or the explicit argument, and an
    empty allowlist means the firer refuses every request. This is the same
    collaborator set the Phase 5 Coordinator assembles per run — one firer, one
    payload library, one graph — so the tool behaviour is identical whether a
    human or the Coordinator drives it (§9, §13).
    """
    resolved_base = base_url or os.environ.get(_ENV_BASE_URL, _DEFAULT_BASE_URL)
    if scope_hosts is None:
        raw = os.environ.get(_ENV_SCOPE_HOSTS, "")
        scope_hosts = [h.strip() for h in raw.split(",") if h.strip()]
    if not scope_hosts:
        # Default the allowlist to the target host so an out-of-the-box run can
        # reach VAmPI, but never wider — deny-by-default still holds for any
        # other host (§10).
        host = httpx.URL(resolved_base).host
        scope_hosts = [host] if host else []

    scope = ScopeGuard.from_hosts(scope_hosts)
    firer = RequestFirer(httpx.Client(), scope, AuditLog())
    return ExplorerContext(
        graph=ReachabilityGraph(),
        firer=firer,
        library=_load_library(),
        base_url=resolved_base,
    )


def _load_library() -> PayloadLibrary:
    """Load the full library (base slice + vendored corpus), degrading gracefully.

    The running Explorer should see the whole 14k-entry corpus, not just the base
    slice, so the Phase 5 Coordinator drives the same payloads a live run would
    (§9). ``build_library`` reads the ``third_party/`` snapshot off disk; a checkout
    that hasn't vendored it (or a malformed one) must still start — so any corpus
    load failure falls back to the base slice with a logged warning rather than
    blocking tool startup. 14k entries is an in-memory list; load is cheap.
    """
    try:
        return build_library()
    except Exception as exc:  # noqa: BLE001 — startup must survive an absent/broken snapshot
        _log.warning(
            "corpus load failed (%s); falling back to base payload slice — "
            "the vendored third_party/ snapshot may be absent (see docs/vendored-corpora.md)",
            exc,
        )
        return PayloadLibrary.from_file()


@dataclass
class DifferentialEvidenceInput:
    """Serializable form of the differential oracle's evidence (§7).

    The real :class:`~reachagent.oracles.differential.DifferentialEvidence` nests
    ``Observation`` records; flattened here so the whole thing is a single JSON
    object a human (or the Coordinator) can fill in. ``axis`` and ``expectation``
    are the string values of the oracle's enums; the two observations are the
    baseline and probe responses to diff. Bodies should already be normalized of
    volatile fields by the caller — the oracle only whitespace-normalizes (§7).
    """

    axis: str
    expectation: str
    baseline_status: int = 0
    probe_status: int = 0
    baseline_body: str = ""
    probe_body: str = ""
    baseline_label: str = "baseline"
    probe_label: str = "probe"
    evidence_ref: str = ""
    # Optional handle indirection: instead of inlining bodies, name the two
    # ``fire_ref`` handles from ``fire_request`` and let the server read their
    # (server-side) bodies for the diff — so a secret response body is never sent
    # over the wire to be echoed back (§10, safety_guardrails). ``json_field``, if
    # set, projects one top-level JSON field from each body before comparison,
    # which is how mass-assignment / IDOR confirm a single privileged field
    # (e.g. ``admin``) changed rather than diffing whole documents (§5, §7).
    baseline_fire_ref: str | None = None
    probe_fire_ref: str | None = None
    json_field: str | None = None
    # Optional per-side record selection for a list body (e.g. ``/users/v1/_debug``
    # returns every user): ``"username:name2"`` picks the record whose ``username``
    # is ``name2`` before ``json_field`` is projected from it. This is what lets a
    # single read-only dump confirm a change to *one* record (IDOR: name2's password
    # before vs. after) or compare two records (mass-assignment: a control user's
    # ``admin`` vs. the injected user's) without ever indexing by position.
    baseline_select: str | None = None
    probe_select: str | None = None
    error_signatures: tuple[str, ...] = ()

    def to_evidence(self) -> object:
        """Rebuild the oracle's own evidence dataclass from this flat MCP input.

        Only *evidence* is reconstructed here — never a verdict. The verdict is
        still minted solely inside the oracle family (Task 6 AST invariant); this
        just hands the deterministic oracle the inputs it scores.
        """
        from reachagent.oracles.differential import (
            DiffAxis,
            DifferentialEvidence,
            DiffExpectation,
            Observation,
        )

        return DifferentialEvidence(
            axis=DiffAxis(self.axis),
            expectation=DiffExpectation(self.expectation),
            baseline=Observation(self.baseline_label, self.baseline_status, self.baseline_body),
            probe=Observation(self.probe_label, self.probe_status, self.probe_body),
            evidence_ref=self.evidence_ref,
            error_signatures=self.error_signatures,
        )


def _project(body: bytes, json_field: str | None, select: str | None = None) -> str:
    """Reduce a raw response body to the comparable string the oracle diffs.

    Two optional, composable reductions, applied in order:

    * ``select`` (``"key:value"``) picks one record from a list body — the first
      object whose ``key`` equals ``value``. This is how a single read-only dump
      (``/users/v1/_debug`` returns every user) is narrowed to *one* record before
      projection: IDOR compares ``name2``'s password before vs. after, and
      mass-assignment compares a control user's ``admin`` against the injected
      user's — neither ever indexes by position.
    * ``json_field`` then returns that one field's value (recursively searched),
      so confirmation turns on a *specific* attribute (``admin``, ``password``,
      ``secret``) rather than a whole document with volatile fields.

    With neither set, the decoded body is returned verbatim (a full cross-identity
    diff, e.g. BOLA on a single-object response). Never raises: an unparseable body,
    absent record, or absent field falls back sensibly so a missing signal stays
    inconclusive rather than crashing the run.
    """
    text = body.decode("utf-8", errors="replace")
    if json_field is None and select is None:
        return text
    try:
        parsed: object = json.loads(text)
    except (ValueError, TypeError):
        return text
    if select is not None:
        key, _, value = select.partition(":")
        parsed = _select_record(parsed, key, value)
        if parsed is None:
            return ""
    if json_field is None:
        return json.dumps(parsed, sort_keys=True)
    found = _find_field(parsed, json_field)
    return "" if found is None else json.dumps(found, sort_keys=True)


def _select_record(obj: object, key: str, value: str) -> object | None:
    """First object (anywhere in a nested JSON structure) whose ``key`` == ``value``."""
    if isinstance(obj, dict):
        if str(obj.get(key)) == value:
            return obj
        for v in obj.values():
            hit = _select_record(v, key, value)
            if hit is not None:
                return hit
    elif isinstance(obj, list):
        for item in obj:
            hit = _select_record(item, key, value)
            if hit is not None:
                return hit
    return None


def _find_field(obj: object, field_name: str) -> object:
    """First value for ``field_name`` anywhere in a nested JSON structure, or None."""
    if isinstance(obj, dict):
        if field_name in obj:
            return obj[field_name]
        for value in obj.values():
            hit = _find_field(value, field_name)
            if hit is not None:
                return hit
    elif isinstance(obj, list):
        for item in obj:
            hit = _find_field(item, field_name)
            if hit is not None:
                return hit
    return None


@dataclass
class FingerprintReportOut:
    """Serializable view of a fingerprint report (§9 step 1)."""

    endpoint_node: str
    param_node: str
    inferred_sink_type: str | None
    reflected: bool
    error_signature: str | None
    observed_content_type: str | None


@dataclass
class PayloadEntryOut:
    """Serializable view of one tagged payload plus its fireable value (§9)."""

    vuln_class: str
    context: str
    inferred_sink_type: str | None
    oracle_type: str
    payload_ref: str
    graph_edge_on_success: str
    resolved_value: str
    slot_kit: dict[str, Any]


@dataclass
class FireResultOut:
    """Serializable view of a fired response, plus the handle for chaining (§13).

    Carries only JSON-safe signal (status, decoded-length, timing) and never the
    raw ``httpx.Headers``/``bytes``; ``fire_ref`` is the opaque handle
    ``classify_response`` consumes so the full response never crosses the wire.
    """

    fire_ref: str
    status_code: int
    elapsed_seconds: float
    body_length: int
    content_type: str | None


@dataclass
class CandidateOut:
    """Serializable view of the Explorer's inert candidate handoff (§13).

    Mirrors :class:`~reachagent.tools.candidate.Candidate`: it names the target,
    the raw signal, and which oracle *should* judge it — but carries no verdict
    and no path to ``write_finding``. Confirmation is the Validator's alone.
    """

    identity: str
    endpoint_node: str
    param_node: str | None
    vuln_class: str
    suggested_oracle: str
    payload_ref: str | None
    status_code: int
    body_length: int
    elapsed_seconds: float
    error_strings: list[str]
    notes: list[str]


@dataclass
class VerdictOut:
    """Serializable view of an oracle verdict, plus the handle for chaining (§7, §13).

    ``verdict_ref`` is the opaque handle ``write_finding`` consumes; the verdict
    object itself stays server-side (oracle-minted, never rebuilt from JSON). The
    booleans expose the Task 6 distinction: ``confirmed`` (a deterministic verdict
    was reached) vs. ``is_violation`` (specifically a ``confirmed_violation``, the
    only status that unlocks ``write_finding``).
    """

    verdict_ref: str
    mechanism: str
    status: str
    confirmed: bool
    is_violation: bool
    evidence_ref: str


@dataclass
class FindingOut:
    """Serializable view of a committed finding (§13)."""

    finding_node: str
    vuln_class: str
    severity: str
    oracle_used: str
    evidence_ref: str
    status: str
    metadata: dict[str, str] = field(default_factory=dict)


def register_tools(mcp: FastMCP, session: _Session) -> None:
    """Register the Explorer + Validator tools on ``mcp``, bound to ``session`` (§13).

    Exactly eight tools, matching the §13 manifest's Explorer and Validator rows —
    no Coordinator tool is registered here. Each wrapper binds the server-side
    context/graph and exposes the bare §13 contract (domain arguments only), so a
    human — and later the Coordinator — calls the same signature. The wrappers add
    no detection logic; they translate the JSON boundary to and from the real tool
    functions, including the handle indirection that keeps non-serializable
    objects and the oracle-minted verdict off the wire.
    """
    ctx = session.ctx

    # -- Explorer subset (generates candidates, never confirms) ------------

    @mcp.tool()
    def fingerprint_parameter(
        identity: str, endpoint_node: str, param_node: str, method: str = "GET"
    ) -> FingerprintReportOut:
        """Send a benign canary and set the parameter's inferred sink (§9 step 1)."""
        report = _explorer.fingerprint_parameter(
            ctx, identity, endpoint_node, param_node, method=method
        )
        sink = report.inferred_sink_type
        return FingerprintReportOut(
            endpoint_node=report.endpoint_node,
            param_node=report.param_node,
            inferred_sink_type=sink.value if sink is not None else None,
            reflected=report.reflected,
            error_signature=report.error_signature,
            observed_content_type=report.observed_content_type,
        )

    @mcp.tool()
    def get_payloads(
        vuln_class: str,
        sink_type: str | None = None,
        slot_kit: dict[str, Any] | None = None,
    ) -> list[PayloadEntryOut]:
        """Return sink-matched entries with resolved, fireable values (§9).

        A fresh kit is minted for each entry, so per-fire correlators are unique even
        when one lookup returns multiple payloads. Caller-supplied values (for example
        an OOB collaborator domain or timing delay) override minted defaults. Resolver
        errors propagate: dead refs and missing required slots never become empty
        payloads.
        """
        sink = _nodes.SinkType(sink_type) if sink_type is not None else None
        entries = _explorer.get_payloads(ctx, vuln_class, sink)
        outputs = []
        for e in entries:
            kit = mint_fire_kit(**(slot_kit or {}))
            outputs.append(
                PayloadEntryOut(
                    vuln_class=e.vuln_class,
                    context=e.context,
                    inferred_sink_type=(
                        e.inferred_sink_type.value if e.inferred_sink_type is not None else None
                    ),
                    oracle_type=e.oracle_type.value,
                    payload_ref=e.payload_ref,
                    graph_edge_on_success=e.graph_edge_on_success,
                    resolved_value=resolve_entry(e, **kit),
                    slot_kit=kit,
                )
            )
        return outputs

    @mcp.tool()
    def fire_request(
        identity: str,
        endpoint_node: str,
        param_node: str,
        payload: str,
        method: str = "GET",
        state_changing: bool = False,
        extra_fields: dict[str, Any] | None = None,
        upload: dict[str, Any] | None = None,
    ) -> FireResultOut:
        """Fire one payload-bearing request through the firer; returns a fire_ref (§13).

        ``extra_fields`` supplies sibling body/form keys when one injected field is
        not a complete request (multi-field JSON, or a multipart form's non-file
        parts). ``upload`` (keys ``filename``, ``content``, ``content_type``)
        selects a ``multipart/form-data`` fire — ``content`` is a UTF-8 string sent
        as the file bytes. The response body is still withheld from this result
        (only ``body_length`` crosses); ``run_oracle`` resolves the body server-side
        by ``fire_ref`` (§13).
        """
        upload_spec = None
        if upload is not None:
            upload_spec = UploadSpec(
                filename=str(upload.get("filename", "upload.bin")),
                content=str(upload.get("content", "")).encode("utf-8"),
                content_type=str(upload.get("content_type", "application/octet-stream")),
            )
        result = _explorer.fire_request(
            ctx,
            identity,
            endpoint_node,
            param_node,
            payload,
            method=method,
            state_changing=state_changing,
            extra_fields=extra_fields,
            upload=upload_spec,
        )
        ref = session.put_fire(result)
        return FireResultOut(
            fire_ref=ref,
            status_code=result.status_code,
            elapsed_seconds=result.elapsed_seconds,
            body_length=len(result.body),
            content_type=result.headers.get("content-type"),
        )

    @mcp.tool()
    def classify_response(
        fire_ref: str,
        identity: str,
        endpoint_node: str,
        vuln_class: str,
        suggested_oracle: str,
        param_node: str | None = None,
        payload_ref: str | None = None,
        notes: list[str] | None = None,
    ) -> CandidateOut:
        """Extract raw signal from a fired response into an inert candidate (§13).

        Consumes a ``fire_ref`` from ``fire_request`` — the full response never
        crossed the wire. Returns a candidate handoff only; there is no path from
        here to ``write_finding``.
        """
        result = session.get_fire(fire_ref)
        candidate = _explorer.classify_response(
            result,
            identity=identity,
            endpoint_node=endpoint_node,
            param_node=param_node,
            vuln_class=vuln_class,
            suggested_oracle=OracleMechanism(suggested_oracle),
            payload_ref=payload_ref,
            notes=tuple(notes or ()),
        )
        return CandidateOut(
            identity=candidate.identity,
            endpoint_node=candidate.endpoint_node,
            param_node=candidate.param_node,
            vuln_class=candidate.vuln_class,
            suggested_oracle=candidate.suggested_oracle.value,
            payload_ref=candidate.payload_ref,
            status_code=candidate.signal.status_code,
            body_length=candidate.signal.body_length,
            elapsed_seconds=candidate.signal.elapsed_seconds,
            error_strings=list(candidate.signal.error_strings),
            notes=list(candidate.notes),
        )

    # -- Validator subset (the only side that confirms / writes findings) --

    @mcp.tool()
    def run_oracle(
        mechanism: str = OracleMechanism.DIFFERENTIAL,
        evidence: dict[str, Any] | None = None,
    ) -> VerdictOut:
        """Run any of the six §7 oracle families; keep the verdict server-side, return a ref.

        ``mechanism`` selects the oracle family (default: ``differential`` for
        backward compatibility with existing callers). ``evidence`` is a flat dict
        whose keys depend on the mechanism:

        * **differential** — same keys as before: ``axis``, ``expectation``,
          ``baseline_status``, ``probe_status``, ``baseline_body``, ``probe_body``,
          ``baseline_fire_ref``, ``probe_fire_ref``, ``json_field``,
          ``baseline_select``, ``probe_select``, ``evidence_ref``.
        * **structural** — ``check_type`` (``file_upload_bypass`` /
          ``path_traversal`` / ``union_extraction`` / ``jwt_forgery`` / ``clickjacking`` /
          ``cors_misconfig`` / ``csrf_missing_protection``),
          ``baseline_status``, ``probe_status``, ``sentinel``, ``union_sentinel``,
          ``response_body``, ``evidence_ref``; for ``clickjacking``:
          ``x_frame_options``, ``csp``; for ``cors_misconfig``: ``acao``,
          ``acac``, ``probe_origin``; for ``csrf_missing_protection``:
          ``set_cookie``, ``csrf_token_present``. For ``clickjacking`` /
          ``cors_misconfig`` the four header fields (``x_frame_options``,
          ``csp``, ``acao``, ``acac``) are resolved from ``probe_fire_ref``
          server-side when not inlined — headers never cross the wire, same
          rule as bodies (§10/§13). ``probe_origin`` stays caller-supplied. For
          ``csrf_missing_protection`` the ``set_cookie`` field is resolved from
          ``probe_fire_ref`` server-side (never crosses the wire, same rule as
          the other headers); ``csrf_token_present`` is a caller-supplied
          boolean signal the detector determines, not header-derived.
        * **timing_statistical** — ``probe_latencies_ms`` (list[float]),
          ``baseline_latencies_ms`` (list[float]), ``threshold_multiplier``
          (float, default 3.0), ``evidence_ref``.
        * **oob_callback** — ``probe_nonce`` (str), ``observed_nonces``
          (list[str]), ``evidence_ref``.
        * **execution_confirmation** — ``flows`` (list of
          ``{source, sink, value_snippet, url}`` dicts), ``payload_tag`` (str),
          ``response_body`` (str), ``evidence_ref``.
        * **business_rule_invariant** — ``rule`` (str), ``baseline_status``
          (int), ``baseline_body`` (str), ``violating_status`` (int),
          ``violating_body`` (str), ``evidence_ref``.
        """
        ev = evidence or {}
        mech = OracleMechanism(mechanism)
        oracle_evidence: object

        if mech is OracleMechanism.DIFFERENTIAL:
            evidence_in = (
                ev if isinstance(ev, DifferentialEvidenceInput) else DifferentialEvidenceInput(**ev)
            )
            if evidence_in.baseline_fire_ref is not None:
                base = session.get_fire(evidence_in.baseline_fire_ref)
                evidence_in.baseline_status = base.status_code
                evidence_in.baseline_body = _project(
                    base.body, evidence_in.json_field, evidence_in.baseline_select
                )
            if evidence_in.probe_fire_ref is not None:
                probe = session.get_fire(evidence_in.probe_fire_ref)
                evidence_in.probe_status = probe.status_code
                evidence_in.probe_body = _project(
                    probe.body, evidence_in.json_field, evidence_in.probe_select
                )
            oracle_evidence = evidence_in.to_evidence()

        elif mech is OracleMechanism.STRUCTURAL:
            from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

            # Resolve response_body AND the framing/CORS response headers from a
            # fire_ref when supplied (mirrors the differential branch's server-side
            # body resolution — fix C, §13). The fire is fetched once and reused;
            # headers never cross the MCP wire (§10/§13). An explicit inline value
            # in ``ev`` always wins over what the fire_ref carries.
            probe_fire = None
            if ev.get("probe_fire_ref"):
                probe_fire = session.get_fire(str(ev["probe_fire_ref"]))

            response_body = str(ev.get("response_body", ""))
            if not response_body and probe_fire is not None:
                response_body = probe_fire.body.decode("utf-8", errors="replace")

            def _hdr(ev_key: str, header_name: str) -> str:
                explicit = ev.get(ev_key)
                if explicit is not None:
                    return str(explicit)
                if probe_fire is not None:
                    return str(probe_fire.headers.get(header_name, ""))
                return ""

            oracle_evidence = StructuralEvidence(
                check_type=StructuralCheckType(ev.get("check_type", "")),
                baseline_status=int(ev.get("baseline_status", 0)),
                probe_status=int(ev.get("probe_status", 0)),
                sentinel=str(ev.get("sentinel", "")),
                union_sentinel=str(ev.get("union_sentinel", "")),
                response_body=response_body,
                x_frame_options=_hdr("x_frame_options", "x-frame-options"),
                csp=_hdr("csp", "content-security-policy"),
                acao=_hdr("acao", "access-control-allow-origin"),
                acac=_hdr("acac", "access-control-allow-credentials"),
                probe_origin=str(ev.get("probe_origin", "")),
                set_cookie=_hdr("set_cookie", "set-cookie"),
                csrf_token_present=bool(ev.get("csrf_token_present", False)),
                evidence_ref=str(ev.get("evidence_ref", "")),
            )

        elif mech is OracleMechanism.TIMING_STATISTICAL:
            from reachagent.oracles.timing_statistical import PairedTrialEvidence

            oracle_evidence = PairedTrialEvidence(
                probe_latencies_ms=tuple(float(x) for x in ev.get("probe_latencies_ms", [])),
                baseline_latencies_ms=tuple(float(x) for x in ev.get("baseline_latencies_ms", [])),
                threshold_multiplier=float(ev.get("threshold_multiplier", 3.0)),
                evidence_ref=str(ev.get("evidence_ref", "")),
            )

        elif mech is OracleMechanism.OOB_CALLBACK:
            from reachagent.oracles.oob_callback import OOBCallbackEvidence

            oracle_evidence = OOBCallbackEvidence(
                probe_nonce=str(ev.get("probe_nonce", "")),
                observed_nonces=frozenset(ev.get("observed_nonces", [])),
                evidence_ref=str(ev.get("evidence_ref", "")),
            )

        elif mech is OracleMechanism.EXECUTION_CONFIRMATION:
            from reachagent.browser.shim import TaintFlow
            from reachagent.oracles.execution_confirmation import ExecutionConfirmationEvidence

            flows = tuple(
                TaintFlow(
                    source=str(f.get("source", "")),
                    sink=str(f.get("sink", "")),
                    value_snippet=str(f.get("value_snippet", "")),
                    url=str(f.get("url", "")),
                )
                for f in ev.get("flows", [])
            )
            # Resolve response_body from a fire_ref when supplied (fix C, §13).
            exec_body = str(ev.get("response_body", ""))
            if not exec_body and ev.get("probe_fire_ref"):
                exec_fire = session.get_fire(str(ev["probe_fire_ref"]))
                exec_body = exec_fire.body.decode("utf-8", errors="replace")

            oracle_evidence = ExecutionConfirmationEvidence(
                flows=flows,
                payload_tag=str(ev.get("payload_tag", "")),
                response_body=exec_body,
                evidence_ref=str(ev.get("evidence_ref", "")),
            )

        elif mech is OracleMechanism.BUSINESS_RULE_INVARIANT:
            from reachagent.oracles.business_rule import (
                BusinessRule,
                BusinessRuleEvidence,
                ReplayObservation,
            )

            oracle_evidence = BusinessRuleEvidence(
                rule=BusinessRule(ev.get("rule", "")),
                baseline=ReplayObservation(
                    label="baseline",
                    status_code=int(ev.get("baseline_status", 0)),
                    body=str(ev.get("baseline_body", "")),
                ),
                violating=ReplayObservation(
                    label="violating",
                    status_code=int(ev.get("violating_status", 0)),
                    body=str(ev.get("violating_body", "")),
                ),
                evidence_ref=str(ev.get("evidence_ref", "")),
            )

        else:
            raise ValueError(f"unhandled mechanism: {mechanism!r}")

        verdict = _validator.run_oracle(mech, oracle_evidence)
        ref = session.put_verdict(verdict)
        return VerdictOut(
            verdict_ref=ref,
            mechanism=verdict.mechanism.value,
            status=verdict.status.value,
            confirmed=verdict.confirmed,
            is_violation=verdict.is_violation,
            evidence_ref=verdict.evidence_ref,
        )

    @mcp.tool()
    def write_finding(
        verdict_ref: str,
        vuln_class: str,
        severity: str = "high",
        metadata: dict[str, str] | None = None,
    ) -> FindingOut:
        """Commit a Finding — only if ``verdict_ref`` names a confirmed_violation (§13).

        Resolves the server-side verdict minted by ``run_oracle`` and delegates to
        the real ``write_finding``, which refuses anything that is not a
        ``confirmed_violation``. There is no way to pass a fabricated verdict: the
        client holds only an opaque ref, never a verdict it could forge.

        ``metadata`` carries deterministic provenance the confirmation established
        (e.g. a chained hop's precondition: whether its consumed identifier is
        disclosed upstream or enumerable). It never affects the write gate.
        """
        verdict = session.get_verdict(verdict_ref)
        finding = _nodes.Finding(
            vuln_class=vuln_class,
            severity=severity,
            oracle_used="",
            evidence_ref="",
        )
        node = _validator.write_finding(session.graph, finding, verdict, metadata=metadata)
        return FindingOut(
            finding_node=node,
            vuln_class=finding.vuln_class,
            severity=finding.severity,
            oracle_used=finding.oracle_used,
            evidence_ref=finding.evidence_ref,
            status=finding.status.value,
            metadata=dict(finding.metadata),
        )

    @mcp.tool()
    def mark_inconclusive(identity_node: str, endpoint_node: str, evidence: str = "") -> str:
        """Write a negative result back to a can_call edge so it isn't retested (§13)."""
        _validator.mark_inconclusive(session.graph, identity_node, endpoint_node, evidence=evidence)
        return "inconclusive"

    # -- fire_browser: Explorer-owned browser transport for DOM XSS (§13, Task 5) --

    @mcp.tool()
    async def fire_browser(identity: str, url: str, inject_shim: bool = True) -> dict[str, object]:
        """Install the taint-tracking shim and navigate to ``url`` (§13, Phase 3 Task 6).

        Explorer-owned. Returns discovered source→sink flows as a JSON-safe dict.
        Each flow is a candidate for the EXECUTION_CONFIRMATION oracle. The
        PlaywrightDriver is built server-side; it never crosses the JSON boundary,
        matching the same handle-indirection discipline as fire_request.
        """

        ctx.firer.scope.enforce(url)

        from playwright.async_api import async_playwright

        from reachagent.browser.playwright_driver import AsyncPlaywrightDriver
        from reachagent.browser.shim import BrowserFireResult, run_taint_shim_async

        async def _run() -> BrowserFireResult:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page()
                    driver = AsyncPlaywrightDriver(page)
                    return await run_taint_shim_async(
                        driver, identity, url, inject_shim=inject_shim
                    )
                finally:
                    await browser.close()

        result = await _run()
        return {
            "url": result.url,
            "identity": result.identity,
            "shim_installed": result.shim_installed,
            "flows": [
                {"source": f.source, "sink": f.sink, "value_snippet": f.value_snippet}
                for f in result.flows
            ],
        }


def build_server(
    *,
    base_url: str | None = None,
    scope_hosts: list[str] | None = None,
) -> FastMCP:
    """Construct the ``reachagent-mcp`` server with all seven tools registered (§13).

    Builds the bound context, wraps it in a :class:`_Session`, and registers the
    Explorer and Validator subsets. Importing :class:`FastMCP` here (not at module
    top) keeps import of this module cheap and side-effect-free for the tests that
    only introspect the registered tool set.
    """
    from mcp.server.fastmcp import FastMCP

    ctx = _build_context(base_url=base_url, scope_hosts=scope_hosts)
    session = _Session(ctx=ctx)
    mcp = FastMCP("reachagent")
    register_tools(mcp, session)
    return mcp


def main() -> None:
    """Console-script entry point (``reachagent-mcp``): serve over stdio (§13).

    Stdio is the transport Claude Desktop/Code drive by hand in Phase 1; the tool
    contracts are identical to what the Phase 5 Coordinator will call, so this
    entry point does not change at that handoff.
    """
    build_server().run()
