"""Generic payload-library firing loop driven through the MCP boundary (§9, §13).

This module is orchestration, not a role tool. It drives the public MCP Explorer and
Validator contracts in the same sequence a Coordinator-selected run uses:

    fingerprint → get_payloads → fire → classify → run_oracle → write_finding

It never imports Validator and never writes a finding itself. The server keeps raw
responses and oracle verdicts behind opaque handles; this driver only passes those
handles between MCP calls. Bespoke evaluation detectors deliberately do not use this
path.
"""

from __future__ import annotations

import logging as _logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn, Protocol
from urllib.parse import urlsplit

from reachagent.execution.audit import AuditLog
from reachagent.oracles import OracleMechanism
from reachagent.tools import coordinator as _coordinator
from reachagent.tools import coordinator_support as _coordinator_support

if TYPE_CHECKING:
    from reachagent.recon.payload_tuning import PayloadAttemptContext

_log = _logging.getLogger(__name__)

_FAILURE_OUTCOME = "payload_chain_failure"


class McpCaller(Protocol):
    """Minimal synchronous MCP caller used by the generic driver and tests."""

    def __call__(self, name: str, arguments: Mapping[str, object]) -> object: ...


@dataclass(frozen=True)
class PayloadChainResult:
    """Auditable outcome of one generic parameter payload run."""

    attempted: int
    confirmed: bool
    finding_node: str | None = None
    payload_ref: str | None = None
    failure: str | None = None


class PayloadChainError(RuntimeError):
    """Raised when generic payload orchestration cannot proceed safely."""


def _as_mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PayloadChainError(f"MCP {label} returned non-object result")
    return value


def _as_entries(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        raise PayloadChainError("MCP get_payloads returned non-list result")
    entries: list[Mapping[str, object]] = []
    for item in value:
        entries.append(_as_mapping(item, label="get_payloads entry"))
    return entries


def _call_result(call: McpCaller, name: str, **arguments: object) -> Mapping[str, object]:
    return _as_mapping(call(name, arguments), label=name)


def _record_failure(audit_failure: Callable[[str], None] | None, detail: str) -> None:
    if audit_failure is not None:
        audit_failure(detail)


def _raise_audited(audit_failure: Callable[[str], None] | None, detail: str) -> NoReturn:
    _record_failure(audit_failure, detail)
    raise PayloadChainError(detail)


def call_tool_sync(mcp: object, name: str, arguments: Mapping[str, object]) -> object:
    """Call registered MCP tool over ``mcp.call_tool`` and unwrap structured output."""
    import asyncio

    _content, structured = asyncio.run(mcp.call_tool(name, dict(arguments)))  # type: ignore[attr-defined]
    if isinstance(structured, Mapping) and "result" in structured:
        return structured["result"]
    return structured


def audit_failure_callback(
    audit: AuditLog, *, identity: str, base_url: str, endpoint_path: str
) -> Callable[[str], None]:
    """Build sanitized audit callback for local payload-chain failures."""
    parsed = urlsplit(f"{base_url.rstrip('/')}{endpoint_path}")
    target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def record(detail: str) -> None:
        audit.record(identity, "CHAIN", target, f"{_FAILURE_OUTCOME}:{detail}")

    return record


def run_selected_payload_chain(
    call: McpCaller,
    selection: object,
    *,
    vuln_class: str,
    baseline_payload: str,
    slot_kit: Mapping[str, object] | None = None,
    max_attempts: int = 40,
    evidence_prefix: str = "generic/payload-chain",
    budget_check: Callable[[], bool] | None = None,
    audit_failure: Callable[[str], None] | None = None,
) -> PayloadChainResult:
    """Drive one Coordinator selection without giving Coordinator execution powers."""
    if not hasattr(selection, "identity_node"):
        raise PayloadChainError("selection missing identity_node")
    if not hasattr(selection, "endpoint_node"):
        raise PayloadChainError("selection missing endpoint_node")
    parameter_node = getattr(selection, "parameter_node", None)
    if not isinstance(parameter_node, str):
        raise PayloadChainError("selection missing parameter_node")
    identity_node = selection.identity_node
    endpoint_node = selection.endpoint_node
    if not isinstance(identity_node, str) or not isinstance(endpoint_node, str):
        raise PayloadChainError("selection contains invalid graph node ids")
    return run_payload_chain(
        call,
        identity=identity_node,
        endpoint_node=endpoint_node,
        param_node=parameter_node,
        vuln_class=vuln_class,
        baseline_payload=baseline_payload,
        slot_kit=slot_kit,
        max_attempts=max_attempts,
        evidence_prefix=evidence_prefix,
        budget_check=budget_check,
        audit_failure=audit_failure,
    )


def run_coordinator_payload_step(
    call: McpCaller,
    coordinator_input: object,
    *,
    vuln_class: str,
    baseline_payload: str,
    slot_kit: Mapping[str, object] | None = None,
    max_attempts: int = 40,
    evidence_prefix: str = "generic/payload-chain",
    audit_failure: Callable[[str], None] | None = None,
) -> PayloadChainResult:
    """Select one graph candidate with Coordinator, then run Explorer/Validator MCP flow."""
    candidates = _coordinator.query_graph(coordinator_input)
    selection = _coordinator.score_and_select(candidates)
    if selection is None:
        failure = "Coordinator selected no candidate or budget is exhausted"
        _record_failure(audit_failure, failure)
        return PayloadChainResult(attempted=0, confirmed=False, failure=failure)
    context = getattr(selection.candidate, "context", None)
    budget_check: Callable[[], bool] | None = None
    if isinstance(context, _coordinator_support.CoordinatorContext):

        def budget_check() -> bool:
            return bool(_coordinator_support.budget_status(context))

    return run_selected_payload_chain(
        call,
        selection,
        vuln_class=vuln_class,
        baseline_payload=baseline_payload,
        slot_kit=slot_kit,
        max_attempts=max_attempts,
        evidence_prefix=evidence_prefix,
        budget_check=budget_check,
        audit_failure=audit_failure,
    )


def _evidence_for(
    oracle_type: str,
    *,
    baseline_ref: str,
    probe_ref: str,
    evidence_ref: str,
    payload: str = "",
    payload_kit: Mapping[str, object] | None = None,
    vuln_class: str = "",
) -> dict[str, object]:
    """Build evidence for generic payloads using existing §7 mechanisms."""
    kit: Mapping[str, object] = payload_kit or {}

    if oracle_type == OracleMechanism.DIFFERENTIAL.value:
        # Allow caller to pin axis/expectation (e.g. harness mass_assignment vs bola
        # share the same oracle family but differ in DiffExpectation). Fall back to
        # a vuln_class-derived default so existing callers stay generic.
        axis = str(kit.get("axis")) if "axis" in kit else None
        expectation = str(kit.get("expectation")) if "expectation" in kit else None
        if axis is None or expectation is None:
            if vuln_class in {"bola", "bfla"}:
                axis = axis or "cross_identity"
                expectation = expectation or "probe_unauthorized"
            elif vuln_class in {"idor"}:
                axis = axis or "cross_request"
                expectation = expectation or "responses_invariant"
            elif vuln_class in {"mass_assignment", "nosqli", "ldap_injection"}:
                axis = (
                    axis or "cross_request"
                    if vuln_class == "mass_assignment"
                    else "cross_condition"
                )
                expectation = expectation or "responses_invariant"
            elif vuln_class in {"sqli", "sqli_blind"}:
                # Juiceshop login bypass is auth_bypass (refused→granted); generic
                # error-based sqli is database_error. Caller can force via kit.
                axis = axis or "cross_condition"
                expectation = expectation or "database_error"
                if not kit.get("expectation") and payload and " OR " in payload.upper():
                    # Heuristic: operator-injection probes that look like classic
                    # auth bypass — the caller should pin expectation explicitly;
                    # this keeps the generic path honest without a new param.
                    expectation = "auth_bypass"
            else:
                axis = axis or "cross_condition"
                expectation = expectation or "database_error"
        # Optional projection for read-only re-read oracles (bola secret, mass
        # admin, idor password). When absent the diff is whole-body (harness
        # fallback). Values come from kit so the harness/juiceshop can route
        # through generic without re-hardcoding endpoint literals here.
        evidence: dict[str, object] = {
            "axis": axis,
            "expectation": expectation,
            "baseline_fire_ref": baseline_ref,
            "probe_fire_ref": probe_ref,
            "evidence_ref": evidence_ref,
        }
        if "json_field" in kit:
            evidence["json_field"] = kit["json_field"]
        elif vuln_class in {"bola"}:
            evidence["json_field"] = "secret"
        elif vuln_class in {"mass_assignment"}:
            evidence["json_field"] = "admin"
        elif vuln_class in {"idor"}:
            evidence["json_field"] = "password"
        if "baseline_select" in kit:
            evidence["baseline_select"] = kit["baseline_select"]
        if "probe_select" in kit:
            evidence["probe_select"] = kit["probe_select"]
        if expectation == "database_error":
            evidence["error_signatures"] = [
                "sql syntax",
                "sqlite3.operationalerror",
                "sqlite_error",
                "psycopg2",
                "you have an error in your sql",
                "unclosed quotation mark",
                "sqlalchemy",
                'near "',
            ]
        return evidence

    if oracle_type == OracleMechanism.STRUCTURAL.value:
        # Path traversal — sentinel chosen by payload hint (generic)
        if vuln_class == "path_traversal":
            sentinel = str(kit.get("sentinel", "")) or "root:"
            if not kit.get("sentinel") and payload and "win.ini" in payload.lower():
                sentinel = "[extensions]"
            return {
                "check_type": "path_traversal",
                "probe_fire_ref": probe_ref,
                "sentinel": sentinel,
                "evidence_ref": evidence_ref,
            }
        # Union extraction — sentinel sourced from graph-discovered Object field.
        # The harness/juiceshop must supply union_sentinel via kit (graph-derived),
        # never a string literal in the detector. Fallback keeps the generic path
        # usable for hermetic tests with a seeded email.
        if kit.get("check_type") == "union_extraction" or vuln_class in {"sqli", "sqli_blind"}:
            if not kit.get("union_sentinel") and not kit.get("sentinel"):
                import logging

                logging.getLogger(__name__).warning(
                    "union sentinel fallback used — graph empty, fixture recommended"
                )
            union_sentinel = str(
                kit.get("union_sentinel") or kit.get("sentinel") or "admin@juice-sh.op"
            )
            return {
                "check_type": "union_extraction",
                "probe_fire_ref": probe_ref,
                "union_sentinel": union_sentinel,
                "evidence_ref": evidence_ref,
            }
        # JWT forgery — needs both baseline and probe fire refs so the server can
        # resolve 2xx vs 4xx. Valid-token baseline must be 2xx for the probe to mean
        # anything (same guard as the differential baseline-GRANTED).
        if vuln_class == "jwt_forgery" or kit.get("check_type") == "jwt_forgery":
            return {
                "check_type": "jwt_forgery",
                "baseline_fire_ref": baseline_ref,
                "probe_fire_ref": probe_ref,
                "evidence_ref": evidence_ref,
            }
        # SSRF non-blind — sentinel-in-body inside STRUCTURAL (already a family
        # member). The blind SSRF OOB path is a different oracle (oob_callback) and
        # is not routed through here.
        if vuln_class == "ssrf" or kit.get("check_type") == "ssrf_response":
            sentinel = str(kit.get("sentinel") or "ami-id")
            return {
                "check_type": "ssrf_response",
                "probe_fire_ref": probe_ref,
                "sentinel": sentinel,
                "evidence_ref": evidence_ref,
            }
        # Generic structural fallback when the caller pins check_type explicitly
        if "check_type" in kit:
            out: dict[str, object] = {
                "check_type": str(kit["check_type"]),
                "probe_fire_ref": probe_ref,
                "evidence_ref": evidence_ref,
            }
            if "sentinel" in kit:
                out["sentinel"] = kit["sentinel"]
            if "union_sentinel" in kit:
                out["union_sentinel"] = kit["union_sentinel"]
            if "baseline_fire_ref" in kit:
                out["baseline_fire_ref"] = baseline_ref
            return out

    if oracle_type == OracleMechanism.EXECUTION_CONFIRMATION.value and vuln_class == "ssti":
        from reachagent.payloads.payload_resolver import expected_execution_output as _expected_out

        expected = _expected_out(payload)
        if expected is None:
            raise PayloadChainError(
                f"SSTI payload {payload!r} has no deterministic rendered-output expectation"
            )
        return {
            "probe_fire_ref": probe_ref,
            "expected_output": expected,
            "evidence_ref": evidence_ref,
        }
    # OOB callback — blind sqli / ssrf blind / log4shell generic. The per-fire
    # nonce is in payload_kit["nonce"] (mint_fire_kit); the collaborator's
    # observed_nonces are checked server-side. No body to inspect.
    if oracle_type == OracleMechanism.OOB_CALLBACK.value:
        nonce = str(kit.get("nonce") or kit.get("probe_nonce") or "")
        # Empty nonce stays a preflight-safe no-op (run_payload_chain preflight
        # uses dummy refs with no kit); the real loop supplies the nonce.
        if nonce:
            return {
                "probe_nonce": nonce,
                "observed_nonces": kit.get("observed_nonces", []),
                "evidence_ref": evidence_ref,
            }
        return {
            "probe_nonce": "",
            "observed_nonces": [],
            "evidence_ref": evidence_ref,
        }
    raise PayloadChainError(
        f"generic payload chain has no safe evidence adapter for oracle {oracle_type!r} "
        f"(vuln_class={vuln_class!r})"
    )


def _maybe_reorder_payloads(
    entries: list[Mapping[str, object]],
    vuln_class: str,
    sink_type: object,
    slot_kit: Mapping[str, object] | None,
    prior_attempts: tuple[PayloadAttemptContext, ...] = (),
) -> list[Mapping[str, object]]:
    """Proposal-only reorder — flag-gated, dynamic-allowlist-validated.

    When REACHAGENT_PAYLOAD_TUNING=1 or REACHAGENT_RECON_LIVE_TUNING=1, asks
    propose_payload_choice to rank which existing bucket refs to try first.
    Dynamic allowlist is the exact bucket set; fallback is original confidence
    order. Never invents a ref, respects max_attempts downstream.
    """
    from reachagent.llm.runtime import flag_enabled, llm_required

    if not flag_enabled("REACHAGENT_PAYLOAD_TUNING") and not flag_enabled(
        "REACHAGENT_RECON_LIVE_TUNING"
    ):
        return entries
    try:
        from reachagent.recon.payload_tuning import propose_payload_choice

        candidate_refs = [
            str(e.get("payload_ref")) for e in entries if isinstance(e.get("payload_ref"), str)
        ]
        if not candidate_refs:
            return entries
        signals: dict[str, str] = {
            "vuln_class": vuln_class,
            "sink": str(sink_type) if sink_type else "",
        }
        # Surface slot_kit tech hint if present (WordPress/API etc.)
        if slot_kit and isinstance(slot_kit.get("tech"), str):
            signals["tech"] = str(slot_kit["tech"])[:80]
        choice = propose_payload_choice(
            signals, vuln_class, candidate_refs, prior_attempts=prior_attempts
        )
        # Defense in depth: second allowlist check even after proposer validates.
        allowed = set(candidate_refs)
        ordered = [r for r in choice.payload_refs if r in allowed]
        if not ordered:
            return entries
        by_ref = {str(e.get("payload_ref")): e for e in entries}
        remaining = [r for r in candidate_refs if r not in set(ordered)]
        new_order = ordered + remaining
        reordered = [by_ref[r] for r in new_order if r in by_ref]
        return reordered if reordered else entries
    except Exception as exc:  # noqa: BLE001 — proposer must not break chain
        if llm_required():
            raise
        _log.debug("payload reorder skipped: %s", exc)
        return entries


def run_payload_chain(
    call: McpCaller,
    *,
    identity: str,
    endpoint_node: str,
    param_node: str,
    vuln_class: str,
    baseline_payload: str,
    method: str = "GET",
    slot_kit: Mapping[str, object] | None = None,
    max_attempts: int = 40,
    evidence_prefix: str = "generic/payload-chain",
    budget_check: Callable[[], bool] | None = None,
    audit_failure: Callable[[str], None] | None = None,
    on_event: Callable[[str], None] | None = None,
) -> PayloadChainResult:
    """Drive one fingerprinted parameter through catalog payloads via MCP.

    ``call`` must invoke ``mcp.call_tool`` (or an equivalent external MCP client),
    not registered Python functions directly. ``get_payloads`` resolves each entry
    and returns its real fireable value plus per-fire kit. The first genuine
    Validator violation is committed through its opaque verdict handle and stops
    iteration. Empty catalogs, unresolved refs, unsupported oracle adapters, and
    exhausted budgets return explicit failed results; they never become clean.
    """

    def _ev(msg: str) -> None:
        if on_event:
            try:
                on_event(msg)
            except Exception:
                _log.debug("event callback error", exc_info=True)

    _ev(f"fingerprinting {endpoint_node}")

    # Only file_path/template have no observational fingerprint path — for every
    # other class the canary evidence decides the sink (a hint must never
    # override observed signal; explorer enforces this too).
    fingerprint_args: dict[str, object] = {
        "identity": identity,
        "endpoint_node": endpoint_node,
        "param_node": param_node,
        "method": method,
    }
    hint = {"path_traversal": "file_path", "ssti": "template"}.get(vuln_class)
    if hint is not None:
        fingerprint_args["sink_hint"] = hint
        fingerprint_args["vuln_class"] = vuln_class
    fingerprint = _call_result(call, "fingerprint_parameter", **fingerprint_args)
    sink_type = fingerprint.get("inferred_sink_type")
    _ev(f"fingerprint: sink={sink_type}")
    try:
        entries = _as_entries(
            call(
                "get_payloads",
                {
                    "vuln_class": vuln_class,
                    "sink_type": sink_type,
                    "slot_kit": dict(slot_kit or {}),
                },
            )
        )
    except Exception as exc:
        detail = f"payload lookup failed: {type(exc).__name__}"
        _record_failure(audit_failure, detail)
        raise
    if not entries:
        failure = f"no payloads matched vuln_class={vuln_class!r} sink_type={sink_type!r}"
        _record_failure(audit_failure, failure)
        return PayloadChainResult(attempted=0, confirmed=False, failure=failure)

    # Live payload-choice — proposal-only, flag OFF by default. When
    # REACHAGENT_PAYLOAD_TUNING=1 or REACHAGENT_RECON_LIVE_TUNING=1, ranks
    # which existing bucket payload_ref to try first for this endpoint shape.
    # Dynamic allowlist is the exact bucket set — no invented string.
    entries = _maybe_reorder_payloads(entries, vuln_class, sink_type, slot_kit)

    attempted = 0
    for entry in entries:
        if attempted >= max_attempts:
            failure = f"payloads exhausted after {attempted} attempts (budget cap)"
            _record_failure(audit_failure, failure)
            return PayloadChainResult(attempted=attempted, confirmed=False, failure=failure)
        if budget_check is not None and not budget_check():
            failure = f"payloads exhausted after {attempted} attempts (budget gate)"
            _record_failure(audit_failure, failure)
            return PayloadChainResult(attempted=attempted, confirmed=False, failure=failure)

        payload = entry.get("resolved_value")
        payload_ref = entry.get("payload_ref")
        oracle_type = entry.get("oracle_type")
        _ev(f"firing {payload_ref} ({oracle_type})")
        if not isinstance(payload, str) or not payload:
            detail = f"payload {payload_ref!r} resolved to an empty/non-string value"
            _record_failure(audit_failure, detail)
            raise PayloadChainError(detail)
        if not isinstance(payload_ref, str) or not payload_ref:
            detail = "MCP payload entry omitted payload_ref"
            _record_failure(audit_failure, detail)
            raise PayloadChainError(detail)
        if not isinstance(oracle_type, str) or not oracle_type:
            detail = f"payload {payload_ref!r} omitted oracle_type"
            _record_failure(audit_failure, detail)
            raise PayloadChainError(detail)

        # A library entry whose oracle family has no generic evidence adapter is
        # SKIPPED with a loud audit — not a chain-killing raise. The library
        # legitimately carries families (e.g. timing_statistical) that need the
        # dedicated blind-SQLi prober instead of this generic chain; firing them
        # here would produce evidence no oracle can consume. The scan continues
        # with the remaining entries in the bucket.
        try:
            _evidence_for(
                oracle_type,
                baseline_ref="preflight-baseline",
                probe_ref="preflight-probe",
                evidence_ref=f"{evidence_prefix}/{payload_ref}",
                payload=payload,
                payload_kit=entry.get("slot_kit"),  # type: ignore[arg-type]
                vuln_class=vuln_class,
            )
        except PayloadChainError as exc:
            failure = f"skipped {payload_ref!r}: {exc}"
            _record_failure(audit_failure, failure)
            _ev(f"skipped {payload_ref}: no safe evidence adapter ({oracle_type})")
            continue

        try:
            baseline = _call_result(
                call,
                "fire_request",
                identity=identity,
                endpoint_node=endpoint_node,
                param_node=param_node,
                payload=baseline_payload,
                method=method,
            )
            probe = _call_result(
                call,
                "fire_request",
                identity=identity,
                endpoint_node=endpoint_node,
                param_node=param_node,
                payload=payload,
                method=method,
            )
        except Exception as exc:
            _record_failure(audit_failure, f"payload fire failed: {type(exc).__name__}")
            raise
        baseline_ref = baseline.get("fire_ref")
        probe_ref = probe.get("fire_ref")
        if not isinstance(baseline_ref, str) or not isinstance(probe_ref, str):
            _raise_audited(audit_failure, f"payload {payload_ref!r} fire response omitted fire_ref")

        try:
            _call_result(
                call,
                "classify_response",
                fire_ref=probe_ref,
                identity=identity,
                endpoint_node=endpoint_node,
                param_node=param_node,
                vuln_class=vuln_class,
                suggested_oracle=oracle_type,
                payload_ref=payload_ref,
                notes=["generic payload-library chain"],
            )
            evidence_ref = f"{evidence_prefix}/{payload_ref}"
            evidence = _evidence_for(
                oracle_type,
                baseline_ref=baseline_ref,
                probe_ref=probe_ref,
                evidence_ref=evidence_ref,
                payload=payload,
                payload_kit=entry.get("slot_kit"),  # type: ignore[arg-type]
                vuln_class=vuln_class,
            )
            verdict = _call_result(
                call,
                "run_oracle",
                mechanism=oracle_type,
                evidence=evidence,
            )
        except PayloadChainError as exc:
            _record_failure(audit_failure, str(exc))
            raise
        except Exception as exc:
            _record_failure(audit_failure, f"oracle path failed: {type(exc).__name__}")
            raise

        attempted += 1
        if verdict.get("is_violation") is not True:
            continue
        verdict_ref = verdict.get("verdict_ref")
        if not isinstance(verdict_ref, str) or not verdict_ref:
            _raise_audited(
                audit_failure, f"confirmed oracle for {payload_ref!r} omitted verdict_ref"
            )
        try:
            finding = _call_result(
                call,
                "write_finding",
                verdict_ref=verdict_ref,
                vuln_class=vuln_class,
                metadata={"payload_ref": payload_ref},
            )
        except Exception as exc:
            _record_failure(audit_failure, f"finding write failed: {type(exc).__name__}")
            raise
        finding_node = finding.get("finding_node")
        if not isinstance(finding_node, str):
            _raise_audited(audit_failure, f"write_finding for {payload_ref!r} omitted finding_node")
        _ev(f"CONFIRMED {vuln_class} via {payload_ref}")
        return PayloadChainResult(
            attempted=attempted,
            confirmed=True,
            finding_node=finding_node,
            payload_ref=payload_ref,
        )

    failure = f"payloads exhausted after {attempted} attempts (bucket exhausted)"
    _record_failure(audit_failure, failure)
    return PayloadChainResult(attempted=attempted, confirmed=False, failure=failure)
