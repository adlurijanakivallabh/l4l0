"""Consolidated Phase 7 gate runner — one command, composite verdict across targets.

§15 Phase 7 exit criterion: "All Phase 1-6 gates re-passed simultaneously in one
consolidated run." This module drives every existing target gate — VAmPI (Phase 1),
crAPI (Phase 2), Juice Shop fresh-container (Phase 3), PortSwigger blind-SQLi
(Phase 3 invariant 3), DVGA GraphQL (Phase 4) — and produces ONE composite report,
verdict, and exit code. Orchestration of existing gates only: zero new detection
logic, one registry, one report loop (ponytail).

Gate lifecycle — three honest states:
  * SKIPPED — the target is not provisioned (env_ready() False). Never counted in
    the composite, with its reason in ``detail`` ("set X to enable").
  * not_measurable — provisioned (env_ready() True) but the run errored / the
    target was unreachable. Counted: it blocks a PASSED composite (same exit-2
    semantics as the existing gates' own not-measurable results).
  * passed / failed — provisioned and a verdict was reached.

Composite: all RAN gates passed → PASSED (exit 0); any ran gate failed → FAILED
(exit 1); any ran gate not_measurable → NOT MEASURABLE (exit 2); SKIPPED never
blocks. All gates skipped → NOT MEASURABLE (nothing ran).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TypedDict


class GateStatus(StrEnum):
    """Per-target gate status — the three honest lifecycle states plus skip."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_MEASURABLE = "not_measurable"
    SKIPPED = "skipped"


class GateOutcome(TypedDict):
    """One gate's outcome: status + a human reason + the gate's own report body."""

    status: str
    detail: str
    report: str


# Composite order is monotone: FAILED (1) beats NOT_MEASURABLE (2) beats PASSED (0).
_EXIT_FOR: dict[GateStatus, int] = {
    GateStatus.PASSED: 0,
    GateStatus.FAILED: 1,
    GateStatus.NOT_MEASURABLE: 2,
}


def _as_outcome(status: GateStatus, *, detail: str = "", report: str = "") -> GateOutcome:
    return {"status": status.value, "detail": detail, "report": report}


# ---------------------------------------------------------------------------
# Real per-target run wrappers — thin seams over the existing gate harnesses.
# Each reads its own env; a raised error is mapped to not_measurable by
# run_consolidated (provisioned-but-errored, exit 2).
# ---------------------------------------------------------------------------


def _vamp_run() -> GateOutcome:
    from reachagent.eval.harness import evaluate

    on = os.environ.get("REACHAGENT_VAMPI_ON", "http://127.0.0.1:5000")
    off = os.environ.get("REACHAGENT_VAMPI_OFF", "http://127.0.0.1:5002")
    result = evaluate(on_base_url=on, off_base_url=off)
    return _as_outcome(
        GateStatus.PASSED if result.passed else GateStatus.FAILED,
        detail="VAmPI on/off toggle gate",
        report=result.report(),
    )


def _crapi_run() -> GateOutcome:
    from reachagent.bola.detector import detect
    from reachagent.graph.store import ReachabilityGraph, identity_id
    from reachagent.identity.store import IdentityStore
    from reachagent.recon.crapi_recon import run_recon

    base = os.environ.get("REACHAGENT_CRAPI_BASE_URL", "http://127.0.0.1:8888")
    identities = IdentityStore.from_env()
    graph = ReachabilityGraph()
    run_recon(
        base_url=base,
        surface_path="config/crapi-surface.yaml",
        graph=graph,
        identities=identities,
    )
    owner_tokens: dict[str, str] = {}
    non_owner_tokens: dict[str, str] = {}
    for name in identities.names():
        iid = identity_id(name)
        tok = identities.token_store(name).get_token()
        if tok is None:
            continue
        owner_tokens[iid] = tok
        non_owner_tokens[iid] = tok
    result = detect(graph, base, owner_tokens=owner_tokens, non_owner_tokens=non_owner_tokens)

    # Honest Phase 2 gate: BOTH documented chains reconstructed — a vehicle-location
    # hop (disclosed-id precondition) and a mechanic-report hop (enumerable id).
    veh = [h for h in result.confirmed_hops if "/vehicle/" in h.path]
    rpt = [h for h in result.confirmed_hops if "report" in h.path]
    passed = bool(
        veh
        and rpt
        and all(
            result.preconditions.get(h.finding_node) == "requires_disclosed_identifier" for h in veh
        )
        and all(result.preconditions.get(h.finding_node) == "enumerable_identifier" for h in rpt)
    )
    return _as_outcome(
        GateStatus.PASSED if passed else GateStatus.FAILED,
        detail="crAPI BOLA chains (vehicle-location + mechanic-report)",
        report=f"confirmed_hops={len(result.confirmed_hops)} preconditions={result.preconditions}",
    )


def _juiceshop_run() -> GateOutcome:
    from reachagent.eval.juiceshop_ephemeral import run_ephemeral_gate

    result = run_ephemeral_gate()
    if not result.environment_ok:
        return _as_outcome(
            GateStatus.NOT_MEASURABLE,
            detail=result.juiceshop.detail or "; ".join(result.setup_failure_details),
            report=result.report(),
        )
    return _as_outcome(
        GateStatus.PASSED if result.passed else GateStatus.FAILED,
        detail="Juice Shop fresh-container gate",
        report=result.report(),
    )


def _portswigger_run() -> GateOutcome:
    from reachagent.eval.portswigger_blind_sqli import build_configured_runner
    from reachagent.graph.store import ReachabilityGraph
    from reachagent.tools import validator as _validator

    graph = ReachabilityGraph()
    runner = build_configured_runner(
        graph,
        oracle_runner=_validator.run_oracle,
        write_finding=lambda finding, verdict: _validator.write_finding(graph, finding, verdict),
    )
    if runner is None:
        return _as_outcome(GateStatus.NOT_MEASURABLE, detail="portswigger runner not configured")
    result = runner.run(evidence_ref="portswigger/blind-sqli/time-delay")
    if not result.available:
        return _as_outcome(GateStatus.NOT_MEASURABLE, detail="PortSwigger lab unreachable")
    return _as_outcome(
        GateStatus.PASSED if result.passes else GateStatus.FAILED,
        detail=f"PortSwigger blind-SQLi ({result.lab_type}/{result.mechanism})",
        report=f"vuln_confirmed={result.vuln_lab_confirmed} clean_fp={result.clean_lab_fp_count}",
    )


def _dvga_run() -> GateOutcome:
    import httpx

    from reachagent.execution.audit import AuditLog
    from reachagent.execution.firer import RequestFirer
    from reachagent.execution.scope import ScopeGuard
    from reachagent.graphql.module import GraphQLClient, discover_schema, resolver_bola_check

    base = os.environ.get("REACHAGENT_DVGA_URL", "").rstrip("/")
    host = httpx.URL(base).host or ""
    firer = RequestFirer(
        httpx.Client(timeout=15.0, trust_env=False), ScopeGuard.from_hosts([host]), AuditLog()
    )
    client = GraphQLClient(firer, base_url=base)
    schema = discover_schema(client, "owner")
    confirmed = 0
    for field in schema.fields:
        if field.arguments:
            continue  # arg-requiring resolvers need per-field values — out of the minimal seam
        baseline = client.query("owner", f"{{ {field.name} }}")
        probe = client.query("non-owner", f"{{ {field.name} }}")
        if resolver_bola_check(baseline, probe, public=bool(field.public)).confirmed:
            confirmed += 1
    return _as_outcome(
        GateStatus.PASSED if confirmed else GateStatus.FAILED,
        detail=f"DVGA GraphQL resolver BOLA (fields checked: {len(schema.fields)})",
        report=f"confirmed_resolver_findings={confirmed}",
    )


# ---------------------------------------------------------------------------
# Registry — ordered (name, env_doc, env_ready, run). env_ready is the gate:
# unset/unprovisioned → SKIPPED, never counted.
# ---------------------------------------------------------------------------


def _env_set(name: str) -> bool:
    return bool(os.environ.get(name))


def _env_equals(name: str, value: str) -> bool:
    return os.environ.get(name) == value


@dataclass(frozen=True)
class GateSpec:
    """One gate: how to know it is provisioned and how to run it."""

    name: str
    env_doc: str
    env_ready: Callable[[], bool]
    run: Callable[[], GateOutcome]


_GATES: tuple[GateSpec, ...] = (
    GateSpec(
        name="vamp",
        env_doc="VAmPI on/off (defaults http://127.0.0.1:5000/:5002)",
        env_ready=lambda: True,
        run=_vamp_run,
    ),
    GateSpec(
        name="crapi",
        env_doc="set REACHAGENT_CRAPI_BASE_URL to enable",
        env_ready=lambda: _env_set("REACHAGENT_CRAPI_BASE_URL"),
        run=_crapi_run,
    ),
    GateSpec(
        name="juiceshop",
        env_doc="set REACHAGENT_JUICESHOP_EPHEMERAL=1 to enable",
        env_ready=lambda: _env_equals("REACHAGENT_JUICESHOP_EPHEMERAL", "1"),
        run=_juiceshop_run,
    ),
    GateSpec(
        name="portswigger",
        env_doc="set REACHAGENT_PORTSWIGGER_LIVE=1 to enable",
        env_ready=lambda: _env_equals("REACHAGENT_PORTSWIGGER_LIVE", "1"),
        run=_portswigger_run,
    ),
    GateSpec(
        name="dvga",
        env_doc="set REACHAGENT_DVGA_URL to enable",
        env_ready=lambda: _env_set("REACHAGENT_DVGA_URL"),
        run=_dvga_run,
    ),
)


# ---------------------------------------------------------------------------
# Composite + report
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConsolidatedGateResult:
    """Per-target outcomes plus the composite verdict."""

    per_target: dict[str, GateOutcome]

    @property
    def composite(self) -> GateStatus:
        """All RAN gates passed → PASSED; any failed → FAILED; any not_measurable
        → NOT MEASURABLE; all skipped → NOT MEASURABLE (nothing ran)."""
        statuses = [GateStatus(outcome["status"]) for outcome in self.per_target.values()]
        ran = [s for s in statuses if s is not GateStatus.SKIPPED]
        if not ran:
            return GateStatus.NOT_MEASURABLE
        if GateStatus.FAILED in ran:
            return GateStatus.FAILED
        if GateStatus.NOT_MEASURABLE in ran:
            return GateStatus.NOT_MEASURABLE
        return GateStatus.PASSED

    @property
    def exit_code(self) -> int:
        return _EXIT_FOR[self.composite]

    def report(self) -> str:
        lines: list[str] = ["Consolidated Phase 7 gate run", "=" * 32]
        for name, outcome in self.per_target.items():
            lines.append("")
            lines.append(f"[{name}] {outcome['status']}")
            if outcome["detail"]:
                lines.append(f"  reason: {outcome['detail']}")
            body = outcome["report"].strip()
            if body:
                lines.append(f"  {body}")
        lines.append("")
        lines.append(f"composite: {self.composite.value} (exit {self.exit_code})")
        return "\n".join(lines)


def run_consolidated(
    targets: list[str] | None = None, *, gates: tuple[GateSpec, ...] | None = None
) -> ConsolidatedGateResult:
    """Run every (or a subset of) target gate; return the composite result.

    ``targets=None`` runs all gates; a non-empty list filters by name. ``gates``
    lets a caller inject stub gate specs for hermetic tests (default = the real
    registry). A provisioned gate whose run raises maps to not_measurable.
    """
    specs = gates if gates is not None else _GATES
    selected = [g for g in specs if targets is None or g.name in targets]
    results: dict[str, GateOutcome] = {}
    for spec in selected:
        if not spec.env_ready():
            results[spec.name] = _as_outcome(
                GateStatus.SKIPPED, detail=f"{spec.env_doc}; SKIPPED (not provisioned)"
            )
            continue
        try:
            results[spec.name] = spec.run()
        except Exception as exc:  # noqa: BLE001 — provisioned-but-errored is not_measurable
            results[spec.name] = _as_outcome(
                GateStatus.NOT_MEASURABLE,
                detail=f"run error: {type(exc).__name__}",
                report="",
            )
    return ConsolidatedGateResult(per_target=results)
