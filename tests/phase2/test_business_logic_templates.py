"""Business-logic 4-template invariant library + oracle (plan §5, §7, §9; Phase 2 Task 5).

Asserts the Task 5 DoD invariants:

  1. Exactly four templates exist — single-use reuse, quantity/limit, price/
     parameter tamper, step-order — and the ``BusinessRule`` family has exactly
     four members (a fifth requires a plan change first).
  2. Each template instantiates from a *recon-discovered resource*, not a
     hand-modeled one: a matching consumable/limited/priced/ordered resource in
     the graph yields a concrete check; a surface with no such resource
     instantiates nothing.
  3. The templates run as the ``business_rule_invariant`` §7 family through
     ``run_oracle`` (Phase 1's registry raised ``UnknownOracleError``); a
     confirmed violation is reachable only via ``run_oracle`` → ``write_finding``,
     with no LLM in the decision path (fixed-input/fixed-output).
  4. Sequential-replay-first: a check fires as sequential replay, never concurrent
     delivery — the audit log shows N separate ``fired:`` entries in order.
  5. Read-only-first-safe: a state-changing step fires only after the endpoint's
     read-only case is cleared — the audit shows a read-only ``fired:`` on the
     target before any mutating ``fired:``, and no ``refused_read_only_first``.
  6. Runtime-dependent surface (same pattern as ownership discovery): the
     step-order template instantiates from the observed sequence of endpoints
     recon materialized, not a pre-declared order.

Requests are fired through a ``MockTransport`` standing in for the target, so the
tests are hermetic but exercise the real fire → read-response → oracle path (same
discipline as the surface-mapper and differential-oracle tests).
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from reachagent.business_logic import (
    TEMPLATES,
    PriceTamperTemplate,
    QuantityLimitTemplate,
    SequentialReplayRunner,
    SingleUseReuseTemplate,
    StepOrderTemplate,
    StepRole,
    instantiate_all,
)
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.execution.audit import AuditLog
from reachagent.graph.nodes import Endpoint, Finding, FindingStatus, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.oracles.business_rule import (
    BusinessRule,
    BusinessRuleEvidence,
    ReplayObservation,
    decide,
)
from reachagent.tools import validator

BASE_URL = "https://shop.test"
HOST = "shop.test"


def _endpoint(graph: ReachabilityGraph, method: str, path: str, *params: str) -> str:
    node = graph.add_endpoint(Endpoint(method=method, path=path))
    for name in params:
        graph.add_parameter(node, Parameter(name=name, location="body"))
    return node


def _runner(
    handler: Callable[[httpx.Request], httpx.Response],
) -> tuple[SequentialReplayRunner, AuditLog]:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    audit = AuditLog()
    firer = RequestFirer(client, ScopeGuard.from_hosts([HOST]), audit)
    return SequentialReplayRunner(firer, BASE_URL), audit


# -- Invariant 1: exactly four templates ----------------------------------


def test_exactly_four_templates_and_rules() -> None:
    assert len(TEMPLATES) == 4
    # Every template maps to a distinct BusinessRule, and there are exactly four.
    template_rules = {t.rule for t in TEMPLATES}
    assert template_rules == set(BusinessRule)
    assert len(BusinessRule) == 4


def test_the_four_rules_are_the_named_four() -> None:
    assert set(BusinessRule) == {
        BusinessRule.SINGLE_USE_REUSE,
        BusinessRule.QUANTITY_LIMIT,
        BusinessRule.PRICE_TAMPER,
        BusinessRule.STEP_ORDER,
    }


# -- Invariant 2: instantiate from a discovered resource, else nothing -----


def test_empty_surface_instantiates_no_checks() -> None:
    graph = ReachabilityGraph()
    # A read-only, non-commerce surface: no consumable/limited/priced/ordered
    # resource, so every template produces nothing.
    _endpoint(graph, "GET", "/status")
    _endpoint(graph, "GET", "/users/v1/me", "username")

    result = instantiate_all(graph)

    assert result.checks == ()
    assert result.rules == frozenset()


def test_single_use_template_instantiates_from_a_coupon_parameter() -> None:
    graph = ReachabilityGraph()
    _endpoint(graph, "POST", "/coupon/redeem", "coupon_code")

    checks = SingleUseReuseTemplate().instantiate(graph)

    assert len(checks) == 1
    check = checks[0]
    assert check.rule is BusinessRule.SINGLE_USE_REUSE
    # A concrete replay: a first redemption, then an identical reuse marked VIOLATING.
    roles = [s.role for s in check.steps]
    assert roles == [StepRole.BASELINE, StepRole.VIOLATING]


def test_quantity_template_instantiates_from_a_quantity_parameter() -> None:
    graph = ReachabilityGraph()
    _endpoint(graph, "POST", "/cart/add", "quantity")

    checks = QuantityLimitTemplate().instantiate(graph)

    assert len(checks) == 1
    assert checks[0].rule is BusinessRule.QUANTITY_LIMIT
    # The out-of-bounds probe is a negative quantity.
    violating = next(s for s in checks[0].steps if s.role is StepRole.VIOLATING)
    assert violating.json_body == {"quantity": -1}


def test_price_template_instantiates_from_a_price_parameter() -> None:
    graph = ReachabilityGraph()
    _endpoint(graph, "POST", "/order", "price")

    checks = PriceTamperTemplate().instantiate(graph)

    assert len(checks) == 1
    assert checks[0].rule is BusinessRule.PRICE_TAMPER


def test_single_use_ignores_a_read_only_coupon_endpoint() -> None:
    # A GET "check my coupon" is not a redemption — no reuse to test, so nothing.
    graph = ReachabilityGraph()
    _endpoint(graph, "GET", "/coupon/status", "coupon_code")

    assert SingleUseReuseTemplate().instantiate(graph) == []


# -- Invariant 6: step-order instantiates from the observed sequence -------


def test_step_order_instantiates_from_the_observed_multi_step_flow() -> None:
    graph = ReachabilityGraph()
    # An ordered checkout flow recon materialized — three state-changing steps.
    _endpoint(graph, "POST", "/checkout/1-cart")
    _endpoint(graph, "POST", "/checkout/2-address")
    _endpoint(graph, "POST", "/checkout/3-pay")

    checks = StepOrderTemplate().instantiate(graph)

    assert len(checks) == 1
    check = checks[0]
    assert check.rule is BusinessRule.STEP_ORDER
    # The final step is the out-of-order jump; earlier steps are the prerequisites.
    assert check.steps[-1].role is StepRole.VIOLATING
    assert check.steps[-1].path == "/checkout/3-pay"
    assert any(s.role is StepRole.BASELINE for s in check.steps)


def test_step_order_needs_at_least_two_ordered_steps() -> None:
    graph = ReachabilityGraph()
    _endpoint(graph, "POST", "/only-one-step")

    assert StepOrderTemplate().instantiate(graph) == []


# -- Invariant 3: run_oracle is the confirmation path; no LLM in decision --


def test_business_rule_oracle_is_now_registered() -> None:
    # Phase 1's registry raised UnknownOracleError for this family; Phase 2 registers it.
    ev = BusinessRuleEvidence(
        rule=BusinessRule.SINGLE_USE_REUSE,
        baseline=ReplayObservation("first", 200),
        violating=ReplayObservation("reuse", 200),
        evidence_ref="single_use/POST /coupon/redeem/coupon_code",
    )
    verdict = validator.run_oracle(OracleMechanism.BUSINESS_RULE_INVARIANT, ev)
    assert isinstance(verdict, OracleVerdict)
    assert verdict.status is FindingStatus.CONFIRMED_VIOLATION
    assert verdict.is_violation is True


def test_accepted_reuse_is_a_violation_refused_reuse_is_denied() -> None:
    # A single-use token honored twice → violation; correctly rejected → denied.
    accepted = BusinessRuleEvidence(
        rule=BusinessRule.SINGLE_USE_REUSE,
        baseline=ReplayObservation("first", 200),
        violating=ReplayObservation("reuse", 200),
    )
    refused = BusinessRuleEvidence(
        rule=BusinessRule.SINGLE_USE_REUSE,
        baseline=ReplayObservation("first", 200),
        violating=ReplayObservation("reuse", 409),
    )
    assert decide(accepted) is FindingStatus.CONFIRMED_VIOLATION
    assert decide(refused) is FindingStatus.CONFIRMED_DENIED


def test_no_valid_baseline_is_inconclusive() -> None:
    # Without a legitimate action that succeeded, the rule-break deviates from
    # nothing — never a manufactured violation.
    ev = BusinessRuleEvidence(
        rule=BusinessRule.QUANTITY_LIMIT,
        baseline=ReplayObservation("in-bounds", 500),
        violating=ReplayObservation("out-of-bounds", 200),
    )
    assert decide(ev) is FindingStatus.INCONCLUSIVE


def test_decide_is_total_and_deterministic() -> None:
    valid = set(FindingStatus)
    ev = BusinessRuleEvidence(
        rule=BusinessRule.PRICE_TAMPER,
        baseline=ReplayObservation("real", 200),
        violating=ReplayObservation("tampered", 200),
    )
    # Fixed input → fixed output, every time.
    verdicts = {decide(ev) for _ in range(50)}
    assert verdicts == {FindingStatus.CONFIRMED_VIOLATION}
    assert verdicts <= valid


def test_confirmed_violation_reaches_write_finding_only_via_the_verdict() -> None:
    graph = ReachabilityGraph()
    ev = BusinessRuleEvidence(
        rule=BusinessRule.PRICE_TAMPER,
        baseline=ReplayObservation("real", 200),
        violating=ReplayObservation("tampered", 200),
        evidence_ref="price_tamper/POST /order/price",
    )
    verdict = validator.run_oracle(OracleMechanism.BUSINESS_RULE_INVARIANT, ev)
    finding_id = validator.write_finding(
        graph,
        Finding(
            vuln_class="business_logic",
            severity="high",
            oracle_used="",
            evidence_ref="",
        ),
        verdict,
    )
    ids = [fid for fid, _ in graph.findings()]
    assert finding_id in ids


def test_oracle_rejects_wrong_evidence_type() -> None:
    from reachagent.oracles.business_rule import BusinessRuleOracle

    with pytest.raises(TypeError):
        BusinessRuleOracle().run({"not": "evidence"})


# -- Invariants 4 & 5: sequential replay, read-only-first-safe -------------


def _fired(audit: AuditLog) -> list[tuple[str, str, str]]:
    """(method, target, outcome) for every audit entry, in order."""
    return [(e.method, e.target, e.outcome) for e in audit.entries]


def test_single_use_replay_is_sequential_and_read_only_first_safe() -> None:
    # Both redemptions succeed → the reuse was honored → a violation.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    graph = ReachabilityGraph()
    _endpoint(graph, "POST", "/coupon/redeem", "coupon_code")
    (check,) = SingleUseReuseTemplate().instantiate(graph)

    runner, audit = _runner(handler)
    outcome = runner.run("owner", check)

    # The oracle confirms the violation from the observed sequential replay.
    verdict = validator.run_oracle(OracleMechanism.BUSINESS_RULE_INVARIANT, outcome.evidence)
    assert verdict.status is FindingStatus.CONFIRMED_VIOLATION

    entries = _fired(audit)
    # Invariant 4 — sequential: every step is its own fired entry, in order, never
    # a single-packet burst.
    fired = [e for e in entries if e[2].startswith("fired:")]
    assert len(fired) >= 2  # at least the two redemptions, each fired separately
    # Invariant 5 — read-only-first-safe: no mutation was ever refused for lack of
    # a cleared read-only case, and each POST is preceded by a read-only GET on the
    # same target.
    assert not any(o == "refused_read_only_first" for _m, _t, o in entries)
    seen_readonly_for: set[str] = set()
    for method, tgt, outcome_str in entries:
        if not outcome_str.startswith("fired:"):
            continue
        if method == "GET":
            seen_readonly_for.add(tgt)
        else:
            # A mutating request only fires after a read-only fire on its target.
            assert tgt in seen_readonly_for, f"mutation on {tgt} fired before a read-only clear"


def test_runner_never_escalates_to_concurrent_delivery() -> None:
    # The audit records one entry per request; a sequential replay of a 2-step
    # check yields discrete, ordered entries (never a burst/single-packet marker).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    graph = ReachabilityGraph()
    _endpoint(graph, "POST", "/cart/add", "quantity")
    (check,) = QuantityLimitTemplate().instantiate(graph)

    runner, audit = _runner(handler)
    runner.run("owner", check)

    # Timestamps are monotonic non-decreasing in append order — a sequential trace.
    times = [e.timestamp for e in audit.entries]
    assert times == sorted(times)
    # No audit vocabulary for concurrent/single-packet delivery exists in Phase 2.
    assert all("concurrent" not in e.outcome and "burst" not in e.outcome for e in audit.entries)
