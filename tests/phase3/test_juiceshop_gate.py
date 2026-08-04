"""Juice Shop Phase 3 gate tests (plan §14, §15; Task 9).

Two layers:

  1. Pure metric tests (no network): verify coverage, fp_rate, gate thresholds,
     and the PortswiggerResult seam against hand-built result tables.
  2. Live gate test (skips if Juice Shop unreachable): drives detection through
     the MCP tool boundary and scores against the challenge tracker API.
     Invariant 3 (PortSwigger) is skipped until lab credentials are provisioned.

MCP boundary: all detection calls in the live run cross ``mcp.call_tool`` —
never a direct Python call into a tool function (Task 9 DoD, §14/§15).
"""

from __future__ import annotations

import os

import pytest

from reachagent.eval.juiceshop_harness import (
    VERIFIED_CHALLENGE_SCOPE,
    BaselineState,
    ChallengeClaim,
    ChallengeResult,
    JuiceshopRun,
    Phase3GateResult,
    PortswiggerResult,
    in_scope_class,
)
from reachagent.eval.juiceshop_live import score_run

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_JUICE_URL = os.environ.get("REACHAGENT_JUICESHOP_URL", "http://127.0.0.1:3000")


def _cr(
    *,
    vuln_class: str = "injection",
    key: str = "k",
    confirmed: bool,
    solved: bool,
) -> ChallengeResult:
    return ChallengeResult(
        vuln_class=vuln_class,
        challenge_key=key,
        confirmed=confirmed,
        tracker_solved=solved,
    )


# ---------------------------------------------------------------------------
# Layer 1: pure metric tests — no network required.
# ---------------------------------------------------------------------------


def test_in_scope_class_maps_known_categories() -> None:
    assert in_scope_class("Injection") == "injection"
    assert in_scope_class("XSS") == "xss"
    assert in_scope_class("Improper Input Validation") == "file_upload"
    assert in_scope_class("Vulnerable Components") == "path_traversal"


def test_in_scope_class_returns_none_for_out_of_scope() -> None:
    assert in_scope_class("Broken Access Control") is None
    assert in_scope_class("Broken Authentication") is None
    assert in_scope_class("Miscellaneous") is None


def test_coverage_all_confirmed() -> None:
    run = JuiceshopRun(
        results=[
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=True),
        ]
    )
    assert run.coverage == pytest.approx(1.0)
    assert run.fp_rate == pytest.approx(0.0)
    assert run.coverage_passes
    assert run.fp_rate_passes


def test_coverage_partial() -> None:
    # 3 of 4 confirmed and solved → coverage 0.75, exactly at floor.
    run = JuiceshopRun(
        results=[
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=True),
            _cr(confirmed=False, solved=True),
        ]
    )
    assert run.coverage == pytest.approx(0.75)
    assert run.coverage_passes  # exactly at floor


def test_coverage_below_floor() -> None:
    run = JuiceshopRun(
        results=[
            _cr(confirmed=True, solved=True),
            _cr(confirmed=False, solved=True),
            _cr(confirmed=False, solved=True),
            _cr(confirmed=False, solved=True),
        ]
    )
    assert run.coverage == pytest.approx(0.25)
    assert not run.coverage_passes


def test_fp_rate_with_false_positives() -> None:
    # 1 TP, 1 FP → fp_rate = 0.5, above ceiling.
    run = JuiceshopRun(
        results=[
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=False),  # false positive
        ]
    )
    assert run.fp_rate == pytest.approx(0.5)
    assert not run.fp_rate_passes


def test_fp_rate_at_ceiling() -> None:
    # 9 TP, 1 FP → fp_rate = 0.10, exactly at ceiling.
    results = [_cr(confirmed=True, solved=True) for _ in range(9)]
    results.append(_cr(confirmed=True, solved=False))
    run = JuiceshopRun(results=results)
    assert run.fp_rate == pytest.approx(0.10)
    assert run.fp_rate_passes  # exactly at ceiling


def test_fp_rate_zero_confirmed_is_zero() -> None:
    run = JuiceshopRun(
        results=[
            _cr(confirmed=False, solved=True),
            _cr(confirmed=False, solved=False),
        ]
    )
    assert run.fp_rate == pytest.approx(0.0)
    assert run.fp_rate_passes


def test_empty_run_coverage_is_zero() -> None:
    run = JuiceshopRun()
    assert run.coverage == pytest.approx(0.0)
    assert not run.coverage_passes


def test_gate_passes_when_both_invariants_met() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    gate = Phase3GateResult(juiceshop=JuiceshopRun(results=results))
    assert gate.passed
    assert "PASSED" in gate.report()


def test_gate_fails_when_coverage_below_floor() -> None:
    results = [_cr(confirmed=False, solved=True) for _ in range(4)]
    gate = Phase3GateResult(juiceshop=JuiceshopRun(results=results))
    assert not gate.passed
    assert "FAILED" in gate.report()


def test_gate_fails_when_fp_rate_above_ceiling() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    results.append(_cr(confirmed=True, solved=False))  # FP → rate = 1/5 = 0.20
    run = JuiceshopRun(results=results)
    gate = Phase3GateResult(juiceshop=run)
    assert not run.fp_rate_passes
    assert not gate.passed


# --- PortswiggerResult seam --------------------------------------------------


def test_portswigger_not_available_does_not_block_gate() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    gate = Phase3GateResult(
        juiceshop=JuiceshopRun(results=results),
        portswigger=PortswiggerResult(available=False),
    )
    assert gate.portswigger.passes
    assert gate.passed
    assert "SKIPPED" in gate.report()


def test_portswigger_available_and_passing() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    gate = Phase3GateResult(
        juiceshop=JuiceshopRun(results=results),
        portswigger=PortswiggerResult(
            available=True, vuln_lab_confirmed=True, clean_lab_fp_count=0
        ),
    )
    assert gate.portswigger.passes
    assert gate.passed


def test_portswigger_available_vuln_not_confirmed_fails() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    gate = Phase3GateResult(
        juiceshop=JuiceshopRun(results=results),
        portswigger=PortswiggerResult(
            available=True, vuln_lab_confirmed=False, clean_lab_fp_count=0
        ),
    )
    assert not gate.portswigger.passes
    assert not gate.passed


def test_portswigger_available_clean_lab_fp_fails() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)]
    gate = Phase3GateResult(
        juiceshop=JuiceshopRun(results=results),
        portswigger=PortswiggerResult(
            available=True, vuln_lab_confirmed=True, clean_lab_fp_count=1
        ),
    )
    assert not gate.portswigger.passes
    assert not gate.passed


def test_report_contains_key_metrics() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(3)]
    results.append(_cr(confirmed=False, solved=True))
    gate = Phase3GateResult(juiceshop=JuiceshopRun(results=results))
    report = gate.report()
    assert "75.0%" in report
    assert "0.0%" in report
    assert "PASSED" in report  # 3/4 = 0.75 exactly at floor → passes


def _verified_snapshot(*, solved: str | None = None) -> dict[str, dict[str, object]]:
    category_by_scope = {
        "injection": "Injection",
        "file_upload": "Improper Input Validation",
        "xss": "XSS",
    }
    return {
        key: {"category": category_by_scope[scope], "solved": key == solved}
        for key, scope in VERIFIED_CHALLENGE_SCOPE.items()
    }


def test_verified_clean_baseline_classifies_clean() -> None:
    from reachagent.eval.juiceshop_harness import classify_baseline

    assert classify_baseline(_verified_snapshot()).state is BaselineState.CLEAN


def test_verified_dirty_baseline_classifies_dirty() -> None:
    from reachagent.eval.juiceshop_harness import classify_baseline

    result = classify_baseline(_verified_snapshot(solved="uploadTypeChallenge"))
    assert result.state is BaselineState.DIRTY
    assert result.solved_keys == ("uploadTypeChallenge",)


def test_verified_missing_key_classifies_invalid() -> None:
    from reachagent.eval.juiceshop_harness import classify_baseline

    snapshot = _verified_snapshot()
    del snapshot["uploadTypeChallenge"]
    assert classify_baseline(snapshot).state is BaselineState.INVALID


def test_report_documents_api_only_ceiling() -> None:
    run = JuiceshopRun(
        results=[
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=True),
            _cr(confirmed=True, solved=True),
            _cr(confirmed=False, solved=True),
        ]
    )
    report = Phase3GateResult(juiceshop=run).report()
    assert "Coverage ceiling" in report
    assert "4/9 API-only" in report


def test_unmeasurable_gate_requires_environment_ok() -> None:
    run = JuiceshopRun.not_measurable(baseline=None, detail="dirty")
    gate = Phase3GateResult(juiceshop=run)
    assert not gate.environment_ok
    assert not gate.passed
    assert "NOT MEASURABLE" in gate.report()


# score_run consumes before/after tracker snapshots plus the set of real
# vuln_class strings whose oracle confirmed this run. The FP rule: an in-scope
# class whose oracle confirmed a finding but where NO in-scope challenge of that
# class flipped unsolved→solved this run counts as one class-level false positive
# (invariant 2), off the coverage denominator. A confirmed vuln_class that maps
# out of scope (jwt_forgery, clickjacking, cors_misconfig, csrf_missing_protection)
# books neither coverage nor an in-scope FP.
# ---------------------------------------------------------------------------


def _snap(*entries: tuple[str, str, bool]) -> dict[str, dict[str, object]]:
    """Build a tracker snapshot from ``(key, category, solved)`` tuples."""
    return {key: {"category": cat, "solved": solved} for key, cat, solved in entries}


def test_score_run_flip_credits_tp_no_class_fp() -> None:
    # One injection challenge flips unsolved→solved; sqli oracle confirmed.
    before = _snap(("c1", "Injection", False))
    after = _snap(("c1", "Injection", True))
    run = score_run(before, after, {"sqli"})
    assert run.true_positives == 1
    assert run.class_false_positives == 0
    assert run.false_positives == 0
    assert run.coverage == pytest.approx(1.0)


def test_score_run_confirmed_but_no_flip_is_class_fp() -> None:
    # sqli oracle confirmed, but the injection challenge was already solved (no flip).
    before = _snap(("c1", "Injection", True))
    after = _snap(("c1", "Injection", True))
    run = score_run(before, after, {"sqli"})
    assert run.true_positives == 0
    assert run.class_false_positives == 1
    assert run.false_positives == 1
    # Class FP stays off the coverage denominator (still 1 in-scope challenge).
    assert run.total_in_scope == 1
    assert run.coverage == pytest.approx(0.0)
    assert run.fp_rate == pytest.approx(1.0)


def test_score_run_no_detection_no_fp() -> None:
    # No vuln_class confirmed → no class FP even though nothing flipped.
    before = _snap(("c1", "Injection", True))
    after = _snap(("c1", "Injection", True))
    run = score_run(before, after, set())
    assert run.class_false_positives == 0
    assert run.false_positives == 0
    assert run.fp_rate == pytest.approx(0.0)


def test_score_run_mixed_classes_counts_fp_per_class() -> None:
    # injection flips (TP, no FP); xss confirmed but no flip (one class FP);
    # file_upload not confirmed (no FP); path_traversal confirmed + flips (TP).
    before = _snap(
        ("i1", "Injection", False),
        ("x1", "XSS", False),
        ("f1", "Improper Input Validation", True),
        ("p1", "Vulnerable Components", False),
    )
    after = _snap(
        ("i1", "Injection", True),
        ("x1", "XSS", False),
        ("f1", "Improper Input Validation", True),
        ("p1", "Vulnerable Components", True),
    )
    confirmed = {"sqli", "xss", "path_traversal"}  # file_upload NOT confirmed
    run = score_run(before, after, confirmed)
    assert run.true_positives == 2  # injection + path_traversal flipped
    assert run.class_false_positives == 1  # xss confirmed, nothing flipped
    assert run.false_positives == 1
    assert run.total_in_scope == 4
    # 2 TP, 1 FP → fp_rate = 1/3.
    assert run.fp_rate == pytest.approx(1 / 3)


def test_score_run_one_class_flip_suppresses_that_classs_fp() -> None:
    # Two injection challenges, only one flips. The class had a flip, so the
    # confirmed sqli oracle is NOT a class FP.
    before = _snap(("i1", "Injection", False), ("i2", "Injection", False))
    after = _snap(("i1", "Injection", True), ("i2", "Injection", False))
    run = score_run(before, after, {"sqli"})
    assert run.true_positives == 1
    assert run.class_false_positives == 0
    assert run.false_positives == 0


def test_score_run_ignores_out_of_scope_categories() -> None:
    # Out-of-scope tracker categories never enter results; a confirmed in-scope
    # vuln_class with no in-scope challenge still books one class FP.
    before = _snap(("b1", "Broken Access Control", False))
    after = _snap(("b1", "Broken Access Control", True))
    run = score_run(before, after, {"sqli"})
    assert run.total_in_scope == 0
    # No in-scope injection challenge exists, so a confirmed sqli oracle still
    # records one class FP (claimed exploitable, nothing in-scope flipped).
    assert run.class_false_positives == 1


def test_score_run_exact_claim_credits_only_matching_tracker_key() -> None:
    before = _snap(
        ("sqli-one", "Injection", False),
        ("sqli-two", "Injection", False),
    )
    after = _snap(
        ("sqli-one", "Injection", True),
        ("sqli-two", "Injection", True),
    )
    run = score_run(
        before,
        after,
        {ChallengeClaim("sqli-one", "sqli", "sqli/one")},
    )
    assert run.true_positives == 1
    assert run.results[0].confirmed is True
    assert run.results[1].confirmed is False


def test_score_run_unsolved_claim_is_a_false_positive() -> None:
    before = _snap(("sqli-one", "Injection", False))
    after = _snap(("sqli-one", "Injection", False))
    run = score_run(before, after, {ChallengeClaim("sqli-one", "sqli")})
    assert run.true_positives == 0
    assert run.claim_false_positives == 1
    assert run.false_positives == 1


def test_score_run_claim_class_mismatch_is_not_credited() -> None:
    before = _snap(("xss-one", "XSS", False))
    after = _snap(("xss-one", "XSS", True))
    run = score_run(before, after, {ChallengeClaim("xss-one", "sqli")})
    assert run.true_positives == 0
    assert run.claim_false_positives == 1
    assert run.false_positives == 1


def test_claim_scope_override_cannot_reclassify_vulnerability() -> None:
    before = _verified_snapshot()
    after = _verified_snapshot(solved="localXssChallenge")
    run = score_run(
        before,
        after,
        {ChallengeClaim("localXssChallenge", "jwt_forgery", scope_class="xss")},
        strict_scope=True,
    )
    assert run.true_positives == 0
    assert run.coverage == pytest.approx(0.0)
    assert run.claim_false_positives == 1
    assert run.false_positives == 1


def test_score_run_strict_scope_never_credits_tracker_only_flip() -> None:
    before = _verified_snapshot()
    after = _verified_snapshot(solved="uploadSizeChallenge")
    run = score_run(before, after, set(), strict_scope=True)
    assert run.true_positives == 0
    assert run.coverage == pytest.approx(0.0)
    assert run.results[-3].challenge_key == "uploadSizeChallenge"
    assert run.results[-3].confirmed is False


def test_api_only_ceiling_does_not_pass_historical_gate() -> None:
    results = [_cr(confirmed=True, solved=True) for _ in range(4)] + [
        _cr(confirmed=False, solved=True) for _ in range(5)
    ]
    gate = Phase3GateResult(juiceshop=JuiceshopRun(results=results))
    assert gate.juiceshop.coverage == pytest.approx(4 / 9)
    assert not gate.juiceshop.coverage_passes
    assert not gate.passed


def test_api_only_unsupported_detectors_emit_no_claims() -> None:
    from reachagent.eval.juiceshop_live import (
        JuiceshopTarget,
        _detect_file_upload,
        _detect_xss_stored,
    )

    target = JuiceshopTarget("http://127.0.0.1:3000")
    assert _detect_file_upload(target, None) == set()
    assert _detect_xss_stored(target, None) == set()

    # jwt_forgery is out of scope; it must not book a path-traversal FP.
    before = _snap(("p1", "Vulnerable Components", False))
    after = _snap(("p1", "Vulnerable Components", False))
    run = score_run(before, after, {"jwt_forgery"})
    assert run.class_false_positives == 0
    assert run.false_positives == 0
    assert run.fp_rate == pytest.approx(0.0)


def test_score_run_out_of_scope_confirmation_not_masked_by_unrelated_flip() -> None:
    # A path_traversal challenge flips (real TP). A separate jwt_forgery
    # confirmation must stay out of scope regardless — it is neither coverage nor
    # an in-scope FP, and the unrelated flip must not silently absorb it.
    before = _snap(("p1", "Vulnerable Components", False))
    after = _snap(("p1", "Vulnerable Components", True))
    run = score_run(before, after, {"jwt_forgery", "path_traversal"})
    assert run.true_positives == 1  # the /ftp flip
    assert run.class_false_positives == 0  # jwt_forgery books nothing
    assert run.false_positives == 0


def test_score_run_path_traversal_fp_still_books_when_ftp_confirmed_no_flip() -> None:
    # Legacy class-only path scoring remains explicit and class-level.
    before = _snap(("p1", "Vulnerable Components", False))
    after = _snap(("p1", "Vulnerable Components", False))
    run = score_run(before, after, {"path_traversal"})
    assert run.class_false_positives == 1
    assert run.false_positives == 1


def test_score_run_client_side_structural_classes_book_no_in_scope_fp() -> None:
    # clickjacking / cors_misconfig / csrf_missing_protection all map out of scope
    # (pinned behavior): confirming all three, with no in-scope challenge and no
    # flip, books zero class FPs.
    before = _snap(("i1", "Injection", True))
    after = _snap(("i1", "Injection", True))
    run = score_run(before, after, {"clickjacking", "cors_misconfig", "csrf_missing_protection"})
    assert run.class_false_positives == 0
    assert run.false_positives == 0
    assert run.fp_rate == pytest.approx(0.0)


# --- Fix B: drive the real class-FP path to the ceiling and gate verdict ------


def test_class_fp_rate_exactly_at_ceiling_passes() -> None:
    # Nine in-scope TPs (nine injection flips) + one class-level FP from a
    # confirmed-but-no-flip file_upload → fp_rate = 1/10 = 0.10, exactly at ceiling.
    before = _snap(*[(f"i{n}", "Injection", False) for n in range(9)])
    after = _snap(*[(f"i{n}", "Injection", True) for n in range(9)])
    # file_upload confirmed but no in-scope file_upload challenge flips (none present).
    run = score_run(before, after, {"sqli", "file_upload"})
    assert run.true_positives == 9
    assert run.class_false_positives == 1
    assert run.false_positives == 1
    assert run.fp_rate == pytest.approx(0.10)
    assert run.fp_rate_passes  # exactly at ceiling


def test_class_fp_rate_one_over_ceiling_fails() -> None:
    # Eight in-scope TPs + one class FP → fp_rate = 1/9 ≈ 0.111 > 0.10 → fails.
    before = _snap(*[(f"i{n}", "Injection", False) for n in range(8)])
    after = _snap(*[(f"i{n}", "Injection", True) for n in range(8)])
    run = score_run(before, after, {"sqli", "file_upload"})
    assert run.true_positives == 8
    assert run.class_false_positives == 1
    assert run.fp_rate == pytest.approx(1 / 9)
    assert not run.fp_rate_passes


def test_gate_fails_on_class_fp_driven_over_ceiling_run() -> None:
    # Same over-ceiling run, wrapped in the composite gate: coverage floor is met
    # (all in-scope challenges flipped), but the class-FP-driven fp_rate breaches
    # the ceiling, so Phase3GateResult.passed must be False.
    before = _snap(*[(f"i{n}", "Injection", False) for n in range(8)])
    after = _snap(*[(f"i{n}", "Injection", True) for n in range(8)])
    run = score_run(before, after, {"sqli", "file_upload"})
    gate = Phase3GateResult(juiceshop=run)
    assert run.coverage_passes  # 8/8 flipped
    assert not run.fp_rate_passes
    assert not gate.passed
    assert "FAILED" in gate.report()


# ---------------------------------------------------------------------------
# Layer 2: live gate — skips when Juice Shop is unreachable.
# ---------------------------------------------------------------------------


def _juiceshop_reachable() -> bool:
    import httpx

    try:
        resp = httpx.get(f"{_JUICE_URL}/api/Challenges", timeout=3.0)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


def _juiceshop_live_enabled() -> bool:
    return os.environ.get("REACHAGENT_JUICESHOP_EPHEMERAL") == "1" and _juiceshop_reachable()


@pytest.mark.skipif(
    not _juiceshop_live_enabled(),
    reason=(
        "set REACHAGENT_JUICESHOP_EPHEMERAL=1 and provide reachable Juice Shop for live MCP gate"
    ),
)
def test_live_juiceshop_run_scores_through_mcp() -> None:
    """Live run drives all four in-scope classes through the MCP boundary and scores.

    This is not a pass/fail gate on ReachAgent's coverage (Juice Shop's per-seed
    randomised state makes an absolute floor flaky in CI); it asserts the run
    *executes end to end through mcp.call_tool*, populates the tracker-scored
    JuiceshopRun with in-scope challenges, and produces a coherent metric object.
    The numeric gate is enforced by ``python -m reachagent.eval.juiceshop``.
    """
    from reachagent.eval.juiceshop_live import JuiceshopTarget, run_juiceshop

    target = JuiceshopTarget(base_url=_JUICE_URL)
    run = run_juiceshop(target)

    if not run.measurable:
        pytest.skip(f"persistent target is not a clean measurable baseline: {run.detail}")

    # The run touched real in-scope challenges from the live tracker.
    assert run.total_in_scope > 0
    # Every scored result is an in-scope class (generic category mapping held).
    assert all(in_scope_class_of(r.vuln_class) for r in run.results)
    # Metrics are computable and bounded.
    assert 0.0 <= run.coverage <= 1.0
    assert 0.0 <= run.fp_rate <= 1.0


def in_scope_class_of(vuln_class: str) -> bool:
    """A run result's vuln_class must be one of the four in-scope keys."""
    return vuln_class in {"injection", "xss", "file_upload", "path_traversal"}
