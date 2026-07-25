"""Differential-diff oracle + verification engine (plan §7; Task 6).

Asserts the Task 6 DoD invariants:

  1. The oracle takes cross-identity / cross-request / cross-condition evidence
     and returns exactly one of ``confirmed_allowed`` / ``confirmed_denied`` /
     ``confirmed_violation`` / ``inconclusive`` — deterministically, with zero
     LLM input anywhere in the decision path.
  2. ``run_oracle`` is the only code path capable of producing a *confirmed*
     result — proven structurally, the way Task 5 proved ``classify_response``
     has no path to ``write_finding``.
  3. Fixed input → fixed output: the same evidence yields the same verdict on
     every call.
"""

from __future__ import annotations

import pytest

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DifferentialOracle,
    DiffExpectation,
    Observation,
    decide,
)
from reachagent.oracles.registry import UnknownOracleError
from reachagent.tools import validator


def _ev(
    expectation: DiffExpectation,
    *,
    baseline: Observation,
    probe: Observation,
    axis: DiffAxis = DiffAxis.CROSS_IDENTITY,
    ref: str = "trial-1",
) -> DifferentialEvidence:
    return DifferentialEvidence(
        axis=axis, expectation=expectation, baseline=baseline, probe=probe, evidence_ref=ref
    )


# -- Invariant 1: the four-status decision table --------------------------


def test_cross_identity_bola_read_is_a_violation() -> None:
    # Owner reads their object (200, body X); another identity reads the SAME
    # object and gets the SAME body — the probe obtained data it shouldn't have.
    ev = _ev(
        DiffExpectation.PROBE_UNAUTHORIZED,
        baseline=Observation("owner", 200, '{"ssn":"123"}'),
        probe=Observation("attacker", 200, '{"ssn":"123"}'),
    )
    assert decide(ev) is FindingStatus.CONFIRMED_VIOLATION


def test_cross_identity_properly_blocked_is_confirmed_denied() -> None:
    # The unauthorized identity is refused (403) — authorization worked. That's a
    # confirmed *fact* about the edge, not a violation and not inconclusive.
    ev = _ev(
        DiffExpectation.PROBE_UNAUTHORIZED,
        baseline=Observation("owner", 200, '{"ssn":"123"}'),
        probe=Observation("attacker", 403, "forbidden"),
    )
    assert decide(ev) is FindingStatus.CONFIRMED_DENIED


def test_authorized_identity_getting_access_is_confirmed_allowed() -> None:
    ev = _ev(
        DiffExpectation.PROBE_AUTHORIZED,
        baseline=Observation("owner", 200, '{"data":1}'),
        probe=Observation("teammate", 200, '{"data":1}'),
    )
    assert decide(ev) is FindingStatus.CONFIRMED_ALLOWED


def test_authorized_identity_blocked_is_confirmed_denied() -> None:
    ev = _ev(
        DiffExpectation.PROBE_AUTHORIZED,
        baseline=Observation("owner", 200, '{"data":1}'),
        probe=Observation("teammate", 401, "unauthorized"),
    )
    assert decide(ev) is FindingStatus.CONFIRMED_DENIED


def test_missing_baseline_is_inconclusive() -> None:
    # No valid owner/authorized reference to diff against → no verdict.
    ev = _ev(
        DiffExpectation.PROBE_UNAUTHORIZED,
        baseline=Observation("owner", 500, "error"),
        probe=Observation("attacker", 200, "x"),
    )
    assert decide(ev) is FindingStatus.INCONCLUSIVE


def test_mass_assignment_cross_request_violation() -> None:
    # Cross-request: a mutation claimed admin=true; the independent re-read shows
    # the privileged field stuck (probe body == the privileged baseline).
    ev = _ev(
        DiffExpectation.PROBE_UNAUTHORIZED,
        axis=DiffAxis.CROSS_REQUEST,
        baseline=Observation("intended-admin-view", 200, '{"role":"admin"}'),
        probe=Observation("reread-after-mutation", 200, '{"role":"admin"}'),
    )
    assert decide(ev) is FindingStatus.CONFIRMED_VIOLATION


def test_cross_condition_boolean_blind_divergence_is_violation() -> None:
    # Injection: two conditions a safe app answers identically. Both served but
    # diverging bodies → the condition reached the backend.
    ev = _ev(
        DiffExpectation.RESPONSES_INVARIANT,
        axis=DiffAxis.CROSS_CONDITION,
        baseline=Observation("cond-true", 200, "welcome back"),
        probe=Observation("cond-false", 200, "no such user"),
    )
    assert decide(ev) is FindingStatus.CONFIRMED_VIOLATION


def test_cross_condition_identical_responses_is_inconclusive() -> None:
    # Same condition-pair, identical responses → no blind signal → not a "safe"
    # verdict, just inconclusive (absence of evidence, not evidence of absence).
    ev = _ev(
        DiffExpectation.RESPONSES_INVARIANT,
        axis=DiffAxis.CROSS_CONDITION,
        baseline=Observation("cond-true", 200, "same"),
        probe=Observation("cond-false", 200, "same"),
    )
    assert decide(ev) is FindingStatus.INCONCLUSIVE


def test_decide_is_total_over_every_expectation() -> None:
    # Whatever the expectation, decide() always returns one of the four statuses —
    # never None, never an exception, for a well-typed evidence record.
    valid = set(FindingStatus)
    for expectation in DiffExpectation:
        ev = _ev(
            expectation,
            baseline=Observation("b", 200, "x"),
            probe=Observation("p", 200, "y"),
        )
        assert decide(ev) in valid


# -- Invariant 3: fixed input -> fixed output, every time -----------------


@pytest.mark.parametrize(
    ("expectation", "baseline", "probe", "expected"),
    [
        (
            DiffExpectation.PROBE_UNAUTHORIZED,
            Observation("owner", 200, "secret"),
            Observation("attacker", 200, "secret"),
            FindingStatus.CONFIRMED_VIOLATION,
        ),
        (
            DiffExpectation.PROBE_UNAUTHORIZED,
            Observation("owner", 200, "secret"),
            Observation("attacker", 403, "no"),
            FindingStatus.CONFIRMED_DENIED,
        ),
        (
            DiffExpectation.PROBE_AUTHORIZED,
            Observation("owner", 200, "d"),
            Observation("peer", 200, "d"),
            FindingStatus.CONFIRMED_ALLOWED,
        ),
        (
            DiffExpectation.RESPONSES_INVARIANT,
            Observation("t", 200, "a"),
            Observation("f", 200, "b"),
            FindingStatus.CONFIRMED_VIOLATION,
        ),
    ],
)
def test_same_evidence_same_verdict_every_time(
    expectation: DiffExpectation,
    baseline: Observation,
    probe: Observation,
    expected: FindingStatus,
) -> None:
    ev = _ev(expectation, baseline=baseline, probe=probe)
    # Run many times: a deterministic decision never wavers.
    verdicts = {decide(ev) for _ in range(50)}
    assert verdicts == {expected}


def test_whitespace_is_the_only_body_normalization() -> None:
    # Bodies equal up to whitespace compare equal; the comparison is otherwise
    # exact (auditable, non-fuzzy).
    equal = _ev(
        DiffExpectation.PROBE_UNAUTHORIZED,
        baseline=Observation("owner", 200, '{"a": 1}'),
        probe=Observation("attacker", 200, '{"a":   1}'),
    )
    assert decide(equal) is FindingStatus.CONFIRMED_VIOLATION


# -- run_oracle plumbing: verdict carries status + mechanism --------------


def test_run_oracle_returns_verdict_with_status_and_mechanism() -> None:
    ev = _ev(
        DiffExpectation.PROBE_UNAUTHORIZED,
        baseline=Observation("owner", 200, "x"),
        probe=Observation("attacker", 200, "x"),
        ref="bola/orders/42",
    )
    verdict = validator.run_oracle(OracleMechanism.DIFFERENTIAL, ev)
    assert isinstance(verdict, OracleVerdict)
    assert verdict.status is FindingStatus.CONFIRMED_VIOLATION
    assert verdict.mechanism is OracleMechanism.DIFFERENTIAL
    assert verdict.evidence_ref == "bola/orders/42"
    assert verdict.confirmed is True
    assert verdict.is_violation is True


def test_run_oracle_accepts_string_mechanism() -> None:
    ev = _ev(
        DiffExpectation.PROBE_AUTHORIZED,
        baseline=Observation("owner", 200, "d"),
        probe=Observation("peer", 200, "d"),
    )
    verdict = validator.run_oracle("differential", ev)
    assert verdict.status is FindingStatus.CONFIRMED_ALLOWED
    # confirmed_allowed is a confirmed fact but NOT a violation — write_finding
    # (Task 7) is gated behind is_violation, not merely confirmed.
    assert verdict.confirmed is True
    assert verdict.is_violation is False


def test_run_oracle_unknown_mechanism_raises() -> None:
    ev = _ev(
        DiffExpectation.PROBE_AUTHORIZED,
        baseline=Observation("o", 200, "d"),
        probe=Observation("p", 200, "d"),
    )
    # All six §7 families are now built. The registry still refuses a genuinely
    # unknown mechanism — proven by passing an invalid string.
    with pytest.raises((UnknownOracleError, ValueError)):
        validator.run_oracle("not_a_real_mechanism", ev)  # type: ignore[arg-type]


def test_oracle_rejects_wrong_evidence_type() -> None:
    with pytest.raises(TypeError):
        DifferentialOracle().run({"not": "evidence"})


# -- Invariant 2: run_oracle is the ONLY path to a confirmed result -------


def test_only_the_oracle_family_constructs_a_verdict() -> None:
    # OracleVerdict is the sole type carrying a `confirmed` verdict, and it is
    # constructed only inside an Oracle.run — which run_oracle is the only tool
    # that invokes. Prove no other production module constructs an OracleVerdict.
    import ast
    import pathlib

    src_root = pathlib.Path(validator.__file__).parents[1]  # src/reachagent
    constructors: list[str] = []
    for path in src_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = (
                    func.id
                    if isinstance(func, ast.Name)
                    else func.attr
                    if isinstance(func, ast.Attribute)
                    else None
                )
                if name == "OracleVerdict":
                    constructors.append(str(path.relative_to(src_root)))
    # A verdict is minted only inside an oracle family (§7) — never anywhere else
    # in the codebase. Phase 1 added differential, Phase 2 business_rule, Phase 3
    # timing_statistical and oob_callback. Every path is under oracles/ (no tool,
    # recon, or graph module mints one).
    assert sorted(constructors) == [
        "oracles/business_rule.py",
        "oracles/differential.py",
        "oracles/execution_confirmation.py",
        "oracles/oob_callback.py",
        "oracles/structural.py",
        "oracles/timing_statistical.py",
    ]
    assert all(p.startswith("oracles/") for p in constructors)


def test_candidate_cannot_carry_a_confirmed_status() -> None:
    # The Explorer's terminal output (Task 5) has no confirmed verdict: a Candidate
    # carries a *suggested* oracle, never a status/verdict. Confirmation exists
    # only downstream, in the OracleVerdict run_oracle returns.
    from reachagent.tools.candidate import Candidate

    fields = Candidate.__dataclass_fields__
    assert "status" not in fields
    assert "verdict" not in fields
    assert "confirmed" not in fields


def test_explorer_module_cannot_reach_run_oracle() -> None:
    # Structural: the Explorer never imports run_oracle or the validator module.
    from reachagent.tools import explorer

    assert not hasattr(explorer, "run_oracle")
    assert not hasattr(explorer, "validator")
    assert "run_oracle" not in vars(explorer)
