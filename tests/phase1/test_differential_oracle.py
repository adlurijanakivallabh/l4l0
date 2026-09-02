"""Differential-diff evidence shapes + verification engine (plan §7; Task 6).

The fixed per-mechanism ``decide()`` decision table and the tests that
asserted its specific outcomes were removed under the v3 architecture
decision (CLAUDE.md): live confirmation judgment now happens in
``oracles/llm_judgment.py`` instead of a scripted table, so those outcomes
are no longer this module's behavior to test. What remains here:

  2. ``run_oracle`` is the only code path capable of producing a *confirmed*
     result — proven structurally, the way Task 5 proved ``classify_response``
     has no path to ``write_finding``.
"""

from __future__ import annotations

import pytest

from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
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
    # v3 (CLAUDE.md): the six legacy per-family modules' decide() tables are gone
    # (their run() methods raise NotImplementedError instead of returning a
    # verdict), so none of them constructs an OracleVerdict any more — the live
    # judgment path, oracles/llm_judgment.py, is the only remaining site. The
    # discipline itself — verdict construction confined to a small, known,
    # reviewed set of files — is unchanged, just narrower now.
    assert constructors  # llm_judgment.py mints at least one (success + inconclusive)
    assert set(constructors) == {"oracles/llm_judgment.py"}


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
