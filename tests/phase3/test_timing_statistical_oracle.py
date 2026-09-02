"""Paired-trial statistical timing oracle tests (plan §7, Phase 3 Task 2).

v3: the fixed decide() decision logic this file tested was removed (live
judgment now goes through reachagent.oracles.llm_judgment.judge), so every
test that asserted on decide()'s or TimingStatisticalOracle().run()'s
fixed-logic outcome (with no injected LLM client) was deleted. What remains
covers behavior independent of decide(): registration in the §7 family
registry, and the oracle's type discipline.
"""

from __future__ import annotations

import pytest

from reachagent.oracles import OracleMechanism
from reachagent.oracles.registry import _REGISTRY, UnknownOracleError, get_oracle
from reachagent.oracles.timing_statistical import TimingStatisticalOracle

# --- registration (DoD: callable via run_oracle, three families) -------------


def test_timing_family_is_registered() -> None:
    oracle = get_oracle(OracleMechanism.TIMING_STATISTICAL)
    assert isinstance(oracle, TimingStatisticalOracle)
    assert oracle.mechanism is OracleMechanism.TIMING_STATISTICAL


def test_all_six_families_registered() -> None:
    # §7 names six families; all six are now built (differential Phase 1,
    # business_rule Phase 2, timing_statistical + oob_callback +
    # execution_confirmation + structural Phase 3). This is the exact-set
    # tripwire against an uncontrolled family addition — it must equal the enum.
    assert set(_REGISTRY) == set(OracleMechanism)


def test_timing_mechanism_is_one_of_the_six_declared_families() -> None:
    # The mechanism must already exist in the §7 enum — registering it is not
    # adding a seventh family, it's building a declared-but-stubbed one.
    assert OracleMechanism.TIMING_STATISTICAL in set(OracleMechanism)


# --- type discipline (mirrors differential/business_rule) --------------------


def test_wrong_evidence_type_raises_typeerror() -> None:
    with pytest.raises(TypeError, match="PairedTrialEvidence"):
        TimingStatisticalOracle().run(object())


def test_unknown_mechanism_still_raises() -> None:
    # All six §7 families are now built. The registry must still refuse a
    # genuinely unknown mechanism — proven by passing an invalid string that
    # cannot be coerced to any OracleMechanism enum member.
    with pytest.raises((UnknownOracleError, ValueError)):
        get_oracle("not_a_real_mechanism")  # type: ignore[arg-type]
