"""Blind SQL injection detection tests (plan §7, §9; Phase 3 Task 1).

Covers the Task 1 DoD:
  * OOB_CALLBACK family registered and callable via run_oracle (no
    UnknownOracleError); a known-good DNS callback confirms.
  * OOB-first: a received callback confirms; no callback does NOT confirm
    (the oracle is not timing-only by default).
  * per-request nonce attribution: two concurrent probes never cross-attribute.
  * collaborator base domain / token loaded from env, never hardcoded.
  * OOB genuinely attempted before timing (the ordering proof).
  * timing fallback only reached when OOB produced no callback.
  * boolean-blind differential requires ≥3 consistent TRUE/FALSE trial pairs.
"""

from __future__ import annotations

import pytest

from reachagent.graph.nodes import FindingStatus
from reachagent.oob.collaborator import (
    _ENV_BASE_DOMAIN,
    InteractshCollaborator,
    OOBCollaborator,
    OOBConfigError,
)
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.oracles.differential import Observation
from reachagent.oracles.oob_callback import OOBCallbackEvidence, OOBCallbackOracle, decide
from reachagent.sqli.blind_detector import (
    BlindSqliProber,
    BooleanTrialPair,
    OOBProbe,
    TimingProbe,
    detect_blind_sqli,
)
from reachagent.tools.validator import run_oracle

# A stable sub-second baseline (10 trials) and a ~5 s injected-delay probe.
_STABLE_BASELINE = (100.0, 105.0, 98.0, 102.0, 101.0, 99.0, 103.0, 100.0, 104.0, 97.0)
_DELAYED_PROBE = tuple(5000.0 + i for i in range(10))


# === OOB oracle family (DoD: registered, callable, DNS callback confirms) =====


def test_oob_family_registered_and_callable() -> None:
    ev = OOBCallbackEvidence(probe_nonce="n1", observed_nonces=frozenset({"n1"}))
    verdict = run_oracle(OracleMechanism.OOB_CALLBACK, ev)
    assert isinstance(verdict, OracleVerdict)
    assert verdict.is_violation  # known-good callback confirms


def test_oob_no_callback_is_inconclusive_not_confirmed() -> None:
    # No callback received → not a confirmation (and not a false "safe" either).
    ev = OOBCallbackEvidence(probe_nonce="n1", observed_nonces=frozenset())
    assert decide(ev) is FindingStatus.INCONCLUSIVE


def test_oob_empty_nonce_never_confirms() -> None:
    # A probe with no nonce must not match a bare/empty callback — never confirm.
    ev = OOBCallbackEvidence(probe_nonce="", observed_nonces=frozenset({""}))
    assert decide(ev) is FindingStatus.INCONCLUSIVE


def test_oob_wrong_evidence_type_raises() -> None:
    with pytest.raises(TypeError, match="OOBCallbackEvidence"):
        OOBCallbackOracle().run(object())


# === nonce attribution (DoD: two probes never cross-attribute) ================


def test_two_probes_do_not_cross_attribute_callbacks() -> None:
    # Probe A's nonce was observed; probe B's was not. Each resolves to its own.
    observed = frozenset({"nonce-A"})
    a = OOBCallbackEvidence(probe_nonce="nonce-A", observed_nonces=observed)
    b = OOBCallbackEvidence(probe_nonce="nonce-B", observed_nonces=observed)
    assert decide(a) is FindingStatus.CONFIRMED_VIOLATION  # A's callback is A's
    assert decide(b) is FindingStatus.INCONCLUSIVE  # B does not claim A's callback


# === collaborator: env-loaded, per-nonce subdomain, no hardcoded host =========


def test_collaborator_base_domain_from_env() -> None:
    c = InteractshCollaborator(environ={_ENV_BASE_DOMAIN: "oob.self-hosted.internal"})
    assert c.callback_domain("abc") == "abc.oob.self-hosted.internal"


def test_collaborator_missing_domain_raises_no_silent_default() -> None:
    # No env, no arg → must fail loudly, never fall back to a public collaborator.
    with pytest.raises(OOBConfigError, match=_ENV_BASE_DOMAIN):
        InteractshCollaborator(environ={})


def test_collaborator_per_nonce_subdomains_are_distinct() -> None:
    c = InteractshCollaborator(base_domain="oob.test.internal")
    assert c.callback_domain("n1") != c.callback_domain("n2")


def test_collaborator_records_and_reports_observed() -> None:
    c = InteractshCollaborator(base_domain="oob.test.internal")
    assert c.observed_nonces() == frozenset()
    c.record_interaction("seen-1")
    assert c.observed_nonces() == frozenset({"seen-1"})


def test_collaborator_satisfies_protocol() -> None:
    c = InteractshCollaborator(base_domain="oob.test.internal")
    assert isinstance(c, OOBCollaborator)


def test_oob_module_has_no_hardcoded_collaborator_host() -> None:
    # DoD: grep of the OOB module for a literal collaborator hostname is clean.
    import pathlib

    import reachagent.oob.collaborator as mod

    src = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
    # No literal interact.sh public hosts, no bare public collaborator domains.
    for banned in ("oast.fun", "oast.pro", "oast.site", "burpcollaborator.net", "interact.sh"):
        # "interact.sh" appears only in comments/docstrings as the *product* name;
        # assert it never appears as a hostname literal (quoted, dotted URL).
        assert f'"{banned}"' not in src
        assert f"https://{banned}" not in src


# === blind-SQLi detector: OOB-first ordering (THE proof) ======================


def _prober(
    *,
    oob: OOBProbe | None,
    observed: frozenset[str],
    timing: TimingProbe,
    boolean: list[BooleanTrialPair] | None = None,
    trace: list[str],
) -> BlindSqliProber:
    """Build a prober whose callbacks append to a shared trace on each fire."""

    def fire_oob() -> OOBProbe | None:
        trace.append("fire_oob")
        return oob

    def observed_nonces() -> frozenset[str]:
        return observed

    def fire_timing() -> TimingProbe:
        trace.append("fire_timing")
        return timing

    def fire_boolean_pairs() -> list[BooleanTrialPair]:
        trace.append("fire_boolean")
        return boolean or []

    return BlindSqliProber(
        fire_oob=fire_oob,
        observed_nonces=observed_nonces,
        fire_timing=fire_timing,
        fire_boolean_pairs=fire_boolean_pairs,
    )


def test_oob_confirms_and_timing_is_never_fired() -> None:
    # THE ordering proof: when a callback arrives, OOB confirms and the detector
    # returns WITHOUT ever firing timing — not "timing used unconditionally".
    trace: list[str] = []
    prober = _prober(
        oob=OOBProbe(nonce="n-hit", callback_domain="n-hit.oob.internal"),
        observed=frozenset({"n-hit"}),
        timing=TimingProbe(_DELAYED_PROBE, _STABLE_BASELINE),
        trace=trace,
    )
    result = detect_blind_sqli(prober, evidence_ref="sqli/blind/probe1")
    assert result.confirmed
    assert result.mechanism is OracleMechanism.OOB_CALLBACK
    assert result.attempted == (OracleMechanism.OOB_CALLBACK,)
    assert "fire_oob" in trace
    assert "fire_timing" not in trace  # timing genuinely not reached


def test_oob_attempted_first_then_timing_when_no_callback() -> None:
    # OOB is attempted (fired) first; only because no callback arrived does the
    # detector fall back to timing. Order in the trace proves OOB came first.
    trace: list[str] = []
    prober = _prober(
        oob=OOBProbe(nonce="n-miss", callback_domain="n-miss.oob.internal"),
        observed=frozenset(),  # no callback received
        timing=TimingProbe(_DELAYED_PROBE, _STABLE_BASELINE),
        trace=trace,
    )
    result = detect_blind_sqli(prober)
    assert result.confirmed
    assert result.mechanism is OracleMechanism.TIMING_STATISTICAL
    assert trace.index("fire_oob") < trace.index("fire_timing")
    assert result.attempted == (
        OracleMechanism.OOB_CALLBACK,
        OracleMechanism.TIMING_STATISTICAL,
    )


def test_timing_fallback_when_target_has_no_oob_payload() -> None:
    # fire_oob returns None (no OOB-capable payload) → straight to timing.
    trace: list[str] = []
    prober = _prober(
        oob=None,
        observed=frozenset(),
        timing=TimingProbe(_DELAYED_PROBE, _STABLE_BASELINE),
        trace=trace,
    )
    result = detect_blind_sqli(prober)
    assert result.confirmed
    assert result.mechanism is OracleMechanism.TIMING_STATISTICAL


def test_no_confirmation_when_neither_oob_nor_timing_signals() -> None:
    trace: list[str] = []
    prober = _prober(
        oob=OOBProbe(nonce="n-miss", callback_domain="n-miss.oob.internal"),
        observed=frozenset(),
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),  # equal → no signal
        trace=trace,
    )
    result = detect_blind_sqli(prober, try_boolean=False)
    assert not result.confirmed
    assert result.mechanism is None
    assert result.attempted == (
        OracleMechanism.OOB_CALLBACK,
        OracleMechanism.TIMING_STATISTICAL,
    )


# === boolean-blind: ≥3 consistent trial pairs required ========================


def _diverging_pair() -> BooleanTrialPair:
    # TRUE and FALSE conditions a safe app answers identically; here they diverge
    # (both 200 but different bodies) → the condition reached the backend.
    return BooleanTrialPair(
        true_condition=Observation("true", 200, "id=1 name=alice"),
        false_condition=Observation("false", 200, "no rows"),
    )


def _identical_pair() -> BooleanTrialPair:
    return BooleanTrialPair(
        true_condition=Observation("true", 200, "same body"),
        false_condition=Observation("false", 200, "same body"),
    )


def test_boolean_blind_confirms_with_three_consistent_diverging_pairs() -> None:
    trace: list[str] = []
    prober = _prober(
        oob=None,
        observed=frozenset(),
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),  # no timing signal
        boolean=[_diverging_pair(), _diverging_pair(), _diverging_pair()],
        trace=trace,
    )
    result = detect_blind_sqli(prober)
    assert result.confirmed
    assert result.mechanism is OracleMechanism.DIFFERENTIAL


def test_boolean_blind_rejects_two_pairs_below_threshold() -> None:
    # Only 2 diverging pairs (< 3) → not enough repetition, no confirmation.
    prober = _prober(
        oob=None,
        observed=frozenset(),
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),
        boolean=[_diverging_pair(), _diverging_pair()],
        trace=[],
    )
    result = detect_blind_sqli(prober)
    assert not result.confirmed


def test_boolean_blind_rejects_inconsistent_pairs() -> None:
    # 3 pairs but one is identical (no divergence) → inconsistent → rejected.
    prober = _prober(
        oob=None,
        observed=frozenset(),
        timing=TimingProbe(_STABLE_BASELINE, _STABLE_BASELINE),
        boolean=[_diverging_pair(), _identical_pair(), _diverging_pair()],
        trace=[],
    )
    result = detect_blind_sqli(prober)
    assert not result.confirmed


# === payload library ordering (DoD: OOB entries tried before pure-timing) =====


def test_sqli_blind_payloads_rank_oob_before_timing() -> None:
    # §7/§9 ordering rule: get_payloads returns OOB-capable entries before
    # pure-timing ones, so the detector's OOB-first sequencing matches the
    # library's own confidence order (not an accident of the detector).
    from reachagent.graph.nodes import SinkType
    from reachagent.payloads import PayloadLibrary

    entries = PayloadLibrary.from_file().get_payloads("sqli_blind", SinkType.SQL)
    oracle_order = [e.oracle_type for e in entries]
    assert OracleMechanism.OOB_CALLBACK in oracle_order
    assert OracleMechanism.TIMING_STATISTICAL in oracle_order
    assert oracle_order.index(OracleMechanism.OOB_CALLBACK) < oracle_order.index(
        OracleMechanism.TIMING_STATISTICAL
    )
