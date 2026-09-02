"""Paired-trial statistical timing oracle (plan §7, Phase 3 Task 2).

The ``timing_statistical`` §7 oracle family. Confirms a time-delay injection
only when a statistically significant latency effect is present in the probe
trials and absent in the negative-control (baseline) trials — ruling out
network jitter as the cause.

OOB-first discipline (§7): this oracle is the *fallback* for blind SQLi (the
``OOB_CALLBACK`` family is tried first); it is the *primary* oracle for NoSQLi
and LDAP extraction, which have no OOB channel. The caller (detector) decides
which oracle to invoke — this oracle has no knowledge of OOB availability.

Negative control is mandatory: a single timing measurement cannot confirm a
violation. Callers still pair a baseline trial fired under identical
conditions (same endpoint, same identity, same non-delay payload) with the
probe trial — :class:`PairedTrialEvidence` keeps that shape.

v3 architecture decision: the fixed ``decide(evidence)`` if/elif decision
chain (pure arithmetic over probe vs. baseline latencies) has been REMOVED.
Live confirmation now goes through LLM judgment
(``reachagent.oracles.llm_judgment.judge``), wired directly into
``tools/validator.py::run_oracle`` and ``detection/oracle_gateway.py::
registry_runner``. ``TimingStatisticalOracle`` is kept only as an inert shim
so ``reachagent.oracles.registry`` can still register
``OracleMechanism.TIMING_STATISTICAL``; its ``run()`` no longer decides
anything.

The dataclass in this module (``PairedTrialEvidence``) remains in active use
as the evidence-shape vocabulary: every timing detector still builds a
``PairedTrialEvidence`` and hands it to LLM judgment for confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict
from reachagent.oracles.evidence import EvidenceMetadata


class ValidationError(ValueError):
    """Raised when evidence fails structural requirements before any decision.

    Distinct from inconclusive: a missing baseline or too-few trials is a
    caller bug, not an ambiguous timing result. The oracle never silently
    returns inconclusive for a structurally invalid input.
    """


@dataclass(frozen=True)
class PairedTrialEvidence:
    """Latency measurements from a paired probe/baseline trial run.

    ``probe_latencies_ms``: N≥10 measurements with the time-delay payload.
    ``baseline_latencies_ms``: N≥10 measurements with the benign control
    payload, fired under identical conditions (same endpoint, same identity).
    ``threshold_multiplier``: how many baseline standard deviations above the
    baseline mean the probe mean must exceed to confirm. Default 3.0 — chosen
    to reject jitter (typically 1–2σ) while confirming deliberate delays
    (a 5 s delay against a sub-second baseline is always >> 3σ).
    ``evidence_ref``: short, secret-free provenance handle (§13).
    """

    probe_latencies_ms: tuple[float, ...]
    baseline_latencies_ms: tuple[float, ...]
    threshold_multiplier: float = 3.0
    evidence_ref: str = ""
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)


class TimingStatisticalOracle(Oracle):
    """Inert v3 shim — kept only so ``oracles.registry`` can still register
    ``OracleMechanism.TIMING_STATISTICAL`` (and so ``get_oracle(TIMING_
    STATISTICAL)`` keeps validating as a known mechanism for callers like
    ``recon/tools/signal_gated.py``, which only checks that the lookup does
    not raise and never calls ``.run()``).

    The fixed ``decide()`` chain that used to back this class is gone; no
    caller on the live confirmation path invokes ``run()`` any more
    (``tools/validator.py::run_oracle`` goes straight to
    ``oracles.llm_judgment.judge`` instead), so this raises rather than
    pretend to decide anything.
    """

    mechanism = OracleMechanism.TIMING_STATISTICAL

    def run(self, evidence: object) -> OracleVerdict:
        """No longer decides a verdict — see the class docstring.

        The type guard below predates ``decide()`` and is independent of it
        (a mis-wired caller passing the wrong evidence type is still a bug,
        not a removed-feature question), so it is kept. Before v3, ``run()``
        also auto-filled ``evidence_metadata.timing_samples_ms`` (the first
        1000 baseline + first 1000 probe latencies, only when the caller had
        not already supplied samples) ahead of calling the now-removed
        ``decide()``. That auto-fill logic was independent of ``decide()``
        too and is not dead by necessity — it is preserved verbatim in this
        task's report for a human to relocate (e.g. into
        ``oracles/llm_judgment.py``'s own verdict construction) rather than
        silently lost.
        """
        if not isinstance(evidence, PairedTrialEvidence):
            raise TypeError(
                f"TimingStatisticalOracle needs PairedTrialEvidence, got {type(evidence).__name__}"
            )
        raise NotImplementedError(
            "TimingStatisticalOracle.run() was removed in v3 — confirmation now "
            "goes through reachagent.oracles.llm_judgment.judge"
        )
