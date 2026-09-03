"""Cross-identity IDOR via a genuine state-changing write (§7 differential, §9).

A sibling to ``bola/detector.py``, not a modification of it: that detector is
read-only-first by design ("only GET endpoints are probed here" — its own
docstring) and every ``vuln_class="bola"``/enumerable-vs-disclosed
precondition tag it writes stays exactly as-is. This module confirms the one
case BOLA's read probe cannot: a write (PUT/PATCH) against ANOTHER identity's
live object actually succeeds when it should be refused. Same DIFFERENTIAL
oracle family (``CROSS_IDENTITY``/``PROBE_UNAUTHORIZED``), no new mechanism.

Unlike a read, two different writes' response bodies are not directly
comparable (a legitimate echo of "what I just wrote" differs between the
owner's and the non-owner's requests even when both succeed) — so the raw
oracle's body-equivalence check would never fire correctly here. Instead both
Observations are engineered to carry only the ACCESS OUTCOME, mirroring
``mass_assignment/detector.py``'s synthetic-observation shape: the baseline
always reads "an authorized write here succeeds", and the probe reduces the
non-owner's actual response to the same ok/denied vocabulary.

This is the one detector in the project whose confirmed path mutates another
real identity's live data — the driver that owns firing (``run_authz_idor``
in ``scan/orchestrator.py``) gates it behind an explicit opt-in, default off.

Optional technique-diversity corroboration (v3 V3): when a THIRD identity
(beyond the owner and the first non-owner) is available, ``fire_second_probe``
lets the driver wire in its write against the same object — a confirmed
first probe is only trusted once a second, independent identity's write also
succeeds, ruling out the first non-owner session having its own unrelated
delegated/shared access to this specific object rather than a systemic
authorization flaw. Fired lazily (only if the first probe already looks like
a violation) via ``corroborate_with_variant`` — never an unconditional extra
mutation. Optional and additive: when omitted (the default, and the common
case where only 2 identities are configured), behavior is byte-for-byte
unchanged from before this was added.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.confirmation.corroboration import corroborate_with_variant
from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
)


@dataclass(frozen=True)
class IdorProbe:
    """The non-owner's write status against the owner's live object.

    The owner's own baseline write is fired and checked by the driver BEFORE
    this probe ever runs (the precondition: proves the endpoint is a genuinely
    live write for this object) — its result gates whether the non-owner probe
    fires at all, so it plays no further role in the comparison here.
    """

    non_owner_status: int


@dataclass
class IdorProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_second_probe`` (v3 V3, optional): a second, independent identity's
    write against the SAME object — see module docstring.
    """

    fire_probe: Callable[[], IdorProbe]
    oracle_runner: OracleRunner = registry_runner
    fire_second_probe: Callable[[], IdorProbe] | None = None


@dataclass(frozen=True)
class IdorResult:
    """Outcome of an IDOR detection attempt.

    ``confirmed`` is true only if the oracle returned ``confirmed_violation``
    (and, when a second probe was configured, only if it also confirmed).
    """

    confirmed: bool
    evidence_ref: str = ""
    corroborated: bool = False


def _idor_evidence(probe: IdorProbe, *, evidence_ref: str, label: str) -> DifferentialEvidence:
    non_owner_ok = 200 <= probe.non_owner_status < 300
    return DifferentialEvidence(
        axis=DiffAxis.CROSS_IDENTITY,
        expectation=DiffExpectation.PROBE_UNAUTHORIZED,
        baseline=Observation("expected-authorized-write", 200, "ok"),
        probe=Observation(label, probe.non_owner_status, "ok" if non_owner_ok else "denied"),
        evidence_ref=evidence_ref,
    )


def detect_idor(
    prober: IdorProber,
    *,
    evidence_ref: str = "",
) -> IdorResult:
    """Fire the probe, reduce the write to an access outcome, confirm via CROSS_IDENTITY.

    When ``prober.fire_second_probe`` is set, a confirmed first probe is
    corroborated against a second, independent identity's write before being
    trusted (v3 V3) — a contradicted corroboration fails closed to
    not-confirmed, never falls back to the uncorroborated first result.
    """
    probe = prober.fire_probe()
    evidence = _idor_evidence(probe, evidence_ref=evidence_ref, label="non-owner-write")
    verdict = prober.oracle_runner(OracleMechanism.DIFFERENTIAL, evidence)
    if prober.fire_second_probe is None:
        return IdorResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)

    def _second_attempt() -> object:
        second_probe = prober.fire_second_probe()  # type: ignore[misc]
        second_evidence = _idor_evidence(
            second_probe, evidence_ref=evidence_ref, label="second-non-owner-write"
        )
        return prober.oracle_runner(OracleMechanism.DIFFERENTIAL, second_evidence)

    result = corroborate_with_variant(verdict, _second_attempt)
    return IdorResult(
        confirmed=result.corroborated, evidence_ref=evidence_ref, corroborated=result.corroborated
    )
