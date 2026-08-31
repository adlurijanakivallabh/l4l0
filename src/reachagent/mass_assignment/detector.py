"""Mass-assignment detection — write-then-independent-reread (§7, §9).

Reuses the existing ``differential`` oracle family (no new mechanism, no new
enum member): a benign write is sent alongside an unauthorized privileged field
(e.g. ``{"isAdmin": true}``), and an INDEPENDENT read-back of the same resource
is diffed against the expected-privileged marker via
``DiffAxis.CROSS_REQUEST`` / ``DiffExpectation.PROBE_UNAUTHORIZED`` — already
proven by ``test_mass_assignment_cross_request_violation``
(tests/phase1/test_differential_oracle.py). This module contains no I/O and no
JSON parsing — pure oracle wiring, mirroring ``nosql/detector.py``'s shape.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
)


@dataclass(frozen=True)
class MassAssignmentProbe:
    """The expected-privileged marker and the independent post-write reread.

    ``reference`` is what a genuinely-privileged value looks like (a synthetic
    marker built from the exact value injected — not a second live fire, since
    the injected value is already known); ``reread`` is an INDEPENDENT read of
    the resource after the write, never the write's own response body.
    """

    reference: Observation
    reread: Observation


@dataclass
class MassAssignmentProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable."""

    fire_probe: Callable[[], MassAssignmentProbe]
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class MassAssignmentResult:
    """Outcome of a mass-assignment detection attempt.

    ``confirmed`` is true only if the oracle returned ``confirmed_violation``.
    """

    confirmed: bool
    mechanism: OracleMechanism | None
    evidence_ref: str = ""


def detect_mass_assignment(
    prober: MassAssignmentProber, *, evidence_ref: str = ""
) -> MassAssignmentResult:
    """Fire the probe, build CROSS_REQUEST/PROBE_UNAUTHORIZED evidence, confirm."""
    probe = prober.fire_probe()
    evidence = DifferentialEvidence(
        axis=DiffAxis.CROSS_REQUEST,
        expectation=DiffExpectation.PROBE_UNAUTHORIZED,
        baseline=probe.reference,
        probe=probe.reread,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.DIFFERENTIAL, evidence)
    return MassAssignmentResult(
        confirmed=verdict.is_violation,
        mechanism=OracleMechanism.DIFFERENTIAL if verdict.is_violation else None,
        evidence_ref=evidence_ref,
    )
