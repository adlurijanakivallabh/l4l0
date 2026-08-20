"""Path traversal retrieval of out-of-scope file (§7, §9; Phase 3 Task 8).

Uses the STRUCTURAL oracle's PATH_TRAVERSAL branch. One probe:

  Fire a request with a ``../``-traversal payload in a ``file`` parameter;
  check whether a known sentinel string from an out-of-scope file appears
  verbatim in the response body. Sentinel present → traversal confirmed.

Read-only-first (§10): the traversal probe is a read (GET), not a write.
No state-changing request is needed; the read-only-first constraint is
satisfied by the nature of the attack class.

Prober-injection seam: ``PathTraversalProber`` holds one callback; tests
supply in-memory fakes; the live path supplies firer-backed implementations.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence


@dataclass(frozen=True)
class TraversalProbeResult:
    """Response body and status from one traversal probe."""

    body: str
    status_code: int = 200


@dataclass
class PathTraversalProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_probe``: fire the traversal request and return the response body.
    ``sentinel``: known string that proves out-of-scope file access.
    ``oracle_runner``: injectable oracle seam; defaults to registry (no validator import).
    """

    fire_probe: Callable[[], TraversalProbeResult]
    sentinel: str
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class PathTraversalResult:
    """Outcome of a path traversal detection attempt."""

    confirmed: bool
    evidence_ref: str = ""


def detect_path_traversal(
    prober: PathTraversalProber,
    *,
    evidence_ref: str = "",
) -> PathTraversalResult:
    """Detect path traversal — sentinel-in-body confirmation (§7, §9).

    Fires the traversal probe and checks whether the sentinel appears verbatim
    in the response body. No state-changing request required (read-only GET).
    """
    probe = prober.fire_probe()
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.PATH_TRAVERSAL,
        sentinel=prober.sentinel,
        probe_status=probe.status_code,
        response_body=probe.body,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    return PathTraversalResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)
