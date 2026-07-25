"""Structural oracle — file upload bypass, path traversal, JWT forgery (§7, Phase 3).

The sixth and final §7 oracle family. Confirms structural input-handling
violations deterministically:

  * **FILE_UPLOAD_BYPASS** — a file that should be rejected by the server's
    extension/content-type allowlist was accepted (2xx). Baseline: a legitimately
    allowed file is accepted (confirms the endpoint works). Probe: a disguised
    file (wrong extension, double extension, mismatched content-type). Probe
    accepted → bypass confirmed.

  * **PATH_TRAVERSAL** — a known sentinel string (e.g. ``root:x:0:0``) appears
    verbatim in the response body, proving the server read a file outside the
    intended directory.

  * **JWT_FORGERY** — a forged token (none-algorithm, weak-secret, key-confusion)
    was accepted (2xx) when it should have been refused (401/403). Baseline: a
    valid token is accepted. Probe: the forged token.

All three paths are deterministic: no LLM, no heuristics. Same evidence in,
same verdict out, every time.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict


class StructuralCheckType(StrEnum):
    """Which structural check this evidence covers."""

    FILE_UPLOAD_BYPASS = "file_upload_bypass"
    PATH_TRAVERSAL = "path_traversal"
    JWT_FORGERY = "jwt_forgery"


@dataclass(frozen=True)
class StructuralEvidence:
    """Evidence for the structural oracle.

    ``check_type`` selects the decision branch.

    FILE_UPLOAD_BYPASS:
      ``baseline_status``: response to a legitimately allowed file (must be 2xx
      for the probe to mean anything — same guard as the differential oracle's
      baseline-GRANTED requirement).
      ``probe_status``: response to the disguised/disallowed file. 2xx = bypass.

    PATH_TRAVERSAL:
      ``sentinel``: known string that proves out-of-scope file access (e.g.
      ``root:x:0:0``). ``response_body``: the server's response. Sentinel present
      verbatim → traversal confirmed.

    JWT_FORGERY:
      ``baseline_status``: response to a valid token (must be 2xx).
      ``probe_status``: response to the forged token. 2xx = forgery accepted.

    ``evidence_ref``: short, secret-free provenance handle (§13).
    """

    check_type: StructuralCheckType
    baseline_status: int = 0
    probe_status: int = 0
    sentinel: str = ""
    response_body: str = ""
    evidence_ref: str = ""


def decide(evidence: StructuralEvidence) -> FindingStatus:
    """Map structural evidence to one verdict — the whole decision (§7).

    Pure and total: every valid input returns exactly one FindingStatus.
    No LLM anywhere in the path.
    """
    if evidence.check_type is StructuralCheckType.FILE_UPLOAD_BYPASS:
        # Baseline must be accepted to confirm the endpoint is functional.
        if not (200 <= evidence.baseline_status < 300):
            return FindingStatus.INCONCLUSIVE
        # Probe accepted when it should have been rejected → bypass.
        if 200 <= evidence.probe_status < 300:
            return FindingStatus.CONFIRMED_VIOLATION
        # Probe correctly rejected.
        if evidence.probe_status in range(400, 500):
            return FindingStatus.CONFIRMED_DENIED
        return FindingStatus.INCONCLUSIVE

    if evidence.check_type is StructuralCheckType.PATH_TRAVERSAL:
        if evidence.sentinel and evidence.sentinel in evidence.response_body:
            return FindingStatus.CONFIRMED_VIOLATION
        return FindingStatus.INCONCLUSIVE

    if evidence.check_type is StructuralCheckType.JWT_FORGERY:
        if not (200 <= evidence.baseline_status < 300):
            return FindingStatus.INCONCLUSIVE
        if 200 <= evidence.probe_status < 300:
            return FindingStatus.CONFIRMED_VIOLATION
        if evidence.probe_status in range(400, 500):
            return FindingStatus.CONFIRMED_DENIED
        return FindingStatus.INCONCLUSIVE

    return FindingStatus.INCONCLUSIVE


class StructuralOracle(Oracle):
    """Confirms structural input-handling violations — sixth §7 family."""

    mechanism = OracleMechanism.STRUCTURAL

    def run(self, evidence: object) -> OracleVerdict:
        """Return the deterministic verdict for ``evidence``.

        ``evidence`` must be :class:`StructuralEvidence`. Raises ``TypeError``
        on wrong type — a mis-wired caller is a bug, not an inconclusive result.
        """
        if not isinstance(evidence, StructuralEvidence):
            raise TypeError(
                f"StructuralOracle needs StructuralEvidence, got {type(evidence).__name__}"
            )
        status = decide(evidence)
        return OracleVerdict(
            mechanism=self.mechanism,
            status=status,
            evidence_ref=evidence.evidence_ref,
        )
