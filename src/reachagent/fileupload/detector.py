"""File upload type/extension bypass detection (§7, §9; Phase 3 Task 7).

Uses the STRUCTURAL oracle (sixth §7 family). Two probes:

  1. **Baseline**: upload a legitimately allowed file (e.g. image/jpeg .jpg).
     Must be accepted (2xx) — confirms the endpoint is functional.
  2. **Probe**: upload a disguised file (wrong extension, double extension,
     mismatched content-type, or polyglot). Accepted (2xx) → bypass confirmed.

Read-only-first (§10): the baseline probe fires first; the disguised probe fires
only after the baseline confirms the endpoint accepts legitimate files.

Prober-injection seam: ``FileUploadProber`` holds two callbacks; tests supply
in-memory fakes; the live path supplies firer-backed implementations.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence
from reachagent.tools.validator import run_oracle


@dataclass(frozen=True)
class UploadProbeResult:
    """HTTP status from one upload attempt."""

    status_code: int


@dataclass
class FileUploadProber:
    """Injectable probe callbacks — keeps detection hermetic and ordering testable.

    ``fire_baseline``: upload a legitimately allowed file; return its HTTP status.
    ``fire_probe``: upload the disguised/disallowed file; return its HTTP status.
    """

    fire_baseline: Callable[[], UploadProbeResult]
    fire_probe: Callable[[], UploadProbeResult]


@dataclass(frozen=True)
class FileUploadResult:
    """Outcome of a file upload bypass detection attempt."""

    confirmed: bool
    evidence_ref: str = ""


def detect_file_upload_bypass(
    prober: FileUploadProber,
    *,
    evidence_ref: str = "",
) -> FileUploadResult:
    """Detect file upload type/extension bypass (§7, §9).

    Fires the baseline first (read-only-first discipline: confirms the endpoint
    accepts legitimate files before firing the disguised probe). Returns at the
    first confirmation.
    """
    baseline = prober.fire_baseline()
    probe = prober.fire_probe()

    evidence = StructuralEvidence(
        check_type=StructuralCheckType.FILE_UPLOAD_BYPASS,
        baseline_status=baseline.status_code,
        probe_status=probe.status_code,
        evidence_ref=evidence_ref,
    )
    verdict = run_oracle(OracleMechanism.STRUCTURAL, evidence)
    return FileUploadResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)
