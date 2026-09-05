"""Recall-first scoring: nothing in L4L0 is gated on precision or confidence, so
this harness measures them as secondary, informational signals — never a pass/fail
threshold a scan has to clear. A composite is tracked over time as an append-only,
byte-verified history so the project's own eval trend is visible across development,
not just a single run's snapshot.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from ..core.atomic_io import atomic_write_verified
from .cases import CaseResult


def recall(result: CaseResult) -> float:
    """Fraction of the case's ground-truth classes that were actually found."""
    truth = result.case.ground_truth_classes
    if not truth:
        return 1.0
    return len(truth & result.found_classes) / len(truth)


def precision(result: CaseResult) -> float:
    """Fraction of found classes that were actually in the ground truth.

    A case that found nothing is treated as precision 1.0 (nothing reported,
    nothing wrong reported) rather than undefined — a deliberate convention
    choice consistent with recall's own empty-ground-truth convention above.
    """
    if not result.found_classes:
        return 1.0
    return len(result.case.ground_truth_classes & result.found_classes) / len(result.found_classes)


def calibration_gap(results: list[CaseResult]) -> float | None:
    """Mean confidence of true-positive class matches minus mean confidence of
    false-positive ones, across every case's findings. Positive means real
    findings score higher, on average, than spurious ones - a coarse,
    interpretable signal, not a formal calibration statistic, matching
    CLAUDE.md's "precision/calibration secondary" framing for this harness.

    Returns ``None`` when there is no mix of both to compare (every case
    found nothing, or every found class happened to be correct) - reporting
    a number here would imply a comparison that never actually occurred.
    """
    true_positive_scores: list[int] = []
    false_positive_scores: list[int] = []
    for result in results:
        for vuln_class, score in result.confidence_by_class.items():
            if vuln_class in result.case.ground_truth_classes:
                true_positive_scores.append(score)
            else:
                false_positive_scores.append(score)
    if not true_positive_scores or not false_positive_scores:
        return None
    return (sum(true_positive_scores) / len(true_positive_scores)) - (
        sum(false_positive_scores) / len(false_positive_scores)
    )


@dataclass(frozen=True)
class CompositeScore:
    mean_recall: float
    mean_precision: float
    calibration_gap: float | None
    case_count: int


def score_composite(results: list[CaseResult]) -> CompositeScore:
    if not results:
        return CompositeScore(
            mean_recall=0.0, mean_precision=0.0, calibration_gap=None, case_count=0
        )
    return CompositeScore(
        mean_recall=sum(recall(r) for r in results) / len(results),
        mean_precision=sum(precision(r) for r in results) / len(results),
        calibration_gap=calibration_gap(results),
        case_count=len(results),
    )


def append_composite_history(
    score: CompositeScore, path: Path, *, label: str, recorded_at: str | None = None
) -> None:
    """Append one dated, labeled entry to a durable, byte-verified score history.

    Never overwrites prior entries - the history file is the project's own
    eval trend across its development, not a single run's snapshot.

    Not safe against two concurrent callers appending to the same ``path``
    at once (read-modify-write, no lock): the second writer's read misses
    the first's not-yet-flushed append, and one entry is silently lost
    rather than both landing. Accepted rather than fixed with file locking -
    this project's own convention (CLAUDE.md: bring an eval target up only
    for one live run, tear it down immediately after) means eval runs
    happen one at a time by construction, so the race has no real caller to
    trigger it today. A genuinely concurrent eval runner would need to close
    this properly (a lock file, or a single writer process), not just get a
    bigger try/except around the same race.
    """
    existing = json.loads(path.read_bytes()) if path.exists() else []
    existing.append({"label": label, "recorded_at": recorded_at, **asdict(score)})
    atomic_write_verified(path, json.dumps(existing, indent=2).encode("utf-8"))


def load_composite_history(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    data: list[dict[str, object]] = json.loads(path.read_bytes())
    return data
