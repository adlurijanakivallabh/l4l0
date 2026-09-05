"""Semantic-ish response diffing.

Deterministic and dependency-free (``difflib``): structural signals + a
similarity ratio feeding the specificity component of confidence scoring. An
embedding backend can slot in later behind the same ``ResponseDiff`` shape.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

# Cap inputs so SequenceMatcher stays cheap on large bodies.
_MAX_COMPARE = 20_000
_TOKEN = re.compile(r"[A-Za-z0-9_]{3,}")


@dataclass
class ResponseDiff:
    similarity: float  # 0..1 (1 = identical)
    status_changed: bool
    length_delta: int
    added_markers: list[str] = field(default_factory=list)

    @property
    def magnitude(self) -> float:
        """Deviation from baseline in 0..1 (higher = more different)."""
        base = 1.0 - self.similarity
        if self.status_changed:
            base = min(1.0, base + 0.3)
        return round(base, 4)


def semantic_diff(
    baseline: str,
    candidate: str,
    *,
    baseline_status: int | None = None,
    candidate_status: int | None = None,
    max_markers: int = 10,
) -> ResponseDiff:
    a = baseline[:_MAX_COMPARE]
    b = candidate[:_MAX_COMPARE]
    similarity = difflib.SequenceMatcher(None, a, b).ratio()
    baseline_tokens = set(_TOKEN.findall(a))
    added = [t for t in dict.fromkeys(_TOKEN.findall(b)) if t not in baseline_tokens]
    return ResponseDiff(
        similarity=round(similarity, 4),
        status_changed=(
            baseline_status is not None
            and candidate_status is not None
            and baseline_status != candidate_status
        ),
        length_delta=len(candidate) - len(baseline),
        added_markers=added[:max_markers],
    )
