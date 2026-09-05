"""Confirmation — semantic diffing + non-blocking confidence scoring.

There is no gate here. Every fired candidate that trips a detector becomes a
Finding immediately; this package attaches a deterministic, auditable Confidence
Score (0–100) with a component breakdown so signal strength is visible without
anything being withheld.
"""

from .diff import ResponseDiff, semantic_diff
from .review import ReviewVerdict, adversarial_review, apply_review
from .scoring import ConfidenceScorer, ScoreBreakdown, score_finding

__all__ = [
    "ConfidenceScorer",
    "ResponseDiff",
    "ReviewVerdict",
    "ScoreBreakdown",
    "adversarial_review",
    "apply_review",
    "score_finding",
    "semantic_diff",
]
