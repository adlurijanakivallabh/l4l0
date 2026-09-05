"""Findings: the confirmation layer — record, ground, score, and adversarially review.

Phase 12. Every finding lands in :class:`~lalo.graph.model.ReachabilityGraph`
the moment ``record_finding`` succeeds — nothing here ever withholds a
finding. Two non-blocking layers run after landing: a deterministic
:mod:`~lalo.findings.confidence` score, and an independent LLM
:mod:`~lalo.findings.review` that only ever adjusts that score.
"""

from .confidence import ConfidenceScore, compute_confidence
from .cvss import CvssResult, compute_cvss
from .dedup import dedup_key, find_duplicate
from .grounding import is_grounded
from .model import REQUIRED_TEXT_FIELDS, Finding, validate_finding_fields
from .review import ReviewResult, ReviewVerdict, run_adversarial_review
from .tool import build_record_finding_tool

__all__ = [
    "REQUIRED_TEXT_FIELDS",
    "ConfidenceScore",
    "CvssResult",
    "Finding",
    "ReviewResult",
    "ReviewVerdict",
    "build_record_finding_tool",
    "compute_confidence",
    "compute_cvss",
    "dedup_key",
    "find_duplicate",
    "is_grounded",
    "run_adversarial_review",
    "validate_finding_fields",
]
