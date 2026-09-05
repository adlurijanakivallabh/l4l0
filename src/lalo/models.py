"""Shared domain models used across the graph, confirmation, agent, and report.

Kept dependency-free so every subsystem can import them without cycles. Enums are
``str``-backed so ``dataclasses.asdict`` yields JSON-ready values.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceKind(StrEnum):
    """The evidence-family vocabulary a confidence signal is drawn from."""

    DIFFERENTIAL = "differential"
    STRUCTURAL = "structural"
    TIMING = "timing"
    EXECUTION = "execution"
    OOB_CALLBACK = "oob_callback"
    BUSINESS_RULE = "business_rule"


@dataclass
class Evidence:
    """One piece of captured evidence backing a finding.

    ``observed`` is the actual text captured from the target (used by the
    provenance component of confidence scoring); ``fire_ref`` links to the
    request/response that produced it.
    """

    kind: EvidenceKind
    summary: str
    fire_ref: str | None = None
    observed: str = ""
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class Finding:
    """A reported finding. Never gated — always written; confidence annotates it."""

    id: str
    title: str
    vuln_class: str
    severity: Severity
    target: str
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float | None = None  # 0-100, set by the confidence scorer
    confidence_breakdown: dict[str, float] = field(default_factory=dict)
    poc: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        title: str,
        vuln_class: str,
        severity: Severity,
        target: str,
        evidence: list[Evidence] | None = None,
    ) -> Finding:
        return cls(
            id=uuid.uuid4().hex,
            title=title,
            vuln_class=vuln_class,
            severity=severity,
            target=target,
            evidence=list(evidence or []),
        )
