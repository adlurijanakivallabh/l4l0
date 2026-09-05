"""Turn an external tool's claim into weak evidence — never a standalone finding.

A third-party scanner saying "vulnerable" is one input the confidence scorer
reasons over, at low specificity, so it needs corroboration to reach high
confidence. It never becomes a Finding on its own.
"""

from __future__ import annotations

from ..models import Evidence, EvidenceKind


def tool_claim_to_evidence(
    tool_name: str, claim: str, *, fire_ref: str | None = None, observed: str = ""
) -> Evidence:
    return Evidence(
        kind=EvidenceKind.STRUCTURAL,
        summary=f"[{tool_name}] {claim}",
        fire_ref=fire_ref,
        observed=observed,
        metadata={"source": "external_tool", "tool": tool_name, "diff_magnitude": 0.3},
    )
