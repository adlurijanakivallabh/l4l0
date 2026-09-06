"""The ``Finding`` shape and its required-field gate.

The required-text fields and their wording are informed directly by a
reference agent's own ``create_vulnerability_report`` validation (read in
full in ``tools/reporting/tool.py``): counterevidence and
severity-change-conditions are mandatory on every finding, not optional
extras, because a finding with no stated case against itself and no stated
condition for revising its severity is an unfalsifiable claim. This gate is
a tool-call-shape check only — "you forgot to fill in a required field" —
never a truth judgment. A finding with weak or ungrounded evidence still
records once every field is present; :mod:`~lalo.findings.confidence`
scores the weakness, it never blocks the recording.

A fresh re-read of that same real source (this project's Phase 12 shannon/
strix reference-pass cycle) surfaced a genuine gap against its own ten
required fields: that reference requires ``remediation_steps`` on every
finding and L4L0 had no equivalent — a report telling an operator what is
broken without saying how to fix it is a real product gap, not
evidentiary rigor, so it is added here as its own mandatory field rather
than folded into ``description``. Deliberately NOT adopted from that same
list: separate ``impact``/``technical_analysis`` fields (redundant with
``description`` plus the CVSS breakdown's own impact metrics for this
project's own field set), a self-declared ``confidence``/
``confidence_rationale`` (superseded by :mod:`~lalo.findings.confidence`'s
computed score — compute, don't trust, the same stance already taken for
CVSS), and ``poc_script_code`` (superseded by this project's own
evidence-provenance grounding against real captured traffic, which that
reference's own equivalent field is never checked against).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .cvss import validate_cvss_breakdown

REQUIRED_TEXT_FIELDS = {
    "title": "title cannot be empty",
    "description": "description cannot be empty",
    "vuln_class": "vuln_class cannot be empty",
    "target": "target cannot be empty",
    "evidence_excerpt": "evidence_excerpt cannot be empty - state the specific proof text",
    "counterevidence": (
        "counterevidence cannot be empty - state the strongest case against this "
        "finding, or what you checked and found none of"
    ),
    "severity_change_conditions": (
        "severity_change_conditions cannot be empty - state the one concrete piece "
        "of evidence that would raise or lower the severity"
    ),
    "remediation": (
        "remediation cannot be empty - state concrete steps to fix or mitigate this finding"
    ),
}


@dataclass(frozen=True)
class Finding:
    title: str
    description: str
    vuln_class: str
    target: str
    evidence: list[str]
    evidence_excerpt: str
    counterevidence: str
    severity_change_conditions: str
    remediation: str
    cvss_breakdown: dict[str, str]
    param: str | None = None
    reproduced: bool = False
    identities_confirmed: list[str] = field(default_factory=list)


def validate_finding_fields(fields: dict[str, object]) -> list[str]:
    """Every required-text and CVSS-breakdown error, collected in one pass."""
    errors = [
        message
        for name, message in REQUIRED_TEXT_FIELDS.items()
        if not str(fields.get(name) or "").strip()
    ]
    evidence = fields.get("evidence")
    if not isinstance(evidence, list) or not any(str(item).strip() for item in evidence):
        errors.append(
            "evidence cannot be empty - provide at least one captured proof blob "
            "(a response body, an OAST correlation, a command's real output)"
        )
    errors.extend(validate_cvss_breakdown(fields.get("cvss_breakdown")))
    return errors
