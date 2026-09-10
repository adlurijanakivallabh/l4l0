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

A fresh re-read of that same real source (this project's Phase 12
reference-pass cycle) surfaced a genuine gap against its own ten
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

_VALID_REACHABILITY = frozenset({"confirmed", "likely", "unlikely", "unknown"})


def validate_dependency_fields(fields: dict[str, object]) -> list[str]:
    """Extra checks for a dependency/SCA-shaped finding - a no-op for every
    ordinary finding, since the default ``reachability`` is ``"unknown"``
    and an absent key reads the same way. A closed enum, and every
    non-"unknown" value must carry a stated reason: a reachability CLAIM
    with no evidence behind it is the same unfalsifiable-claim problem
    REQUIRED_TEXT_FIELDS already polices for counterevidence and
    severity_change_conditions above - a scanner-reported CVE against an
    installed version proves nothing about whether the vulnerable code
    path is ever actually reached.
    """
    reachability = str(fields.get("reachability") or "unknown").strip().lower()
    errors: list[str] = []
    if reachability not in _VALID_REACHABILITY:
        errors.append(
            f"reachability must be one of {sorted(_VALID_REACHABILITY)}, got {reachability!r}"
        )
    elif reachability != "unknown" and not str(fields.get("reachability_evidence") or "").strip():
        errors.append(
            "reachability_evidence cannot be empty when reachability is not 'unknown' - "
            "state what you traced (a real call path, or a confirmed-absent import) "
            "to reach that verdict"
        )
    return errors


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
    # Either a single "path:line" string (unchanged since introduction), or,
    # for a traced multi-hop path, an ordered list of hops from source to
    # sink: [{"role": "source", "location": "app/routes.py:10"}, ...]. See
    # report/sarif.py, which renders a single string as one physicalLocation
    # (today's behavior, unchanged) and a multi-hop list as an additional
    # SARIF codeFlows/threadFlows block.
    source_location: str | list[dict[str, str]] | None = None
    # Both optional (default ""), agent-authored at record_finding time -
    # what access/credentials an attacker needs before this is reachable,
    # and what an attacker can DO with it (business-consequence framed,
    # distinct from `description`'s "what the bug is"). Neither is required
    # - an empty string renders as "(none stated)", matching every other
    # optional narrative field's own existing convention.
    prerequisites: str = ""
    impact: str = ""
    exploitation_steps: list[str] = field(default_factory=list)
    # Set when an agent re-tests a PREVIOUSLY reported finding against a
    # claimed fix and confirms it actually holds - never required, never
    # blocking anything; a finding with fix_verified=False simply has no
    # verification opinion yet, the same "absence is not a claim" stance
    # every other optional field here already takes.
    fix_verified: bool = False
    fix_verification_notes: str = ""
    # Each entry: {"location": "path:line", "fix_before": str, "fix_after": str} -
    # what actually changed at a specific location, distinct from
    # source_location's single vulnerability-location/chain-hop role above.
    code_locations: list[dict[str, str]] = field(default_factory=list)
    # Dependency/SCA-shaped finding fields - all optional, all "" / "unknown"
    # by default so an ordinary (non-dependency) finding is entirely
    # unaffected. contextual_cvss is deliberately distinct from
    # cvss_breakdown/the computed cvss_score above: an advisory's own base
    # score describes the vulnerability in the abstract, this one reflects
    # THIS specific deployment's actual reachability and blast radius.
    package_name: str = ""
    installed_version: str = ""
    ecosystem: str = ""
    manifest_path: str = ""
    reachability: str = "unknown"
    reachability_evidence: str = ""
    contextual_cvss: float | None = None


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
