"""Deterministic Markdown report rendering."""

from __future__ import annotations

from ..core.redaction import redact, safe_target_url
from ..detectors.ledger import CoverageLedger
from ..models import Finding, Severity
from .cvss import nominal_cvss
from .poc import curl_poc

_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (_SEV_ORDER.get(f.severity, 5), -(f.confidence or 0.0)),
    )


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicates (same class+target+parameter), keeping the highest
    confidence; a survivor records how many duplicates it absorbed."""
    best: dict[tuple[str, str, str], Finding] = {}
    dupes: dict[tuple[str, str, str], int] = {}
    for f in findings:
        key = f.dedup_key()
        current = best.get(key)
        if current is None or (f.confidence or 0.0) > (current.confidence or 0.0):
            best[key] = f
        dupes[key] = dupes.get(key, 0) + 1
    for key, f in best.items():
        if dupes[key] > 1:
            f.metadata.setdefault("duplicates_absorbed", dupes[key] - 1)
    return list(best.values())


def render_markdown(
    findings: list[Finding],
    *,
    coverage: CoverageLedger | None = None,
    title: str = "L4L0 Security Report",
    dedup: bool = True,
) -> str:
    if dedup:
        findings = dedup_findings(findings)
    lines = [f"# {title}", ""]
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    lines.append("## Summary")
    lines.append(f"- Findings: {len(findings)}")
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            lines.append(f"- {sev.capitalize()}: {counts[sev]}")
    lines.append("")

    lines.append("## Findings")
    if not findings:
        lines.append("_No findings recorded._")
    for f in _sorted(findings):
        lines.append(f"### [{f.severity.value.upper()}] {redact(f.title)}")
        lines.append(f"- Class: `{f.vuln_class}`  |  CVSS (nominal): {nominal_cvss(f.severity)}")
        lines.append(f"- Confidence: **{f.confidence}** {f.confidence_breakdown}")
        flags = f.metadata.get("confidence_flags")
        if flags:
            lines.append(f"- Flags: {flags}")
        lines.append(f"- Target: {safe_target_url(f.target)}")
        lines.append("- Evidence:")
        for e in f.evidence:
            lines.append(f"    - [{e.kind.value}] {redact(e.summary)}")
        if f.counterevidence:
            lines.append(f"- Counterevidence: {redact(f.counterevidence)}")
        if f.severity_change_conditions:
            lines.append(f"- Severity would change if: {redact(f.severity_change_conditions)}")
        lines.append("- PoC:")
        lines.append("  ```")
        lines.append(f"  {f.poc or curl_poc(f)}")
        lines.append("  ```")
        lines.append("")

    if coverage is not None:
        gaps = coverage.not_assessed()
        lines.append("## Not assessed")
        lines.append(
            "_These (target, class) pairs were applicable but not assessed — "
            "absence of a finding here is NOT evidence of safety._"
        )
        if gaps:
            for target, vuln_class in gaps:
                lines.append(f"- {safe_target_url(target)} — {vuln_class}")
        else:
            lines.append("- (none)")
    return "\n".join(lines)
