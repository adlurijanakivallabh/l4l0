"""Deterministic Markdown rendering — pure string assembly, never an LLM call.

Adopts two specific, security-relevant ideas from a reference agent's own
``report/writer.py`` (read in full): ``safe_fence`` (a backtick fence one
character longer than the longest backtick run already inside the content
being fenced, since a CommonMark fence is only closed by a run at least as
long as the one that opened it — attacker-influenced evidence text, quoted
verbatim from a captured target response, can otherwise break out of its
own code block) and the general per-finding section structure (title,
metadata line, then labeled sections for description/evidence/
counterevidence/etc.), adapted to this project's own field names. A
reference SAST platform's ``findings-renderer.ts`` fail-partial discipline
("a per-class render failure is isolated... rather than aborting the whole
report") is adopted directly for :func:`render_report_md`: one malformed
finding renders as its own failure note, never a reason to drop or blank
the rest of the report.
"""

from __future__ import annotations

import re

from .collect import FindingRecord
from .coverage import CoverageSummary

_BACKTICK_RUN = re.compile(r"`+")


def safe_fence(content: str) -> str:
    """A fence long enough that ``content`` cannot break out of its own code block."""
    longest = max((len(m.group()) for m in _BACKTICK_RUN.finditer(content)), default=0)
    return "`" * max(3, longest + 1)


def render_finding_md(record: FindingRecord) -> str:
    lines = [
        f"## {record.title or record.finding_id}",
        f"**ID:** {record.finding_id}",
        f"**Class:** {record.vuln_class}",
        f"**Target:** {record.target}" + (f" (param: `{record.param}`)" if record.param else ""),
        f"**Severity:** {record.effective_severity.upper()}"
        + (f" — _overridden: {record.override_reason}_" if record.override_reason else ""),
        f"**CVSS:** {record.cvss_score:.1f} ({record.cvss_severity}) — `{record.cvss_vector}`",
        f"**Confidence:** {record.confidence.score}/100",
    ]
    if record.review_verdict:
        proof = f" ({record.review_proof_level})" if record.review_proof_level else ""
        lines.append(f"**Adversarial Review:** {record.review_verdict}{proof}")
    lines.append("")

    lines.append("### Description\n")
    lines.append(record.description or "(none provided)")
    lines.append("")

    lines.append("### Evidence\n")
    if not record.evidence_grounded:
        lines.append(
            "**Warning:** the stated evidence excerpt could not be verified "
            "against the evidence below - treat this finding's proof as unconfirmed.\n"
        )
    for i, blob in enumerate(record.evidence, start=1):
        fence = safe_fence(blob)
        lines.append(f"Evidence {i}:")
        lines.append(fence)
        lines.append(blob)
        lines.append(fence)
        lines.append("")

    lines.append("### Counterevidence\n")
    lines.append(record.counterevidence or "(none stated)")
    lines.append("")

    lines.append("### What Would Change This Severity\n")
    lines.append(record.severity_change_conditions or "(none stated)")
    lines.append("")

    lines.append("### Confidence Breakdown\n")
    lines.extend(f"- {name}: {points}" for name, points in record.confidence.breakdown.items())
    if record.confidence.flags:
        lines.append("")
        lines.append("Flags:")
        lines.extend(f"- {flag}" for flag in record.confidence.flags)
    lines.append("")

    return "\n".join(lines)


def render_report_md(
    records: list[FindingRecord],
    coverage: CoverageSummary,
    *,
    generated_at: str | None = None,
) -> str:
    lines = ["# L4L0 Security Assessment Report", ""]
    if generated_at:
        lines.append(f"**Generated:** {generated_at}")
        lines.append("")
    lines.append(f"**Findings:** {len(records)}")
    lines.append("")

    lines.append("## Coverage\n")
    lines.append(f"**Assessed:** {', '.join(coverage.assessed) or '(none)'}")
    lines.append(f"**Not assessed:** {', '.join(coverage.not_assessed) or '(none)'}")
    lines.append(
        "\n_A class marked 'not assessed' means no finding was filed for it - this "
        "does not distinguish 'tested and found clean' from 'never examined'._"
    )
    lines.append("")

    lines.append("## Findings\n")
    if not records:
        lines.append("No findings recorded.")
    for record in records:
        try:
            lines.append(render_finding_md(record))
        except Exception as exc:  # noqa: BLE001 - one malformed finding must not blank the report
            lines.append(f"## {record.finding_id}\n\n_Failed to render this finding: {exc}_\n")

    return "\n".join(lines)
