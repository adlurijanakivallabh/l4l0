"""Deterministic Markdown rendering — pure string assembly, never an LLM call.

Adopts two specific, security-relevant ideas from a reference agent's own
``report/writer.py`` (read in full): the *idea* behind ``safe_fence`` (a
backtick fence one character longer than the longest backtick run already
inside the content being fenced, since a CommonMark fence is only closed by
a run at least as long as the one that opened it — attacker-influenced
evidence text, quoted verbatim from a captured target response, can
otherwise break out of its own code block) and the general per-finding
section structure (title, metadata line, then labeled sections for
description/evidence/counterevidence/etc.), adapted to this project's own
field names. :func:`safe_fence` below is a genuine reimplementation, not a
port of the reference's regex-based version — a single-pass character scan
computing the same longest-run value, precisely because a 2-line
CommonMark-fence-length calculation has no meaningfully different "better"
shape to invent, only a different one to independently derive. That
reference's own ``csv_safe()`` (a same-file, adjacent CWE-1236 CSV-formula-
injection guard prefixing a leading apostrophe on cells starting with
``= + - @``/tab/CR) is a real, separate defensive idea this module itself
does not need: this module only ever emits Markdown, never CSV, so there is
no spreadsheet-formula-injection surface *here* to guard against — the same
idea is instead applied, independently, in :mod:`lalo.report.csv_export`,
the module that actually owns L4L0's CSV output. A reference SAST platform's
``findings-renderer.ts`` fail-partial discipline ("a per-class render
failure is isolated... rather than aborting the whole report") is adopted
directly for :func:`render_report_md`: one malformed finding renders as its
own failure note, never a reason to drop or blank the rest of the report.

:func:`_render_chains_mermaid` is additive, not a replacement: the existing
plain-text chain bullet (``" → ".join(chain.titles)``) stays as the fallback
for a viewer with no Mermaid renderer, and the Mermaid ``flowchart LR`` block
renders alongside it for the viewers that do (GitHub/GitLab render fenced
```mermaid blocks natively).
"""

from __future__ import annotations

from collections.abc import Sequence

from .collect import (
    AttackSurfaceSummary,
    ChainRecord,
    ExecutiveSummary,
    FindingRecord,
    ReportMetadata,
    ReportUsage,
    first_finding_id_by_vuln_class,
    group_by_verdict,
)
from .coverage import CoverageSummary
from .taxonomy import cwe_for, owasp_api_for, owasp_api_name_for


def safe_fence(content: str) -> str:
    """A fence long enough that ``content`` cannot break out of its own code block."""
    longest = current = 0
    for char in content:
        current = current + 1 if char == "`" else 0
        longest = max(longest, current)
    return "`" * max(3, longest + 1)


def _render_chains_mermaid(chains: Sequence[ChainRecord]) -> str:
    """A Mermaid ``flowchart LR`` counterpart to the plain-text chain bullets
    - GitHub/GitLab/most modern Markdown viewers render this natively, while
    the bullet list above remains the explicit plain-text fallback for
    viewers that don't. A double-quote inside a chain title would otherwise
    terminate the Mermaid node's own quoted label early, so it is swapped
    for a single quote here - the same "neutralize what could break the
    surrounding syntax" discipline as this module's own :func:`safe_fence`,
    applied to Mermaid's node-label syntax instead of a Markdown fence."""
    if not chains:
        return ""
    lines = ["```mermaid", "flowchart LR"]
    for i, chain in enumerate(chains):
        node_ids = [f"c{i}n{j}" for j in range(len(chain.titles))]
        for node_id, title in zip(node_ids, chain.titles, strict=True):
            lines.append(f'    {node_id}["{title.replace(chr(34), chr(39))}"]')
        # node_ids and node_ids[1:] are deliberately one element apart to
        # form adjacent pairs - strict=True here (unlike the node/title zip
        # above, where matching lengths is a real invariant) would raise on
        # every chain with 1+ nodes, since the two sequences can never be
        # equal length by construction.
        for a, b in zip(node_ids, node_ids[1:], strict=False):
            lines.append(f"    {a} --> {b}")
    lines.append("```")
    return "\n".join(lines)


def render_finding_md(record: FindingRecord) -> str:
    lines = [
        f'<a id="{record.finding_id}"></a>',
        f"## {record.title or record.finding_id}",
        f"**ID:** {record.finding_id}",
        f"**Class:** {record.vuln_class}",
    ]
    cwe = cwe_for(record.vuln_class)
    if cwe:
        lines.append(f"**CWE:** {cwe}")
    owasp = owasp_api_for(record.vuln_class)
    if owasp:
        owasp_name = owasp_api_name_for(record.vuln_class)
        lines.append(f"**OWASP API Top 10:** {owasp}" + (f" — {owasp_name}" if owasp_name else ""))
    lines += [
        f"**Target:** {record.target}" + (f" (param: `{record.param}`)" if record.param else ""),
        f"**Severity:** {record.effective_severity.upper()}"
        + (f" — _overridden: {record.override_reason}_" if record.override_reason else ""),
        f"**CVSS:** {record.cvss_score:.1f} ({record.cvss_severity}) — `{record.cvss_vector}`",
        f"**Confidence:** {record.confidence.score}/100",
    ]
    if record.review_verdict:
        proof = f" ({record.review_proof_level})" if record.review_proof_level else ""
        lines.append(f"**Adversarial Review:** {record.review_verdict}{proof}")
    if record.prerequisites:
        lines.append(f"**Prerequisites:** {record.prerequisites}")
    if record.impact:
        lines.append(f"**Impact:** {record.impact}")
    lines.append("")

    lines.append("### Description\n")
    lines.append(record.description or "(none provided)")
    lines.append("")

    if record.exploitation_steps:
        lines.append("### Exploitation Steps\n")
        lines.extend(f"{i}. {step}" for i, step in enumerate(record.exploitation_steps, start=1))
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

    lines.append("### Remediation\n")
    lines.append(record.remediation or "(none stated)")
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
    chains: Sequence[ChainRecord] = (),
    generated_at: str | None = None,
    status: str | None = None,
    summary: ExecutiveSummary | None = None,
    usage: ReportUsage | None = None,
    metadata: ReportMetadata | None = None,
    attack_surface: AttackSurfaceSummary | None = None,
) -> str:
    lines = ["# L4L0 Security Assessment Report", ""]
    if generated_at:
        lines.append(f"**Generated:** {generated_at}")
        lines.append("")
    if status:
        lines.append(f"**Scan Status:** {status}")
        lines.append("")
    lines.append(f"**Findings:** {len(records)}")
    lines.append("")

    if usage is not None:
        cost_note = (
            f", est. cost ${usage.total_cost_usd:.4f}" if usage.total_cost_usd is not None else ""
        )
        lines.append(
            f"**LLM Usage:** {usage.total_requests} requests, "
            f"{usage.total_input_tokens:,} input / {usage.total_output_tokens:,} output "
            f"tokens{cost_note}"
        )
        lines.append("")

    if summary is not None:
        lines.append("## Executive Summary\n")
        severity_line = (
            ", ".join(f"{sev}: {count}" for sev, count in summary.by_severity.items()) or "(none)"
        )
        category_line = (
            ", ".join(f"{cls}: {count}" for cls, count in summary.by_vuln_class.items()) or "(none)"
        )
        lines.append(f"**By severity:** {severity_line}")
        lines.append(f"**By category:** {category_line}")
        if summary.highest_severity:
            lines.append(f"**Highest severity:** {summary.highest_severity.upper()}")
        if summary.by_confidence:
            conf_line = ", ".join(
                f"{band}: {count}" for band, count in summary.by_confidence.items() if count
            )
            if conf_line:
                lines.append(f"**By confidence:** {conf_line}")
        if summary.critical_findings:
            lines.append("**Critical Findings:**")
            lines.extend(f"- {title}" for title in summary.critical_findings)
        if metadata is not None:
            lines.append(f"**Model / Provider:** {metadata.model_provider}")
            lines.append("**Target / Scope:**")
            lines.append(metadata.engagement_scope)
        lines.append("")

        lines.append("## Summary by Vulnerability Type\n")
        if not summary.by_vuln_class:
            lines.append("(none)")
        else:
            anchor_by_class = first_finding_id_by_vuln_class(records)
            for cls, count in summary.by_vuln_class.items():
                anchor = anchor_by_class.get(cls)
                label = f"{cls} ({count})"
                lines.append(f"- [{label}](#{anchor})" if anchor else f"- {label}")
        lines.append("")

    lines.append("## Coverage\n")
    lines.append(f"**Assessed:** {', '.join(coverage.assessed) or '(none)'}")
    lines.append(f"**Not assessed:** {', '.join(coverage.not_assessed) or '(none)'}")
    if coverage.verified_safe:
        lines.append(f"**Assessed, confirmed clean:** {', '.join(coverage.verified_safe)}")
        for cls in coverage.verified_safe:
            lines.append(f"- *{cls}*: {coverage.safe_reasons[cls]}")
    lines.append(
        "\n_A class marked 'not assessed' means no finding was filed for it - this "
        "does not distinguish 'tested and found clean' from 'never examined'._"
    )
    lines.append("")

    if attack_surface is not None and (
        attack_surface.endpoints or attack_surface.services or attack_surface.fingerprints
    ):
        lines.append("## Attack Surface\n")
        lines.append(
            "_Recon facts captured during the run, independent of whether they "
            "produced a finding._\n"
        )
        if attack_surface.endpoints:
            lines.append("**Endpoints:**")
            lines.extend(f"- {e}" for e in attack_surface.endpoints)
        if attack_surface.services:
            lines.append("**Services:**")
            lines.extend(f"- {s}" for s in attack_surface.services)
        if attack_surface.fingerprints:
            lines.append("**Fingerprints:**")
            lines.extend(f"- {f}" for f in attack_surface.fingerprints)
        lines.append("")

    if chains:
        lines.append("## Attack Chains\n")
        lines.append(
            "_Each chain below was explicitly declared by the agent (record_finding's own "
            "enabled_by_finding_id), not inferred - one finding's exploitation genuinely "
            "enabled reaching the next._\n"
        )
        lines.extend(f"- {' → '.join(chain.titles)}" for chain in chains)
        lines.append("")
        mermaid = _render_chains_mermaid(chains)
        if mermaid:
            lines.append(mermaid)
            lines.append("")

    if records:
        lines.append("## Findings Overview\n")
        lines.append("| ID | Title | Class | Severity | Confidence |")
        lines.append("|---|---|---|---|---|")
        for record in records:
            try:
                lines.append(
                    f"| [{record.finding_id}](#{record.finding_id}) | {record.title} | "
                    f"{record.vuln_class} | {record.effective_severity.upper()} | "
                    f"{record.confidence.score} |"
                )
            except Exception:  # noqa: BLE001 - a malformed finding must not blank the table
                lines.append(f"| {record.finding_id} | (failed to render) | | | |")
        lines.append("")

    lines.append("## Findings\n")
    if not records:
        lines.append("No findings recorded.")
    else:
        for label, group in group_by_verdict(records):
            lines.append(f"### Verdict: {label} ({len(group)})\n")
            if not group:
                lines.append("_None._\n")
                continue
            for record in group:
                try:
                    lines.append(render_finding_md(record))
                except Exception as exc:  # noqa: BLE001 - malformed finding must not blank the report
                    lines.append(
                        f"## {record.finding_id}\n\n_Failed to render this finding: {exc}_\n"
                    )

    return "\n".join(lines)
