"""Deterministic HTML rendering — the shared source both PDF and DOCX export
convert from, never an LLM call, matching :mod:`lalo.report.markdown`'s own
"pure string assembly" discipline for the exact same reason.

Every dynamic value (target-observed evidence, an LLM-authored title or
description, anything that ultimately traces back to content this project
does not control) goes through :func:`html.escape` before it is ever
concatenated into the document. This is the HTML analogue of
:mod:`lalo.report.markdown`'s ``safe_fence`` - but simpler, not a port of
anything: Markdown's fenced-code-block problem (a backtick run inside
content long enough to close the fence early) has no HTML equivalent to
guard against in the same way, because HTML escaping neutralizes markup
injection unconditionally, regardless of what characters or structure the
escaped text contains — there is no "run of some character" that can ever
close a tag once ``<``/``>``/``&`` are all entity-escaped. A different real
risk this rendering path does carry, absent from the Markdown/JSON/SARIF
outputs entirely: :mod:`lalo.report.pdf`'s WeasyPrint renderer can fetch
external resources an ``<img src>``/``@import`` references — a report
containing target-influenced content is exactly adversarial-input-reaching-
a-renderer, the same category of concern a reference agent's own
PDF-generation path (``reportlab``, read via its comparison doc) explicitly
guards against by escaping unrecognized markup tokens. Escaping here closes
the injection vector at the source (no live tag ever reaches the renderer);
:mod:`lalo.report.pdf`'s own locked-down ``url_fetcher`` is the second,
independent layer in case an escaping bug ever let one through anyway.
"""

from __future__ import annotations

from collections.abc import Sequence
from html import escape

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

_STYLE = """
body { font-family: sans-serif; font-size: 11pt; color: #1a1a1a; }
h1 { font-size: 20pt; }
h2 { font-size: 14pt; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 28px; }
h3 { font-size: 11pt; margin-bottom: 4px; }
dl { margin: 0 0 12px 0; }
dt { font-weight: bold; float: left; clear: left; width: 130px; }
dd { margin-left: 140px; }
pre { background: #f4f4f4; padding: 8px; white-space: pre-wrap; word-break: break-word; }
.warning { color: #a33; font-weight: bold; }
.stat-chips { display: flex; flex-wrap: wrap; gap: 8px; margin: 4px 0 16px;
  padding: 0; list-style: none; }
.stat-chip { display: inline-flex; align-items: baseline; gap: 5px; padding: 4px 12px;
  border-radius: 999px; font-size: 10pt; font-weight: 600; }
.stat-chip .stat-count { font-size: 12pt; font-weight: 800; }
.stat-chip.sev-critical { background: #fee2e2; color: #991b1b; }
.stat-chip.sev-high { background: #ffedd5; color: #9a3412; }
.stat-chip.sev-medium { background: #fef9c3; color: #854d0e; }
.stat-chip.sev-low { background: #dbeafe; color: #1e40af; }
.stat-chip.sev-info { background: #f1f5f9; color: #475569; }
.cover-page { border: 1px solid #ccc; border-radius: 6px; padding: 12px 16px;
  margin: 12px 0 24px; background: #fafafa; }
.cover-page p { margin: 4px 0; }
.confidentiality { color: #a33; font-weight: bold; font-style: italic; }
.overview-table { border-collapse: collapse; width: 100%; margin: 8px 0 20px; }
.overview-table th, .overview-table td { border: 1px solid #ddd; padding: 6px 10px;
  text-align: left; font-size: 10pt; }
.overview-table th { background: #f4f4f4; }
"""

_KNOWN_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_CONFIDENTIALITY_NOTICE = "Confidential — authorized engagement only."


def _e(value: object) -> str:
    return escape(str(value))


def _stat_chips(by_severity: dict[str, int]) -> str:
    """A visual per-severity count row - more scannable at a glance than the
    equivalent plain-prose numbers alone. An unrecognized severity string
    (never produced by this codebase's own fixed CVSS scale today, but
    display_severity is operator-supplied via SeverityOverride, so this
    stays defensive) falls back to an unstyled chip rather than being
    silently dropped from the summary."""
    chips = [
        f'<li class="stat-chip sev-{sev if sev in _KNOWN_SEVERITIES else "info"}">'
        f'<span class="stat-count">{count}</span> {_e(sev.upper())}</li>'
        for sev, count in by_severity.items()
    ]
    return f'<ul class="stat-chips">{"".join(chips)}</ul>'


def render_finding_html(record: FindingRecord) -> str:
    parts = [
        f'<h2 id="{_e(record.finding_id)}">{_e(record.title or record.finding_id)}</h2>',
        "<dl>",
    ]
    parts.append(f"<dt>ID</dt><dd>{_e(record.finding_id)}</dd>")
    parts.append(f"<dt>Class</dt><dd>{_e(record.vuln_class)}</dd>")
    cwe = cwe_for(record.vuln_class)
    if cwe:
        parts.append(f"<dt>CWE</dt><dd>{_e(cwe)}</dd>")
    owasp = owasp_api_for(record.vuln_class)
    if owasp:
        owasp_name = owasp_api_name_for(record.vuln_class)
        label = f"{owasp} — {owasp_name}" if owasp_name else owasp
        parts.append(f"<dt>OWASP API Top 10</dt><dd>{_e(label)}</dd>")
    target_line = _e(record.target)
    if record.param:
        target_line += f" (param: <code>{_e(record.param)}</code>)"
    parts.append(f"<dt>Target</dt><dd>{target_line}</dd>")
    severity_line = _e(record.effective_severity.upper())
    if record.override_reason:
        severity_line += f" <em>(overridden: {_e(record.override_reason)})</em>"
    parts.append(f"<dt>Severity</dt><dd>{severity_line}</dd>")
    parts.append(
        f"<dt>CVSS</dt><dd>{record.cvss_score:.1f} ({_e(record.cvss_severity)}) "
        f"— <code>{_e(record.cvss_vector)}</code></dd>"
    )
    confidence_dd = f"{record.confidence.score}/100"
    if (
        record.review_adjusted_score is not None
        and record.review_adjusted_score != record.confidence.score
    ):
        # The adversarial review's own adjustment, distinct from the raw
        # score above - never overwrites it, since "what did we compute
        # before review" and "what did review conclude" are both real,
        # separately meaningful numbers.
        confidence_dd += f" → {record.review_adjusted_score}/100 after review"
    parts.append(f"<dt>Confidence</dt><dd>{confidence_dd}</dd>")
    if record.review_verdict:
        proof = f" ({_e(record.review_proof_level)})" if record.review_proof_level else ""
        parts.append(f"<dt>Adversarial Review</dt><dd>{_e(record.review_verdict)}{proof}</dd>")
    if record.prerequisites:
        parts.append(f"<dt>Prerequisites</dt><dd>{_e(record.prerequisites)}</dd>")
    if record.impact:
        parts.append(f"<dt>Impact</dt><dd>{_e(record.impact)}</dd>")
    parts.append("</dl>")

    parts.append(f"<h3>Description</h3><p>{_e(record.description) or '(none provided)'}</p>")

    parts.append("<h3>Exploitation Steps</h3>" if record.reproduced else "<h3>Analysis</h3>")
    if record.exploitation_steps:
        parts.append("<ol>")
        for step in record.exploitation_steps:
            parts.append(f"<li>{_e(step)}</li>")
        parts.append("</ol>")
    else:
        parts.append("<p>(none provided)</p>")

    parts.append("<h3>Evidence</h3>")
    if not record.evidence_grounded:
        parts.append(
            '<p class="warning">Warning: the stated evidence excerpt could not be verified '
            "against the evidence below - treat this finding's proof as unconfirmed.</p>"
        )
    for i, blob in enumerate(record.evidence, start=1):
        parts.append(f"<p>Evidence {i}:</p><pre>{_e(blob)}</pre>")

    parts.append(f"<h3>Counterevidence</h3><p>{_e(record.counterevidence) or '(none stated)'}</p>")
    parts.append(
        "<h3>What Would Change This Severity</h3>"
        f"<p>{_e(record.severity_change_conditions) or '(none stated)'}</p>"
    )
    parts.append(f"<h3>Remediation</h3><p>{_e(record.remediation) or '(none stated)'}</p>")

    parts.append("<h3>Confidence Breakdown</h3><ul>")
    parts += [
        f"<li>{_e(name)}: {points}</li>" for name, points in record.confidence.breakdown.items()
    ]
    parts.append("</ul>")
    if record.confidence.flags:
        parts.append("<p>Flags:</p><ul>")
        parts += [f"<li>{_e(flag)}</li>" for flag in record.confidence.flags]
        parts.append("</ul>")

    return "\n".join(parts)


def render_report_html(
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
    parts = [
        "<!doctype html>",
        f"<html><head><meta charset='utf-8'><style>{_STYLE}</style></head><body>",
        "<h1>L4L0 Security Assessment Report</h1>",
    ]
    # Cover page. engagement_scope/model_provider come straight off the
    # ReportMetadata the sibling report-metadata task threads onto this same
    # signature - degrades to "(not recorded)" when metadata is None, same
    # as every other optional Executive Summary block here.
    engagement_scope = metadata.engagement_scope if metadata is not None else None
    model_provider = metadata.model_provider if metadata is not None else None
    parts.append('<section class="cover-page">')
    scope_display = _e(engagement_scope or "(not recorded)")
    parts.append(f"<p><strong>Target / Engagement Scope:</strong> {scope_display}</p>")
    parts.append(f"<p><strong>Report Date:</strong> {_e(generated_at or '(not recorded)')}</p>")
    parts.append(
        f"<p><strong>Model / Provider:</strong> {_e(model_provider or '(not recorded)')}</p>"
    )
    parts.append(f'<p class="confidentiality">{_e(_CONFIDENTIALITY_NOTICE)}</p>')
    parts.append("</section>")
    if generated_at:
        parts.append(f"<p><strong>Generated:</strong> {_e(generated_at)}</p>")
    if status:
        parts.append(f"<p><strong>Scan Status:</strong> {_e(status)}</p>")
    parts.append(f"<p><strong>Findings:</strong> {len(records)}</p>")
    if usage is not None:
        cost_note = (
            f", est. cost ${usage.total_cost_usd:.4f}" if usage.total_cost_usd is not None else ""
        )
        parts.append(
            f"<p><strong>LLM Usage:</strong> {usage.total_requests} requests, "
            f"{usage.total_input_tokens:,} input / {usage.total_output_tokens:,} output "
            f"tokens{cost_note}</p>"
        )
        if not usage.accounting_complete:
            parts.append(
                '<p class="warning">Warning: a usage-accounting write failed during '
                "this run - the totals above may be an undercount.</p>"
            )

    if summary is not None:
        parts.append("<h2>Executive Summary</h2>")
        if summary.by_severity:
            parts.append(_stat_chips(summary.by_severity))
        category_line = (
            ", ".join(f"{_e(cls)}: {count}" for cls, count in summary.by_vuln_class.items())
            or "(none)"
        )
        parts.append(f"<p><strong>By category:</strong> {category_line}</p>")
        if summary.highest_severity:
            parts.append(
                f"<p><strong>Highest severity:</strong> {_e(summary.highest_severity.upper())}</p>"
            )
        if summary.by_confidence:
            conf_line = ", ".join(
                f"{_e(band)}: {count}" for band, count in summary.by_confidence.items() if count
            )
            if conf_line:
                parts.append(f"<p><strong>By confidence:</strong> {conf_line}</p>")
        if summary.critical_findings:
            parts.append("<p><strong>Critical Findings:</strong></p><ul>")
            for title in summary.critical_findings:
                parts.append(f"<li>{_e(title)}</li>")
            parts.append("</ul>")
        if metadata is not None:
            parts.append(f"<p><strong>Model / Provider:</strong> {_e(metadata.model_provider)}</p>")
            parts.append("<p><strong>Target / Scope:</strong></p>")
            parts.append(f"<pre>{_e(metadata.engagement_scope)}</pre>")

        parts.append("<h2>Summary by Vulnerability Type</h2>")
        if not summary.by_vuln_class:
            parts.append("<p>(none)</p>")
        else:
            anchor_by_class = first_finding_id_by_vuln_class(records)
            parts.append("<ul>")
            for cls, count in summary.by_vuln_class.items():
                anchor = anchor_by_class.get(cls)
                label = f"{_e(cls)} ({count})"
                if anchor:
                    parts.append(f'<li><a href="#{_e(anchor)}">{label}</a></li>')
                else:
                    parts.append(f"<li>{label}</li>")
            parts.append("</ul>")

    parts.append("<h2>Coverage</h2>")
    parts.append(
        f"<p><strong>Assessed:</strong> {_e(', '.join(coverage.assessed) or '(none)')}</p>"
    )
    parts.append(
        f"<p><strong>Not assessed:</strong> {_e(', '.join(coverage.not_assessed) or '(none)')}</p>"
    )
    if coverage.verified_safe:
        parts.append(
            f"<p><strong>Assessed, confirmed clean:</strong> "
            f"{_e(', '.join(coverage.verified_safe))}</p>"
        )
        parts.append("<ul>")
        for cls in coverage.verified_safe:
            parts.append(f"<li><em>{_e(cls)}</em>: {_e(coverage.safe_reasons[cls])}</li>")
        parts.append("</ul>")
    parts.append(
        "<p><em>A class marked 'not assessed' means no finding was filed for it - this "
        "does not distinguish 'tested and found clean' from 'never examined'.</em></p>"
    )

    if attack_surface is not None and (
        attack_surface.endpoints or attack_surface.services or attack_surface.fingerprints
    ):
        parts.append("<h2>Attack Surface</h2>")
        parts.append(
            "<p><em>Recon facts captured during the run, independent of whether "
            "they produced a finding.</em></p>"
        )
        for label, items in (
            ("Endpoints", attack_surface.endpoints),
            ("Services", attack_surface.services),
            ("Fingerprints", attack_surface.fingerprints),
        ):
            if items:
                parts.append(f"<p><strong>{label}:</strong></p><ul>")
                parts += [f"<li>{_e(item)}</li>" for item in items]
                parts.append("</ul>")

    if chains:
        parts.append("<h2>Attack Chains</h2>")
        parts.append(
            "<p><em>Each chain below was explicitly declared by the agent "
            "(record_finding's own enabled_by_finding_id), not inferred.</em></p>"
        )
        # No Mermaid diagram here (unlike lalo.report.markdown's own
        # _render_chains_mermaid): this document loads no <script> tag at
        # all (see the module docstring - every dynamic value is escaped,
        # never executed), so a Mermaid renderer is never present in this
        # rendering context. A `<pre class="mermaid">` block with no library
        # to interpret it would render as inert, confusing plain text -
        # worse than the plain list below, not better - so this stays
        # HTML/CSS only, same as :mod:`lalo.report.pdf`/:mod:`lalo.report.docx`,
        # which both convert FROM this exact HTML.
        parts.append("<ul>")
        parts += [f"<li>{' → '.join(_e(title) for title in chain.titles)}</li>" for chain in chains]
        parts.append("</ul>")

    if records:
        parts.append("<h2>Findings Overview</h2>")
        parts.append(
            '<table class="overview-table"><tr><th>ID</th><th>Title</th><th>Class</th>'
            "<th>Severity</th><th>Confidence</th></tr>"
        )
        for record in records:
            try:
                confidence_cell = str(record.confidence.score)
                if (
                    record.review_adjusted_score is not None
                    and record.review_adjusted_score != record.confidence.score
                ):
                    confidence_cell = f"{record.confidence.score} → {record.review_adjusted_score}"
                parts.append(
                    f'<tr><td><a href="#{_e(record.finding_id)}">{_e(record.finding_id)}</a></td>'
                    f"<td>{_e(record.title)}</td><td>{_e(record.vuln_class)}</td>"
                    f"<td>{_e(record.effective_severity.upper())}</td>"
                    f"<td>{_e(confidence_cell)}</td></tr>"
                )
            except Exception:  # noqa: BLE001 - a malformed finding must not blank the table
                parts.append(
                    f"<tr><td>{_e(record.finding_id)}</td><td>(failed to render)</td></tr>"
                )
        parts.append("</table>")

    parts.append("<h2>Findings</h2>")
    if not records:
        parts.append("<p>No findings recorded.</p>")
    else:
        for label, group in group_by_verdict(records):
            parts.append(f"<h3>Verdict: {_e(label)} ({len(group)})</h3>")
            if not group:
                parts.append("<p><em>None.</em></p>")
                continue
            for record in group:
                try:
                    parts.append(render_finding_html(record))
                except Exception as exc:  # noqa: BLE001 - malformed finding must not blank the report
                    parts.append(
                        f"<h2>{_e(record.finding_id)}</h2>"
                        f"<p>Failed to render this finding: {_e(exc)}</p>"
                    )

    parts.append("</body></html>")
    return "\n".join(parts)
