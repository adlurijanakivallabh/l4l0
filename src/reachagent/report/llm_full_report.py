"""LLM-authored full report — the LLM writes the ENTIRE report (v2 W13).

Unlike ``generate_narrative`` (the LLM writes only the executive-summary prose over
a fixed template, in ``report/llm_report.py``), this hands the LLM full creative
authority over structure, the executive summary, per-finding narrative (description,
risk, affected system, remediation), and prioritization/ordering — a genuinely
LLM-authored report, not slot-filling.

**The one hard boundary (CLAUDE.md's non-negotiable, unchanged): the LLM cannot
invent a CONFIRMED finding.** The confirmed-findings list and their evidence are
built from ``run_oracle`` results (via ``build_evidence_index``) *before* this
module is ever called and handed to the LLM as immutable ground truth. A
defense-in-depth check after generation confirms every one of those finding_ids
appears verbatim in the LLM's output — if even one is missing, the report is
silently discarded in favor of the existing deterministic template
(``report/professional.py::render_professional_report_markdown``), never partially
trusted. This check is belt-and-braces on the *presentation*, not the safety
boundary itself: the LLM has no mechanism to write a ``Finding`` either way — it
never calls ``run_oracle``/``write_finding`` from anywhere in this module.
"""

from __future__ import annotations

import json
import logging
from typing import Protocol

from reachagent.graph.store import ReachabilityGraph
from reachagent.llm.client import (
    OpenAICompatibleClient,
    build_openai_compatible_client,
    is_model_output_error,
)
from reachagent.report.professional import methodology_markdown
from reachagent.report.renderer import build_evidence_index, sanitize_report_markdown

_log = logging.getLogger(__name__)

_MAX_REPORT_CHARS = 40_000
_MAX_CONTEXT_CHARS = 12_000

_FULL_REPORT_PROMPT = """You are writing a complete, professional penetration-testing \
report in Markdown. You have FULL creative authority over structure, tone, the \
executive summary, per-finding narrative (description, risk, affected system, \
remediation), and prioritization/ordering. Write it as a senior human pentester \
would for a client, not as a restatement of raw evidence fields.

WRITING STYLE (this is what separates a real analyst report from a data dump - \
follow it for every finding):
  * Never open a finding's description with "A [vuln class] violation was confirmed" \
or any other templated restatement of its own type - state the ROOT CAUSE instead \
(what specifically is missing or wrong, in the actual request/response terms given).
  * Describe what an attacker could concretely DO with it - the specific data or \
action reachable - never a vague "could allow unauthorized access."
  * Name the actual affected functionality/endpoint from the evidence given - never \
a generic placeholder like "sensitive data" or "the system."
  * Remediation must name the specific fix (the check, function, or control to add), \
not a generic OWASP-cheatsheet line.
  * Vary sentence structure and opening phrasing across findings - never repeat the \
same first sentence template for every finding.
  * The executive summary states overall risk posture and worst-case business impact \
in plain language for a non-technical stakeholder - not a bare finding-count table \
(the report card table below covers counts already).

HARD RULE (non-negotiable): the "Confirmed findings" list below is the exhaustive, \
authoritative, ALREADY-CONFIRMED set - the agent's own judgment already confirmed \
every one of them before you ever saw this data. You must:
  * include EVERY confirmed finding listed below, referenced by its exact finding_id \
string, somewhere in your report
  * NEVER invent an additional confirmed finding beyond this list
  * base every description/impact claim ONLY on the evidence fields actually given \
below (evidence_ref, oracle_used, metadata, vuln_class) - never invent a request/ \
response detail, parameter name, or file path that is not present in that data
  * do NOT write your own "Methodology" section - a factual one describing scope, \
approach, and proof standard is appended automatically after your report

Confirmed findings (JSON, ground truth): {confirmed_json}

Target: {target}
Testing objective: {objective}

Respond with ONLY the markdown report text - no preamble, no code fences."""


class FullReportClient(Protocol):
    """Thin swappable LLM client boundary — just needs free-text completion."""

    def complete(self, prompt: str, *, max_tokens: int = 512) -> str: ...


def generate_llm_authored_report(
    graph: ReachabilityGraph,
    audit: object | None = None,
    *,
    client: FullReportClient | None = None,
    operator_prompt: str | None = None,
    target: str = "",
) -> str | None:
    """Ask the LLM to author the COMPLETE report.

    Returns the markdown on success, or ``None`` if the LLM is unavailable, errors,
    or its output fails the confirmed-finding-coverage check — callers must fall
    back to ``render_professional_report_markdown`` on ``None`` rather than
    partially trust a report that might be missing a real finding.
    """
    index = build_evidence_index(graph, audit)
    all_findings = index["findings"]
    confirmed = [f for f in all_findings if str(f["severity"]).lower() != "informational"]
    confirmed_ids = {str(f["finding_id"]) for f in confirmed}

    try:
        tuner: FullReportClient | OpenAICompatibleClient | None = client
        if tuner is None:
            compatible = build_openai_compatible_client()
            if compatible is None:
                raise RuntimeError("no LLM provider configured for report generation")
            tuner = compatible
        prompt = _FULL_REPORT_PROMPT.format(
            confirmed_json=json.dumps(confirmed, indent=2, default=str)[:_MAX_CONTEXT_CHARS],
            target=target or "(not specified)",
            objective=(operator_prompt or "(none given)")[:500],
        )
        raw = tuner.complete(prompt, max_tokens=4000)
    except Exception as exc:  # noqa: BLE001 — the LLM must never crash reporting
        from reachagent.llm.runtime import llm_required

        if llm_required() and not is_model_output_error(exc):
            raise
        _log.warning("LLM full-authority report failed (%s); caller should fall back", exc)
        return None

    report = sanitize_report_markdown(raw.strip()[:_MAX_REPORT_CHARS])
    if not report:
        _log.warning("LLM full-authority report was empty; caller should fall back")
        return None
    missing = [fid for fid in confirmed_ids if fid not in report]
    if missing:
        _log.warning(
            "LLM full-authority report omitted %d confirmed finding(s) (%s...); "
            "discarding in favor of the deterministic template",
            len(missing),
            missing[:5],
        )
        return None
    # Methodology is appended verbatim, never left to the LLM to describe — the
    # same "deterministic ground truth the LLM cannot override" discipline as the
    # confirmed-findings list above, so a Methodology section can never drift from
    # what the scan actually did or be silently omitted by the model. Re-sanitized
    # as a whole for the same reason the template path sanitizes its full output.
    return sanitize_report_markdown(report + "\n" + methodology_markdown(graph, target=target))
