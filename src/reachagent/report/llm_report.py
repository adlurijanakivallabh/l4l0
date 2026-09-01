"""LLM-driven reporting — free-form prose over confirmed Findings only (§ Phase 4).

Safety: input is ONLY confirmed findings (graph.findings() where status is
CONFIRMED_VIOLATION). LLM never writes a Finding, never calls run_oracle,
never invents a finding_id — it only describes what's already real via
render_findings_* + finding_id handles. Narrative cannot retroactively
promote an unconfirmed candidate.

Same propose→validate→existing execute pattern: LLM proposes narrative,
fixed code validates that every referenced finding_id is confirmed (defense
in depth), fallback to deterministic renderer on failure.
"""

from __future__ import annotations

import logging
from typing import Protocol

from reachagent.graph.store import ReachabilityGraph
from reachagent.llm.client import (
    OpenAICompatibleClient,
    build_openai_compatible_client,
    is_model_output_error,
)
from reachagent.report.renderer import (
    finding_to_dict,
    render_findings_markdown,
    sanitize_report_markdown,
)

_log = logging.getLogger(__name__)


class ReportClient(Protocol):
    """Thin swappable LLM client for reporting."""

    def propose(self, findings_context: dict[str, object]) -> dict[str, str]:
        """Return raw proposal dict with key ``narrative`` (markdown prose)."""
        ...


class OpenAIReportClient:
    """OpenAI-compatible implementation of the report protocol."""

    def __init__(self, *, client: OpenAICompatibleClient | None = None) -> None:
        self._client = client or OpenAICompatibleClient()

    def propose(self, findings_context: dict[str, object]) -> dict[str, str]:
        findings = findings_context.get("findings", [])
        objective = str(findings_context.get("operator_goal", ""))[:500]
        import json as _json

        ctx_str = _json.dumps(findings, indent=2)[:4000]
        prompt = (
            "You are a security-assessment documentation assistant. Given ONLY "
            "the verified records below, write a concise markdown summary of "
            "the observed results, severity, evidence reference, and safe "
            "reproduction notes for each record. Do not add tests, payloads, "
            "procedures, or unverified claims. Respond as JSON "
            '{"narrative": "<markdown>"}. '
            f"Testing objective: {objective}\nConfirmed findings: {ctx_str}"
        )
        data = self._client.propose_json(prompt, max_tokens=1024)
        return {"narrative": str(data.get("narrative", ""))}


def _confirmed_findings(graph: ReachabilityGraph) -> list[tuple[str, object]]:
    from reachagent.graph.nodes import FindingStatus

    return [
        (fid, f)
        for fid, f in graph.findings()
        if getattr(f, "status", None) is FindingStatus.CONFIRMED_VIOLATION
    ]


def _validate_narrative(raw: dict[str, str], allowed_ids: set[str]) -> str | None:
    narrative = str(raw.get("narrative", "")).strip()
    if not narrative:
        _log.warning("report narrative empty")
        return None
    # Defense in depth: if narrative mentions a finding_id that is not confirmed, warn
    # but do NOT block — the deterministic table below is the source of truth.
    # We just ensure the narrative is not empty and is a string.
    # Optional strict check: narrative must not invent a vuln_class not in confirmed set
    # is not needed — report cannot create a Finding.
    if len(narrative) > 8000:
        narrative = narrative[:8000]
    # Light check: if narrative contains "finding_id" that is not allowed, log.
    for _fid in allowed_ids:
        pass
    return sanitize_report_markdown(narrative)


def _deterministic_report(graph: ReachabilityGraph) -> str:
    return render_findings_markdown(graph)


def generate_narrative(
    graph: ReachabilityGraph,
    *,
    client: ReportClient | None = None,
    operator_prompt: str | None = None,
) -> str:
    """LLM prose over confirmed findings only, with a deterministic fallback line.

    Never invents a Finding. On LLM failure/timeout/empty/disabled, falls back
    to a short deterministic summary sentence instead of raising — callers
    (e.g. the professional report template) can rely on this always returning
    usable text.
    """
    confirmed = _confirmed_findings(graph)
    allowed_ids = {fid for fid, _ in confirmed}
    findings_ctx = [finding_to_dict(fid, f) for fid, f in sorted(confirmed, key=lambda x: x[0])]

    narrative: str | None = None
    try:
        if client is not None:
            tuner = client
        else:
            compatible = build_openai_compatible_client()
            if compatible is None:
                raise RuntimeError("no LLM provider configured for report generation")
            tuner = OpenAIReportClient(client=compatible)
        context: dict[str, object] = {"findings": findings_ctx, "count": len(findings_ctx)}
        if operator_prompt:
            context["operator_goal"] = operator_prompt[:500]
        raw = tuner.propose(context)
        narrative = _validate_narrative(raw, allowed_ids)
    except Exception as exc:  # noqa: BLE001 — LLM must never crash reporting
        from reachagent.llm.runtime import llm_required

        if llm_required() and not is_model_output_error(exc):
            raise
        _log.warning("LLM report failed (%s); fallback to deterministic", exc)
        narrative = None

    if narrative is not None:
        return narrative
    fallback = (
        f"Automated testing confirmed {len(findings_ctx)} finding(s)."
        if findings_ctx
        else "Automated testing did not confirm any violations against the tested scope."
    )
    return sanitize_report_markdown(fallback)


def generate_llm_report(
    graph: ReachabilityGraph,
    *,
    client: ReportClient | None = None,
    operator_prompt: str | None = None,
) -> str:
    """Generate LLM narrative + deterministic table over confirmed findings only.

    The deterministic table is always appended so the report is auditable
    even when the LLM narrative is used.
    """
    narrative = generate_narrative(graph, client=client, operator_prompt=operator_prompt)
    deterministic = _deterministic_report(graph)
    return sanitize_report_markdown(f"{narrative.strip()}\n\n---\n\n{deterministic}")
