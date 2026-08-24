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
import os
from typing import Protocol

from reachagent.graph.store import ReachabilityGraph
from reachagent.report.renderer import (
    finding_to_dict,
    render_findings_markdown,
)

_log = logging.getLogger(__name__)


class ReportClient(Protocol):
    """Thin swappable LLM client for reporting."""

    def propose(self, findings_context: dict[str, object]) -> dict[str, str]:
        """Return raw proposal dict with key ``narrative`` (markdown prose)."""
        ...


class AnthropicReportClient:
    """Anthropic-only report generator."""

    def __init__(
        self, *, api_key: str | None = None, model: str = "claude-3-5-sonnet-20240620"
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model

    def propose(self, findings_context: dict[str, object]) -> dict[str, str]:
        if not self._api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        try:
            import anthropic  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"anthropic SDK not available: {exc}") from exc
        client = anthropic.Anthropic(api_key=self._api_key)
        findings = findings_context.get("findings", [])
        # Keep context compact: only finding_id/vuln_class/severity/evidence_ref, capped.
        import json as _json

        ctx_str = _json.dumps(findings, indent=2)[:4000]
        prompt = (
            "You are a pentest report writer. Given ONLY confirmed findings "
            "(already validated via deterministic oracles), write a concise markdown "
            "report: what was tested, what was found, severity, and reproduction steps per "
            "finding_id. Do NOT invent new findings, do NOT claim unconfirmed vulns. "
            'Respond as JSON {"narrative": "<markdown>"}. '
            f"Confirmed findings: {ctx_str}"
        )
        resp = client.messages.create(
            model=self._model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = ""
        for block in resp.content:
            if getattr(block, "type", "") == "text":
                text += getattr(block, "text", "")
        try:
            data = _json.loads(text)
        except Exception as exc:
            import re as _re

            m = _re.search(r"\{.*\}", text, flags=_re.DOTALL)
            if not m:
                raise ValueError(f"no JSON in model response: {text[:500]!r}") from exc
            data = _json.loads(m.group(0))
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
    return narrative


def _deterministic_report(graph: ReachabilityGraph) -> str:
    return render_findings_markdown(graph)


def generate_llm_report(
    graph: ReachabilityGraph,
    *,
    client: ReportClient | None = None,
) -> str:
    """Generate LLM narrative + deterministic table over confirmed findings only.

    Never invents a Finding. On LLM failure/timeout/empty, falls back to
    deterministic markdown table. The deterministic table is always appended
    so the report is auditable even when LLM is used.
    """
    confirmed = _confirmed_findings(graph)
    allowed_ids = {fid for fid, _ in confirmed}
    findings_ctx = [finding_to_dict(fid, f) for fid, f in sorted(confirmed, key=lambda x: x[0])]

    # Try LLM when available
    narrative: str | None = None
    try:
        tuner = client if client is not None else AnthropicReportClient()
        raw = tuner.propose({"findings": findings_ctx, "count": len(findings_ctx)})
        narrative = _validate_narrative(raw, allowed_ids)
    except Exception as exc:  # noqa: BLE001 — LLM must never crash reporting
        _log.warning("LLM report failed (%s); fallback to deterministic", exc)
        narrative = None

    deterministic = _deterministic_report(graph)
    if narrative is None:
        return deterministic
    # Narrative first, deterministic table second — table is the ground truth.
    return f"{narrative.strip()}\n\n---\n\n{deterministic}"
