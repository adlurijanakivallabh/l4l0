"""Deterministic Finding renderers — read-only over ReachabilityGraph (plan §2, §14).

No oracle, no firer, no write. The graph is the system of record; rendering
turns Finding nodes into human/auditable output without ever constructing a
Finding or mutating the graph.
"""

from __future__ import annotations

import html as _html
import json
from typing import Any

from reachagent.graph.store import ReachabilityGraph


def finding_to_dict(finding_id: str, finding: object) -> dict[str, Any]:
    """Single Finding → sorted dict (deterministic, provenance-complete)."""
    f: Any = finding
    meta = getattr(f, "metadata", {}) or {}
    return {
        "finding_id": finding_id,
        "vuln_class": getattr(f, "vuln_class", ""),
        "severity": getattr(f, "severity", ""),
        "oracle_used": getattr(f, "oracle_used", ""),
        "evidence_ref": getattr(f, "evidence_ref", ""),
        "status": getattr(getattr(f, "status", ""), "value", str(getattr(f, "status", ""))),
        "metadata": dict(sorted(meta.items())) if isinstance(meta, dict) else {},
    }


def _sorted_findings(graph: ReachabilityGraph) -> list[tuple[str, Any]]:
    return sorted(
        graph.findings(),
        key=lambda x: (
            getattr(x[1], "vuln_class", ""),
            getattr(x[1], "evidence_ref", ""),
            x[0],
        ),
    )


def render_findings_json(graph: ReachabilityGraph) -> str:
    """Deterministic JSON list of Findings, sorted, keys sorted."""
    rows = [finding_to_dict(fid, f) for fid, f in _sorted_findings(graph)]
    return json.dumps(rows, sort_keys=True, indent=2) + "\n"


def render_findings_markdown(graph: ReachabilityGraph) -> str:
    """Deterministic Markdown table of Findings, sorted."""
    rows = _sorted_findings(graph)
    if not rows:
        return "No findings.\n"
    header = "| finding_id | vuln_class | severity | oracle_used | evidence_ref | status |\n"
    sep = "|---|---|---|---|---|---|\n"
    lines = [header, sep]
    for fid, f in rows:
        d = finding_to_dict(fid, f)

        # Escape pipe in values so table stays valid.
        def esc(v: object) -> str:
            return str(v).replace("|", "\\|").replace("\n", " ")

        lines.append(
            f"| {esc(d['finding_id'])} | {esc(d['vuln_class'])} | {esc(d['severity'])} | "
            f"{esc(d['oracle_used'])} | {esc(d['evidence_ref'])} | {esc(d['status'])} |\n"
        )
        if d["metadata"]:
            meta_str = ", ".join(f"{k}={v}" for k, v in d["metadata"].items())
            lines.append(f"|  |  |  |  | _{esc(meta_str)}_ |  |\n")
    return "".join(lines)


def render_findings_html(graph: ReachabilityGraph) -> str:
    """Deterministic minimal HTML report of Findings, sorted."""
    rows = _sorted_findings(graph)
    esc = _html.escape
    title = "ReachAgent Findings"
    parts: list[str] = [
        f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title></head><body>\n",
        "<h1>Findings</h1>\n",
    ]
    if not rows:
        parts.append("<p>No findings.</p>\n")
    else:
        parts.append("<table border='1' cellpadding='4' cellspacing='0'>\n")
        parts.append(
            "<tr><th>finding_id</th><th>vuln_class</th><th>severity</th>"
            "<th>oracle_used</th><th>evidence_ref</th><th>status</th></tr>\n"
        )
        for fid, f in rows:
            d = finding_to_dict(fid, f)
            parts.append(
                f"<tr><td>{esc(str(d['finding_id']))}</td><td>{esc(str(d['vuln_class']))}</td>"
                f"<td>{esc(str(d['severity']))}</td><td>{esc(str(d['oracle_used']))}</td>"
                f"<td>{esc(str(d['evidence_ref']))}</td><td>{esc(str(d['status']))}</td></tr>\n"
            )
            if d["metadata"]:
                meta_pairs = ", ".join(f"{k}={esc(str(v))}" for k, v in d["metadata"].items())
                parts.append(f"<tr><td colspan='6'><em>{meta_pairs}</em></td></tr>\n")
        parts.append("</table>\n")
    parts.append("</body></html>\n")
    return "".join(parts)
