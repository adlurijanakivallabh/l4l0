"""Deterministic, redaction-safe report renderers.

The graph is the reporting source of truth. Rendering never calls an oracle,
fires a request, creates a finding, or treats model prose as evidence. The
JSON/Markdown/HTML/SARIF projections are independent of the GUI so exports and
persisted-run comparisons use the same rules.
"""

from __future__ import annotations

import hashlib
import html as _html
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from reachagent.graph.merge import extract_endpoint_path
from reachagent.graph.nodes import FindingStatus
from reachagent.graph.store import ReachabilityGraph

_MAX_TEXT = 8_000
_MAX_METADATA = 64
_MAX_AUDIT = 2_000
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:bearer\s+[A-Za-z0-9._~+/=-]+|(?:password|passwd|secret|token|"
    r"api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|cookie|"
    r"authorization)\s*[:=]\s*[\"']?(?:bearer\s+)?[^\s,;}\"']+)"
)
_SECRET_TOKEN = re.compile(
    r"(?i)\b(?:sk-[A-Za-z0-9_-]{12,}|rk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_-]{12,}|"
    r"AKIA[A-Z0-9]{12,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
)
_SECRET_URL = re.compile(r"(?i)\bhttps?://[^\s/@:]+:[^\s/@]+@")
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:password|passwd|secret|authorization|cookie|set-cookie|bearer|"
    r"api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|raw[_-]?body|"
    r"request[_-]?body|response[_-]?body)"
)
_HIDDEN_VALUE_KEYS = frozenset(
    {
        "body",
        "raw_body",
        "request_body",
        "response_body",
        "headers",
        "cookies",
        "payload",
        "request",
        "response",
    }
)
_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}
_SEVERITY_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
    "informational": "1.0",
}
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _safe_text(value: object, maximum: int = _MAX_TEXT) -> str:
    text = str(value).replace("\x00", "").replace("\r", " ").replace("\n", " ")
    text = _SECRET_ASSIGNMENT.sub("<redacted>", text)
    text = _SECRET_TOKEN.sub("<redacted>", text)
    text = _SECRET_URL.sub("https://<redacted>@", text)
    return text[:maximum]


def sanitize_report_markdown(value: object, *, maximum: int = 100_000) -> str:
    """Remove credential-shaped values from model prose before storage/export."""
    text = str(value).replace("\x00", "")[:maximum]
    text = _SECRET_ASSIGNMENT.sub("<redacted>", text)
    text = _SECRET_TOKEN.sub("<redacted>", text)
    text = _SECRET_URL.sub("https://<redacted>@", text)
    return text


def _safe_value(value: object, *, key: str = "", depth: int = 0) -> object:
    if depth > 4:
        return "<truncated>"
    lowered = key.lower().replace("-", "_")
    if lowered in _HIDDEN_VALUE_KEYS:
        return "<redacted>"
    if _SENSITIVE_KEY.search(lowered) and not lowered.endswith(("_ref", "_id")):
        return "<redacted>"
    if isinstance(value, Mapping):
        return {
            _safe_text(raw_key, 128): _safe_value(raw_value, key=str(raw_key), depth=depth + 1)
            for raw_key, raw_value in list(value.items())[:_MAX_METADATA]
        }
    if isinstance(value, (list, tuple)):
        return [_safe_value(item, key=key, depth=depth + 1) for item in list(value)[:_MAX_METADATA]]
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _safe_text(value)


def _safe_metadata(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    result = _safe_value(value, key="metadata")
    return result if isinstance(result, dict) else {}


def evidence_snippet(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """The real proof behind a finding — a bounded, already-secret-scrubbed body
    projection (and any decisive response headers) an oracle captured at decision
    time (v2 Phase 6 Stage E1), for the GUI's finding cards and the markdown/HTML
    report alike. ``write_finding`` already stores this as a JSON blob under
    ``metadata["evidence_metadata"]`` (``EvidenceMetadata.as_json()``) whenever an
    oracle populated one — this only reads it back for display, no new capture.
    """
    raw = metadata.get("evidence_metadata")
    if not isinstance(raw, str) or not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    snippet: dict[str, Any] = {}
    for key in ("body_projection", "baseline_body_projection", "probe_body_projection"):
        value = parsed.get(key)
        if isinstance(value, str) and value:
            snippet[key] = _safe_text(value, 2048)
    headers = parsed.get("headers")
    if isinstance(headers, list):
        snippet["headers"] = [
            [_safe_text(str(pair[0]), 80), _safe_text(str(pair[1]), 300)]
            for pair in headers
            if isinstance(pair, (list, tuple)) and len(pair) == 2
        ][:20]
    return snippet


def finding_to_dict(finding_id: str, finding: object) -> dict[str, Any]:
    """Project one stored finding without mutating it or exposing secrets."""
    f: Any = finding
    status = getattr(f, "status", "")
    status_value = getattr(status, "value", str(status))
    return {
        "finding_id": _safe_text(finding_id, 256),
        "vuln_class": _safe_text(getattr(f, "vuln_class", ""), 128),
        "severity": _safe_text(getattr(f, "severity", ""), 32),
        "oracle_used": _safe_text(getattr(f, "oracle_used", ""), 128),
        "evidence_ref": _safe_text(getattr(f, "evidence_ref", ""), 256),
        "status": _safe_text(status_value, 64),
        "metadata": _safe_metadata(getattr(f, "metadata", {})),
    }


def _sorted_findings(graph: ReachabilityGraph) -> list[tuple[str, Any]]:
    """Return only committed confirmations in stable order."""
    rows = [
        (fid, finding)
        for fid, finding in graph.findings()
        if getattr(finding, "status", None) is FindingStatus.CONFIRMED_VIOLATION
    ]
    return sorted(
        rows,
        key=lambda item: (
            str(getattr(item[1], "vuln_class", "")),
            str(getattr(item[1], "evidence_ref", "")),
            item[0],
        ),
    )


def render_findings_json(graph: ReachabilityGraph) -> str:
    """Deterministic JSON list retained for backwards compatibility."""
    rows = [finding_to_dict(fid, finding) for fid, finding in _sorted_findings(graph)]
    return json.dumps(rows, sort_keys=True, indent=2) + "\n"


def render_findings_markdown(graph: ReachabilityGraph) -> str:
    """Deterministic Markdown table of confirmed findings."""
    rows = _sorted_findings(graph)
    if not rows:
        return "No findings.\n"
    header = "| finding_id | vuln_class | severity | oracle_used | evidence_ref | status |\n"
    sep = "|---|---|---|---|---|---|\n"
    lines = [header, sep]
    for fid, finding in rows:
        record = finding_to_dict(fid, finding)

        def esc(value: object) -> str:
            return _safe_text(value, 2_000).replace("|", "\\|")

        lines.append(
            f"| {esc(record['finding_id'])} | {esc(record['vuln_class'])} | "
            f"{esc(record['severity'])} | {esc(record['oracle_used'])} | "
            f"{esc(record['evidence_ref'])} | {esc(record['status'])} |\n"
        )
        metadata = record["metadata"]
        if metadata:
            meta_str = ", ".join(f"{key}={value}" for key, value in sorted(metadata.items()))
            lines.append(f"|  |  |  |  | _{esc(meta_str)}_ |  |\n")
    return "".join(lines)


def render_findings_html(graph: ReachabilityGraph) -> str:
    """Deterministic minimal HTML table of confirmed findings."""
    rows = _sorted_findings(graph)
    esc = _html.escape
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>ReachAgent Findings</title></head><body>\n<h1>Findings</h1>\n"
    ]
    if not rows:
        parts.append("<p>No findings.</p>\n")
    else:
        parts.append(
            "<table border='1' cellpadding='4' cellspacing='0'>\n<tr>"
            "<th>finding_id</th><th>vuln_class</th><th>severity</th>"
            "<th>oracle_used</th><th>evidence_ref</th><th>status</th></tr>\n"
        )
        for fid, finding in rows:
            record = finding_to_dict(fid, finding)
            parts.append(
                "<tr>"
                f"<td>{esc(str(record['finding_id']))}</td>"
                f"<td>{esc(str(record['vuln_class']))}</td>"
                f"<td>{esc(str(record['severity']))}</td>"
                f"<td>{esc(str(record['oracle_used']))}</td>"
                f"<td>{esc(str(record['evidence_ref']))}</td>"
                f"<td>{esc(str(record['status']))}</td></tr>\n"
            )
            metadata = record["metadata"]
            if metadata:
                details = ", ".join(
                    f"{esc(str(key))}={esc(str(value))}" for key, value in sorted(metadata.items())
                )
                parts.append(f"<tr><td colspan='6'><em>{details}</em></td></tr>\n")
        parts.append("</table>\n")
    parts.append("</body></html>\n")
    return "".join(parts)


def _graph_counts(graph: ReachabilityGraph) -> dict[str, int]:
    return {
        "hosts": len(graph.hosts()),
        "services": len(graph.services()),
        "endpoints": len(graph.endpoints()),
        "parameters": sum(len(graph.parameters_of(endpoint)) for endpoint, _ in graph.endpoints()),
        "findings": len(_sorted_findings(graph)),
        "sessions": len(graph.sessions()),
    }


def _chain_label(node: str) -> str:
    if node.startswith("finding:"):
        parts = node.split(":", 2)
        return _safe_text(parts[1] if len(parts) > 1 else node, 128)
    if node.startswith("session:"):
        return "session"
    if node.startswith("identity:"):
        return _safe_text(node.split(":", 1)[-1], 128)
    return _safe_text(node, 128)


def _chain_records(graph: ReachabilityGraph, finding_id: str) -> list[dict[str, Any]]:
    derived = set(graph.derived_credential_edges())
    records: list[dict[str, Any]] = []
    for path in graph.chain_paths(finding_id):
        kinds: list[str] = []
        for index in range(len(path) - 1):
            kinds.append(
                "derived_credential" if (path[index], path[index + 1]) in derived else "enables"
            )
        records.append({"nodes": [_chain_label(node) for node in path], "kinds": kinds})
    return records


def _audit_records(audit: object | None) -> list[dict[str, str]]:
    entries = getattr(audit, "entries", ()) if audit is not None else ()
    rows: list[dict[str, str]] = []
    for entry in list(entries)[-_MAX_AUDIT:]:
        rows.append(
            {
                "timestamp": _safe_text(getattr(entry, "timestamp", ""), 64),
                "identity": _safe_text(getattr(entry, "identity", ""), 128),
                "method": _safe_text(getattr(entry, "method", ""), 32),
                "target": _safe_text(getattr(entry, "target", ""), 512),
                "outcome": _safe_text(getattr(entry, "outcome", ""), 512),
            }
        )
    return rows


_PROVENANCE_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("scope", ("scope", "in_scope", "scope_ref")),
    ("identity", ("identity", "identity_ref", "principal")),
    ("tool", ("tool", "tool_name", "adapter")),
    ("payload_ref", ("payload_ref", "payload_id")),
    ("oracle", ("oracle", "oracle_used")),
    ("evidence", ("evidence", "evidence_ref")),
    ("timing", ("timing", "timing_ms", "latency_ms", "duration_ms")),
    ("chain_precondition", ("chain_precondition",)),
    ("target", ("target", "url")),
    ("endpoint", ("endpoint", "path")),
    ("method", ("method",)),
)


def _provenance(record: dict[str, Any], context: Mapping[str, object] | None) -> dict[str, object]:
    metadata = record.get("metadata", {})
    if not isinstance(metadata, Mapping):
        metadata = {}
    source: dict[str, object] = {str(key): value for key, value in metadata.items()}
    if context:
        source.update(
            {str(key): _safe_value(value, key=str(key)) for key, value in context.items()}
        )
    source.setdefault("oracle", record.get("oracle_used", ""))
    source.setdefault("evidence", record.get("evidence_ref", ""))
    result: dict[str, object] = {}
    for canonical, aliases in _PROVENANCE_FIELDS:
        for alias in aliases:
            if alias in source and source[alias] not in (None, ""):
                result[canonical] = _safe_value(source[alias], key=canonical)
                break
    return result


def _finding_record(
    graph: ReachabilityGraph,
    finding_id: str,
    finding: object,
    *,
    audit_rows: list[dict[str, str]],
    context: Mapping[str, object] | None,
) -> dict[str, Any]:
    record = finding_to_dict(finding_id, finding)
    record["provenance"] = _provenance(record, context)
    handles: dict[str, str] = {"evidence_ref": record["evidence_ref"]}
    metadata = record.get("metadata", {})
    if isinstance(metadata, Mapping):
        for key, value in metadata.items():
            if str(key).endswith(("_ref", "_id")) and isinstance(value, str) and value:
                handles[str(key)] = value
            if key == "evidence_metadata" and isinstance(value, str):
                try:
                    nested = json.loads(value)
                except (TypeError, ValueError):
                    nested = {}
                if isinstance(nested, Mapping):
                    for nested_key, nested_value in nested.items():
                        if (
                            str(nested_key).endswith(("_ref", "_id"))
                            and isinstance(nested_value, str)
                            and nested_value
                        ):
                            handles[str(nested_key)] = _safe_text(nested_value, 256)
    record["evidence_handles"] = dict(sorted(handles.items()))
    record["chains"] = _chain_records(graph, finding_id)
    # `outcome` is a short status label ("fired:200"), never evidence_ref, so
    # the old `ref in row["outcome"]` join matched nothing for a real fired
    # request -- match by endpoint path (AuditEntry.target) first, falling
    # back to the outcome check for record_oracle_result()'s ref-embedding.
    ref = str(record["evidence_ref"])
    path = extract_endpoint_path(ref, str(record.get("vuln_class", "")))
    by_path = [row for row in audit_rows if path and path in row["target"]]
    by_outcome = [row for row in audit_rows if ref and ref in row["outcome"]]
    record["audit"] = (by_path or by_outcome)[:20]
    timing = {
        str(key): value
        for key, value in (metadata.items() if isinstance(metadata, Mapping) else ())
        if "tim" in str(key).lower() or "latency" in str(key).lower()
    }
    if timing:
        record["timing"] = timing
    return record


def build_evidence_index(
    graph: ReachabilityGraph,
    audit: object | None = None,
    *,
    context: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Build a bounded evidence index over confirmed findings and audit rows."""
    audit_rows = _audit_records(audit)
    records = [
        _finding_record(graph, finding_id, finding, audit_rows=audit_rows, context=context)
        for finding_id, finding in _sorted_findings(graph)
    ]
    severity: dict[str, int] = {}
    for record in records:
        key = str(record["severity"]).lower() or "unknown"
        severity[key] = severity.get(key, 0) + 1
    result: dict[str, Any] = {
        "schema_version": 1,
        "summary": {"counts": _graph_counts(graph), "severity": dict(sorted(severity.items()))},
        "findings": records,
    }
    if context:
        result["context"] = _safe_value(dict(context), key="context")
    return result


def render_evidence_index_json(
    graph: ReachabilityGraph,
    audit: object | None = None,
    *,
    context: Mapping[str, object] | None = None,
) -> str:
    return (
        json.dumps(build_evidence_index(graph, audit, context=context), sort_keys=True, indent=2)
        + "\n"
    )


def _anchor(value: object) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]
    return f"evidence-{digest}"


def render_evidence_index_markdown(
    graph: ReachabilityGraph,
    audit: object | None = None,
    *,
    context: Mapping[str, object] | None = None,
) -> str:
    index = build_evidence_index(graph, audit, context=context)
    summary = index["summary"]
    lines = ["# Evidence index\n", "\n", "## Summary\n", "\n"]
    lines.append(
        f"Confirmed findings: **{summary['counts']['findings']}**  \n"
        f"Hosts: **{summary['counts']['hosts']}** · "
        f"Endpoints: **{summary['counts']['endpoints']}**  \n"
    )
    lines.append("\n## Findings\n")
    findings = index["findings"]
    if not findings:
        return "".join(lines) + "\nNo confirmed findings.\n"
    for record in findings:
        finding_anchor = _anchor(record["finding_id"])
        lines.append(f'\n<a id="{finding_anchor}"></a>\n')
        lines.append(
            f"### {record['vuln_class']} — {record['severity']}\n\n"
            f"- Finding: `{_safe_text(record['finding_id'], 256)}`\n"
            f"- Oracle: `{_safe_text(record['oracle_used'], 128)}`\n"
            f"- Status: `{_safe_text(record['status'], 64)}`\n"
        )
        for key, value in record["evidence_handles"].items():
            handle_anchor = _anchor(f"{record['finding_id']}:{key}")
            lines.append(f'- {key}: <a id="{handle_anchor}"></a>`{_safe_text(value, 256)}`\n')
        provenance = record.get("provenance", {})
        if provenance:
            lines.append(
                "- Provenance: "
                + ", ".join(
                    f"{key}=`{_safe_text(value, 512)}`" for key, value in provenance.items()
                )
                + "\n"
            )
        if record.get("chains"):
            lines.append(
                "- Chain paths: "
                + "; ".join(" → ".join(path["nodes"]) for path in record["chains"])
                + "\n"
            )
        if record.get("audit"):
            lines.append(f"- Matching audit entries: **{len(record['audit'])}**\n")
    return "".join(lines)


def render_evidence_index_html(
    graph: ReachabilityGraph,
    audit: object | None = None,
    *,
    context: Mapping[str, object] | None = None,
) -> str:
    index = build_evidence_index(graph, audit, context=context)
    esc = _html.escape
    cards: list[str] = []
    for record in index["findings"]:
        anchor = _anchor(record["finding_id"])
        handle_rows = "".join(
            f"<tr><th>{esc(str(key))}</th>"
            f"<td id='{_anchor(str(record['finding_id']) + ':' + str(key))}'>"
            f"<code>{esc(str(value))}</code></td></tr>"
            for key, value in record["evidence_handles"].items()
        )
        provenance = record.get("provenance", {})
        provenance_rows = "".join(
            f"<tr><th>{esc(str(key))}</th><td>{esc(str(value))}</td></tr>"
            for key, value in provenance.items()
        )
        chains = "".join(
            f"<li>{esc(' → '.join(path['nodes']))}</li>" for path in record.get("chains", [])
        )
        cards.append(
            f"<article id='{anchor}'><h3>{esc(str(record['vuln_class']))}"
            f" <span class='severity'>{esc(str(record['severity']))}</span></h3>"
            f"<p><b>Finding:</b> <code>{esc(str(record['finding_id']))}</code> · "
            f"<b>Oracle:</b> <code>{esc(str(record['oracle_used']))}</code> · "
            f"<b>Status:</b> <code>{esc(str(record['status']))}</code></p>"
            f"<table>{handle_rows}{provenance_rows}</table>"
            f"{('<h4>Chain paths</h4><ul>' + chains + '</ul>') if chains else ''}"
            f"<p class='audit'>Matching audit entries: {len(record.get('audit', []))}</p></article>"
        )
    summary = index["summary"]["counts"]
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>ReachAgent evidence index</title>"
        "<style>body{font:14px system-ui;max-width:980px;margin:2rem auto;padding:0 1rem;"
        "color:#172033}article{border:1px solid #dfe6ef;border-radius:10px;padding:1rem;"
        "margin:1rem 0}table{border-collapse:collapse;width:100%}th,td{padding:.4rem;"
        "border-bottom:1px solid #eef2f7;text-align:left}th{width:11rem;color:#5f6f82}"
        ".severity{font-size:.7em;text-transform:uppercase;color:#5f6f82}.audit{color:#5f6f82}"
        "code{font-family:ui-monospace,monospace}</style></head><body>"
        f"<h1>Evidence index</h1><p>Confirmed findings: {summary['findings']} · "
        f"Hosts: {summary['hosts']} · Endpoints: {summary['endpoints']}</p>"
        + ("".join(cards) or "<p>No confirmed findings.</p>")
        + "</body></html>\n"
    )


def build_sarif_report(
    graph: ReachabilityGraph,
    *,
    context: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from confirmed findings only."""
    index = build_evidence_index(graph, context=context)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for record in index["findings"]:
        slug = re.sub(r"[^a-z0-9]+", "-", str(record["vuln_class"]).lower()).strip("-") or "finding"
        rule_id = f"reachagent/{slug}"
        severity = str(record["severity"]).lower()
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": _safe_text(record["vuln_class"], 128),
                "shortDescription": {"text": _safe_text(record["vuln_class"], 128)},
                "defaultConfiguration": {"level": _SEVERITY_LEVEL.get(severity, "note")},
                "properties": {
                    "security-severity": _SEVERITY_SCORE.get(severity, "1.0"),
                    "oracle": _safe_text(record["oracle_used"], 128),
                },
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY_LEVEL.get(severity, "note"),
            "message": {
                "text": _safe_text(
                    f"{record['vuln_class']} confirmed by {record['oracle_used']}", 1_000
                )
            },
            "properties": {
                "finding_id": record["finding_id"],
                "oracle": record["oracle_used"],
                "evidence_ref": record["evidence_ref"],
                "provenance": record.get("provenance", {}),
                "evidence_handles": record.get("evidence_handles", {}),
            },
        }
        provenance = record.get("provenance", {})
        if isinstance(provenance, Mapping):
            location = provenance.get("endpoint") or provenance.get("target")
            if location:
                result["locations"] = [
                    {"logicalLocations": [{"fullyQualifiedName": _safe_text(location, 512)}]}
                ]
        results.append(result)
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "ReachAgent",
                "version": "0.1.0",
                "rules": list(rules.values()),
            }
        },
        "results": results,
        "properties": {"confirmedFindingCount": len(results)},
    }
    return {"version": "2.1.0", "$schema": _SARIF_SCHEMA, "runs": [run]}


def render_findings_sarif(
    graph: ReachabilityGraph,
    *,
    context: Mapping[str, object] | None = None,
) -> str:
    return json.dumps(build_sarif_report(graph, context=context), sort_keys=True, indent=2) + "\n"


def render_report_html(
    report_markdown: object,
    graph: ReachabilityGraph,
    audit: object | None = None,
    *,
    context: Mapping[str, object] | None = None,
) -> str:
    """Self-contained report + evidence export with markdown safely escaped."""
    report = _html.escape(sanitize_report_markdown(report_markdown))
    evidence = render_evidence_index_html(graph, audit, context=context)
    evidence_body = evidence.split("<body>", 1)[-1].rsplit("</body>", 1)[0]
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>ReachAgent report</title>"
        "<style>body{font-family:system-ui;max-width:980px;margin:2rem auto;padding:0 1rem;"
        "line-height:1.55}pre{white-space:pre-wrap;border:1px solid #dfe6ef;padding:1rem;"
        "border-radius:8px;background:#f7f9fd}</style></head><body><h1>ReachAgent report</h1>"
        f"<pre>{report}</pre><hr>{evidence_body}</body></html>\n"
    )


def build_report_bundle(
    graph: ReachabilityGraph,
    audit: object | None = None,
    *,
    report_markdown: object = "",
    context: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Return one deterministic machine-readable report package."""
    return {
        "schema_version": 1,
        "report_markdown": sanitize_report_markdown(report_markdown),
        "evidence": build_evidence_index(graph, audit, context=context),
        "sarif": build_sarif_report(graph, context=context),
    }


def render_report_bundle_json(
    graph: ReachabilityGraph,
    audit: object | None = None,
    *,
    report_markdown: object = "",
    context: Mapping[str, object] | None = None,
) -> str:
    return (
        json.dumps(
            build_report_bundle(graph, audit, report_markdown=report_markdown, context=context),
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def _audit_key(row: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(
        str(row.get(key, "")) for key in ("timestamp", "identity", "method", "target", "outcome")
    )


def compare_graphs(
    left_graph: ReachabilityGraph,
    right_graph: ReachabilityGraph,
    left_audit: object | None = None,
    right_audit: object | None = None,
    *,
    left_label: str = "left",
    right_label: str = "right",
) -> dict[str, Any]:
    """Compare two graph/audit snapshots without re-running oracles."""
    left_index = build_evidence_index(left_graph, left_audit)
    right_index = build_evidence_index(right_graph, right_audit)
    left_findings = {str(row["finding_id"]): row for row in left_index["findings"]}
    right_findings = {str(row["finding_id"]): row for row in right_index["findings"]}
    changed = [
        {"finding_id": key, "before": left_findings[key], "after": right_findings[key]}
        for key in sorted(left_findings.keys() & right_findings.keys())
        if left_findings[key] != right_findings[key]
    ]
    left_endpoints = {(ep.method, ep.path) for _, ep in left_graph.endpoints()}
    right_endpoints = {(ep.method, ep.path) for _, ep in right_graph.endpoints()}
    left_audit_rows = _audit_records(left_audit)
    right_audit_rows = _audit_records(right_audit)
    left_audit_set = {_audit_key(row) for row in left_audit_rows}
    right_audit_set = {_audit_key(row) for row in right_audit_rows}
    left_counts = left_index["summary"]["counts"]
    right_counts = right_index["summary"]["counts"]
    delta = {
        key: int(right_counts.get(key, 0)) - int(left_counts.get(key, 0)) for key in left_counts
    }
    return {
        "schema_version": 1,
        "left": {"label": _safe_text(left_label, 128), "counts": left_counts},
        "right": {"label": _safe_text(right_label, 128), "counts": right_counts},
        "delta": delta,
        "findings": {
            "added": [
                right_findings[key] for key in sorted(right_findings.keys() - left_findings.keys())
            ],
            "removed": [
                left_findings[key] for key in sorted(left_findings.keys() - right_findings.keys())
            ],
            "changed": changed,
        },
        "endpoints": {
            "added": [
                [_safe_text(method, 16), _safe_text(path, 512)]
                for method, path in sorted(right_endpoints - left_endpoints)
            ],
            "removed": [
                [_safe_text(method, 16), _safe_text(path, 512)]
                for method, path in sorted(left_endpoints - right_endpoints)
            ],
        },
        "audit": {
            "added": [row for row in right_audit_rows if _audit_key(row) not in left_audit_set],
            "removed": [row for row in left_audit_rows if _audit_key(row) not in right_audit_set],
        },
    }


def compare_persisted_snapshots(left: str | Path, right: str | Path) -> dict[str, Any]:
    """Load two atomic graph snapshots and compare facts; no requests are fired."""
    from reachagent.graph.persistence import load_graph

    left_graph, _left_solver, left_audit = load_graph(left)
    right_graph, _right_solver, right_audit = load_graph(right)
    return compare_graphs(
        left_graph,
        right_graph,
        left_audit,
        right_audit,
        left_label=Path(left).name,
        right_label=Path(right).name,
    )


def render_history_comparison_json(comparison: Mapping[str, object]) -> str:
    return json.dumps(_safe_value(comparison, key="comparison"), sort_keys=True, indent=2) + "\n"


def render_history_comparison_markdown(comparison: Mapping[str, object]) -> str:
    safe = _safe_value(comparison, key="comparison")
    if not isinstance(safe, Mapping):
        return "# History comparison\n\nUnavailable.\n"
    delta = safe.get("delta", {})
    findings = safe.get("findings", {})
    lines = ["# History comparison\n", "\n", "## Count delta\n", "\n"]
    if isinstance(delta, Mapping):
        lines.extend(f"- {key}: `{value}`\n" for key, value in delta.items())
    if isinstance(findings, Mapping):
        lines.append("\n## Finding changes\n\n")
        lines.append(f"- Added: **{len(findings.get('added', []))}**\n")
        lines.append(f"- Removed: **{len(findings.get('removed', []))}**\n")
        lines.append(f"- Changed: **{len(findings.get('changed', []))}**\n")
    return "".join(lines)


# Compatibility aliases for callers that prefer shorter names.
render_sarif = render_findings_sarif
compare_persisted_runs = compare_persisted_snapshots
