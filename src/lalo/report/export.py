"""Report exporters: Markdown / JSON / SARIF."""

from __future__ import annotations

import json
from typing import Any

from ..detectors.ledger import CoverageLedger
from ..models import Finding
from .cvss import nominal_cvss
from .poc import curl_poc
from .render import render_markdown

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def to_markdown(findings: list[Finding], *, coverage: CoverageLedger | None = None) -> str:
    return render_markdown(findings, coverage=coverage)


def to_json(findings: list[Finding]) -> str:
    payload = [
        {
            "id": f.id,
            "title": f.title,
            "vuln_class": f.vuln_class,
            "severity": f.severity.value,
            "cvss_nominal": nominal_cvss(f.severity),
            "confidence": f.confidence,
            "confidence_breakdown": f.confidence_breakdown,
            "target": f.target,
            "poc": f.poc or curl_poc(f),
            "evidence": [
                {"kind": e.kind.value, "summary": e.summary, "fire_ref": e.fire_ref}
                for e in f.evidence
            ],
            "metadata": f.metadata,
        }
        for f in findings
    ]
    return json.dumps(payload, indent=2, sort_keys=True)


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    results = [
        {
            "ruleId": f.vuln_class,
            "level": _SARIF_LEVEL.get(f.severity.value, "warning"),
            "message": {"text": f"{f.title} (confidence {f.confidence})"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.target}}}],
        }
        for f in findings
    ]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "L4L0", "rules": []}},
                "results": results,
            }
        ],
    }
