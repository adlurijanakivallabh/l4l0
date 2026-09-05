"""SARIF 2.1.0 export — for CI ingestion (e.g. GitHub code-scanning upload).

Reads a reference agent's own ``report/sarif.py`` (1185 lines; read for
structure and the parts that generalize, not verbatim) for the overall
document shape and two specific, directly-reusable ideas: collapsing a
richer severity scale into SARIF's three result levels
(``error``/``warning``/``note``), and populating GitHub code-scanning's
``security-severity`` rule property from a real computed CVSS score. Most
of that reference's machinery is source-code-specific (file/line
``physicalLocation``s, cross-rename class fingerprints, inline ``fixes``
from a ``code_locations`` diff) and does not apply here: L4L0's findings
are target/endpoint-shaped, not file/line-shaped, so a result's location is
a SARIF ``logicalLocation`` (the target plus its parameter) rather than a
physical one, and the fingerprint is L4L0's own already-computed
:func:`~lalo.findings.dedup.dedup_key` rather than a bespoke hash — the
same identity Phase 12a already uses to decide whether two findings are
"the same finding," reused rather than re-derived.
"""

from __future__ import annotations

from typing import Any

from ..findings.dedup import dedup_key
from .collect import FindingRecord

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "L4L0"

_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SEVERITY_TO_SCORE: dict[str, str] = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}


def _rule_id(record: FindingRecord) -> str:
    return record.vuln_class.strip().lower() or "unknown"


def _security_severity(record: FindingRecord) -> str:
    if record.cvss_score:
        return f"{record.cvss_score:.1f}"
    return _SEVERITY_TO_SCORE.get(record.effective_severity, "5.0")


def _sarif_level(record: FindingRecord) -> str:
    return _SEVERITY_TO_LEVEL.get(record.effective_severity, "warning")


def _build_rule(record: FindingRecord) -> dict[str, Any]:
    rule_id = _rule_id(record)
    return {
        "id": rule_id,
        "name": record.vuln_class or rule_id,
        "shortDescription": {"text": record.title or rule_id},
        "fullDescription": {"text": record.description or record.title or rule_id},
        "defaultConfiguration": {"level": _sarif_level(record)},
        "properties": {"security-severity": _security_severity(record)},
    }


def _build_result(record: FindingRecord, rule_index: int) -> dict[str, Any]:
    logical_name = record.target + (f"#{record.param}" if record.param else "")
    message = f"{record.title}\n\n{record.description}" if record.description else record.title
    return {
        "ruleId": _rule_id(record),
        "ruleIndex": rule_index,
        "level": _sarif_level(record),
        "message": {"text": message or record.finding_id},
        "locations": [
            {"logicalLocations": [{"fullyQualifiedName": logical_name, "kind": "target"}]}
        ],
        "partialFingerprints": {
            "lalo/dedupKey": dedup_key(record.vuln_class, record.target, record.param)
        },
        "properties": {
            "security-severity": _security_severity(record),
            "lalo": {
                "confidence": record.confidence.score,
                "cvss_vector": record.cvss_vector,
                "evidence_grounded": record.evidence_grounded,
                "review_verdict": record.review_verdict,
            },
        },
    }


def render_sarif(records: list[FindingRecord]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document with one rule per vuln_class and one result per finding."""
    rule_index_by_id: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for record in records:
        rule_id = _rule_id(record)
        if rule_id not in rule_index_by_id:
            rule_index_by_id[rule_id] = len(rules)
            rules.append(_build_rule(record))
        results.append(_build_result(record, rule_index_by_id[rule_id]))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": {"name": TOOL_NAME, "rules": rules}},
                "results": results,
            }
        ],
    }
