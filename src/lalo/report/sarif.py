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
from .taxonomy import OWASP_API_BY_VULN_CLASS, OWASP_API_TOP10_NAMES, cwe_for, owasp_api_for

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "L4L0"

# The one taxonomy this project's own curated OWASP_API_BY_VULN_CLASS
# mapping ever references - declared in SARIF's own run-level "taxonomies"
# array (added by render_sarif, only when at least one rule actually uses
# it) so every OWASP relationship a rule emits below resolves against
# something real, mirroring the existing CWE relationship shape exactly.
_OWASP_API_TAXONOMY_NAME = "OWASP-API-Security-Top-10-2023"

_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _rule_id(record: FindingRecord) -> str:
    return record.vuln_class.strip().lower() or "unknown"


def _security_severity(record: FindingRecord) -> str:
    # Unlike the reference this idea is adapted from, cvss_score here is
    # never optional: record_finding requires a cvss_breakdown for every
    # finding, so it is always a real, meaningfully computed value - a
    # genuine 0.0 (an all-"N"-impact breakdown) is a legitimate score, not
    # an absence to fall back from. A truthy check here would silently
    # discard that real score and report an arbitrary "1.0" instead.
    return f"{record.cvss_score:.1f}"


def _sarif_level(record: FindingRecord) -> str:
    return _SEVERITY_TO_LEVEL.get(record.effective_severity, "warning")


def _build_rule(record: FindingRecord) -> dict[str, Any]:
    rule_id = _rule_id(record)
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": record.vuln_class or rule_id,
        "shortDescription": {"text": record.title or rule_id},
        "fullDescription": {"text": record.description or record.title or rule_id},
        "help": {"text": record.remediation or "(no remediation stated)"},
        "defaultConfiguration": {"level": _sarif_level(record)},
        "properties": {"security-severity": _security_severity(record)},
    }
    # Only added when a mapping actually exists - an unmapped vuln_class
    # must never render as a fabricated/empty relationship, per
    # lalo.report.taxonomy's own "degrades to no CWE line, never an error"
    # contract. Same contract now applies to the OWASP relationship below.
    relationships: list[dict[str, Any]] = []
    cwe = cwe_for(record.vuln_class)
    if cwe:
        relationships.append(
            {"target": {"id": cwe, "toolComponent": {"name": "CWE"}}, "kinds": ["relevant"]}
        )
    owasp = owasp_api_for(record.vuln_class)
    if owasp:
        relationships.append(
            {
                "target": {"id": owasp, "toolComponent": {"name": _OWASP_API_TAXONOMY_NAME}},
                "kinds": ["relevant"],
            }
        )
    if relationships:
        rule["relationships"] = relationships
    return rule


def _owasp_taxonomy_component() -> dict[str, Any]:
    """The run-level ToolComponent every OWASP relationship above resolves
    against - SARIF's own ``run.taxonomies`` array. Declares only the
    category ids this project's curated OWASP_API_BY_VULN_CLASS mapping can
    ever emit, not the full external OWASP list - an undeclared
    relationship would be as misleading as a fabricated one, but so is
    declaring ten taxa when this codebase's own mapping only ever points at
    a handful of them."""
    used_ids = sorted(set(OWASP_API_BY_VULN_CLASS.values()))
    return {
        "name": _OWASP_API_TAXONOMY_NAME,
        "organization": "OWASP",
        "informationUri": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
        "taxa": [{"id": cat_id, "name": OWASP_API_TOP10_NAMES[cat_id]} for cat_id in used_ids],
    }


def _result_markdown(record: FindingRecord) -> str:
    """A richer, formatted counterpart to the result's own plain ``text``
    message - SARIF viewers that support ``message.markdown`` (GitHub code
    scanning among them) render this instead, falling back to ``text``
    otherwise. Built entirely from fields already on the record - no new
    data, no LLM call, matching this whole module's own deterministic,
    pure-string-assembly discipline."""
    parts = [f"## {record.title or record.finding_id}"]
    if record.description:
        parts.append(record.description)
    parts.append(
        f"**CVSS:** {record.cvss_score:.1f} ({record.cvss_severity}) — `{record.cvss_vector}`  \n"
        f"**Confidence:** {record.confidence.score}/100"
    )
    if record.remediation:
        parts.append(f"### Remediation\n\n{record.remediation}")
    return "\n\n".join(parts)


def _build_result(record: FindingRecord, rule_index: int) -> dict[str, Any]:
    logical_name = record.target + (f"#{record.param}" if record.param else "")
    message = f"{record.title}\n\n{record.description}" if record.description else record.title
    locations: list[dict[str, Any]] = [
        {"logicalLocations": [{"fullyQualifiedName": logical_name, "kind": "target"}]}
    ]
    if record.source_location and ":" in record.source_location:
        path, _, line_str = record.source_location.rpartition(":")
        if line_str.isdigit():
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": int(line_str)},
                    }
                }
            )
    return {
        "ruleId": _rule_id(record),
        "ruleIndex": rule_index,
        "level": _sarif_level(record),
        "message": {"text": message or record.finding_id, "markdown": _result_markdown(record)},
        "locations": locations,
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


def render_sarif(
    records: list[FindingRecord],
    *,
    execution_successful: bool = True,
    automation_id: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document with one rule per vuln_class and one result per finding.

    ``execution_successful`` reports whether the *scan itself* ran to a clean
    stop (never whether vulnerabilities were found) - a CI consumer reading
    ``invocations[].executionSuccessful`` needs to distinguish "the tool
    crashed/was cut off" from "the tool ran fine and found nothing," which
    the results list alone cannot tell it. ``automation_id`` identifies which
    scan run produced this document, so a CI system uploading SARIF from
    repeated runs can tell them apart.
    """
    rule_index_by_id: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    owasp_taxonomy_used = False
    for record in records:
        rule_id = _rule_id(record)
        if rule_id not in rule_index_by_id:
            rule_index_by_id[rule_id] = len(rules)
            rules.append(_build_rule(record))
            if owasp_api_for(record.vuln_class):
                owasp_taxonomy_used = True
        results.append(_build_result(record, rule_index_by_id[rule_id]))

    run: dict[str, Any] = {
        "tool": {"driver": {"name": TOOL_NAME, "rules": rules}},
        "results": results,
        "invocations": [{"executionSuccessful": execution_successful}],
    }
    if owasp_taxonomy_used:
        run["taxonomies"] = [_owasp_taxonomy_component()]
    if automation_id:
        run["automationDetails"] = {"id": automation_id}

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
