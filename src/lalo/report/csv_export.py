"""CSV export of findings - flat, spreadsheet-friendly, with
formula-injection escaping since finding fields are attacker-influenced
text flowing into a spreadsheet formula-injection sink (a cell starting
with =, +, -, @, tab, or CR is interpreted by Excel/Sheets as a formula,
not literal text)."""

from __future__ import annotations

import csv
import io

from .collect import FindingRecord

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_HEADER = [
    "finding_id",
    "title",
    "vuln_class",
    "target",
    "param",
    "severity",
    "cvss_score",
    "confidence",
    "status",
    "remediation",
]


def csv_safe(value: str) -> str:
    """Prefix a leading apostrophe if value would otherwise be interpreted
    as a spreadsheet formula by Excel/Sheets."""
    return "'" + value if value and value[0] in _FORMULA_PREFIXES else value


def build_csv(records: list[FindingRecord]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_HEADER)
    for record in records:
        writer.writerow(
            [
                csv_safe(str(v))
                for v in [
                    record.finding_id,
                    record.title,
                    record.vuln_class,
                    record.target,
                    record.param or "",
                    record.effective_severity,
                    record.cvss_score,
                    record.confidence.score,
                    record.status,
                    record.remediation,
                ]
            ]
        )
    return buf.getvalue()
