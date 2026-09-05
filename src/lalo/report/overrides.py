"""Severity overrides — a display-only audit trail that never mutates a finding.

Adopts the audit-trail idea from a reference agent's own
``render_update_history`` (``report/writer.py``, read in full): every
revision to a finding is rendered as a dated, attributed, reasoned entry
rather than silently replacing the old value. L4L0 does not (yet) let a
finding's own record be revised in place at all — Phase 12's
``record_finding`` only creates or merges evidence — so an override here is
kept structurally separate and one-directional: it can change what a
*report* shows for a finding's severity, and why, but it can never write
back onto the graph node itself. The underlying, evidence-computed
``cvss_severity`` stays exactly what Phase 12a computed, always, for anyone
who reads the finding directly rather than through a rendered report.

That same reference's actual *human-facing* feature this idea is drawn from
(``VulnerabilityDetail.tsx``, its shared local-viewer/public-share finding
page, confirmed via source, not just its comparison doc) renders a
``severity_override_reason``/``original_severity`` pair when a human has
manually corrected the LLM's assigned severity — but its own comparison
documentation notes this is confirmed inert/null-only in the surveyed OSS
build (no code path there ever writes a non-null override). L4L0's
:class:`SeverityOverride` and :func:`apply_overrides` are a real,
functioning implementation of the same idea — an operator (or, later, any
other reviewer) can actually produce and apply one — rather than a wired-up
display for a value nothing yet sets.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .collect import FindingRecord


@dataclass(frozen=True)
class SeverityOverride:
    finding_id: str
    severity: str
    reason: str
    overridden_by: str


def apply_overrides(
    records: list[FindingRecord], overrides: list[SeverityOverride]
) -> list[FindingRecord]:
    """Return new records with a display severity applied — the originals are untouched.

    An override for a finding_id absent from ``records`` is silently
    ignored (nothing to display it against); at most one override applies
    per finding — the last one for a given ``finding_id`` wins, matching an
    audit trail's "most recent entry is current" semantics.
    """
    by_finding: dict[str, SeverityOverride] = {o.finding_id: o for o in overrides}
    return [
        replace(
            record,
            display_severity=override.severity,
            override_reason=f"{override.reason} (overridden by {override.overridden_by})",
        )
        if (override := by_finding.get(record.finding_id)) is not None
        else record
        for record in records
    ]
