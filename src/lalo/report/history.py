"""Diff findings across two runs of the same target by dedup_key - lets an
operator re-scanning a target see what's new/resolved/persisting instead
of eyeballing two report.json files by hand."""

from __future__ import annotations

from dataclasses import dataclass

from .collect import FindingRecord


@dataclass(frozen=True)
class FindingDiff:
    new: list[FindingRecord]
    resolved: list[FindingRecord]
    persisting: list[tuple[FindingRecord, FindingRecord]]


def diff_findings(previous: list[FindingRecord], current: list[FindingRecord]) -> FindingDiff:
    """Bucket ``current`` against ``previous`` by ``dedup_key``.

    A record with an empty ``dedup_key`` (unset) never matches anything -
    it is excluded from all three buckets rather than spuriously
    colliding with every other unset record.
    """
    previous_by_key = {r.dedup_key: r for r in previous if r.dedup_key}
    current_by_key = {r.dedup_key: r for r in current if r.dedup_key}
    new = [r for key, r in current_by_key.items() if key not in previous_by_key]
    resolved = [r for key, r in previous_by_key.items() if key not in current_by_key]
    persisting = [
        (previous_by_key[key], current_by_key[key])
        for key in current_by_key
        if key in previous_by_key
    ]
    return FindingDiff(new=new, resolved=resolved, persisting=persisting)
