"""Completeness critic — turn coverage gaps into re-queue work.

Asks "what surface/class did we not assess?" from the coverage ledger so the
orchestrator can re-queue it, closing the silent-gap problem.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..detectors.ledger import CoverageLedger


@dataclass(frozen=True)
class ReQueueItem:
    target: str
    vuln_class: str

    def as_objective(self) -> str:
        return f"Assess {self.vuln_class} on {self.target} — it was applicable but not tested."


def completeness_critic(ledger: CoverageLedger) -> list[ReQueueItem]:
    """Return the not-yet-assessed (target, class) cells as re-queue items."""
    return [ReQueueItem(target=t, vuln_class=c) for t, c in ledger.not_assessed()]
