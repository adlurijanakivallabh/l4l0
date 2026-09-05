"""Recon orchestrator: an availability-gated chain of runners, facts accumulated across all.

Adapted from a reference platform's real `web_search.go` (482 lines, read in
full): the agent expresses an intent, the host walks an ordered engine
chain, SKIPPING any engine whose availability check fails (e.g. no API key
configured), and only surfaces an error after every available engine has
been tried. Deliberately diverges on one point: that reference's search tool
stops at the FIRST successful engine (one good answer is enough); recon
fact-gathering here accumulates facts from EVERY available runner instead,
since independent signal sources mean more coverage, not a single winner to
pick — and one runner's ordinary failure (crash, timeout, unreachable
target) never aborts the rest of the chain, mirroring the per-item fault
isolation read from a different reference's own scan pipeline (cited in the
Phase 6 commit).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .facts import ReconFact


@runtime_checkable
class ReconRunner(Protocol):
    name: str

    def is_available(self) -> bool: ...
    def run(self) -> list[ReconFact]: ...


@dataclass
class ChainReport:
    facts: list[ReconFact] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)


def run_recon_chain(runners: list[ReconRunner]) -> ChainReport:
    report = ChainReport()
    for runner in runners:
        if not runner.is_available():
            report.skipped.append(runner.name)
            continue
        try:
            report.facts.extend(runner.run())
        except Exception as exc:  # noqa: BLE001 - one runner's crash must not sink the others
            report.failed.append((runner.name, f"{type(exc).__name__}: {exc}"))
    return report
