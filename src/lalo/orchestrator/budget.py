"""Budget governance: graduated bands, role-differentiated ceilings, real hard stops.

Read a reference agent's actual budget-hook source in full (not just its own
comparison notes) before building this. Adopted directly: the *highest* crossed
band wins (a sudden jump straight to 96% reads CRITICAL, not NOTICE), root and
sub-agent roles get different band sets (sub-agents pull back earlier — 75/80/85
— to preserve a hard reserve for the root's final report), and threshold
crossings raise real typed exceptions that unwind the run rather than merely
logging.

Deliberately corrected relative to that reference: its own CI-integration skill
file explicitly discloses that a budget-exhausted run still exits 0 / records
"completed" — a genuine fail-open gap. Here, hitting the ceiling produces a
:class:`RunStatus` of ``BUDGET_EXHAUSTED``, never ``COMPLETED`` — a caller can
never mistake incomplete coverage for a clean, finished scan. Budget state
(``spent``) is meant to be persisted through the durable journal, not reset to
zero on resume — the reference's own engineering notes on this exact problem
("a resumed agent cannot earn a fresh nudge budget on every auto-resume") are
the reason a resumed run must be constructed with its true cumulative spend.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class BudgetBand(StrEnum):
    OK = "ok"
    NOTICE = "notice"
    URGENT = "urgent"
    CRITICAL = "critical"
    EXHAUSTED = "exhausted"


class RunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"  # genuinely finished — the agent called finish
    BUDGET_EXHAUSTED = "budget_exhausted"  # stopped by the ceiling; NEVER "completed"
    ERROR = "error"
    UNVERIFIED_STOP = "unverified_stop"  # a stop was requested but termination unconfirmed


class BudgetExceededError(RuntimeError):
    """The hard ceiling was reached — the run must stop, status BUDGET_EXHAUSTED."""


class SubagentReserveExceededError(RuntimeError):
    """A sub-agent crossed its reserve threshold — stop it, not the whole run."""


_ROOT_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_SUBAGENT_BANDS: tuple[float, ...] = (0.75, 0.80, 0.85)
_SUBAGENT_RESERVE = 0.90


def _highest_crossed(fraction: float, bands: tuple[float, ...]) -> BudgetBand:
    crossed: BudgetBand = BudgetBand.OK
    labels = (BudgetBand.NOTICE, BudgetBand.URGENT, BudgetBand.CRITICAL)
    for band, label in zip(bands, labels, strict=True):
        if fraction >= band:
            crossed = label
    if fraction >= 1.0:
        crossed = BudgetBand.EXHAUSTED
    return crossed


@dataclass
class Budget:
    """Tracks spend against a ceiling with role-differentiated graduated bands.

    ``spent`` is a plain field (not private) precisely so an orchestrator can
    restore it from the durable journal on resume — construct with
    ``Budget(ceiling=..., spent=<persisted value>)`` rather than always starting
    at 0.
    """

    ceiling: int
    spent: int = 0
    subagent_reserve: float = _SUBAGENT_RESERVE

    def fraction(self) -> float:
        return self.spent / self.ceiling if self.ceiling else 1.0

    def band(self, *, is_root: bool = True) -> BudgetBand:
        bands = _ROOT_BANDS if is_root else _SUBAGENT_BANDS
        return _highest_crossed(self.fraction(), bands)

    def spend(self, amount: int = 1) -> None:
        self.spent += amount

    def remaining(self) -> int:
        return max(0, self.ceiling - self.spent)

    def check_root(self) -> None:
        """Raise if the whole run's hard ceiling has been reached."""
        if self.spent >= self.ceiling:
            raise BudgetExceededError(
                f"budget ceiling reached: spent {self.spent} of {self.ceiling}"
            )

    def check_subagent(self) -> None:
        """Raise if a sub-agent has crossed its reserve threshold.

        Sub-agents stop earlier than the root so the reserve fraction of the
        ceiling stays available for the root to compile a final report.
        """
        reserve_limit = self.ceiling * self.subagent_reserve
        if self.spent >= reserve_limit:
            raise SubagentReserveExceededError(
                f"sub-agent reserve reached: spent {self.spent} of {self.ceiling} "
                f"(>= {round(self.subagent_reserve * 100)}% reserve)"
            )

    def outcome(self) -> RunStatus:
        """The honest terminal status if the run stops right now due to budget."""
        return RunStatus.BUDGET_EXHAUSTED if self.spent >= self.ceiling else RunStatus.RUNNING
