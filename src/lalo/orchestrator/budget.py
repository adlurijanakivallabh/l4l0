"""Budget governance: a hard ceiling, graduated warning bands, sub-agent reserve."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class BudgetBand(StrEnum):
    OK = "ok"
    NOTICE = "notice"  # >= 70%
    URGENT = "urgent"  # >= 85%
    CRITICAL = "critical"  # >= 95%
    EXHAUSTED = "exhausted"  # >= 100%


@dataclass
class Budget:
    ceiling: int
    subagent_reserve: float = 0.1  # fraction of ceiling held back for sub-agents
    _spent: int = 0

    def spend(self, amount: int = 1) -> None:
        self._spent += amount

    @property
    def spent(self) -> int:
        return self._spent

    def remaining(self) -> int:
        return max(0, self.ceiling - self._spent)

    def fraction(self) -> float:
        return self._spent / self.ceiling if self.ceiling else 1.0

    def band(self) -> BudgetBand:
        frac = self.fraction()
        if frac >= 1.0:
            return BudgetBand.EXHAUSTED
        if frac >= 0.95:
            return BudgetBand.CRITICAL
        if frac >= 0.85:
            return BudgetBand.URGENT
        if frac >= 0.70:
            return BudgetBand.NOTICE
        return BudgetBand.OK

    def can_spend(self, amount: int = 1) -> bool:
        return self._spent + amount <= self.ceiling

    def can_spend_subagent(self, amount: int = 1) -> bool:
        """Sub-agents must leave the reserve intact for the root agent to finish."""
        reserve = int(self.ceiling * self.subagent_reserve)
        return self._spent + amount <= self.ceiling - reserve
