"""Durable orchestration — checkpoint/resume + budget governance + scheduling.

Every side-effecting step is journaled the instant it completes, so a crashed or
restarted scan resumes exactly where it stopped with no duplicated side effect.
Budget state persists across a resume (a resumed run must not earn a fresh
budget), and a budget-exhausted run's terminal status is explicitly distinct
from a genuinely completed one — a real gap in a reference project's own
documented cost-governance design that this module deliberately avoids.
"""

from .budget import Budget, BudgetBand, RunStatus
from .journal import Checkpoint, DurableJournal
from .scheduler import ScanSchedule, due_schedules

__all__ = [
    "Budget",
    "BudgetBand",
    "Checkpoint",
    "DurableJournal",
    "RunStatus",
    "ScanSchedule",
    "due_schedules",
]
