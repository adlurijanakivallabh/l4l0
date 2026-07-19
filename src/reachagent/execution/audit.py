"""Audit log for every execution-layer action (plan §10).

"Full, clear logging of every action taken, for audit and reproducibility" is a
named safety control (§10), so it lives as its own concern rather than as a side
effect of firing. Every attempt — fired, refused, or errored — produces one
:class:`AuditEntry`; nothing the firer does is silent.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

_logger = logging.getLogger("reachagent.execution.audit")


@dataclass(frozen=True)
class AuditEntry:
    """One recorded action (§10).

    ``target`` is host+path only — query strings and userinfo are never recorded,
    since they may carry secrets (safety_guardrails).
    """

    timestamp: datetime
    identity: str
    method: str
    target: str
    outcome: str


class AuditLog:
    """In-memory, append-only record of every execution-layer action (§10).

    Also mirrors each entry to the stdlib logger so a run is auditable live, not
    only after the fact.
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record(self, identity: str, method: str, target: str, outcome: str) -> AuditEntry:
        """Append one action and mirror it to the logger. Returns the entry."""
        entry = AuditEntry(
            timestamp=datetime.now(UTC),
            identity=identity,
            method=method.upper(),
            target=target,
            outcome=outcome,
        )
        self._entries.append(entry)
        _logger.info(
            "action identity=%s method=%s target=%s outcome=%s",
            entry.identity,
            entry.method,
            entry.target,
            entry.outcome,
        )
        return entry

    @property
    def entries(self) -> Sequence[AuditEntry]:
        """Read-only view of everything recorded, in order."""
        return tuple(self._entries)
