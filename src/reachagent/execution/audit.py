"""Audit log for every execution-layer action (plan §10).

"Full, clear logging of every action taken, for audit and reproducibility" is a
named safety control (§10), so it lives as its own concern rather than as a side
effect of firing. Every attempt — fired, refused, or errored — produces one
:class:`AuditEntry`; nothing the firer does is silent.
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

_logger = logging.getLogger("reachagent.execution.audit")
_AUDIT_SECRET = re.compile(
    r"(?i)(?:bearer\s+[^\s,;]+|(?:password|passwd|secret|token|api[_-]?key|cookie|"
    r"authorization)\s*[:=]\s*[^\s,;]+)"
)


def _safe_audit_value(value: str, *, maximum: int = 256) -> str:
    """Keep oracle explanations/handles safe for the append-only audit log."""
    text = str(value).replace("\n", " ").replace("\r", " ").replace("\t", " ")
    text = "".join(char for char in text if ord(char) >= 32 and ord(char) != 127)
    text = _AUDIT_SECRET.sub("<redacted>", text)
    return text[:maximum]


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
        self._lock = threading.Lock()

    def record(self, identity: str, method: str, target: str, outcome: str) -> AuditEntry:
        """Append one action and mirror it to the logger. Returns the entry."""
        entry = AuditEntry(
            timestamp=datetime.now(UTC),
            identity=identity,
            method=method.upper(),
            target=target,
            outcome=outcome,
        )
        with self._lock:
            self._entries.append(entry)
        _logger.info(
            "action identity=%s method=%s target=%s outcome=%s",
            entry.identity,
            entry.method,
            entry.target,
            entry.outcome,
        )
        return entry

    def record_oracle_result(
        self,
        identity: str,
        target: str,
        reason: str,
        *,
        evidence_ref: str = "",
    ) -> AuditEntry:
        """Record a deterministic negative/positive oracle decision safely.

        Only bounded reason text and opaque evidence handles are retained; raw
        request/response bodies and authentication material never enter the log.
        """
        safe_reason = _safe_audit_value(reason)
        safe_ref = _safe_audit_value(evidence_ref)
        suffix = f" ref={safe_ref}" if safe_ref else ""
        return self.record(
            _safe_audit_value(identity),
            "ORACLE",
            _safe_audit_value(target),
            f"oracle:{safe_reason}{suffix}",
        )

    @property
    def entries(self) -> Sequence[AuditEntry]:
        """Read-only view of everything recorded, in order."""
        with self._lock:
            return tuple(self._entries)
