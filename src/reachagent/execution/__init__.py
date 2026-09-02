"""Execution layer (plan §10, §12).

Fires requests via HTTPX (Playwright for browser-context oracles later, §12) and
enforces the safety controls of §10 at call time:
  * scope allowlist — enforced here, not just documented (CLAUDE.md, §10)
  * read-only-first — no state-changing request until the read-only case is
    confirmed safe (§10)
  * full logging of every action for audit and reproducibility (§10)
"""

from __future__ import annotations

from reachagent.execution.audit import AuditEntry, AuditLog
from reachagent.execution.firer import (
    CircuitOpenError,
    FireResult,
    ReadOnlyFirstError,
    RequestFirer,
)
from reachagent.execution.scope import OutOfScopeError, ScopeGuard, ScopeRule
from reachagent.execution.transports import (
    TOOL_ANNOTATIONS,
    TRANSPORTS,
    ProgressEvent,
    ToolAnnotation,
    TransportCancelledError,
    TransportControl,
    TransportDispatcher,
    TransportRequest,
)

__all__ = [
    "AuditEntry",
    "AuditLog",
    "CircuitOpenError",
    "FireResult",
    "OutOfScopeError",
    "ReadOnlyFirstError",
    "RequestFirer",
    "ScopeGuard",
    "ScopeRule",
    "TRANSPORTS",
    "TOOL_ANNOTATIONS",
    "ProgressEvent",
    "ToolAnnotation",
    "TransportCancelledError",
    "TransportControl",
    "TransportDispatcher",
    "TransportRequest",
]
