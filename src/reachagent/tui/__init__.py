"""Textual TUI — observer over ReachabilityGraph + AuditLog (§14, Phase 1).

No detection logic lives here: the TUI reads ``ReachabilityGraph.hosts()`` /
``endpoints()`` / ``parameters_of()`` / ``findings()`` and ``AuditLog.entries``
via callback/poll, that is all. Detection stays in ``scan/entrypoint.py`` +
``tools/payload_chain.py`` + the six oracle families. Both ``reachagent-scan``
(headless) and ``reachagent-tui`` share the same ``scan_target`` entrypoint.
"""

from reachagent.tui.app import ReachAgentApp

__all__ = ["ReachAgentApp"]
