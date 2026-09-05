"""Execution layer: the declared-engagement target model, the scope guard, and
the request firers (HTTP multi-protocol + raw TCP).

This is where L4L0's structured tools reach the network. Per the safety posture
(CLAUDE.md): the firers stay on the operator-declared engagement — an
out-of-engagement request is skipped (or hard-denied when the optional egress
lock is on), and cloud-metadata endpoints are denied by default. The free shell
(`run_command`) is not routed through here; it is prompt-scoped.
"""

from .firer import FireResult, HttpFirer
from .rawsock import RawResult, tcp_send_recv
from .scope import Decision, ScopeDecision, ScopeGuard
from .target import Engagement, TargetRule

__all__ = [
    "Decision",
    "Engagement",
    "FireResult",
    "HttpFirer",
    "RawResult",
    "ScopeDecision",
    "ScopeGuard",
    "TargetRule",
    "tcp_send_recv",
]
