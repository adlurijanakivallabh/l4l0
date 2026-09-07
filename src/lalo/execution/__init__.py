"""Execution layer: the declared-engagement target model, the scope guard, and
the request firers (HTTP multi-protocol + raw TCP).

This is where L4L0's structured tools reach the network. Scope is enforced
inside the firer before any I/O; the firer also DIALS the same pinned IP the
scope check resolved (not a second, independent resolution) — closing a real
DNS-rebinding TOCTOU gap a naive "check then fire" design leaves open. The free
shell (`run_command`) is not routed through here; it is prompt-scoped.
"""

from .firer import FireResult, HttpFirer
from .rawsock import RawResult, tcp_send_recv
from .scope import Decision, ScopeDecision, ScopeGuard
from .target import Engagement, TargetRule
from .tool import (
    build_access_control_matrix_tool,
    build_diff_responses_tool,
    build_fire_concurrent_tool,
    build_http_tool,
    build_raw_tcp_tool,
)

__all__ = [
    "Decision",
    "Engagement",
    "FireResult",
    "HttpFirer",
    "RawResult",
    "ScopeDecision",
    "ScopeGuard",
    "TargetRule",
    "build_access_control_matrix_tool",
    "build_diff_responses_tool",
    "build_fire_concurrent_tool",
    "build_http_tool",
    "build_raw_tcp_tool",
    "tcp_send_recv",
]
