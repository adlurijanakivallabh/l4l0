"""Explorer runtime state and pipeline errors (plan §9, §13).

Kept out of ``explorer.py`` for the same reason as the candidate records: the
role-boundary test (``tests/phase1/test_tool_boundaries.py``) asserts the
Explorer module exposes *exactly* its four tool names among non-underscore
callables, so a class or exception defined there would leak into the tool
surface. ``explorer.py`` imports this as a module instead.

:class:`ExplorerContext` is the working state a single Explorer holds against one
target: its collaborators (the Task 1 firer, the Task 4 payload library, the
graph) and the set of parameters it has already fingerprinted. When the
autonomous Coordinator arrives (Phase 5) it constructs one of these; today a
human driving the MCP tools (Task 8) constructs the identical thing — the tool
contracts don't change (§13).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reachagent.execution.firer import RequestFirer
    from reachagent.graph.store import ReachabilityGraph
    from reachagent.payloads import PayloadLibrary


class FingerprintRequiredError(RuntimeError):
    """Raised when ``fire_request`` targets a parameter that was never fingerprinted.

    This is the code-level enforcement of the §9 pipeline order: the benign
    canary of ``fingerprint_parameter`` must complete before any attack payload
    fires downstream. An un-fingerprinted parameter has no ``inferred_sink_type``,
    so firing at it would also mean firing a payload with no sink to justify it.
    """


@dataclass
class ExplorerContext:
    """One Explorer's state against a single target (§9, §13).

    ``base_url`` is combined with an endpoint's path to build a concrete request;
    ``canary`` is the benign marker ``fingerprint_parameter`` injects to read
    reflection/error behaviour before any real payload is sent.
    """

    graph: ReachabilityGraph
    firer: RequestFirer
    library: PayloadLibrary
    base_url: str
    canary: str = "reachagent-canary-7f3a2b"
    # Parameter node ids that have been fingerprinted. Tracked explicitly rather
    # than inferred from ``inferred_sink_type`` because a legitimate fingerprint
    # can resolve to *no* sink (None) — "unknown sink" and "not yet probed" are
    # different states, and only the latter must block firing.
    _fingerprinted: set[str] = field(default_factory=set, init=False, repr=False)

    @property
    def target_base(self) -> str:
        """The base URL with any trailing slash removed, for path joining."""
        return self.base_url.rstrip("/")

    def mark_fingerprinted(self, param_node: str) -> None:
        """Record that ``param_node`` has completed fingerprinting."""
        self._fingerprinted.add(param_node)

    def is_fingerprinted(self, param_node: str) -> bool:
        """Whether ``param_node`` has been fingerprinted (gates ``fire_request``)."""
        return param_node in self._fingerprinted
