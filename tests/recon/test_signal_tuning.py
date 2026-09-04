"""Signal-tool selection layer - LLM reasoning about which tools to invoke.

Hermetic (no network). Covers: allowlist validation, unknown tool dropping,
empty-graph, and the orchestrator wiring. No flag gate (v4 R3 removed it).
"""

from __future__ import annotations

from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Host, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.signal_tuning import (
    SIGNAL_TOOL_ALLOWLIST,
    propose_signal_tools,
)

_TARGET = "target.test"
_BASE = "http://target.test"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET])


def _graph() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(Host(address=_TARGET, hostname=_TARGET, source="test", technology="nginx"))
    ep_login = g.add_endpoint(Endpoint(method="POST", path="/login"))
    pn = g.add_parameter(ep_login, Parameter(name="username", location="body"))
    g.set_parameter_sink_type(pn, SinkType.SQL)
    return g


class FakeTuner:
    def __init__(self, tools: list[str], rationale: str = "test") -> None:
        self._tools = tools
        self._rationale = rationale

    def propose(
        self,
        surface_summary: str,
        allowlist: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        return {"selected_tools": self._tools, "rationale": self._rationale}


def test_no_flag_needed_client_used_directly() -> None:
    """v4 R3: no REACHAGENT_SIGNAL_TUNING gate — a configured client is used
    unconditionally, not only when an env flag also happens to be set."""
    result = propose_signal_tools(_graph(), client=FakeTuner(["sqlmap"]))
    assert result is not None
    assert result.selected_tools == ("sqlmap",)


def test_valid_selection() -> None:
    """A valid selection passes and carries the rationale."""
    tuner = FakeTuner(["sqlmap", "nikto"], rationale="sql sink found")
    result = propose_signal_tools(_graph(), client=tuner)
    assert result is not None
    assert result.selected_tools == ("sqlmap", "nikto")
    assert result.rationale == "sql sink found"


def test_drops_unknown_tools() -> None:
    """Invented tool names are dropped; only allowlisted ones survive."""
    tuner = FakeTuner(["sqlmap", "invented-tool", "nikto"])
    result = propose_signal_tools(_graph(), client=tuner)
    assert result is not None
    assert result.selected_tools == ("sqlmap", "nikto")


def test_empty_graph_returns_none() -> None:
    """An empty graph returns None without calling the LLM."""
    assert propose_signal_tools(ReachabilityGraph(), client=FakeTuner([])) is None


def test_all_invalid_returns_none() -> None:
    """All-invalid selections return None (caller falls back)."""
    tuner = FakeTuner(["made-up-1", "made-up-2"])
    assert propose_signal_tools(_graph(), client=tuner) is None


def test_client_error_returns_none() -> None:
    """An LLM error is caught; never crashes the scan."""

    class Broken:
        def propose(self, *a: object) -> dict[str, object]:
            raise RuntimeError("LLM down")

    assert propose_signal_tools(_graph(), client=Broken()) is None  # type: ignore[arg-type]


def test_allowlist_matches_dispatch_registry() -> None:
    """Every allowlisted name has a registered SignalGatedToolRunner."""
    from reachagent.recon.signal_dispatch import (
        CommixRunner,
        DalfoxRunner,
        JwtToolRunner,
        NiktoRunner,
        NucleiRunner,
        SqlmapRunner,
    )

    registered = {
        cls.name
        for cls in (
            CommixRunner,
            DalfoxRunner,
            JwtToolRunner,
            NiktoRunner,
            NucleiRunner,
            SqlmapRunner,
        )
    }
    assert set(SIGNAL_TOOL_ALLOWLIST) == registered
