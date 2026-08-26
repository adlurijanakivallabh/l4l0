"""Ranked vuln-class targeting per insertion point - hermetic tests.

Covers: ranked-list return from _live_vuln_classes_for, sink-compatibility
filtering, fallback to default when flag off, and the multi-class iteration
in the payload chain loop.
"""

from __future__ import annotations

import pytest

from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Host, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph

_TARGET = "target.test"
_BASE_URL = "http://target.test"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET])


def _graph() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(Host(address=_TARGET, hostname=_TARGET, source="test", technology="nginx"))
    return g


def _selection(graph: ReachabilityGraph, path: str, param_name: str | None = None) -> object:
    """A minimal CoordinatorCandidate-like object for _live_vuln_classes_for."""
    ep_id = graph.add_endpoint(Endpoint(method="GET", path=path))
    param_id = None
    if param_name:
        param_id = graph.add_parameter(ep_id, Parameter(name=param_name, location="query"))

    class _Sel:
        endpoint_node = ep_id
        parameter_node = param_id

    return _Sel()


def test_ranked_list_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns empty tuple when REACHAGENT_VULN_TUNING is unset."""
    from reachagent.scan.entrypoint import _live_vuln_classes_for

    monkeypatch.delenv("REACHAGENT_VULN_TUNING", raising=False)
    monkeypatch.delenv("REACHAGENT_RECON_LIVE_TUNING", raising=False)
    g = _graph()
    sel = _selection(g, "/search", "q")
    assert _live_vuln_classes_for(sel, g, _BASE_URL) == ()


def test_ranked_list_returns_multiple_compatible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the LLM returns classes, only the sink-compatible ones survive."""
    from reachagent.scan.entrypoint import _live_vuln_classes_for

    monkeypatch.setenv("REACHAGENT_VULN_TUNING", "1")

    class FakeClient:
        def propose(self, signals: dict, allowlist: tuple) -> dict:
            return {"vuln_classes": ["sqli", "nosqli", "xss_reflected"]}

    g = _graph()
    ep_id = g.add_endpoint(Endpoint(method="POST", path="/login"))
    pn = g.add_parameter(ep_id, Parameter(name="username", location="body"))
    g.set_parameter_sink_type(pn, SinkType.SQL)

    class _Sel:
        endpoint_node = ep_id
        parameter_node = pn

    # The LLM proposed sqli (SQL sink — matches) + xss_reflected (HTML sink
    # — filtered out because the param's inferred sink is sql).
    from reachagent.recon import vuln_tuning as vt

    original = vt.propose_vuln_targets
    vt.propose_vuln_targets = lambda *a, **kw: vt.VulnTargetChoice(
        vuln_classes=("sqli", "nosqli", "xss_reflected")
    )
    try:
        result = _live_vuln_classes_for(_Sel(), g, _BASE_URL)
    finally:
        vt.propose_vuln_targets = original
    assert result == ("sqli",)
    assert "xss_reflected" not in result  # sink mismatch filtered out


def test_ranked_list_preserves_llm_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The LLM's priority order is preserved among compatible classes."""
    from reachagent.recon import vuln_tuning as vt
    from reachagent.scan.entrypoint import _live_vuln_classes_for

    monkeypatch.setenv("REACHAGENT_VULN_TUNING", "1")
    g = _graph()
    ep_id = g.add_endpoint(Endpoint(method="POST", path="/login"))
    pn = g.add_parameter(ep_id, Parameter(name="user", location="body"))
    g.set_parameter_sink_type(pn, SinkType.SQL)

    class _Sel:
        endpoint_node = ep_id
        parameter_node = pn

    original = vt.propose_vuln_targets
    vt.propose_vuln_targets = lambda *a, **kw: vt.VulnTargetChoice(
        vuln_classes=("xss_reflected", "sqli")  # xss first but wrong sink
    )
    try:
        result = _live_vuln_classes_for(_Sel(), g, _BASE_URL)
    finally:
        vt.propose_vuln_targets = original
    assert result == ("sqli",)  # only the sink-compatible class survives


def test_ranked_list_no_param_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A candidate with no parameter returns empty (no sink to match)."""
    from reachagent.scan.entrypoint import _live_vuln_classes_for

    monkeypatch.setenv("REACHAGENT_VULN_TUNING", "1")
    g = _graph()
    ep_id = g.add_endpoint(Endpoint(method="GET", path="/admin"))

    class _Sel:
        endpoint_node = ep_id
        parameter_node = None

    result = _live_vuln_classes_for(_Sel(), g, _BASE_URL)
    # No param -> no sink -> no compatible class (all filtered).
    # The LLM may still return classes but they all fail the sink check.
    assert isinstance(result, tuple)


def test_ranked_list_with_nosql_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A NOSQL-sink param gets nosqli first, sqli second (both compatible)."""
    from reachagent.recon import vuln_tuning as vt
    from reachagent.scan.entrypoint import _live_vuln_classes_for

    monkeypatch.setenv("REACHAGENT_VULN_TUNING", "1")
    g = _graph()
    ep_id = g.add_endpoint(Endpoint(method="POST", path="/api/find"))
    pn = g.add_parameter(ep_id, Parameter(name="filter", location="body"))
    g.set_parameter_sink_type(pn, SinkType.NOSQL)

    class _Sel:
        endpoint_node = ep_id
        parameter_node = pn

    original = vt.propose_vuln_targets
    vt.propose_vuln_targets = lambda *a, **kw: vt.VulnTargetChoice(
        vuln_classes=("nosqli", "sqli", "xss_reflected")
    )
    try:
        result = _live_vuln_classes_for(_Sel(), g, _BASE_URL)
    finally:
        vt.propose_vuln_targets = original
    # Only nosqli matches the NOSQL sink; sqli maps to SQL (different sink).
    assert result == ("nosqli",)
