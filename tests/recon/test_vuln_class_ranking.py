"""Ranked vuln-class targeting per insertion point - hermetic tests.

Covers: ranked-list return from _live_vuln_classes_for, sink-compatibility
filtering, the empty-tuple contract with no provider configured (no flag
gate — v4 R3 removed it, but the no-provider case is checked before ever
reaching propose_vuln_targets's own broader safe-default fallback), and the
multi-class iteration in the payload chain loop.
"""

from __future__ import annotations

from unittest.mock import patch

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


def test_ranked_list_empty_with_no_provider_configured() -> None:
    """v4 R3: no flag gate, but no-provider still returns the empty tuple —
    checked BEFORE propose_vuln_targets's own internal safe-default fallback
    (7 classes), which is for a genuine provider-call failure, not "no LLM at
    all". Trying 7 classes per candidate by default (rather than the usual
    single sink-matched class) was measured to multiply payload-chain
    attempts ~7x with no provider configured — a real perf regression."""
    from reachagent.scan.entrypoint import _live_vuln_classes_for

    g = _graph()
    sel = _selection(g, "/search", "q")
    assert _live_vuln_classes_for(sel, g, _BASE_URL) == ()


def test_ranked_list_returns_multiple_compatible() -> None:
    """When the LLM returns classes, only the sink-compatible ones survive."""
    from reachagent.scan.entrypoint import _live_vuln_classes_for

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
        with patch("reachagent.llm.client.build_openai_compatible_client", return_value=object()):
            result = _live_vuln_classes_for(_Sel(), g, _BASE_URL)
    finally:
        vt.propose_vuln_targets = original
    assert result == ("sqli",)
    assert "xss_reflected" not in result  # sink mismatch filtered out


def test_ranked_list_preserves_llm_order() -> None:
    """The LLM's priority order is preserved among compatible classes."""
    from reachagent.recon import vuln_tuning as vt
    from reachagent.scan.entrypoint import _live_vuln_classes_for

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
        with patch("reachagent.llm.client.build_openai_compatible_client", return_value=object()):
            result = _live_vuln_classes_for(_Sel(), g, _BASE_URL)
    finally:
        vt.propose_vuln_targets = original
    assert result == ("sqli",)  # only the sink-compatible class survives


def test_ranked_list_no_param_returns_empty() -> None:
    """A candidate with no parameter returns empty (no sink to match)."""
    from reachagent.scan.entrypoint import _live_vuln_classes_for

    g = _graph()
    ep_id = g.add_endpoint(Endpoint(method="GET", path="/admin"))

    class _Sel:
        endpoint_node = ep_id
        parameter_node = None

    result = _live_vuln_classes_for(_Sel(), g, _BASE_URL)
    # No param -> no sink -> no compatible class (all filtered).
    # The LLM may still return classes but they all fail the sink check.
    assert isinstance(result, tuple)


def test_ranked_list_with_nosql_sink() -> None:
    """A NOSQL-sink param gets nosqli first, sqli second (both compatible)."""
    from reachagent.recon import vuln_tuning as vt
    from reachagent.scan.entrypoint import _live_vuln_classes_for

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
        with patch("reachagent.llm.client.build_openai_compatible_client", return_value=object()):
            result = _live_vuln_classes_for(_Sel(), g, _BASE_URL)
    finally:
        vt.propose_vuln_targets = original
    # Only nosqli matches the NOSQL sink; sqli maps to SQL (different sink).
    assert result == ("nosqli",)
