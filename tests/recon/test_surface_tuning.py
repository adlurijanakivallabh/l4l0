"""Surface-tuning layer - LLM endpoint prioritization, hermetic (no network).

Tests the propose/validate/wire cycle with a fake client. The Coordinator
scoring bonus is verified against the real formula.
"""

from __future__ import annotations

import pytest

from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Host, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.surface_tuning import (
    EndpointSummary,
    build_endpoint_summaries,
    propose_surface_priority,
)

_TARGET = "target.test"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET])


def _graph_with_endpoints() -> ReachabilityGraph:
    """A small surface: /admin (param), /api/users, /static/app.js."""
    g = ReachabilityGraph()
    g.add_host(Host(address=_TARGET, hostname=_TARGET, source="test"))
    ep_admin = g.add_endpoint(Endpoint(method="GET", path="/admin"))
    g.add_parameter(ep_admin, Parameter(name="user_id", location="query"))
    g.add_endpoint(Endpoint(method="POST", path="/api/users"))
    g.add_endpoint(Endpoint(method="GET", path="/static/app.js"))
    return g


class FakeTuner:
    """A fake SurfaceTunerClient that always returns a fixed ranking."""

    def __init__(self, ranked_ids: list[str], rationale: str = "test") -> None:
        self._ids = ranked_ids
        self._rationale = rationale

    def propose(
        self,
        summaries: tuple[EndpointSummary, ...],
        operator_prompt: str,
        target_type: str,
    ) -> dict[str, object]:
        return {"ranked_ids": self._ids, "rationale": self._rationale}


def _find_ep_by_path(g: ReachabilityGraph, path: str) -> str:
    for nid, ep in g.endpoints():
        if ep.path == path:
            return nid
    raise ValueError(path)


def test_summaries_include_params() -> None:
    """Endpoint summaries carry parameter names + locations."""
    g = _graph_with_endpoints()
    summaries = build_endpoint_summaries(g)
    assert len(summaries) == 3
    admin = next(s for s in summaries if "/admin" in s.path)
    assert "user_id(query)" in admin.parameters


def test_summaries_bounded() -> None:
    """The summary list is capped at _MAX_ENDPOINTS."""
    from reachagent.recon.surface_tuning import _MAX_ENDPOINTS

    g = ReachabilityGraph()
    for i in range(_MAX_ENDPOINTS + 10):
        g.add_endpoint(Endpoint(method="GET", path=f"/page{i}"))
    assert len(build_endpoint_summaries(g)) == _MAX_ENDPOINTS


def test_propose_disabled_without_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns None when REACHAGENT_SURFACE_TUNING is unset."""
    monkeypatch.delenv("REACHAGENT_SURFACE_TUNING", raising=False)
    assert propose_surface_priority(_graph_with_endpoints(), client=FakeTuner([])) is None


def test_propose_valid_ranking(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid ranking passes validation and carries the rationale."""
    monkeypatch.setenv("REACHAGENT_SURFACE_TUNING", "1")
    g = _graph_with_endpoints()
    admin_id = _find_ep_by_path(g, "/admin")
    users_id = _find_ep_by_path(g, "/api/users")
    tuner = FakeTuner([admin_id, users_id], rationale="auth first")
    result = propose_surface_priority(g, client=tuner)
    assert result is not None
    assert result.ranked_ids == (admin_id, users_id)
    assert result.rationale == "auth first"


def test_propose_drops_unknown_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invented node ids are dropped; only graph-known ids survive."""
    monkeypatch.setenv("REACHAGENT_SURFACE_TUNING", "1")
    g = _graph_with_endpoints()
    static_id = _find_ep_by_path(g, "/static/app.js")
    tuner = FakeTuner(["fake-id-1", static_id, "fake-id-2"])
    result = propose_surface_priority(g, client=tuner)
    assert result is not None
    assert result.ranked_ids == (static_id,)


def test_propose_empty_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty graph returns None without calling the LLM."""
    monkeypatch.setenv("REACHAGENT_SURFACE_TUNING", "1")
    assert propose_surface_priority(ReachabilityGraph(), client=FakeTuner([])) is None


def test_propose_all_invalid_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """All-invalid ids -> validation returns None (fallback to default)."""
    monkeypatch.setenv("REACHAGENT_SURFACE_TUNING", "1")
    tuner = FakeTuner(["invented-1", "invented-2"])
    assert propose_surface_priority(_graph_with_endpoints(), client=tuner) is None


def test_propose_client_error_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """An LLM error is caught and returns None - never crashes the scan."""
    monkeypatch.setenv("REACHAGENT_SURFACE_TUNING", "1")

    class BrokenClient:
        def propose(self, *args: object) -> dict[str, object]:
            raise RuntimeError("LLM unavailable")

    result = propose_surface_priority(
        _graph_with_endpoints(),
        client=BrokenClient(),  # type: ignore[arg-type]
    )
    assert result is None


class TestPriorityBonus:
    """Coordinator scoring integration with the surface-priority bonus."""

    def test_breaks_ties(self) -> None:
        from reachagent.graph.chain_solver import ChainSolver
        from reachagent.tools.coordinator_support import (
            CoordinatorCandidate,
            CoordinatorContext,
            clear_surface_priority,
            score,
            set_surface_priority,
        )

        g = _graph_with_endpoints()
        ctx = CoordinatorContext(graph=g, solver=ChainSolver(g))
        ep_a = _find_ep_by_path(g, "/admin")
        ep_s = _find_ep_by_path(g, "/static/app.js")
        cand_p = CoordinatorCandidate("seed", ep_a, None, context=ctx)
        cand_u = CoordinatorCandidate("seed", ep_s, None, context=ctx)

        clear_surface_priority()
        assert score(cand_p).score == score(cand_u).score
        set_surface_priority((ep_a,))
        assert score(cand_p).score > score(cand_u).score
        clear_surface_priority()

    def test_never_overrides_object_tier(self) -> None:
        """The flat bonus (+2) cannot override a higher sensitivity tier."""
        from reachagent.graph.chain_solver import ChainSolver
        from reachagent.graph.nodes import Object
        from reachagent.tools.coordinator_support import (
            CoordinatorCandidate,
            CoordinatorContext,
            clear_surface_priority,
            score,
            set_surface_priority,
        )

        g = _graph_with_endpoints()
        admin_id = _find_ep_by_path(g, "/admin")
        obj_node = g.add_object(Object(type="UserRecord", sensitivity_tier=3))
        g.add_returns(admin_id, obj_node)
        ctx = CoordinatorContext(graph=g, solver=ChainSolver(g))
        ep_s = _find_ep_by_path(g, "/static/app.js")
        cand_admin = CoordinatorCandidate("seed", admin_id, None, context=ctx)
        cand_static = CoordinatorCandidate("seed", ep_s, None, context=ctx)

        set_surface_priority((ep_s,))
        assert score(cand_admin).score > score(cand_static).score
        clear_surface_priority()
