"""nmap depth-escalation layer — LLM reasoning about deeper follow-up passes.

Hermetic (no network). Covers: floor semantics (operator's manual selection
can only be strengthened, never weakened), disruptive-category rejection,
empty-graph, and no-op-when-nothing-new-to-add. No flag gate (v4 R3 removed
it) — a configured client is used unconditionally.
"""

from __future__ import annotations

from reachagent.graph.nodes import Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.depth_escalation import (
    NO_ESCALATION,
    DepthChoice,
    apply_floor,
    propose_depth_escalation,
)


def _graph_with_host() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(
        Host(address="target.test", hostname="target.test", source="nmap", technology="nginx")
    )
    return g


class FakeTuner:
    def __init__(self, reply: dict[str, object]) -> None:
        self._reply = reply

    def propose(self, surface_summary: str, operator_prompt: str) -> dict[str, object]:
        return self._reply


def test_no_flag_needed_client_used_directly() -> None:
    """v4 R3: no REACHAGENT_RECON_DEPTH_TUNING gate — a configured client is
    used unconditionally, not only when an env flag also happens to be set."""
    tuner = FakeTuner({"widen_ports": True, "script_category": "vuln", "rationale": "odd port"})
    result = propose_depth_escalation(_graph_with_host().hosts(), client=tuner)
    assert result is not None
    assert result.widen_ports is True
    assert result.script_category == "vuln"
    assert result.rationale == "odd port"


def test_no_escalation_when_llm_sees_nothing_worth_it() -> None:
    tuner = FakeTuner({"widen_ports": False, "script_category": "none"})
    assert propose_depth_escalation(_graph_with_host().hosts(), client=tuner) is None


def test_disruptive_category_is_rejected_not_passed_through() -> None:
    tuner = FakeTuner({"widen_ports": False, "script_category": "exploit"})
    # "exploit" is invalid -> normalized to "none" -> nothing beyond the (empty) floor.
    assert propose_depth_escalation(_graph_with_host().hosts(), client=tuner) is None


def test_operator_floor_is_never_dropped_even_if_llm_asks_for_less() -> None:
    """v3 V2 (operator feedback): an explicit operator selection is a floor the
    LLM's own decision must never weaken."""
    floor = DepthChoice(widen_ports=True, script_category="vuln")
    tuner = FakeTuner({"widen_ports": False, "script_category": "none"})
    result = propose_depth_escalation(_graph_with_host().hosts(), floor=floor, client=tuner)
    # The LLM asked for nothing beyond the floor, so no second pass is needed.
    assert result is None

    # The LLM proposing a DIFFERENT category never overrides one the operator
    # specifically required — script categories aren't linearly ordered, so
    # substituting one for another would silently drop the operator's ask.
    tuner2 = FakeTuner({"widen_ports": False, "script_category": "default"})
    result2 = propose_depth_escalation(_graph_with_host().hosts(), floor=floor, client=tuner2)
    assert result2 is None  # widen_ports floor already satisfied, category floor authoritative


def test_llm_can_add_a_category_the_operator_left_unset() -> None:
    floor = DepthChoice(widen_ports=True, script_category="none")  # operator only required "full"
    tuner = FakeTuner({"widen_ports": False, "script_category": "vuln"})
    result = propose_depth_escalation(_graph_with_host().hosts(), floor=floor, client=tuner)
    assert result is not None
    assert result.widen_ports is True  # floor honored even though the LLM said False
    assert result.script_category == "vuln"  # LLM may add a category the operator never set


def test_empty_graph_returns_none() -> None:
    tuner = FakeTuner({"widen_ports": True, "script_category": "vuln"})
    assert propose_depth_escalation(ReachabilityGraph().hosts(), client=tuner) is None


def test_client_error_returns_none() -> None:
    class Broken:
        def propose(self, *a: object) -> dict[str, object]:
            raise RuntimeError("LLM down")

    assert propose_depth_escalation(_graph_with_host().hosts(), client=Broken()) is None  # type: ignore[arg-type]


def test_apply_floor_only_ever_strengthens() -> None:
    floor = DepthChoice(widen_ports=True, script_category="none")
    weaker = DepthChoice(widen_ports=False, script_category="none")
    assert apply_floor(weaker, floor) == DepthChoice(widen_ports=True, script_category="none")
    assert apply_floor(NO_ESCALATION, NO_ESCALATION) == NO_ESCALATION


def test_depth_choice_env_matches_nmap_env_vars() -> None:
    choice = DepthChoice(widen_ports=True, script_category="vuln")
    assert choice.env() == {
        "REACHAGENT_NMAP_WIDEN_PORTS": "1",
        "REACHAGENT_NMAP_SCRIPT_CATEGORY": "vuln",
    }
    assert NO_ESCALATION.env() == {}
