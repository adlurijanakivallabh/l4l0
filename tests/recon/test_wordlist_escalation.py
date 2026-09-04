"""Wordlist depth-escalation layer — LLM reasoning about a bigger follow-up wordlist.

Hermetic (no network). Mirrors tests/recon/test_depth_escalation.py's own
shape: floor semantics (operator's manual selection can only be strengthened,
never weakened), invalid-choice rejection, empty-graph, and
no-op-when-nothing-new-to-add. No flag gate (v4 R3 removed it) — a
configured client is used unconditionally.
"""

from __future__ import annotations

from reachagent.graph.nodes import Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.wordlist_escalation import (
    NO_ESCALATION,
    WordlistChoice,
    apply_floor,
    propose_wordlist_escalation,
)


def _graph_with_host() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(
        Host(address="target.test", hostname="target.test", source="nmap", technology="wordpress")
    )
    return g


class FakeTuner:
    def __init__(self, reply: dict[str, object]) -> None:
        self._reply = reply

    def propose(self, surface_summary: str, operator_prompt: str) -> dict[str, object]:
        return self._reply


def test_no_flag_needed_client_used_directly() -> None:
    """v4 R3: no REACHAGENT_WORDLIST_DEPTH_TUNING gate — a configured client
    is used unconditionally, not only when an env flag also happens to be set."""
    tuner = FakeTuner({"size": "large", "tech": "wordpress", "rationale": "wp detected"})
    result = propose_wordlist_escalation(_graph_with_host().hosts(), client=tuner)
    assert result is not None
    assert result.size == "large"
    assert result.tech == "wordpress"
    assert result.rationale == "wp detected"


def test_no_escalation_when_llm_sees_nothing_worth_it() -> None:
    tuner = FakeTuner({"size": "", "tech": ""})
    assert propose_wordlist_escalation(_graph_with_host().hosts(), client=tuner) is None


def test_invalid_size_and_tech_are_rejected_not_passed_through() -> None:
    tuner = FakeTuner({"size": "gigantic", "tech": "sharepoint"})
    # Neither value is on the validated allowlist -> normalized to "" -> nothing
    # beyond the (empty) floor.
    assert propose_wordlist_escalation(_graph_with_host().hosts(), client=tuner) is None


def test_operator_floor_is_never_dropped_even_if_llm_asks_for_less() -> None:
    """v3 V2 (operator feedback): an explicit operator selection is a floor the
    LLM's own decision must never weaken."""
    floor = WordlistChoice(size="large", tech="wordpress")
    tuner = FakeTuner({"size": "small", "tech": ""})
    result = propose_wordlist_escalation(_graph_with_host().hosts(), floor=floor, client=tuner)
    # The LLM asked for less than the floor on both axes, so no second pass is needed.
    assert result is None

    # The LLM proposing a DIFFERENT tech hint never overrides one the operator
    # specifically required — tech hints aren't linearly ordered, so
    # substituting one for another would silently drop the operator's ask.
    tuner2 = FakeTuner({"size": "small", "tech": "joomla"})
    result2 = propose_wordlist_escalation(_graph_with_host().hosts(), floor=floor, client=tuner2)
    assert result2 is None  # size floor already satisfies; tech floor authoritative


def test_llm_can_add_a_tech_hint_the_operator_left_unset() -> None:
    floor = WordlistChoice(size="large", tech="")  # operator only required "large"
    tuner = FakeTuner({"size": "small", "tech": "wordpress"})
    result = propose_wordlist_escalation(_graph_with_host().hosts(), floor=floor, client=tuner)
    assert result is not None
    assert result.size == "large"  # floor honored even though the LLM said "small"
    assert result.tech == "wordpress"  # LLM may add a hint the operator never set


def test_llm_can_escalate_beyond_an_explicit_small_floor() -> None:
    """Explicit config is a floor, never a ceiling — an operator's own 'small'
    (a preference for speed) must not cap the LLM from escalating further."""
    floor = WordlistChoice(size="small", tech="")
    tuner = FakeTuner({"size": "large", "tech": ""})
    result = propose_wordlist_escalation(_graph_with_host().hosts(), floor=floor, client=tuner)
    assert result is not None
    assert result.size == "large"


def test_empty_graph_returns_none() -> None:
    tuner = FakeTuner({"size": "large", "tech": "wordpress"})
    assert propose_wordlist_escalation(ReachabilityGraph().hosts(), client=tuner) is None


def test_client_error_returns_none() -> None:
    class Broken:
        def propose(self, *a: object) -> dict[str, object]:
            raise RuntimeError("LLM down")

    assert propose_wordlist_escalation(_graph_with_host().hosts(), client=Broken()) is None  # type: ignore[arg-type]


def test_apply_floor_only_ever_strengthens() -> None:
    floor = WordlistChoice(size="large", tech="")
    weaker = WordlistChoice(size="small", tech="")
    assert apply_floor(weaker, floor) == WordlistChoice(size="large", tech="")
    assert apply_floor(NO_ESCALATION, NO_ESCALATION) == NO_ESCALATION


def test_wordlist_choice_env_matches_resolver_env_vars() -> None:
    choice = WordlistChoice(size="large", tech="wordpress")
    assert choice.env() == {
        "REACHAGENT_WORDLIST_SIZE": "large",
        "REACHAGENT_WORDLIST_TECH": "wordpress",
    }
    assert NO_ESCALATION.env() == {}
