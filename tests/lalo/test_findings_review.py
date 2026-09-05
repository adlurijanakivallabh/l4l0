"""Tests for the LLM adversarial review step."""

from __future__ import annotations

from lalo.core.errors import AllProvidersFailedError
from lalo.core.model_router import CompletionRequest, CompletionResponse, ModelRouter
from lalo.findings.confidence import compute_confidence
from lalo.findings.review import ReviewVerdict, run_adversarial_review
from lalo.graph.model import NodeKind, ReachabilityGraph


class _FakeProvider:
    def __init__(self, *, text: str = "", raises: Exception | None = None) -> None:
        self.name = "fake"
        self._text = text
        self._raises = raises
        self.seen_prompts: list[CompletionRequest] = []

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.seen_prompts.append(request)
        if self._raises is not None:
            raise self._raises
        return CompletionResponse(text=self._text, provider=self.name, model="fake-model")


def _router(provider: _FakeProvider) -> ModelRouter:
    return ModelRouter(providers={"fake": provider}, routes={"review": ("fake",)})


def _graph_with_finding(**attrs: object) -> tuple[ReachabilityGraph, str]:
    graph = ReachabilityGraph()
    merged: dict[str, object] = {
        "vuln_class": "sql-injection",
        "target": "https://x.example.com/search",
        "param": "q",
        "evidence": ["syntax error near 'OR'"],
        "evidence_excerpt": "syntax error near 'OR'",
        "evidence_grounded": True,
        "description": "the finder's own narrative - must never reach the prompt",
        "counterevidence": "the finder's own case against itself - must never reach the prompt",
        **attrs,
    }
    graph.add_node("f1", NodeKind.FINDING, **merged)
    return graph, "f1"


def test_confirmed_verdict_boosts_the_score() -> None:
    provider = _FakeProvider(
        text='{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded in evidence"}'
    )
    graph, finding_id = _graph_with_finding()
    confidence = compute_confidence(graph, finding_id)
    result = run_adversarial_review(graph, finding_id, confidence, _router(provider))
    assert result.verdict is ReviewVerdict.CONFIRMED
    assert result.proof_level == "L3"
    assert result.adjusted_score == min(100, confidence.score + 10)


def test_ruled_out_verdict_sharply_lowers_but_never_zeroes_out_by_itself() -> None:
    provider = _FakeProvider(
        text='{"verdict": "ruled_out", "proof_level": "L1", "reasoning": "not in evidence"}'
    )
    graph, finding_id = _graph_with_finding()
    confidence = compute_confidence(graph, finding_id)
    result = run_adversarial_review(graph, finding_id, confidence, _router(provider))
    assert result.verdict is ReviewVerdict.RULED_OUT
    assert result.adjusted_score == max(0, confidence.score - 50)


def test_open_proof_gap_is_a_moderate_adjustment() -> None:
    provider = _FakeProvider(
        text='{"verdict": "open_proof_gap", "proof_level": "L2", "reasoning": "insufficient"}'
    )
    graph, finding_id = _graph_with_finding()
    confidence = compute_confidence(graph, finding_id)
    result = run_adversarial_review(graph, finding_id, confidence, _router(provider))
    assert result.verdict is ReviewVerdict.OPEN_PROOF_GAP
    assert result.adjusted_score == max(0, confidence.score - 20)


def test_the_finders_own_prose_never_reaches_the_prompt() -> None:
    provider = _FakeProvider(text='{"verdict": "confirmed", "proof_level": "L3"}')
    graph, finding_id = _graph_with_finding()
    confidence = compute_confidence(graph, finding_id)
    run_adversarial_review(graph, finding_id, confidence, _router(provider))
    sent = provider.seen_prompts[0].prompt
    assert "must never reach the prompt" not in sent


def test_a_total_provider_failure_degrades_to_open_proof_gap_not_a_crash() -> None:
    provider = _FakeProvider(raises=AllProvidersFailedError("all down", role="review", failures=[]))
    graph, finding_id = _graph_with_finding()
    confidence = compute_confidence(graph, finding_id)
    result = run_adversarial_review(graph, finding_id, confidence, _router(provider))
    assert result.verdict is ReviewVerdict.OPEN_PROOF_GAP
    assert result.adjusted_score == confidence.score


def test_an_unparseable_response_degrades_to_open_proof_gap_not_a_crash() -> None:
    provider = _FakeProvider(text="I refuse to answer in JSON.")
    graph, finding_id = _graph_with_finding()
    confidence = compute_confidence(graph, finding_id)
    result = run_adversarial_review(graph, finding_id, confidence, _router(provider))
    assert result.verdict is ReviewVerdict.OPEN_PROOF_GAP
    assert result.adjusted_score == confidence.score


def test_an_unrecognized_verdict_degrades_to_open_proof_gap_not_a_crash() -> None:
    provider = _FakeProvider(text='{"verdict": "definitely maybe", "proof_level": "L3"}')
    graph, finding_id = _graph_with_finding()
    confidence = compute_confidence(graph, finding_id)
    result = run_adversarial_review(graph, finding_id, confidence, _router(provider))
    assert result.verdict is ReviewVerdict.OPEN_PROOF_GAP
    assert result.adjusted_score == confidence.score


def test_an_invalid_proof_level_falls_back_to_l1_without_failing_the_review() -> None:
    provider = _FakeProvider(text='{"verdict": "confirmed", "proof_level": "L99"}')
    graph, finding_id = _graph_with_finding()
    confidence = compute_confidence(graph, finding_id)
    result = run_adversarial_review(graph, finding_id, confidence, _router(provider))
    assert result.verdict is ReviewVerdict.CONFIRMED
    assert result.proof_level == "L1"


def test_the_verdict_is_persisted_onto_the_findings_own_graph_node() -> None:
    """A report generated from `graph` afterward has to be able to see this -
    nothing else in the codebase ever writes a review verdict onto a node."""
    provider = _FakeProvider(
        text='{"verdict": "confirmed", "proof_level": "L3", "reasoning": "grounded"}'
    )
    graph, finding_id = _graph_with_finding()
    confidence = compute_confidence(graph, finding_id)
    result = run_adversarial_review(graph, finding_id, confidence, _router(provider))
    node = graph.node(finding_id)
    assert node["review_verdict"] == result.verdict.value == "confirmed"
    assert node["review_proof_level"] == result.proof_level == "L3"
    assert node["review_reasoning"] == result.reasoning == "grounded"


def test_persisting_the_verdict_never_clobbers_the_findings_other_attributes() -> None:
    graph, finding_id = _graph_with_finding()
    confidence = compute_confidence(graph, finding_id)
    provider = _FakeProvider(text='{"verdict": "ruled_out", "proof_level": "L1"}')
    run_adversarial_review(graph, finding_id, confidence, _router(provider))
    node = graph.node(finding_id)
    assert node["vuln_class"] == "sql-injection"
    assert node["kind"] == NodeKind.FINDING.value


def test_score_never_exceeds_100_or_drops_below_0() -> None:
    provider_high = _FakeProvider(text='{"verdict": "confirmed", "proof_level": "L4"}')
    graph, finding_id = _graph_with_finding(
        reproduced=True,
        evidence=["a", "b", "c", "d"],
        evidence_excerpt="a genuinely long and specific proof excerpt for max score",
        identities_confirmed=["alice", "bob"],
    )
    confidence = compute_confidence(graph, finding_id)
    result = run_adversarial_review(graph, finding_id, confidence, _router(provider_high))
    assert result.adjusted_score <= 100

    provider_low = _FakeProvider(text='{"verdict": "ruled_out", "proof_level": "L1"}')
    graph2, finding_id2 = _graph_with_finding(evidence_grounded=False, evidence=[])
    confidence2 = compute_confidence(graph2, finding_id2)
    result2 = run_adversarial_review(graph2, finding_id2, confidence2, _router(provider_low))
    assert result2.adjusted_score >= 0
