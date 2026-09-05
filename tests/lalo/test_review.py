"""Tests for the adversarial confirmation review (LLM-driven, evidence-grounded)."""

from __future__ import annotations

from lalo.confirmation import adversarial_review, apply_review
from lalo.confirmation.review import _parse_verdict
from lalo.core.model_router import CompletionRequest, CompletionResponse, ModelRouter
from lalo.models import Evidence, EvidenceKind, Finding, Severity


class _Provider:
    name = "scripted"

    def __init__(self, text: str) -> None:
        self._text = text

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.last_prompt = request.prompt
        return CompletionResponse(text=self._text, provider=self.name, model="scripted")


def _router(text: str) -> ModelRouter:
    return ModelRouter(providers={"scripted": _Provider(text)}, routes={"reasoning": ("scripted",)})


def _finding() -> Finding:
    f = Finding.create("SQLi in id", "sqli", Severity.HIGH, "https://app/item")
    f.evidence.append(
        Evidence(EvidenceKind.STRUCTURAL, "db error", fire_ref="r1", observed="SQL syntax error")
    )
    f.confidence = 40.0
    return f


def test_confirmed_verdict_raises_confidence_by_proof_level() -> None:
    reply = '{"verdict":"confirmed","proof_level":3,"counterevidence":"none","reasoning":"real"}'
    router = _router(reply)
    v = adversarial_review(_finding(), {"r1": "... SQL syntax error near ..."}, router)
    assert v.verdict == "confirmed" and v.proof_level == 3
    f = _finding()
    apply_review(f, v)
    assert f.confidence >= 85.0  # 40 + 15*3 floor
    assert f.metadata["proof_level"] == 3


def test_ruled_out_lowers_confidence_but_keeps_finding() -> None:
    reply = '{"verdict":"ruled_out","proof_level":1,"counterevidence":"num cast","reasoning":"c"}'
    router = _router(reply)
    f = _finding()
    v = adversarial_review(f, {"r1": "SQL syntax error"}, router)
    apply_review(f, v)
    assert f.confidence < 40.0  # lowered
    assert f.metadata["review_flag"] == "ruled_out_by_adversarial_review"
    assert f.counterevidence  # counterevidence captured


def test_unparseable_review_fails_closed_to_open_gap() -> None:
    v = _parse_verdict("I cannot produce JSON right now, sorry.")
    assert v.verdict == "open_proof_gap"


def test_review_grounds_evidence_against_captures() -> None:
    # An observed string NOT in captures is shown as UNVERIFIED to the validator.
    reply = '{"verdict":"open_proof_gap","proof_level":1,"counterevidence":"","reasoning":"x"}'
    provider = _Provider(reply)
    router = ModelRouter(providers={"scripted": provider}, routes={"reasoning": ("scripted",)})
    f = _finding()
    f.evidence[0].observed = "this text is NOT in the capture"
    adversarial_review(f, {"r1": "completely different body"}, router)
    assert "UNVERIFIED" in provider.last_prompt
