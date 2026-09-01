"""LLM-confidence annotation — hermetic tests (Build Order 5).

Same propose/validate/fail-open pattern as guardian.advisor (see
tests/guardian/test_advisor.py).
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from reachagent.confirmation.confidence import annotate_confidence


def _fake_client(returning: dict[str, object]) -> Mock:
    m = Mock()
    m.propose.return_value = returning
    return m  # type: ignore[no-any-return]


def test_disabled_by_default_returns_no_annotation() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("REACHAGENT_CONFIDENCE_ANNOTATION", raising=False)
        result = annotate_confidence("sqli", "high", "oracle reason")
    assert result == {}


def test_flag_on_valid_response_is_returned() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("REACHAGENT_CONFIDENCE_ANNOTATION", "1")
        client = _fake_client({"confidence": "high", "rationale": "direct content match"})
        result = annotate_confidence("sqli", "high", "oracle reason", client=client)
    assert result == {"llm_confidence": "high", "llm_confidence_rationale": "direct content match"}


@pytest.mark.parametrize("level", ["high", "medium", "low"])
def test_every_allowed_confidence_level_is_accepted(level: str) -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("REACHAGENT_CONFIDENCE_ANNOTATION", "1")
        client = _fake_client({"confidence": level, "rationale": "x"})
        result = annotate_confidence("sqli", "high", "reason", client=client)
    assert result["llm_confidence"] == level


def test_invalid_confidence_level_fails_open_to_no_annotation() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("REACHAGENT_CONFIDENCE_ANNOTATION", "1")
        client = _fake_client({"confidence": "extremely-sure", "rationale": "x"})
        result = annotate_confidence("sqli", "high", "reason", client=client)
    assert result == {}


def test_unsupported_field_fails_open() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("REACHAGENT_CONFIDENCE_ANNOTATION", "1")
        client = _fake_client({"confidence": "high", "rationale": "x", "evil": "y"})
        result = annotate_confidence("sqli", "high", "reason", client=client)
    assert result == {}


def test_client_error_fails_open() -> None:
    boom = Mock()
    boom.propose.side_effect = RuntimeError("provider unavailable")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("REACHAGENT_CONFIDENCE_ANNOTATION", "1")
        result = annotate_confidence("sqli", "high", "reason", client=boom)
    assert result == {}


def test_rationale_is_truncated() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("REACHAGENT_CONFIDENCE_ANNOTATION", "1")
        client = _fake_client({"confidence": "high", "rationale": "x" * 1000})
        result = annotate_confidence("sqli", "high", "reason", client=client)
    assert len(result["llm_confidence_rationale"]) <= 300
