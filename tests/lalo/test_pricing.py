"""Tests for dollar-cost estimation from real token counts."""

from __future__ import annotations

from lalo.core.model_router import CompletionResponse
from lalo.core.pricing import estimate_cost_usd


def _response(
    input_tokens: int | None, output_tokens: int | None, model: str = "m"
) -> CompletionResponse:
    return CompletionResponse(
        text="x", provider="p", model=model, input_tokens=input_tokens, output_tokens=output_tokens
    )


def test_estimate_cost_computes_from_real_token_counts() -> None:
    response = _response(input_tokens=1_000_000, output_tokens=500_000, model="claude-sonnet-5")
    table = {"claude-sonnet-5": (3.0, 15.0)}  # $3/1M input, $15/1M output
    assert estimate_cost_usd(response, table) == 3.0 + 7.5


def test_estimate_cost_returns_none_for_unknown_model_never_zero() -> None:
    """Cost for a model with no pricing entry is unknown, not free - a bare
    `0.0` would be indistinguishable from a genuinely confirmed free model."""
    response = _response(input_tokens=100, output_tokens=100, model="some-new-model")
    assert estimate_cost_usd(response, {"claude-sonnet-5": (3.0, 15.0)}) is None


def test_estimate_cost_returns_none_when_tokens_are_unknown() -> None:
    response = _response(input_tokens=None, output_tokens=None, model="claude-sonnet-5")
    assert estimate_cost_usd(response, {"claude-sonnet-5": (3.0, 15.0)}) is None


def test_estimate_cost_with_an_empty_pricing_table_is_always_none() -> None:
    response = _response(input_tokens=100, output_tokens=100, model="claude-sonnet-5")
    assert estimate_cost_usd(response, {}) is None
