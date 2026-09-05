"""Tests for the Anthropic provider adapter + router assembly."""

from __future__ import annotations

import httpx
import pytest

from lalo.core.config import ProviderConfig, Settings
from lalo.core.errors import ProviderRefusalError, ProviderUnavailableError
from lalo.core.model_router import CompletionRequest
from lalo.core.providers import AnthropicProvider, build_router


def _provider(handler: httpx.MockTransport) -> AnthropicProvider:
    return AnthropicProvider("test-key", client=httpx.Client(transport=handler))


def test_success_returns_text() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"stop_reason": "end_turn", "content": [{"type": "text", "text": "hi there"}]}
        )

    provider = _provider(httpx.MockTransport(handler))
    resp = provider.complete(CompletionRequest(prompt="hello"))
    assert resp.text == "hi there"
    assert resp.provider == "anthropic"


def test_refusal_maps_to_failover_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"stop_reason": "refusal", "content": []})

    provider = _provider(httpx.MockTransport(handler))
    with pytest.raises(ProviderRefusalError):
        provider.complete(CompletionRequest(prompt="x"))


def test_5xx_maps_to_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={})

    provider = _provider(httpx.MockTransport(handler))
    with pytest.raises(ProviderUnavailableError):
        provider.complete(CompletionRequest(prompt="x"))


def test_build_router_wires_configured_anthropic() -> None:
    settings = Settings(
        providers=(ProviderConfig(name="anthropic", api_key="k"),),
        routes={"reasoning": ("anthropic",)},
        default_route=("anthropic",),
    )
    router = build_router(settings)
    assert "anthropic" in router.providers
