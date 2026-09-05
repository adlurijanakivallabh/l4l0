"""Tests for the Anthropic provider adapter + router assembly."""

from __future__ import annotations

import httpx
import pytest

from lalo.core.config import ProviderConfig, Settings
from lalo.core.errors import ProviderRefusalError, ProviderUnavailableError
from lalo.core.model_router import CompletionRequest
from lalo.core.providers import AnthropicProvider, OpenCodexProvider, build_router


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


def test_opencodex_success_and_refusal() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"finish_reason": "stop", "message": {"content": "hi"}}]},
        )

    provider = OpenCodexProvider("k", client=httpx.Client(transport=httpx.MockTransport(ok)))
    assert provider.complete(CompletionRequest(prompt="x")).text == "hi"

    def filtered(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"choices": [{"finish_reason": "content_filter", "message": {}}]}
        )

    blocked = OpenCodexProvider("k", client=httpx.Client(transport=httpx.MockTransport(filtered)))
    with pytest.raises(ProviderRefusalError):
        blocked.complete(CompletionRequest(prompt="x"))


def test_build_router_wires_opencodex() -> None:
    settings = Settings(
        providers=(ProviderConfig(name="opencodex", api_key="k", model="gpt-5.6-luna"),),
        routes={"reasoning": ("opencodex",)},
        default_route=("opencodex",),
    )
    assert "opencodex" in build_router(settings).providers


def test_build_router_wires_configured_anthropic() -> None:
    settings = Settings(
        providers=(ProviderConfig(name="anthropic", api_key="k"),),
        routes={"reasoning": ("anthropic",)},
        default_route=("anthropic",),
    )
    router = build_router(settings)
    assert "anthropic" in router.providers
