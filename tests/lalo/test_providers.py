"""Tests for the concrete provider adapters + build_router assembly."""

from __future__ import annotations

import httpx
import pytest

from lalo.core.config import load_settings
from lalo.core.errors import ProviderRefusalError, ProviderUnavailableError
from lalo.core.model_router import CompletionRequest
from lalo.core.providers import AnthropicProvider, OpenAICompatibleProvider, build_router
from lalo.core.redaction import redact


def test_anthropic_success_and_refusal() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"stop_reason": "end_turn", "content": [{"type": "text", "text": "hi"}]}
        )

    provider = AnthropicProvider(
        "k", model="claude-sonnet-5", client=httpx.Client(transport=httpx.MockTransport(ok))
    )
    assert provider.complete(CompletionRequest(prompt="x")).text == "hi"

    def refused(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"stop_reason": "refusal", "content": []})

    blocked = AnthropicProvider(
        "k", model="m", client=httpx.Client(transport=httpx.MockTransport(refused))
    )
    with pytest.raises(ProviderRefusalError):
        blocked.complete(CompletionRequest(prompt="x"))


def test_anthropic_5xx_maps_to_unavailable() -> None:
    def bad(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={})

    provider = AnthropicProvider(
        "k", model="m", client=httpx.Client(transport=httpx.MockTransport(bad))
    )
    with pytest.raises(ProviderUnavailableError):
        provider.complete(CompletionRequest(prompt="x"))


def test_openai_compatible_success_and_content_filter() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-custom-auth"] == "prefix-k"
        return httpx.Response(
            200, json={"choices": [{"finish_reason": "stop", "message": {"content": "hi"}}]}
        )

    provider = OpenAICompatibleProvider(
        "gw",
        "k",
        model="m",
        base_url="http://x",
        auth_header="x-custom-auth",
        auth_prefix="prefix-",
        client=httpx.Client(transport=httpx.MockTransport(ok)),
    )
    assert provider.complete(CompletionRequest(prompt="x")).text == "hi"

    def filtered(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"choices": [{"finish_reason": "content_filter", "message": {}}]}
        )

    blocked = OpenAICompatibleProvider(
        "gw",
        "k",
        model="m",
        base_url="http://x",
        client=httpx.Client(transport=httpx.MockTransport(filtered)),
    )
    with pytest.raises(ProviderRefusalError):
        blocked.complete(CompletionRequest(prompt="x"))


def test_build_router_wires_configured_providers_and_registers_secrets() -> None:
    settings = load_settings({"ANTHROPIC_API_KEY": "sk-ant-super-secret-value-123456"})
    router = build_router(settings)
    assert "anthropic" in router.providers
    # The credential is now redacted everywhere via the shared instance.
    assert "sk-ant-super-secret-value-123456" not in redact("key=sk-ant-super-secret-value-123456")


def test_build_router_empty_when_nothing_configured() -> None:
    router = build_router(load_settings({}))
    assert router.providers == {}
    assert router.default_route == ()
