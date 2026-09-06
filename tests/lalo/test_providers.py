"""Tests for the concrete provider adapters + build_router assembly."""

from __future__ import annotations

import httpx
import pytest

from lalo.core.config import load_settings
from lalo.core.errors import ProviderRefusalError, ProviderUnavailableError
from lalo.core.model_router import CompletionRequest, ModelRouter
from lalo.core.providers import (
    AnthropicProvider,
    OpenAICompatibleProvider,
    build_router,
    verify_provider,
    verify_router,
)
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


def test_anthropic_reports_real_token_usage() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "hi"}],
                "usage": {"input_tokens": 42, "output_tokens": 7},
            },
        )

    provider = AnthropicProvider(
        "k", model="claude-sonnet-5", client=httpx.Client(transport=httpx.MockTransport(ok))
    )
    response = provider.complete(CompletionRequest(prompt="x"))
    assert response.input_tokens == 42
    assert response.output_tokens == 7


def test_anthropic_missing_usage_leaves_tokens_none_not_zero() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"stop_reason": "end_turn", "content": [{"type": "text", "text": "hi"}]}
        )

    provider = AnthropicProvider(
        "k", model="m", client=httpx.Client(transport=httpx.MockTransport(ok))
    )
    response = provider.complete(CompletionRequest(prompt="x"))
    assert response.input_tokens is None
    assert response.output_tokens is None


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


def test_openai_compatible_reports_real_token_usage() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"finish_reason": "stop", "message": {"content": "hi"}}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 3},
            },
        )

    provider = OpenAICompatibleProvider(
        "gw",
        "k",
        model="m",
        base_url="http://x",
        client=httpx.Client(transport=httpx.MockTransport(ok)),
    )
    response = provider.complete(CompletionRequest(prompt="x"))
    assert response.input_tokens == 11
    assert response.output_tokens == 3


def test_openai_compatible_content_filter() -> None:
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


def test_openai_compatible_treats_explicit_null_content_as_empty_text() -> None:
    # A tool-call finish is a normal response shape where "content" is present
    # but explicitly null (not absent) -- CompletionResponse.text is typed str
    # and must never come back as None for this common, legitimate shape.
    def tool_call_finish(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {"content": None, "tool_calls": [{"id": "1"}]},
                    }
                ]
            },
        )

    provider = OpenAICompatibleProvider(
        "gw",
        "k",
        model="m",
        base_url="http://x",
        client=httpx.Client(transport=httpx.MockTransport(tool_call_finish)),
    )
    response = provider.complete(CompletionRequest(prompt="x"))
    assert response.text == ""
    assert isinstance(response.text, str)


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


def test_verify_provider_true_on_a_real_successful_completion() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"stop_reason": "end_turn", "content": [{"type": "text", "text": "ok"}]}
        )

    provider = AnthropicProvider(
        "k", model="m", client=httpx.Client(transport=httpx.MockTransport(ok))
    )
    healthy, message = verify_provider(provider)
    assert healthy is True
    assert message == "ok"


def test_verify_provider_false_on_a_refusal_never_raises() -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"stop_reason": "refusal", "content": []})

    provider = AnthropicProvider(
        "k", model="m", client=httpx.Client(transport=httpx.MockTransport(refused))
    )
    healthy, message = verify_provider(provider)
    assert healthy is False
    assert message


def test_verify_provider_false_on_an_unavailable_provider_never_raises() -> None:
    def bad(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={})

    provider = AnthropicProvider(
        "k", model="m", client=httpx.Client(transport=httpx.MockTransport(bad))
    )
    healthy, message = verify_provider(provider)
    assert healthy is False
    assert "401" in message


def test_verify_router_checks_every_configured_provider_independently() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"choices": [{"finish_reason": "stop", "message": {"content": "ok"}}]}
        )

    def broken(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={})

    healthy_provider = OpenAICompatibleProvider(
        "gw-a",
        "k",
        model="m",
        base_url="http://x",
        client=httpx.Client(transport=httpx.MockTransport(ok)),
    )
    broken_provider = OpenAICompatibleProvider(
        "gw-b",
        "k",
        model="m",
        base_url="http://y",
        client=httpx.Client(transport=httpx.MockTransport(broken)),
    )
    router = ModelRouter(providers={"gw-a": healthy_provider, "gw-b": broken_provider})
    results = verify_router(router)
    assert results["gw-a"] == (True, "ok")
    assert results["gw-b"][0] is False
