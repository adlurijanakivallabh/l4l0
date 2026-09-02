"""Hermetic tests for the OpenAI-compatible/DeepSeek adapter."""

from __future__ import annotations

import json

import httpx
import pytest

from reachagent.llm.client import (
    OpenAICompatibleClient,
    build_openai_compatible_client,
    extract_json_object,
    require_provider_config,
)


def test_deepseek_request_and_response_parsing() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["authorization"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": 'prefix {"profile_name":"api_target"}'}}]},
        )

    client = OpenAICompatibleClient(
        provider="deepseek",
        api_key="test-key",
        base_url="https://llm.test/v1",
        model="deepseek-v4-flash",
        transport=httpx.MockTransport(handler),
    )
    try:
        assert client.propose_json("choose a profile", max_tokens=64) == {
            "profile_name": "api_target"
        }
    finally:
        client.close()

    assert seen["url"] == "https://llm.test/v1/chat/completions"
    assert seen["authorization"] == "Bearer test-key"
    assert seen["body"] == {
        "model": "deepseek-v4-flash",
        "messages": [{"role": "user", "content": "choose a profile"}],
        "max_tokens": 64,
        "temperature": 0,
    }


def test_responses_api_request_and_response_parsing() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["authorization"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": 'prefix {"answer":2468}'}],
                    }
                ]
            },
        )

    client = OpenAICompatibleClient(
        provider="openai-compatible",
        api_key="test-key",
        base_url="https://llm.test/v1",
        model="model-under-test",
        api_style="responses",
        transport=httpx.MockTransport(handler),
    )
    try:
        assert client.propose_json("what is 1234+1234", max_tokens=64) == {"answer": 2468}
    finally:
        client.close()

    assert seen["url"] == "https://llm.test/v1/responses"
    assert seen["authorization"] == "Bearer test-key"
    assert seen["body"] == {
        "model": "model-under-test",
        "input": "what is 1234+1234",
        "max_output_tokens": 1024,
    }


def test_chat_multi_turn_sends_full_message_list() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "the login form is at /login"}}]},
        )

    client = OpenAICompatibleClient(
        provider="deepseek",
        api_key="test-key",
        base_url="https://llm.test/v1",
        model="deepseek-v4-flash",
        transport=httpx.MockTransport(handler),
    )
    messages = [
        {"role": "system", "content": "You are a read-only assistant."},
        {"role": "user", "content": "what have you found?"},
        {"role": "assistant", "content": "so far, one endpoint."},
        {"role": "user", "content": "where is the login?"},
    ]
    try:
        assert client.chat(messages, max_tokens=128) == "the login form is at /login"
    finally:
        client.close()

    assert seen["url"] == "https://llm.test/v1/chat/completions"
    assert seen["body"] == {
        "model": "deepseek-v4-flash",
        "messages": messages,
        "max_tokens": 128,
        "temperature": 0,
    }


def test_chat_rejects_empty_and_malformed_messages() -> None:
    client = OpenAICompatibleClient(
        provider="deepseek",
        api_key="test-key",
        base_url="https://llm.test/v1",
        model="m",
        transport=httpx.MockTransport(lambda _r: httpx.Response(500)),
    )
    try:
        with pytest.raises(ValueError, match="must not be empty"):
            client.chat([])
        with pytest.raises(ValueError, match="role must be"):
            client.chat([{"role": "tool", "content": "x"}])
        with pytest.raises(ValueError, match="content must be"):
            client.chat([{"role": "user", "content": "   "}])
    finally:
        client.close()


def test_complete_still_sends_single_user_message_unchanged() -> None:
    """Regression: complete()'s wire format must not change now that chat() exists."""
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client = OpenAICompatibleClient(
        provider="deepseek",
        api_key="test-key",
        base_url="https://llm.test/v1",
        model="deepseek-v4-flash",
        transport=httpx.MockTransport(handler),
    )
    try:
        assert client.complete("ping", max_tokens=8) == "ok"
    finally:
        client.close()
    assert seen["body"] == {
        "model": "deepseek-v4-flash",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 8,
        "temperature": 0,
    }


def test_missing_key_fails_before_network() -> None:
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    client = OpenAICompatibleClient(
        provider="deepseek",
        api_key="",
        base_url="https://llm.test",
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(RuntimeError, match="API key not set"):
            client.complete("hello")
    finally:
        client.close()
    assert not called


def test_generic_provider_does_not_guess_vendor_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "wrong-key")
    monkeypatch.delenv("REACHAGENT_LLM_API_KEY", raising=False)
    client = OpenAICompatibleClient(
        provider="openai-compatible",
        base_url="https://llm.test/v1",
        model="model-under-test",
    )
    try:
        with pytest.raises(RuntimeError, match="API key not set"):
            client.complete("hello")
    finally:
        client.close()


def test_generic_provider_requires_explicit_endpoint_and_model() -> None:
    with pytest.raises(ValueError, match="base URL is required"):
        OpenAICompatibleClient(provider="openai-compatible", api_key="test-key")
    with pytest.raises(ValueError, match="model is required"):
        OpenAICompatibleClient(
            provider="openai-compatible",
            api_key="test-key",
            base_url="https://llm.test/v1",
        )


def test_malformed_completion_is_rejected() -> None:
    client = OpenAICompatibleClient(
        provider="deepseek",
        api_key="test-key",
        base_url="https://llm.test",
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={"choices": []})),
    )
    try:
        with pytest.raises(ValueError, match="no choices"):
            client.complete("hello")
    finally:
        client.close()


def test_json_extraction_handles_fence_and_rejects_invalid() -> None:
    assert extract_json_object('```json\n{"a":{"b":1}}\n```') == {"a": {"b": 1}}
    with pytest.raises(ValueError, match="no JSON object"):
        extract_json_object("not json")


def test_factory_returns_none_for_unset_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_LLM_PROVIDER", raising=False)
    for name in (
        "REACHAGENT_LLM_API_KEY",
        "REACHAGENT_LLM_BASE_URL",
        "REACHAGENT_LLM_MODEL",
        "REACHAGENT_LLM_API_STYLE",
    ):
        monkeypatch.delenv(name, raising=False)
    assert build_openai_compatible_client() is None
    monkeypatch.setenv("REACHAGENT_LLM_PROVIDER", "deepseek")
    client = build_openai_compatible_client()
    assert client is not None
    client.close()


def test_grunt_tier_uses_the_configured_grunt_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """v2 W6: per-role model tiering. tier='grunt' with a configured grunt model
    overrides ONLY the model — same provider/key/base_url."""
    monkeypatch.setenv("REACHAGENT_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("REACHAGENT_DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setenv("REACHAGENT_DEEPSEEK_MODEL", "deepseek-chat")
    monkeypatch.setenv("REACHAGENT_LLM_GRUNT_MODEL", "deepseek-cheap")
    client = build_openai_compatible_client(tier="grunt")
    assert client is not None
    try:
        assert client.model == "deepseek-cheap"
        assert client.provider == "deepseek"
    finally:
        client.close()


def test_core_tier_ignores_the_grunt_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REACHAGENT_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("REACHAGENT_DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setenv("REACHAGENT_DEEPSEEK_MODEL", "deepseek-chat")
    monkeypatch.setenv("REACHAGENT_LLM_GRUNT_MODEL", "deepseek-cheap")
    client = build_openai_compatible_client()  # default tier="core"
    assert client is not None
    try:
        assert client.model == "deepseek-chat"
    finally:
        client.close()


def test_grunt_tier_with_no_grunt_model_configured_behaves_like_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REACHAGENT_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("REACHAGENT_DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setenv("REACHAGENT_DEEPSEEK_MODEL", "deepseek-chat")
    monkeypatch.delenv("REACHAGENT_LLM_GRUNT_MODEL", raising=False)
    client = build_openai_compatible_client(tier="grunt")
    assert client is not None
    try:
        assert client.model == "deepseek-chat"  # tiering is additive, never required
    finally:
        client.close()


def test_unknown_tier_raises() -> None:
    with pytest.raises(ValueError, match="tier must be"):
        build_openai_compatible_client(tier="ultra")  # type: ignore[arg-type]


def test_provider_preflight_requires_a_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_LLM_PROVIDER", raising=False)
    with pytest.raises(RuntimeError, match="no LLM provider configured"):
        require_provider_config(None)
    with pytest.raises(RuntimeError, match="no LLM provider configured"):
        require_provider_config("")


def test_provider_preflight_rejects_anthropic_as_unsupported() -> None:
    # anthropic was never a real supported provider (no SDK dependency, no
    # config) -- it must now fail clearly, not silently validate then crash
    # later trying to import a package that was never installed.
    with pytest.raises(ValueError, match="unsupported"):
        require_provider_config("anthropic")


def test_provider_preflight_checks_compatible_key_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("REACHAGENT_DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="API key is required"):
        require_provider_config("deepseek")
    monkeypatch.setenv("REACHAGENT_DEEPSEEK_API_KEY", "test-key")
    require_provider_config("deepseek")


# === Transient-gateway-error retry (§ LLM resilience) =======================
# A real proxy hiccup (502 from the LLM provider itself) used to crash the
# entire scan on the very first LLM call, with zero retry. Mirrors
# execution/firer.py's RequestFirer retry convention exactly.


def test_transient_502_is_retried_and_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    import reachagent.llm.client as client_mod

    monkeypatch.setattr(client_mod.time, "sleep", lambda _seconds: None)
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) < 2:
            return httpx.Response(502, text="bad gateway")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client = OpenAICompatibleClient(
        provider="deepseek",
        api_key="test-key",
        base_url="https://llm.test/v1",
        model="deepseek-v4-flash",
        transport=httpx.MockTransport(handler),
    )
    try:
        assert client.complete("hi", max_tokens=8) == "ok"
        assert len(attempts) == 2
    finally:
        client.close()


def test_persistent_502_raises_after_retry_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    import reachagent.llm.client as client_mod

    monkeypatch.setattr(client_mod.time, "sleep", lambda _seconds: None)
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(503, text="still down")

    client = OpenAICompatibleClient(
        provider="deepseek",
        api_key="test-key",
        base_url="https://llm.test/v1",
        model="deepseek-v4-flash",
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(httpx.HTTPStatusError):
            client.complete("hi", max_tokens=8)
        # Initial attempt + _LLM_RETRY_LIMIT (2) retries = 3 total.
        assert len(attempts) == 3
    finally:
        client.close()


def test_a_genuine_4xx_is_never_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    import reachagent.llm.client as client_mod

    monkeypatch.setattr(
        client_mod.time,
        "sleep",
        lambda _s: (_ for _ in ()).throw(AssertionError("must not retry a 4xx")),
    )
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(401, text="bad key")

    client = OpenAICompatibleClient(
        provider="deepseek",
        api_key="test-key",
        base_url="https://llm.test/v1",
        model="deepseek-v4-flash",
        transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(httpx.HTTPStatusError):
            client.complete("hi", max_tokens=8)
        assert len(attempts) == 1
    finally:
        client.close()
