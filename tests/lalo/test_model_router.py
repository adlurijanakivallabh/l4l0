"""Tests for the multi-provider model router's failover contract."""

from __future__ import annotations

import pytest

from lalo.core.errors import (
    AllProvidersFailedError,
    ProviderRefusalError,
    ProviderUnavailableError,
)
from lalo.core.model_router import (
    CompletionRequest,
    CompletionResponse,
    ModelRouter,
)


class _FakeProvider:
    """A provider whose behavior is scripted for the test."""

    def __init__(self, name: str, *, raises: Exception | None = None, text: str = "ok") -> None:
        self.name = name
        self._raises = raises
        self._text = text
        self.calls = 0

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return CompletionResponse(text=self._text, provider=self.name, model=f"{self.name}-model")


def _router(*providers: _FakeProvider, chain: tuple[str, ...]) -> ModelRouter:
    return ModelRouter(
        providers={p.name: p for p in providers},
        routes={"reasoning": chain},
    )


def test_first_provider_serves_when_healthy() -> None:
    a = _FakeProvider("a", text="from-a")
    b = _FakeProvider("b", text="from-b")
    router = _router(a, b, chain=("a", "b"))
    resp = router.complete("reasoning", CompletionRequest(prompt="hi"))
    assert resp.text == "from-a"
    assert a.calls == 1 and b.calls == 0


def test_refusal_fails_over_to_next_provider() -> None:
    a = _FakeProvider("a", raises=ProviderRefusalError("declined", provider="a"))
    b = _FakeProvider("b", text="from-b")
    router = _router(a, b, chain=("a", "b"))
    resp = router.complete("reasoning", CompletionRequest(prompt="hi"))
    assert resp.provider == "b"
    assert a.calls == 1 and b.calls == 1


def test_unavailable_fails_over() -> None:
    a = _FakeProvider("a", raises=ProviderUnavailableError("503", provider="a"))
    b = _FakeProvider("b", text="from-b")
    router = _router(a, b, chain=("a", "b"))
    assert router.complete("reasoning", CompletionRequest(prompt="hi")).provider == "b"


def test_missing_provider_in_chain_is_skipped() -> None:
    b = _FakeProvider("b", text="from-b")
    router = _router(b, chain=("a", "b"))  # "a" not registered
    assert router.complete("reasoning", CompletionRequest(prompt="hi")).provider == "b"


def test_all_failing_raises_with_failure_trail() -> None:
    a = _FakeProvider("a", raises=ProviderRefusalError("no", provider="a"))
    b = _FakeProvider("b", raises=ProviderUnavailableError("no", provider="b"))
    router = _router(a, b, chain=("a", "b"))
    with pytest.raises(AllProvidersFailedError) as exc:
        router.complete("reasoning", CompletionRequest(prompt="hi"))
    assert exc.value.role == "reasoning"
    assert ("a", "provider_refusal") in exc.value.failures  # type: ignore[operator]
    assert ("b", "provider_unavailable") in exc.value.failures  # type: ignore[operator]


def test_no_chain_configured_raises() -> None:
    router = ModelRouter(providers={}, routes={})
    with pytest.raises(AllProvidersFailedError):
        router.complete("reasoning", CompletionRequest(prompt="hi"))


def test_non_failover_exception_propagates() -> None:
    a = _FakeProvider("a", raises=ValueError("real bug"))
    router = _router(a, chain=("a",))
    with pytest.raises(ValueError, match="real bug"):
        router.complete("reasoning", CompletionRequest(prompt="hi"))
