"""Concrete LLM provider adapters + router assembly.

Providers speak the router's :class:`CompletionRequest`/:class:`CompletionResponse`
contract and raise the two failover-eligible errors. A safety refusal maps to
:class:`ProviderRefusalError` so the router fails over to another provider rather
than aborting the run (this is the fix for the provider-refusal problem).
"""

from __future__ import annotations

import httpx

from .config import Settings
from .errors import ProviderRefusalError, ProviderUnavailableError
from .model_router import CompletionRequest, CompletionResponse, ModelRouter, Provider

_RETRYABLE_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 529})


class AnthropicProvider:
    """Anthropic Messages API adapter over httpx."""

    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        *,
        model: str = "claude-sonnet-5",
        client: httpx.Client | None = None,
        base_url: str = "https://api.anthropic.com",
    ) -> None:
        self._api_key = api_key
        self.model = model
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=120.0)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        payload: dict[str, object] = {
            "model": self.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if request.system:
            payload["system"] = request.system
        try:
            resp = self._client.post(
                f"{self._base_url}/v1/messages",
                json=payload,
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(type(exc).__name__, provider=self.name) from exc

        if resp.status_code in _RETRYABLE_STATUS:
            raise ProviderUnavailableError(f"http {resp.status_code}", provider=self.name)
        if resp.status_code >= 400:
            raise ProviderUnavailableError(f"http {resp.status_code}", provider=self.name)

        data = resp.json()
        if data.get("stop_reason") == "refusal":
            raise ProviderRefusalError("model returned a refusal stop", provider=self.name)
        text = "".join(
            block.get("text", "")
            for block in data.get("content", [])
            if block.get("type") == "text"
        )
        return CompletionResponse(text=text, provider=self.name, model=self.model)


def build_router(settings: Settings) -> ModelRouter:
    """Assemble a router from settings, wiring adapters for configured providers."""
    providers: dict[str, Provider] = {}
    for cfg in settings.providers:
        if cfg.name == "anthropic" and cfg.api_key:
            providers["anthropic"] = AnthropicProvider(
                cfg.api_key, model=cfg.model or "claude-sonnet-5"
            )
        # OpenAI / Gemini / local adapters slot in here as they are added.
    return ModelRouter(
        providers=providers,
        routes=settings.routes,
        default_route=settings.default_route,
    )
