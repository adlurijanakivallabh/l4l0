"""Concrete provider adapters + router/redactor assembly from :mod:`config`.

Two adapter kinds cover every curated provider: a native Anthropic Messages API
adapter, and one generic OpenAI-compatible adapter (chat/completions schema)
that serves OpenAI itself, a local gateway, Gemini's OpenAI-compat endpoint, or
any custom endpoint — generalizing the "one generic credential for anything not
specially curated" idea into a real, reusable adapter rather than a bespoke
class per name.

A safety refusal maps to :class:`ProviderRefusalError` so the router fails over
to another provider rather than aborting the run.
"""

from __future__ import annotations

import httpx

from .config import ResolvedProvider, Settings
from .errors import ProviderRefusalError, ProviderUnavailableError
from .model_router import CompletionRequest, CompletionResponse, ModelRouter, Provider
from .redaction import shared_redactor

_RETRYABLE_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 529})


class AnthropicProvider:
    """Anthropic Messages API adapter over httpx."""

    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        *,
        model: str,
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

        if resp.status_code in _RETRYABLE_STATUS or resp.status_code >= 400:
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


class OpenAICompatibleProvider:
    """Generic chat/completions-schema adapter — OpenAI/local-gateway/Gemini/custom.

    The auth header name/prefix are configurable per provider (most use
    ``Authorization: Bearer <key>``; a local gateway may use its own header),
    so this one class serves every ``openai_compatible`` curated entry.
    """

    def __init__(
        self,
        name: str,
        api_key: str,
        *,
        model: str,
        base_url: str,
        auth_header: str = "Authorization",
        auth_prefix: str = "Bearer ",
        client: httpx.Client | None = None,
    ) -> None:
        self.name = name
        self._api_key = api_key
        self.model = model
        self._base_url = base_url.rstrip("/")
        self._auth_header = auth_header
        self._auth_prefix = auth_prefix
        self._client = client or httpx.Client(timeout=120.0)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        messages: list[dict[str, str]] = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        try:
            resp = self._client.post(
                f"{self._base_url}/v1/chat/completions",
                json=payload,
                headers={
                    self._auth_header: f"{self._auth_prefix}{self._api_key}",
                    "content-type": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(type(exc).__name__, provider=self.name) from exc
        if resp.status_code in _RETRYABLE_STATUS or resp.status_code >= 400:
            raise ProviderUnavailableError(f"http {resp.status_code}", provider=self.name)
        data = resp.json()
        choices = data.get("choices", [])
        finish = choices[0].get("finish_reason") if choices else None
        if finish == "content_filter":
            raise ProviderRefusalError("content_filter", provider=self.name)
        # `.get("content", "")` only defaults when the key is absent; a tool-call
        # finish (finish_reason="tool_calls") is a normal response shape where
        # "content" is present but explicitly null, so the fallback has to be
        # applied with `or`, not just a .get() default, to avoid returning None
        # for a dataclass field typed str.
        message = choices[0].get("message", {}) if choices else {}
        text = message.get("content") or ""
        return CompletionResponse(text=text, provider=self.name, model=self.model)


def _build_adapter(resolved: ResolvedProvider) -> Provider:
    if resolved.kind == "anthropic":
        return AnthropicProvider(resolved.api_key, model=resolved.model)
    if not resolved.base_url:
        raise ValueError(f"provider {resolved.id!r} is missing a base_url")
    return OpenAICompatibleProvider(
        resolved.id,
        resolved.api_key,
        model=resolved.model,
        base_url=resolved.base_url,
        auth_header=resolved.auth_header,
        auth_prefix=resolved.auth_prefix,
    )


def build_router(settings: Settings) -> ModelRouter:
    """Assemble a router from resolved settings and register every credential
    with the shared redactor, so a leaked key can never appear in a log/report.
    """
    redactor = shared_redactor()
    providers: dict[str, Provider] = {}
    for resolved in settings.resolved:
        redactor.register_secret(resolved.api_key)
        providers[resolved.id] = _build_adapter(resolved)
    role_chain = settings.failover_order
    return ModelRouter(
        providers=providers,
        routes={"reasoning": role_chain, "triage": role_chain, "report": role_chain},
        default_route=role_chain,
    )
