"""Concrete provider adapters + router/redactor assembly from :mod:`config`.

Three adapter kinds cover every curated provider: a native Anthropic Messages
API adapter, one generic OpenAI-compatible adapter (chat/completions schema)
that serves OpenAI itself, a local gateway, Gemini's OpenAI-compat endpoint, or
any custom endpoint — generalizing the "one generic credential for anything not
specially curated" idea into a real, reusable adapter rather than a bespoke
class per name — and one OpenAI-Responses-API adapter (``/v1/responses``, a
different wire shape) for gateways exposing that newer API instead.

A safety refusal maps to :class:`ProviderRefusalError` so the router fails over
to another provider rather than aborting the run.

:func:`verify_provider`/:func:`verify_router` are informed by a reference
platform's own ``backend/cmd/ctester`` (its standalone provider-capability-
test CLI, read in full) — see their own docstrings for what was adopted
(a real completion call confirming credentials actually work, not just that
an env var is set) versus what wasn't (a separate CLI tool, since L4L0 has
none by design).

:func:`_post_with_retry` closes a real gap found in an earlier, reference-informed Phase 0 pass:
that reference's own agent-execution-loop tests (``test_execution_transient_
retry.py``/``test_model_retry.py``, read via its comparison doc since the
retry classifier itself lives deep inside its third-party agent-SDK
integration) validate a transient-vs-permanent split — network/timeout/5xx/
429 errors are retried with backoff on the SAME model/connection, while a
definitive 4xx or safety-refusal fails fast, never retried. Each adapter here
already built ``_RETRYABLE_STATUS`` but never actually retried on it — a
single transient blip on the first (often free, local) provider in the
router's chain escalated straight to a paid hosted fallback with zero
retries at all. The retry loop lives here, at the single HTTP call each
adapter makes, so :class:`~lalo.core.model_router.ModelRouter` only considers
failing over to a *different* provider after this one has genuinely
exhausted its own chances — not on the first transient hiccup.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

from .config import ResolvedProvider, Settings
from .errors import ProviderRefusalError, ProviderUnavailableError
from .model_router import CompletionRequest, CompletionResponse, ModelRouter, Provider
from .redaction import shared_redactor

_RETRYABLE_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 529})
_MAX_ATTEMPTS = 3
_BASE_DELAY_S = 0.5


def _post_with_retry(
    client: httpx.Client,
    url: str,
    *,
    json: dict[str, object],
    headers: dict[str, str],
    sleep: Callable[[float], None] = time.sleep,
) -> httpx.Response:
    """POST with bounded retry-with-backoff, but ONLY for transient failures.

    A transport error (``httpx.HTTPError`` — DNS/connection/timeout) or a
    response in ``_RETRYABLE_STATUS`` is retried up to ``_MAX_ATTEMPTS`` times
    with exponential backoff; any other response (success or a definitive
    4xx) is returned immediately on the first attempt, unretried. The final
    attempt's exception/response is what the caller sees either way, so
    existing raise-on-failure logic in each adapter's ``complete`` needs no
    change beyond calling this instead of ``client.post`` directly.
    """
    for attempt in range(_MAX_ATTEMPTS):
        last_attempt = attempt == _MAX_ATTEMPTS - 1
        try:
            resp = client.post(url, json=json, headers=headers)
        except httpx.HTTPError:
            if last_attempt:
                raise
            sleep(_BASE_DELAY_S * (2**attempt))
            continue
        if resp.status_code not in _RETRYABLE_STATUS or last_attempt:
            return resp
        sleep(_BASE_DELAY_S * (2**attempt))
    raise AssertionError("unreachable")  # pragma: no cover


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
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._api_key = api_key
        self.model = model
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=120.0)
        self._sleep = sleep

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
            resp = _post_with_retry(
                self._client,
                f"{self._base_url}/v1/messages",
                json=payload,
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                sleep=self._sleep,
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
        usage = data.get("usage") or {}
        return CompletionResponse(
            text=text,
            provider=self.name,
            model=self.model,
            input_tokens=usage.get("input_tokens"),
            output_tokens=usage.get("output_tokens"),
        )


class _OpenAIStyleProvider:
    """Shared plumbing for every OpenAI-family adapter (auth header/prefix,
    retry-on-transient-status POST, httpx client lifecycle) — the part that
    was byte-for-byte identical across :class:`OpenAICompatibleProvider` and
    :class:`OpenAIResponsesProvider` before this base absorbed it. A new
    adapter for a genuinely new OpenAI-family wire shape only ever needs to
    implement ``complete()``'s payload-building and response-parsing;
    everything about getting a POST there and back (auth, retry, transport
    errors) is written once, here.
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
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.name = name
        self._api_key = api_key
        self.model = model
        self._base_url = base_url.rstrip("/")
        self._auth_header = auth_header
        self._auth_prefix = auth_prefix
        self._client = client or httpx.Client(timeout=120.0)
        self._sleep = sleep

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, Any]:
        """POST ``payload`` to ``{base_url}{path}`` with this provider's own
        auth header, retrying transient failures. Raises
        :class:`ProviderUnavailableError` for a transport error or a
        non-retryable-exhausted/4xx+ status; returns the parsed JSON body on
        any other response, leaving refusal/shape interpretation to the
        caller since that's the one genuinely wire-shape-specific part.
        """
        try:
            resp = _post_with_retry(
                self._client,
                f"{self._base_url}{path}",
                json=payload,
                headers={
                    self._auth_header: f"{self._auth_prefix}{self._api_key}",
                    "content-type": "application/json",
                },
                sleep=self._sleep,
            )
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(type(exc).__name__, provider=self.name) from exc
        if resp.status_code in _RETRYABLE_STATUS or resp.status_code >= 400:
            raise ProviderUnavailableError(f"http {resp.status_code}", provider=self.name)
        result: dict[str, Any] = resp.json()
        return result


class OpenAICompatibleProvider(_OpenAIStyleProvider):
    """Generic chat/completions-schema adapter — OpenAI/local-gateway/Gemini/custom.

    The auth header name/prefix are configurable per provider (most use
    ``Authorization: Bearer <key>``; a local gateway may use its own header),
    so this one class serves every ``openai_compatible`` curated entry.
    """

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
        data = self._post("/v1/chat/completions", payload)
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
        usage = data.get("usage") or {}
        return CompletionResponse(
            text=text,
            provider=self.name,
            model=self.model,
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
        )


class OpenAIResponsesProvider(_OpenAIStyleProvider):
    """OpenAI Responses-API adapter (``/v1/responses``) — a distinct wire
    shape from Chat Completions: ``input`` items instead of ``messages``,
    ``output`` items instead of ``choices``, ``max_output_tokens`` instead of
    ``max_tokens``. Used by gateways exposing the newer Responses API (the
    ``@ai-sdk/openai`` client convention is one such caller) rather than the
    older chat/completions endpoint :class:`OpenAICompatibleProvider` speaks.

    :class:`~lalo.core.model_router.CompletionRequest`/``Response`` stay
    identical either way — L4L0's own tool-calling protocol is a plain-text
    convention the agent loop itself parses out of ``text``, not either
    API's native structured function-calling, so this adapter only needs to
    translate one plain-text turn in and out, exactly like its sibling.
    """

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        input_items: list[dict[str, str]] = []
        if request.system:
            input_items.append({"role": "system", "content": request.system})
        input_items.append({"role": "user", "content": request.prompt})
        payload = {
            "model": self.model,
            "input": input_items,
            "max_output_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        data = self._post("/v1/responses", payload)
        # Output is a list of typed items (a "reasoning" item may precede the
        # "message" item for a reasoning model) - only "message" items carry
        # the actual reply text, as one or more content blocks.
        text_parts: list[str] = []
        for item in data.get("output", []):
            if item.get("type") != "message":
                continue
            for block in item.get("content", []):
                if block.get("type") == "refusal":
                    raise ProviderRefusalError(
                        block.get("refusal") or "model returned a refusal", provider=self.name
                    )
                if block.get("type") == "output_text":
                    text_parts.append(block.get("text", ""))
        usage = data.get("usage") or {}
        return CompletionResponse(
            text="".join(text_parts),
            provider=self.name,
            model=self.model,
            input_tokens=usage.get("input_tokens"),
            output_tokens=usage.get("output_tokens"),
        )


def _build_adapter(resolved: ResolvedProvider) -> Provider:
    if resolved.kind == "anthropic":
        return AnthropicProvider(resolved.api_key, model=resolved.model)
    if not resolved.base_url:
        raise ValueError(f"provider {resolved.id!r} is missing a base_url")
    if resolved.kind == "openai_responses":
        return OpenAIResponsesProvider(
            resolved.id,
            resolved.api_key,
            model=resolved.model,
            base_url=resolved.base_url,
            auth_header=resolved.auth_header,
            auth_prefix=resolved.auth_prefix,
        )
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


_VERIFY_PROMPT = "reply with exactly: ok"


def verify_provider(provider: Provider) -> tuple[bool, str]:
    """A minimal, cheap real completion call confirming ``provider`` actually
    works — not just that its credential env var was present.

    Informed by a reference agent's own ``ctester`` — a standalone CLI that
    instantiates each configured provider and runs a real capability-test
    battery before an operator commits to using it. That reference ships it
    as a separate CLI tool with its own Markdown/table report writer; L4L0
    has no CLI at all by design (GUI-only, per ``pyproject.toml``'s own
    stated convention), so the equivalent here is a single, small function a
    caller (e.g. :mod:`lalo.scan`, before ever starting the disposable
    container) can invoke directly — proving the router health-checks itself
    at the moment it's needed rather than requiring a separate tool a
    human remembers to run beforehand. ``load_settings``/``build_router``
    only ever check that a credential env var is *set*; a typo'd key, an
    expired key, or a wrong model/base-url for a custom gateway all
    currently surface only at the first real completion call deep into a
    live run, after the (potentially slow) container/OAST-server startup
    already happened for nothing.

    Never raises for an ordinary provider failure (refusal/unavailable) —
    returns ``(False, <reason>)`` instead, matching the ``Provider`` protocol's
    own "only ``ProviderRefusalError``/``ProviderUnavailableError`` are
    routine" contract; any other exception is a real bug and still propagates.
    """
    try:
        provider.complete(CompletionRequest(prompt=_VERIFY_PROMPT, max_tokens=10))
    except (ProviderRefusalError, ProviderUnavailableError) as exc:
        return False, str(exc)
    return True, "ok"


def verify_router(router: ModelRouter) -> dict[str, tuple[bool, str]]:
    """:func:`verify_provider` for every provider the router actually has,
    not just whichever one its own failover chain happens to try first —
    an operator with three configured providers wants to know all three are
    healthy, not just that the chain as a whole would succeed via the first
    one that works.
    """
    return {name: verify_provider(provider) for name, provider in router.providers.items()}
