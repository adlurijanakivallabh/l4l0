"""HTTPX client for configurable OpenAI-compatible LLM APIs.

The client is provider-neutral and supports both Chat Completions and Responses
JSON shapes, selected by configuration. It returns model text or a parsed JSON
object; callers still own their allowlists and validation. No tool execution or
finding creation belongs here.
"""

from __future__ import annotations

import json
import os
import time
from json import JSONDecodeError
from typing import Final

import httpx

_DEEPSEEK_BASE_URL: Final = "https://api.deepseek.com"
_OPENAI_BASE_URL: Final = "https://api.openai.com/v1"
_DEFAULT_DEEPSEEK_MODEL: Final = "deepseek-chat"
_DEFAULT_OPENAI_MODEL: Final = "gpt-4o-mini"
_SUPPORTED_PROVIDERS: Final = frozenset({"deepseek", "openai", "openai-compatible"})
_SUPPORTED_API_STYLES: Final = frozenset({"chat_completions", "responses"})
_MIN_RESPONSES_OUTPUT_TOKENS: Final = 1024
# Same convention as execution/firer.py's RequestFirer: a transient gateway
# error from the LLM provider itself (a proxy hiccup, an upstream restart)
# used to crash the entire scan on the very first LLM call of a phase, with
# no retry at all. Only 502/503/504 are retried -- a genuine 4xx (bad key,
# malformed request) retrying would never succeed and shouldn't be masked.
_LLM_RETRY_LIMIT: Final = 2
_LLM_RETRY_BACKOFF: Final[tuple[float, ...]] = (0.5, 1.0)
_LLM_RETRY_STATUSES: Final = frozenset({502, 503, 504})


def _first_env(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def _provider_name(provider: str) -> str:
    normalized = provider.strip().lower().replace("_", "-")
    if normalized == "openai_compatible":
        normalized = "openai-compatible"
    if normalized not in _SUPPORTED_PROVIDERS:
        choices = ", ".join(sorted(_SUPPORTED_PROVIDERS))
        raise ValueError(f"unsupported OpenAI-compatible provider {provider!r}; choose {choices}")
    return normalized


def _validate_base_url(base_url: str) -> str:
    value = base_url.strip().rstrip("/")
    try:
        parsed = httpx.URL(value)
    except Exception as exc:  # noqa: BLE001 - turn malformed config into a stable error
        raise ValueError("LLM base URL is not a valid URL") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.host:
        raise ValueError("LLM base URL must use http(s) and include a host")
    return value


def _chat_completions_url(base_url: str) -> str:
    if base_url.endswith("/chat/completions"):
        return base_url
    return f"{base_url}/chat/completions"


def _responses_url(base_url: str) -> str:
    if base_url.endswith("/responses"):
        return base_url
    return f"{base_url}/responses"


def _api_style(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    if normalized not in _SUPPORTED_API_STYLES:
        choices = ", ".join(sorted(_SUPPORTED_API_STYLES))
        raise ValueError(f"unsupported LLM API style {value!r}; choose {choices}")
    return normalized


def _responses_text(payload: object) -> str:
    """Extract assistant text from a Responses-shaped JSON object."""

    if not isinstance(payload, dict):
        raise ValueError("LLM response must be a JSON object")
    output_text = payload.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text
    output = payload.get("output")
    if isinstance(output, list):
        parts: list[str] = []
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, str):
                parts.append(content)
                continue
            if not isinstance(content, list):
                continue
            for part in content:
                if not isinstance(part, dict):
                    continue
                text = part.get("text")
                if isinstance(text, str):
                    parts.append(text)
        combined = "".join(parts).strip()
        if combined:
            return combined
    raise ValueError("LLM Responses API returned no output text")


def extract_json_object(text: str) -> dict[str, object]:
    """Extract the first JSON object from plain or fenced model output.

    Models often wrap the requested object in a short sentence or a markdown
    code fence. ``JSONDecoder.raw_decode`` handles nested objects without the
    greedy-regex failure mode. A non-object response is rejected so callers do
    not accidentally treat a JSON array/scalar as a proposal.
    """

    decoder = json.JSONDecoder()
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text, index)
        except JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError(f"no JSON object in model response: {text[:500]!r}")


def is_model_output_error(exc: BaseException) -> bool:
    """Identify an unusable model response without masking provider failures."""
    if not isinstance(exc, ValueError):
        return False
    message = str(exc)
    return (
        "LLM Responses API returned no output text" in message
        or "no JSON object in model response" in message
        or "LLM response has no assistant text content" in message
    )


class OpenAICompatibleClient:
    """Minimal synchronous provider client.

    ``provider`` selects environment defaults only. Explicit constructor values
    always win, which keeps tests and GUI server configuration deterministic.
    ``transport`` is an HTTPX injection point for hermetic tests.
    """

    def __init__(
        self,
        *,
        provider: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        api_style: str | None = None,
        timeout: float = 180.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if provider is None:
            from reachagent.llm.runtime import selected_provider

            provider = selected_provider() or "deepseek"
        self.provider = _provider_name(provider)
        self.api_key = api_key or self._api_key_from_env()
        default_base = {
            "deepseek": _DEEPSEEK_BASE_URL,
            "openai": _OPENAI_BASE_URL,
        }.get(self.provider, "")
        configured_base = base_url or self._base_url_from_env()
        if not configured_base and self.provider == "openai-compatible":
            raise ValueError("LLM base URL is required for the openai-compatible provider")
        self.base_url = _validate_base_url(configured_base or default_base)
        default_model = {
            "deepseek": _DEFAULT_DEEPSEEK_MODEL,
            "openai": _DEFAULT_OPENAI_MODEL,
        }.get(self.provider, "")
        self.model = model or self._model_from_env() or default_model
        if not self.model:
            raise ValueError("LLM model is required for the openai-compatible provider")
        self.api_style = _api_style(
            api_style or os.environ.get("REACHAGENT_LLM_API_STYLE", "chat_completions")
        )
        if timeout <= 0:
            raise ValueError("LLM timeout must be positive")
        self._client = httpx.Client(timeout=timeout, transport=transport, trust_env=False)

    def _api_key_from_env(self) -> str:
        if self.provider == "deepseek":
            return _first_env(
                "REACHAGENT_DEEPSEEK_API_KEY",
                "DEEPSEEK_API_KEY",
                "REACHAGENT_LLM_API_KEY",
            )
        if self.provider == "openai":
            return _first_env(
                "REACHAGENT_OPENAI_API_KEY",
                "OPENAI_API_KEY",
                "REACHAGENT_LLM_API_KEY",
            )
        return _first_env("REACHAGENT_LLM_API_KEY")

    def _base_url_from_env(self) -> str:
        if self.provider == "deepseek":
            return _first_env(
                "REACHAGENT_DEEPSEEK_BASE_URL",
                "DEEPSEEK_BASE_URL",
                "REACHAGENT_LLM_BASE_URL",
            )
        if self.provider == "openai":
            return _first_env(
                "REACHAGENT_OPENAI_BASE_URL",
                "OPENAI_BASE_URL",
                "REACHAGENT_LLM_BASE_URL",
            )
        return _first_env("REACHAGENT_LLM_BASE_URL")

    def _model_from_env(self) -> str:
        if self.provider == "deepseek":
            return _first_env("REACHAGENT_DEEPSEEK_MODEL", "DEEPSEEK_MODEL", "REACHAGENT_LLM_MODEL")
        if self.provider == "openai":
            return _first_env("REACHAGENT_OPENAI_MODEL", "OPENAI_MODEL", "REACHAGENT_LLM_MODEL")
        return _first_env("REACHAGENT_LLM_MODEL")

    def _post_with_retry(
        self, url: str, headers: dict[str, str], body: dict[str, object]
    ) -> httpx.Response:
        """POST with a bounded retry on a transient gateway error (§ LLM resilience).

        Mirrors execution/firer.py's RequestFirer retry convention exactly —
        only 502/503/504 are retried; a genuine 4xx/other 5xx is final on the
        first attempt, since retrying it would never succeed.
        """
        for attempt in range(_LLM_RETRY_LIMIT + 1):
            response = self._client.post(url, headers=headers, json=body)
            if response.status_code not in _LLM_RETRY_STATUSES or attempt == _LLM_RETRY_LIMIT:
                response.raise_for_status()
                return response
            time.sleep(_LLM_RETRY_BACKOFF[attempt])
        raise RuntimeError("unreachable")  # pragma: no cover — loop always returns/raises

    def complete(self, prompt: str, *, max_tokens: int = 512) -> str:
        """Send one user prompt and return the assistant's text content."""

        if not self.api_key:
            raise RuntimeError(
                "LLM API key not set; configure the selected provider API-key environment variable"
            )
        if not prompt.strip():
            raise ValueError("LLM prompt must not be empty")
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.api_style == "responses":
            url = _responses_url(self.base_url)
            body = {
                "model": self.model,
                "input": prompt,
                # Responses budgets include hidden reasoning tokens. Keep
                # small proposal limits from ending before output exists.
                "max_output_tokens": max(max_tokens, _MIN_RESPONSES_OUTPUT_TOKENS),
            }
        else:
            url = _chat_completions_url(self.base_url)
            body = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": 0,
            }
        response = self._post_with_retry(url, headers, body)
        payload: object = response.json()
        if self.api_style == "responses":
            return _responses_text(payload)
        if not isinstance(payload, dict):
            raise ValueError("LLM response must be a JSON object")
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ValueError("LLM response has no choices[0] object")
        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise ValueError("LLM response has no choices[0].message object")
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content
        if isinstance(content, list):
            parts = [
                part.get("text", "")
                for part in content
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            ]
            combined = "".join(parts).strip()
            if combined:
                return combined
        raise ValueError("LLM response has no assistant text content")

    def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
        """Send a proposal prompt and parse its JSON object response."""

        return extract_json_object(self.complete(prompt, max_tokens=max_tokens))

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> OpenAICompatibleClient:
        return self

    def __exit__(self, _exc_type: object, _exc_value: object, _traceback: object) -> None:
        self.close()


def build_openai_compatible_client(
    *,
    provider: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> OpenAICompatibleClient | None:
    """Build the adapter only when the env explicitly selects a compatible provider.

    Returning ``None`` for an unset provider lets the caller apply its own
    provider-neutral fallback behavior instead of crashing.
    """

    if provider is None:
        from reachagent.llm.runtime import selected_provider

        provider = selected_provider()
    selected = provider.strip().lower()
    if not selected:
        return None
    return OpenAICompatibleClient(provider=selected, transport=transport)


def require_provider_config(provider: str | None = None) -> None:
    """Fail fast when no LLM provider is configured, or it has no API key.

    This is a local configuration check only; it never sends a request. The
    GUI's strict path calls this before creating a scan.
    """

    if provider is None:
        from reachagent.llm.runtime import selected_provider

        provider = selected_provider()
    selected = provider.strip().lower()
    if not selected:
        raise RuntimeError("no LLM provider configured — select one or set REACHAGENT_LLM_PROVIDER")

    client = build_openai_compatible_client(provider=selected)
    if client is None:
        raise RuntimeError(f"unsupported or unset LLM provider: {provider!r}")
    try:
        if not client.api_key:
            raise RuntimeError(f"API key is required for LLM provider {selected!r}")
    finally:
        client.close()
