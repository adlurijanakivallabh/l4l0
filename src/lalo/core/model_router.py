"""Multi-provider model router with failover.

Roles (e.g. ``"reasoning"``, ``"triage"``, ``"report"``) map to an ordered chain
of provider names. :meth:`ModelRouter.complete` tries them in order; a provider
refusal (safety classifier) or unavailability (transport/5xx/rate-limit) fails
over to the next provider rather than aborting the run. Only when every provider
in the chain fails does it raise :class:`AllProvidersFailedError`.

Concrete provider adapters (Anthropic/OpenAI/Gemini/local over HTTP) are added
in the agent-core phase; this module defines the protocol, the router, and the
failover contract, and is exercised with in-memory fake providers in tests.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .errors import AllProvidersFailedError, ProviderRefusalError, ProviderUnavailableError
from .logging import get_logger

_log = get_logger("lalo.router")


@dataclass(frozen=True)
class CompletionRequest:
    """A provider-agnostic completion request."""

    prompt: str
    system: str | None = None
    max_tokens: int = 1024
    temperature: float = 0.0


@dataclass(frozen=True)
class CompletionResponse:
    """A provider-agnostic completion response, tagged with what served it."""

    text: str
    provider: str
    model: str


@runtime_checkable
class Provider(Protocol):
    """A single LLM provider.

    ``complete`` returns a :class:`CompletionResponse` or raises
    :class:`ProviderRefusalError` / :class:`ProviderUnavailableError` (both
    failover-eligible). Any other exception propagates (it is a real bug, not a
    routine provider condition).
    """

    name: str

    def complete(self, request: CompletionRequest) -> CompletionResponse: ...


@dataclass
class ModelRouter:
    """Routes a completion for a role through its provider failover chain."""

    providers: Mapping[str, Provider]
    routes: Mapping[str, Sequence[str]] = field(default_factory=dict)
    default_route: Sequence[str] = ()

    def chain_for(self, role: str) -> Sequence[str]:
        return self.routes.get(role) or self.default_route

    def complete(self, role: str, request: CompletionRequest) -> CompletionResponse:
        chain = self.chain_for(role)
        if not chain:
            raise AllProvidersFailedError(
                f"no provider chain configured for role {role!r}", role=role, failures=[]
            )
        failures: list[tuple[str, str]] = []
        for name in chain:
            provider = self.providers.get(name)
            if provider is None:
                failures.append((name, "not_registered"))
                continue
            try:
                response = provider.complete(request)
            except (ProviderRefusalError, ProviderUnavailableError) as exc:
                failures.append((name, exc.code))
                _log.warning(
                    "provider %s failed (%s) for role %s; failing over", name, exc.code, role
                )
                continue
            if failures:
                _log.info("role %s served by %s after %d failover(s)", role, name, len(failures))
            return response
        raise AllProvidersFailedError(
            f"all {len(chain)} providers failed for role {role!r}", role=role, failures=failures
        )
