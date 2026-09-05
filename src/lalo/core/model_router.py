"""Multi-provider model router with failover — an L4L0 original.

None of the five studied reference agents fail over between LLM providers at
runtime: each picks one active provider/model per run (a single `<provider>:
<model>` spec, or one hardcoded SDK client). L4L0's router tries an ordered
chain: a provider refusal (a safety classifier) or unavailability (transport/
5xx/rate-limit) fails over to the next provider rather than aborting the whole
run. Only when every provider in the chain fails does it raise.
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
        # `role not configured at all` and `role explicitly mapped to an empty
        # chain` are different things — the latter means "this role is
        # disabled," which `or self.default_route` would silently paper over
        # (an empty tuple is falsy) by substituting the default chain instead.
        chain = self.routes.get(role)
        return chain if chain is not None else self.default_route

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
