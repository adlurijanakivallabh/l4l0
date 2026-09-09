"""Multi-provider model router with failover — an L4L0 original.

None of the five studied reference agents fail over between LLM providers at
runtime: each picks one active provider/model per run (a single `<provider>:
<model>` spec, or one hardcoded SDK client). L4L0's router tries an ordered
chain: a provider refusal (a safety classifier) or unavailability (transport/
5xx/rate-limit) fails over to the next provider rather than aborting the whole
run. Only when every provider in the chain fails does it raise.

``CompletionResponse.input_tokens``/``output_tokens`` are informed by a
reference agent's own real cost/usage-tracking subsystem
(``util/pricing.py``'s ``CostTracker`` + a ``CAI_PRICE_LIMIT`` hard stop, and
``sdk/agents/global_usage_tracker.py``'s local lifetime ``usage.json``, both
read in full) — a genuine capability L4L0 had nothing for before this: an
autonomous run's actual dollar cost is invisible when the only thing tracked
is a raw step/turn count (:mod:`lalo.orchestrator.budget`), and different
providers/models can cost wildly different amounts per token for the same
number of turns. Deliberately NOT ported as designed there: that reference's
pricing table is fetched live from a public GitHub raw URL when opted in
(a real, if minor, supply-chain/network-dependency this project's own
"never fetch-and-run external content" convention argues against), and it
maintains its cost cap as a second, uncoordinated limit alongside a separate
turn-count cap. :mod:`lalo.core.usage` instead persists real, verifiable
token counts via the existing :func:`~lalo.core.atomic_io.atomic_write_verified`
primitive (more rigorous than that reference's own bespoke ``fcntl``-based
write), and :mod:`lalo.core.pricing` ships with NO baked-in dollar-per-token
table at all — token counts are always real and available, but converting
them to a dollar figure requires the operator's own current pricing (which
changes too often, and varies too much per negotiated rate, to ship as a
fact this project would otherwise be asserting on the operator's behalf).
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .errors import AllProvidersFailedError, ProviderRefusalError, ProviderUnavailableError
from .logging import get_logger

_log = get_logger("lalo.router")


@dataclass(frozen=True)
class CompletionRequest:
    """A provider-agnostic completion request.

    ``cancel_event``, if given, is checked BETWEEN retry attempts inside
    each provider's own bounded retry loop (``core/providers.py``'s
    ``_post_with_retry``) - never a true abort of an already-in-flight
    socket read, which httpx has no clean cross-thread primitive for
    without a disproportionate transport-level change. This closes the
    common case honestly: a request that has already failed once and is
    about to retry (or hasn't started at all yet) stops within about one
    retry interval of an operator stop / wall-clock / cost-ceiling kill,
    instead of running out its full attempt schedule regardless.
    """

    prompt: str
    system: str | None = None
    max_tokens: int = 1024
    temperature: float = 0.0
    cancel_event: threading.Event | None = None


@dataclass(frozen=True)
class CompletionResponse:
    """A provider-agnostic completion response, tagged with what served it.

    ``input_tokens``/``output_tokens`` are the real usage figures each
    provider's own API response reports (Anthropic's ``usage.input_tokens``/
    ``usage.output_tokens``, an OpenAI-compatible response's
    ``usage.prompt_tokens``/``usage.completion_tokens``) — ``None`` only if a
    provider's response genuinely omitted them, never a fabricated estimate.
    See :mod:`lalo.core.usage` for what turns these into a persisted spend
    record, and :mod:`lalo.core.pricing` for the (deliberately empty by
    default, operator-supplied) conversion into an actual dollar figure.
    """

    text: str
    provider: str
    model: str
    input_tokens: int | None = None
    output_tokens: int | None = None


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
                retryable = getattr(exc, "retryable", True)
                failures.append((name, exc.code if retryable else f"{exc.code}_non_retryable"))
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
