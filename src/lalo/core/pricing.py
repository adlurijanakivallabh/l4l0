"""Dollar-cost estimation from real token counts — deliberately no baked-in
price table.

Informed directly by a reference agent's own ``util/pricing.py`` (1,543
lines, read in full — not a small file to skim) and
``sdk/agents/global_usage_tracker.py``: a genuinely useful, previously-
missing capability (L4L0's :mod:`lalo.orchestrator.budget` only ever counted
raw turns, never actual spend, and different providers/models cost wildly
different amounts per token for the same turn count) sitting inside a much
larger file whose bulk (agent/terminal cost attribution for a multi-pane TUI,
per-agent pricing-snapshot caching, cache-token-savings modeling for prompt
caching, a debug-log subsystem) is CLI/TUI display plumbing that does not
apply to L4L0 at all (GUI-only, single active scan, no terminal panes to
attribute cost to). The transferable core — "multiply real token counts by a
per-model rate, compare against a ceiling" — is a few lines once separated
from that.

Two things are deliberately NOT ported from that reference's design:
1. **No remote pricing fetch.** That reference's ``get_model_pricing()``
   optionally fetches a live pricing table from a public GitHub raw URL
   (``BerriAI/litellm``) when opted in. A real, if minor, external-network-
   dependency and supply-chain-trust question this project's own "never
   fetch-and-run external content" convention argues against for something
   as easy to get wrong (or have silently change) as a live price table.
2. **No fabricated default.** That reference falls back to ``(0.0, 0.0)``
   for an unrecognized model — a "confirmed free" value that isn't actually
   known to be true, it's just what's left when nothing else matched.
   :func:`estimate_cost_usd` returns ``None`` instead: cost for an
   unrecognized model is *unknown*, not zero, and this module ships with NO
   baked-in price-per-model table at all — real-world token pricing changes
   too often, and varies too much per operator's own negotiated rate, to
   ship as a fact this project would otherwise be asserting on the
   operator's behalf. A pricing table is something the operator supplies
   (or does not, at which point cost is simply never estimated — the real
   token counts stay available regardless, since those come straight from
   each provider's own API response).
"""

from __future__ import annotations

from collections.abc import Mapping

from .model_router import CompletionResponse

# model_id -> (USD per 1,000,000 input tokens, USD per 1,000,000 output tokens).
PricingTable = Mapping[str, tuple[float, float]]


def estimate_cost_usd(response: CompletionResponse, pricing_table: PricingTable) -> float | None:
    """Estimate ``response``'s cost in USD from its real token counts.

    Returns ``None`` — never a fabricated ``0.0`` — when either the token
    counts are unknown (a provider that didn't report ``usage``) or
    ``response.model`` isn't in ``pricing_table``.
    """
    if response.input_tokens is None or response.output_tokens is None:
        return None
    rates = pricing_table.get(response.model)
    if rates is None:
        return None
    input_rate_per_million, output_rate_per_million = rates
    return (response.input_tokens * input_rate_per_million / 1_000_000) + (
        response.output_tokens * output_rate_per_million / 1_000_000
    )
