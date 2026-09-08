"""Persistent, cross-run token/cost usage stats — the local, honest analogue
of a reference agent's own ``global_usage_tracker.py``.

That reference persists lifetime usage to its own per-tool home-directory
usage file using a hand-rolled ``fcntl``-based read/write lock plus a plain temp-file-then-
``Path.replace()`` write (no read-back verification), with a corrupt-file
fallback that renames the bad file aside and starts fresh. L4L0 already has
a stronger primitive for exactly this shape of problem —
:func:`~lalo.core.atomic_io.atomic_write_verified` (write → fsync → read
back → compare → ``os.replace`` — closes the exact "wrote but never
confirmed" gap that reference's own write path leaves open) — so this
module reuses it rather than reimplementing a weaker version.

Deliberately NOT ported: ``fcntl`` inter-process locking. A read-modify-write
race here needs two callers touching the same usage file at once, and this
project's own established convention (this file's persistence pattern
mirrors :func:`~lalo.eval.scoring.append_composite_history`'s already-
accepted decision) is that this is a real but low-probability edge case,
not worth the complexity of process-level file locking for. Every scan the
GUI launches (:mod:`lalo.gui.app`) passes its own ``run_dir / "usage.json"``
rather than this module's shared ``DEFAULT_USAGE_PATH``, so two GUI-launched
scans — even genuinely concurrent ones — never share a file. The race is
narrower than "any two scans," not eliminated: a direct/CLI ``ScanConfig``
construction that doesn't pass its own ``usage_path`` still defaults to the
single shared ``DEFAULT_USAGE_PATH``, so two such processes run concurrently
by an operator (never by the GUI itself) could still race on it — worth
naming here rather than silently assumed away.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .atomic_io import atomic_write_verified
from .errors import CostLimitExceededError
from .model_router import CompletionResponse
from .pricing import PricingTable, estimate_cost_usd

DEFAULT_USAGE_PATH = Path.home() / ".lalo" / "usage.json"


@dataclass
class UsageStats:
    """Lifetime totals, plus per-provider and per-agent breakdowns."""

    total_requests: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    by_provider: dict[str, dict[str, float]] = field(default_factory=dict)
    # Keyed by agent_id (the root agent, or a spawned child) - populated only
    # for callers that pass one; a caller that doesn't opt in (agent_id=None)
    # contributes to the lifetime/by_provider totals exactly as before, same
    # optional-opt-in shape as usage_path itself.
    by_agent: dict[str, dict[str, float]] = field(default_factory=dict)
    # Keyed by the exact same "{agent_key}:{step}" string the durable
    # journal itself uses for that step's own tool-dispatch entry (see
    # agent/loop.py's own journal.run_once call). A crash between this
    # step's own LLM completion recording its usage and that same step's
    # journal write landing means the WHOLE step re-runs live on resume -
    # a genuinely new completion, a genuinely new record_usage() call for
    # what is really the same logical step. Rather than trusting an
    # ever-incrementing running total that can't un-double-count once a
    # step's usage lands twice, record_usage's own step_key argument
    # recomputes the affected totals from the CURRENT set of per-step
    # attempts: an already-seen step_key's prior contribution is
    # subtracted back out before the new attempt's is added, so only the
    # LATEST attempt at any given step ever counts.
    by_step: dict[str, dict[str, object]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "total_requests": self.total_requests,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": self.total_cost_usd,
            "by_provider": self.by_provider,
            "by_agent": self.by_agent,
            "by_step": self.by_step,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> UsageStats:
        by_provider_raw = data.get("by_provider")
        by_provider = dict(by_provider_raw) if isinstance(by_provider_raw, dict) else {}
        by_agent_raw = data.get("by_agent")
        by_agent = dict(by_agent_raw) if isinstance(by_agent_raw, dict) else {}
        by_step_raw = data.get("by_step")
        by_step = dict(by_step_raw) if isinstance(by_step_raw, dict) else {}
        return cls(
            total_requests=int(data.get("total_requests", 0)),  # type: ignore[call-overload]
            total_input_tokens=int(data.get("total_input_tokens", 0)),  # type: ignore[call-overload]
            total_output_tokens=int(data.get("total_output_tokens", 0)),  # type: ignore[call-overload]
            total_cost_usd=float(data.get("total_cost_usd", 0.0)),  # type: ignore[arg-type]
            by_provider=by_provider,
            by_agent=by_agent,
            by_step=by_step,
        )


def load_usage(path: Path = DEFAULT_USAGE_PATH) -> UsageStats:
    """Load persisted lifetime usage, or a fresh, all-zero ``UsageStats`` if
    the file doesn't exist yet or is unreadable/corrupt.

    A corrupt file is never fatal — this is a convenience running total, not
    a source of truth anything else depends on being correct.
    """
    if not path.exists():
        return UsageStats()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return UsageStats()
    if not isinstance(data, dict):
        return UsageStats()
    return UsageStats.from_dict(data)


def _apply_delta(
    stats: UsageStats,
    *,
    provider: str,
    agent_id: str | None,
    input_tokens: int,
    output_tokens: int,
    cost: float | None,
    sign: int,
) -> None:
    stats.total_requests += sign
    stats.total_input_tokens += sign * input_tokens
    stats.total_output_tokens += sign * output_tokens
    if cost is not None:
        stats.total_cost_usd += sign * cost

    provider_stats = stats.by_provider.setdefault(
        provider, {"requests": 0.0, "input_tokens": 0.0, "output_tokens": 0.0, "cost_usd": 0.0}
    )
    provider_stats["requests"] += sign
    provider_stats["input_tokens"] += sign * input_tokens
    provider_stats["output_tokens"] += sign * output_tokens
    if cost is not None:
        provider_stats["cost_usd"] += sign * cost

    if agent_id:
        agent_stats = stats.by_agent.setdefault(
            agent_id, {"requests": 0.0, "input_tokens": 0.0, "output_tokens": 0.0, "cost_usd": 0.0}
        )
        agent_stats["requests"] += sign
        agent_stats["input_tokens"] += sign * input_tokens
        agent_stats["output_tokens"] += sign * output_tokens
        if cost is not None:
            agent_stats["cost_usd"] += sign * cost


def record_usage(
    response: CompletionResponse,
    *,
    path: Path = DEFAULT_USAGE_PATH,
    pricing_table: PricingTable | None = None,
    cost_limit_usd: float | None = None,
    agent_id: str | None = None,
    step_key: str | None = None,
) -> UsageStats:
    """Add ``response``'s usage to the persisted lifetime total and return it.

    The update is always persisted first, even if ``cost_limit_usd`` is then
    exceeded — the API call already happened and already cost real money, so
    the ledger reflects that regardless of whether the caller stops the run
    afterward (see :class:`~lalo.core.errors.CostLimitExceededError`'s own
    docstring for why this is the opposite order from the reference this
    module is informed by).

    ``agent_id`` (root or a spawned child's own id) attributes this response
    to ``by_agent`` the same way ``response.provider`` already attributes it
    to ``by_provider`` - omitted (the default) when the caller has no agent
    identity to report, in which case only the lifetime/by_provider totals
    are updated, exactly as before this parameter existed.

    ``step_key`` (the exact ``f"{agent_key}:{step}"`` string the durable
    journal itself uses for that step) closes a real crash-timing race: a
    resumed step whose LLM completion already recorded usage here, but
    whose own journal entry never landed before a crash, re-runs in full on
    resume - a genuinely new completion. Passing the SAME step_key a second
    time subtracts that step's prior recorded delta back out before adding
    the new one, so only the latest attempt at any given step is ever
    reflected in the totals. ``None`` (the default) preserves the exact
    plain-accumulate behavior every existing caller already relies on.
    """
    stats = load_usage(path)
    input_tokens = response.input_tokens or 0
    output_tokens = response.output_tokens or 0
    cost = estimate_cost_usd(response, pricing_table) if pricing_table else None

    if step_key is not None and step_key in stats.by_step:
        prior = stats.by_step[step_key]
        _apply_delta(
            stats,
            provider=str(prior["provider"]),
            agent_id=prior["agent_id"],  # type: ignore[arg-type]
            input_tokens=int(prior["input_tokens"]),  # type: ignore[call-overload]
            output_tokens=int(prior["output_tokens"]),  # type: ignore[call-overload]
            cost=prior["cost_usd"],  # type: ignore[arg-type]
            sign=-1,
        )

    _apply_delta(
        stats,
        provider=response.provider,
        agent_id=agent_id,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost=cost,
        sign=1,
    )

    if step_key is not None:
        stats.by_step[step_key] = {
            "provider": response.provider,
            "agent_id": agent_id,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": cost,
        }

    atomic_write_verified(
        path, json.dumps(stats.to_dict(), indent=2, sort_keys=True).encode("utf-8")
    )

    if cost_limit_usd is not None and stats.total_cost_usd > cost_limit_usd:
        raise CostLimitExceededError(
            f"lifetime cost ${stats.total_cost_usd:.4f} exceeds the ${cost_limit_usd:.4f} limit",
            total_cost_usd=stats.total_cost_usd,
            limit_usd=cost_limit_usd,
        )
    return stats
