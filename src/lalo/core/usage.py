"""Persistent, cross-run token/cost usage stats — the local, honest analogue
of a reference agent's own ``global_usage_tracker.py``.

That reference persists lifetime usage to ``$HOME/.cai/usage.json`` using a
hand-rolled ``fcntl``-based read/write lock plus a plain temp-file-then-
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
accepted decision) is that L4L0's own single-active-scan design (one GUI,
one mutable "is a scan running" slot, per :mod:`lalo.gui.app`) makes that
race a real but low-probability edge case, not a normal path — worth naming
here rather than silently assumed away, not worth the complexity of adding
process-level file locking for.
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
    """Lifetime totals, plus a per-provider breakdown."""

    total_requests: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    by_provider: dict[str, dict[str, float]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "total_requests": self.total_requests,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": self.total_cost_usd,
            "by_provider": self.by_provider,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> UsageStats:
        by_provider_raw = data.get("by_provider")
        by_provider = dict(by_provider_raw) if isinstance(by_provider_raw, dict) else {}
        return cls(
            total_requests=int(data.get("total_requests", 0)),  # type: ignore[call-overload]
            total_input_tokens=int(data.get("total_input_tokens", 0)),  # type: ignore[call-overload]
            total_output_tokens=int(data.get("total_output_tokens", 0)),  # type: ignore[call-overload]
            total_cost_usd=float(data.get("total_cost_usd", 0.0)),  # type: ignore[arg-type]
            by_provider=by_provider,
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


def record_usage(
    response: CompletionResponse,
    *,
    path: Path = DEFAULT_USAGE_PATH,
    pricing_table: PricingTable | None = None,
    cost_limit_usd: float | None = None,
) -> UsageStats:
    """Add ``response``'s usage to the persisted lifetime total and return it.

    The update is always persisted first, even if ``cost_limit_usd`` is then
    exceeded — the API call already happened and already cost real money, so
    the ledger reflects that regardless of whether the caller stops the run
    afterward (see :class:`~lalo.core.errors.CostLimitExceededError`'s own
    docstring for why this is the opposite order from the reference this
    module is informed by).
    """
    stats = load_usage(path)
    stats.total_requests += 1
    input_tokens = response.input_tokens or 0
    output_tokens = response.output_tokens or 0
    stats.total_input_tokens += input_tokens
    stats.total_output_tokens += output_tokens

    cost = estimate_cost_usd(response, pricing_table) if pricing_table else None
    if cost is not None:
        stats.total_cost_usd += cost

    provider_stats = stats.by_provider.setdefault(
        response.provider,
        {"requests": 0.0, "input_tokens": 0.0, "output_tokens": 0.0, "cost_usd": 0.0},
    )
    provider_stats["requests"] += 1
    provider_stats["input_tokens"] += input_tokens
    provider_stats["output_tokens"] += output_tokens
    if cost is not None:
        provider_stats["cost_usd"] += cost

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
