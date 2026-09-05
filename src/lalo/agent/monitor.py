"""Loop monitor — advisory-only anti-looping.

Watches an agent's tool calls; when the same (tool, args) repeats past a
threshold, it returns a steering note to nudge a different approach. It is
advisory: it never blocks a call or a finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class LoopMonitor:
    repeat_threshold: int = 3
    _counts: dict[str, int] = field(default_factory=dict)

    def observe(self, tool: str, args: dict[str, object]) -> str | None:
        key = tool + "|" + json.dumps(args, sort_keys=True, default=str)
        self._counts[key] = self._counts.get(key, 0) + 1
        if self._counts[key] >= self.repeat_threshold:
            return (
                f"You have called {tool} with identical arguments "
                f"{self._counts[key]} times with no new result — try a different "
                f"approach, target, or tool."
            )
        return None
