"""Minimal tracing: timed spans + counters recorded to an in-memory timeline."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from ..core.logging import get_logger

_log = get_logger("lalo.trace")


@dataclass
class Span:
    """One timed unit of work with arbitrary attributes."""

    name: str
    start: float
    end: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float | None:
        if self.end is None:
            return None
        return (self.end - self.start) * 1000.0


@dataclass
class Tracer:
    """Collects spans and counters for one run."""

    spans: list[Span] = field(default_factory=list)
    counters: dict[str, float] = field(default_factory=dict)

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[Span]:
        current = Span(name=name, start=time.monotonic(), attributes=dict(attributes))
        try:
            yield current
        finally:
            current.end = time.monotonic()
            self.spans.append(current)
            _log.debug(
                "span %s took %.1fms %s", name, current.duration_ms or 0.0, current.attributes
            )

    def counter(self, name: str, value: float = 1.0) -> None:
        self.counters[name] = self.counters.get(name, 0.0) + value


_DEFAULT_TRACER = Tracer()


def get_tracer() -> Tracer:
    """Return the process-default tracer (a dedicated one can be passed explicitly)."""
    return _DEFAULT_TRACER
