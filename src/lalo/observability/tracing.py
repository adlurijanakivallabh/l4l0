"""Minimal tracing: timed spans + counters recorded to an in-memory timeline."""

from __future__ import annotations

import threading
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
    # Wall-clock (time.time()) creation timestamp - start/end above stay
    # time.monotonic()-based (correct for duration math, meaningless across a
    # process restart); this is the separate additive field for "when did
    # this actually happen" in real calendar time, so a span can be
    # correlated with a journaled Checkpoint or a GUI Event's own `ts`.
    wall_start: float = field(default_factory=time.time)

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
    # Guards counter()'s read-modify-write only - span()'s self.spans.append()
    # is a single CPython list operation, already atomic under the GIL with
    # no read-modify-write hazard. Excluded from equality/repr/init, same
    # reasoning as Budget's own lock field.
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False, compare=False
    )

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
        with self._lock:
            self.counters[name] = self.counters.get(name, 0.0) + value


_DEFAULT_TRACER = Tracer()


def get_tracer() -> Tracer:
    """Return the process-default tracer (a dedicated one can be passed explicitly)."""
    return _DEFAULT_TRACER
