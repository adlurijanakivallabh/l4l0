"""Tests for the observability scaffold."""

from __future__ import annotations

import threading
import time

from lalo.observability import Span, Tracer, wall_clock_union


def test_span_records_duration_and_attributes() -> None:
    tracer = Tracer()
    with tracer.span("recon", target="app.example.com") as span:
        span.attributes["endpoints"] = 3
    assert len(tracer.spans) == 1
    recorded = tracer.spans[0]
    assert recorded.name == "recon"
    assert recorded.attributes == {"target": "app.example.com", "endpoints": 3}
    assert recorded.duration_ms is not None and recorded.duration_ms >= 0.0


def test_span_records_even_on_exception() -> None:
    tracer = Tracer()
    try:
        with tracer.span("boom"):
            raise RuntimeError("x")
    except RuntimeError:
        pass
    assert len(tracer.spans) == 1
    assert tracer.spans[0].end is not None


def test_counter_accumulates() -> None:
    tracer = Tracer()
    tracer.counter("requests_fired")
    tracer.counter("requests_fired", 4)
    assert tracer.counters["requests_fired"] == 5.0


def test_counter_is_thread_safe_under_concurrent_increments() -> None:
    """Without the lock, self.counters[name] = self.counters.get(name, 0.0)
    + value from N threads loses increments (multi-lane concurrent
    sub-agents share ONE Tracer)."""
    tracer = Tracer()
    threads = [threading.Thread(target=lambda: tracer.counter("tool_calls")) for _ in range(500)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert tracer.counters["tool_calls"] == 500.0


def test_wall_clock_union_of_non_overlapping_spans_sums_durations() -> None:
    a = Span(name="a", start=0.0, end=1.0, wall_start=100.0)
    b = Span(name="b", start=1.0, end=2.0, wall_start=200.0)
    assert wall_clock_union([a, b]) == (a.duration_ms or 0.0) / 1000 + (b.duration_ms or 0.0) / 1000


def test_wall_clock_union_of_overlapping_spans_counts_the_overlap_once() -> None:
    a = Span(name="a", start=0.0, end=10.0, wall_start=100.0)  # covers [100, 110)
    b = Span(name="b", start=0.0, end=10.0, wall_start=102.0)  # covers [102, 112), overlaps a
    assert wall_clock_union([a, b]) == 12.0  # union of [100,110) and [102,112) is [100,112)


def test_wall_clock_union_ignores_spans_with_no_end() -> None:
    unfinished = Span(name="a", start=0.0, end=None, wall_start=100.0)
    assert wall_clock_union([unfinished]) == 0.0


def test_wall_clock_union_of_empty_list_is_zero() -> None:
    assert wall_clock_union([]) == 0.0


def test_span_wall_start_is_a_real_wall_clock_time() -> None:
    """start/end stay time.monotonic()-based (correct for duration math, and
    meaningless across process restarts) - wall_start is the separate,
    additive field for "when did this actually happen" in real calendar
    time, e.g. to correlate a span with a journaled checkpoint or a GUI
    event's own `ts`."""
    tracer = Tracer()
    before = time.time()
    with tracer.span("x") as span:
        pass
    after = time.time()
    assert before <= span.wall_start <= after
