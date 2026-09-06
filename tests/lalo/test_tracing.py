"""Tests for the observability scaffold."""

from __future__ import annotations

import threading

from lalo.observability import Tracer


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
