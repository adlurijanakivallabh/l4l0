"""Observability scaffold: spans, counters, and a per-run timeline.

Lightweight and stdlib-only for now (structured so it can be backed by a real
OpenTelemetry exporter later without changing call sites). Long autonomous runs
are hard to debug without this, so instrument liberally.
"""

from .tracing import Span, Tracer, get_tracer

__all__ = ["Span", "Tracer", "get_tracer"]
