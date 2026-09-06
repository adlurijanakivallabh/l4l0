"""L4L0's GUI: the primary entry point (no CLI, no TUI) — FastAPI + a cursor-resumable WebSocket."""

from .app import build_app, main
from .events import Event, EventLog

__all__ = [
    "Event",
    "EventLog",
    "build_app",
    "main",
]
