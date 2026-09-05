"""FastAPI GUI — launch scans, stream live events over a cursor-resumable WebSocket.

Events are categorized (status/log/agent/finding) and buffered per scan so a
reconnecting client resumes from its last cursor (reconnect reconciliation).
"""

from .app import ScanManager, ScanState, build_app, main

__all__ = ["ScanManager", "ScanState", "build_app", "main"]
