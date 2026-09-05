"""Scan assembly — wires the execution/graph/agent pieces into a runnable scan.

``run_scan`` builds the engagement scope, firer, graph, and tool registry, then
drives the agent loop over a mission. Findings are recorded (never gated) with
confidence scores computed against real captured traffic.
"""

from .runner import ScanResult, run_scan
from .tools import ScanContext, build_registry

__all__ = ["ScanContext", "ScanResult", "build_registry", "run_scan"]
