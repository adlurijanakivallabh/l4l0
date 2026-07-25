"""Detection-side shared plumbing (Phase 3).

Detectors (blind SQLi, NoSQLi, LDAP, XSS, file upload, path traversal) sequence
probes and dispatch evidence to a deterministic oracle — but they must never
import the Validator's ``run_oracle`` directly. Confirmation is role-bounded
(CLAUDE.md non-negotiable): only the Validator calls ``run_oracle``. In a live
run the detector reaches the oracle *through the MCP tool boundary*
(``mcp.call_tool("run_oracle", ...)``), exactly like the Phase 1 VAmPI and
Phase 2 crAPI harnesses.

To keep detection hermetic and unit-testable without spinning up an MCP server,
each detector holds an injectable :data:`OracleRunner` callback on its prober.
Tests and in-process callers supply :func:`registry_runner` (dispatches straight
through the oracle registry — the same deterministic families, no verdict
forgery possible). The live gate supplies an MCP-backed runner that crosses
``mcp.call_tool``. Either way the detector code contains no validator import, so
the "no detector bypasses the MCP boundary" grep stays clean.
"""

from __future__ import annotations

from reachagent.detection.oracle_gateway import (
    OracleOutcome,
    OracleRunner,
    registry_runner,
)

__all__ = ["OracleOutcome", "OracleRunner", "registry_runner"]
