"""VAmPI evaluation harness — the Phase 1 numeric gate (plan §14, §15; Task 9).

Drives the full detection pipeline through the Task 8 MCP tools (never direct
function calls) against a running VAmPI, using the Task 2 identities and the
Task 3–7 payload/oracle pipeline, and scores the result against VAmPI's built-in
ground truth. Measured on BOLA / IDOR / mass-assignment only — JWT is deferred
past Phase 1 with the structural oracle family (docs/phase1-tasks.md scope note).

The gate (§14, §15): with the vulnerable toggle **on**, ≥90% precision and ≥80%
recall; with it **off**, exactly zero confirmed findings.
"""

from __future__ import annotations

from reachagent.eval.harness import (
    GateResult,
    GroundTruth,
    ScenarioResult,
    ToggleRun,
    VampiTarget,
    evaluate,
    precision_recall,
    run_toggle,
)

__all__ = [
    "GateResult",
    "GroundTruth",
    "ScenarioResult",
    "ToggleRun",
    "VampiTarget",
    "evaluate",
    "precision_recall",
    "run_toggle",
]
