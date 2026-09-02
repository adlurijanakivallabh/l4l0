"""Graceful termination of the adaptive control loop ("My additions").

Before this fix, LoopDetected/IdleTimeout raised out of AdaptiveControlState
propagated straight out of scan_all_classes uncaught, killing the whole scan
even though only the LLM-driven re-ranking/adaptation was stuck — every
deterministic phase/class driver underneath was completely unaffected and
could have kept running in default order. Pre-seeding a resumed control
checkpoint whose decision budget is already exhausted reproduces that
exact condition deterministically, with no need to drive 8+ real adaptive
round-trips through a live scan.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from reachagent.scan.orchestrator import scan_all_classes

_BASE = "https://control-loop.test"


def _clean_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(404, text="not found")


class _FakePlannerClient:
    """Minimal valid plan + an immediate recon-selection stop — just enough
    for scan_all_classes(require_llm=True) to run past recon cleanly."""

    def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
        if "adaptive recon planner" in prompt:
            return {"tools": [], "rationale": "no further recon needed", "stop": True}
        return {
            "rationale": "Recon first, then the deterministic classes drive confirmation.",
            "request_budget": 10,
            "tool_budget": 1,
            "phases": [
                {"name": "recon", "rationale": "Map the read-only surface.", "tools": ["httpx"]},
                {"name": "surface", "rationale": "Parse discovered facts."},
                {"name": "insertion-points", "rationale": "No dedicated tools needed."},
                {"name": "payloads", "rationale": "Use only sink-matched library entries."},
                {"name": "verification", "rationale": "No signal-gated tools needed."},
                {"name": "report", "rationale": "Render only oracle-confirmed findings."},
            ],
        }


class _ContinueAdvisor:
    """Always proposes 'continue' — a real decision, still recorded by
    AdaptiveControlState.apply(), which is exactly what makes it count
    toward an already-exhausted decision budget."""

    def advise(
        self,
        completed_phase: str,
        phase_summary: str,
        remaining_phases: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        return {"action": "continue", "rationale": "test advisor", "hint": "", "target_phase": None}


def _seed_exhausted_checkpoint(path: Path) -> None:
    """A resumable AdaptiveControlState whose decision budget is already spent."""
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "run_id": "exhausted",
                "phases": ["recon", "endpoints", "payloads", "verification", "report"],
                "revision": 1,
                "completed": [],
                "skipped": [],
                "hints": {},
                "revisit_counts": {},
                "decisions": [
                    {
                        "phase": "recon",
                        "action": "continue",
                        "target_phase": "endpoints",
                        "rationale": "seed",
                        "hint": "",
                        "revision": 0,
                        "timestamp": 0.0,
                    }
                ],
                "last_counts": {},
                "max_decisions": 1,
                "max_revisits": 2,
                "idle_timeout": 900.0,
                "cancelled": False,
            }
        ),
        encoding="utf-8",
    )


def test_exhausted_decision_budget_stops_adapting_but_not_the_scan(tmp_path: Path) -> None:
    checkpoint = tmp_path / "control.json"
    _seed_exhausted_checkpoint(checkpoint)
    events: list = []

    result = scan_all_classes(
        base_url=_BASE,
        in_scope="control-loop.test",
        transport=httpx.MockTransport(_clean_handler),
        require_llm=True,
        planner_client=_FakePlannerClient(),
        control_client=_ContinueAdvisor(),
        resume_checkpoint=str(checkpoint),
        events=events,
    )

    assert result["graph"].findings() == []  # clean target — the scan actually ran to completion
    stopped = [e for e in events if e.kind == "control-stopped"]
    assert stopped, "expected a graceful control-stopped event, scan should not have crashed"
    assert "LoopDetected" in stopped[0].message


class _RecoveryHintAdvisor:
    """Answers 'continue' normally, but once asked to recover from a detected
    loop (its phase_summary starts with the sentinel below), offers a revised
    strategy hint instead — the D-CIPHER-style auto-prompter refinement."""

    def advise(
        self,
        completed_phase: str,
        phase_summary: str,
        remaining_phases: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        if phase_summary.startswith("Adaptive control loop stopped"):
            return {
                "action": "revise",
                "rationale": "loop detected",
                "hint": "skip re-ranking, use default order for the rest of the scan",
                "target_phase": None,
            }
        return {"action": "continue", "rationale": "test advisor", "hint": "", "target_phase": None}


def test_recovery_hint_is_folded_into_the_operator_prompt(tmp_path: Path) -> None:
    checkpoint = tmp_path / "control.json"
    _seed_exhausted_checkpoint(checkpoint)
    events: list = []

    result = scan_all_classes(
        base_url=_BASE,
        in_scope="control-loop.test",
        transport=httpx.MockTransport(_clean_handler),
        require_llm=True,
        planner_client=_FakePlannerClient(),
        control_client=_RecoveryHintAdvisor(),
        resume_checkpoint=str(checkpoint),
        events=events,
    )

    assert result["graph"].findings() == []
    stopped = [e for e in events if e.kind == "control-stopped"]
    assert stopped
    assert "recovery hint applied: skip re-ranking" in stopped[0].message


class _BoomOnRecoveryAdvisor:
    """continue normally, but raises when asked to recover from a loop —
    the recovery attempt must be best-effort and never crash the scan."""

    def advise(
        self,
        completed_phase: str,
        phase_summary: str,
        remaining_phases: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        if phase_summary.startswith("Adaptive control loop stopped"):
            raise RuntimeError("advisor down")
        return {"action": "continue", "rationale": "test advisor", "hint": "", "target_phase": None}


def test_recovery_hint_failure_still_degrades_gracefully(tmp_path: Path) -> None:
    checkpoint = tmp_path / "control.json"
    _seed_exhausted_checkpoint(checkpoint)
    events: list = []

    result = scan_all_classes(
        base_url=_BASE,
        in_scope="control-loop.test",
        transport=httpx.MockTransport(_clean_handler),
        require_llm=True,
        planner_client=_FakePlannerClient(),
        control_client=_BoomOnRecoveryAdvisor(),
        resume_checkpoint=str(checkpoint),
        events=events,
    )

    assert result["graph"].findings() == []
    stopped = [e for e in events if e.kind == "control-stopped"]
    assert stopped
    assert "recovery hint applied" not in stopped[0].message


def test_decision_rationale_is_surfaced_as_an_assistant_note_for_the_chat() -> None:
    """W1: the agent's own loop-decision reasoning is emitted as kind 'assistant-note'
    so the GUI can render it into the chat panel, not just the terminal feed."""
    events: list = []

    scan_all_classes(
        base_url=_BASE,
        in_scope="control-loop.test",
        transport=httpx.MockTransport(_clean_handler),
        require_llm=True,
        planner_client=_FakePlannerClient(),
        control_client=_ContinueAdvisor(),
        events=events,
    )

    notes = [e for e in events if e.kind == "assistant-note"]
    assert notes, "expected at least one assistant-note event carrying the decision rationale"
    assert any("test advisor" in e.message for e in notes)
