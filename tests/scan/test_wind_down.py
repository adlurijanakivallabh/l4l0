"""Forced graceful wind-down (Agentic Coordinator, Phase 4).

Reuses the mid-scan steering-hint queue (gui/app.py's _ScanControl,
agentic_loop.py's _safe_operator_prompt) -- no new plumbing. Repeat-
candidate throttling (PentAGI's repeat-tool-call pattern) is already
covered by entrypoint.py's existing attempted_edges dedup set, so this
covers only the remaining Phase 4 gap: a wind-down note as the generic
coordinator loop nears its iteration ceiling.
"""

from __future__ import annotations

from reachagent.scan.entrypoint import _wind_down_hint


def test_wind_down_hint_names_the_remaining_budget() -> None:
    text = _wind_down_hint(3)
    assert "3" in text
    assert "prioritize" in text.lower()


def test_wind_down_hint_is_deterministic_text_not_a_verdict() -> None:
    # This is a strategy nudge, never anything oracle/finding-shaped.
    text = _wind_down_hint(1).lower()
    for banned in ("confirmed", "finding", "oracle", "vulnerable"):
        assert banned not in text
