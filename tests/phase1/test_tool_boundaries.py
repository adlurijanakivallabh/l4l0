"""Role-bounded tool access is enforced by module membership (plan §13).

These tests assert the CLAUDE.md non-negotiables structurally: the Explorer
subset must never expose ``write_finding``; the Coordinator must never expose
``fire_request`` or ``run_oracle``; only the Validator exposes ``run_oracle`` and
``write_finding``. If a future edit leaks a tool across a role boundary, this
test fails.
"""

from __future__ import annotations

from reachagent.tools import coordinator, explorer, validator


def _tool_names(module: object) -> set[str]:
    return {
        name
        for name in vars(module)
        if callable(getattr(module, name)) and not name.startswith("_")
    }


def test_explorer_never_exposes_write_finding() -> None:
    names = _tool_names(explorer)
    assert "write_finding" not in names
    assert "run_oracle" not in names
    # fire_browser (Phase 3 Task 5) is the fifth Explorer tool — the browser-side
    # transport for DOM XSS discovery. It is Explorer-owned like the other four
    # and, critically, has no write_finding/run_oracle path (asserted above).
    assert names == {
        "fingerprint_parameter",
        "get_payloads",
        "fire_request",
        "classify_response",
        "fire_browser",
    }


def test_fire_browser_is_explorer_only_and_unreachable_from_other_roles() -> None:
    # The named, concrete boundary proof required by the v1.4.1 plan edit:
    # fire_browser lives on the Explorer and nowhere else. Coordinator and
    # Validator must not expose it under any wiring.
    assert "fire_browser" in _tool_names(explorer)
    assert "fire_browser" not in _tool_names(coordinator)
    assert "fire_browser" not in _tool_names(validator)


def test_coordinator_never_fires_or_runs_oracles() -> None:
    names = _tool_names(coordinator)
    assert "fire_request" not in names
    assert "run_oracle" not in names
    assert names == {"query_graph", "score_and_select", "check_budget"}


def test_only_validator_confirms_and_writes_findings() -> None:
    names = _tool_names(validator)
    assert names == {"run_oracle", "write_finding", "mark_inconclusive"}
