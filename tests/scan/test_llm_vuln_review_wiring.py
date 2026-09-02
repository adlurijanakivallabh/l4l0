"""scan_all_classes -> scan.llm_vuln_review wiring (v2, operator-requested).

run_llm_vulnerability_review itself is fully covered by
tests/scan/test_llm_vuln_review.py; this file only proves the orchestrator wiring:
called TWICE with the scan's own graph (an "early" pass before Phase 3, a "final"
pass after — operator feedback: leads should surface live across the scan, not in
one batch at the end), only when an LLM is actually configured (require_llm=True),
and a failure never aborts the scan.
"""

from __future__ import annotations

import httpx

from reachagent.scan.orchestrator import scan_all_classes

_BASE = "https://safe.example"


def _clean_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(404, text="not found")


class _FakePlannerClient:
    """Minimal valid plan + always-stop recon selection — just enough to let a
    require_llm=True scan reach Phase 3 without exercising unrelated LLM seams."""

    def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
        if "adaptive recon planner" in prompt:
            return {"tools": [], "rationale": "no further recon needed", "stop": True}
        return {
            "rationale": "Recon first, then the deterministic classes drive confirmation.",
            "request_budget": 15,
            "tool_budget": 2,
            "phases": [
                {"name": "recon", "rationale": "Map the read-only surface.", "tools": ["httpx"]},
                {"name": "surface", "rationale": "Parse discovered facts."},
                {"name": "insertion-points", "rationale": "No dedicated tools needed."},
                {"name": "payloads", "rationale": "Use only sink-matched library entries."},
                {"name": "verification", "rationale": "No signal-gated tools needed."},
                {"name": "report", "rationale": "Render only oracle-confirmed findings."},
            ],
        }


class _FakeAdvisor:
    """A no-op adaptive-control advisor: always continue as planned."""

    def advise(
        self,
        completed_phase: str,
        phase_summary: str,
        remaining_phases: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        return {"action": "continue", "rationale": "test advisor — no reassessment needed"}


def test_llm_vuln_review_is_called_twice_with_the_scans_own_graph_when_llm_required(
    monkeypatch,  # noqa: ANN001
) -> None:
    from reachagent.payloads import PayloadLibrary

    calls: list[dict] = []

    def fake_review(*, graph, client=None, events=None):  # noqa: ANN001
        calls.append({"graph": graph})
        return 0

    monkeypatch.setattr("reachagent.scan.llm_vuln_review.run_llm_vulnerability_review", fake_review)

    result = scan_all_classes(
        base_url=_BASE,
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
        require_llm=True,
        planner_client=_FakePlannerClient(),
        control_client=_FakeAdvisor(),
    )

    # early (before Phase 3) + final (after Phase 3) — not one batch at the end.
    assert len(calls) == 2
    assert all(call["graph"] is result["graph"] for call in calls)


def test_llm_vuln_review_is_not_called_when_llm_is_not_required(monkeypatch) -> None:  # noqa: ANN001
    from reachagent.payloads import PayloadLibrary

    calls: list[dict] = []

    def fake_review(*, graph, client=None, events=None):  # noqa: ANN001
        calls.append({"graph": graph})
        return 0

    monkeypatch.setattr("reachagent.scan.llm_vuln_review.run_llm_vulnerability_review", fake_review)

    scan_all_classes(
        base_url=_BASE,
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
    )

    assert calls == []


def test_llm_vuln_review_failure_never_aborts_the_scan(monkeypatch) -> None:  # noqa: ANN001
    from reachagent.payloads import PayloadLibrary

    def _boom(*, graph, client=None, events=None):  # noqa: ANN001
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr("reachagent.scan.llm_vuln_review.run_llm_vulnerability_review", _boom)

    events: list = []
    result = scan_all_classes(
        base_url=_BASE,
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
        require_llm=True,
        planner_client=_FakePlannerClient(),
        control_client=_FakeAdvisor(),
        events=events,
    )

    assert result["graph"] is not None
    assert any("LLM vulnerability review" in e.message and "failed" in e.message for e in events)


def test_llm_vuln_review_new_leads_land_in_the_scans_graph_as_suspected_only(
    monkeypatch,  # noqa: ANN001
) -> None:
    from reachagent.graph.nodes import SuspectedFinding
    from reachagent.payloads import PayloadLibrary

    def fake_review(*, graph, client=None, events=None):  # noqa: ANN001
        graph.add_suspected_finding(
            SuspectedFinding(vuln_class="idor", endpoint="/x", source="llm_judgment")
        )
        return 1

    monkeypatch.setattr("reachagent.scan.llm_vuln_review.run_llm_vulnerability_review", fake_review)

    result = scan_all_classes(
        base_url=_BASE,
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
        require_llm=True,
        planner_client=_FakePlannerClient(),
        control_client=_FakeAdvisor(),
    )

    classes = {s.vuln_class for _sid, s in result["graph"].suspected_findings()}
    assert "idor" in classes
    assert result["graph"].findings() == []  # never a Finding
