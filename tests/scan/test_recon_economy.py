"""Phase C recon-economy regression tests, driven through the REAL orchestrator path.

Before this phase, nothing drove ``scan_all_classes(require_llm=True, ...)`` at
all — the exact code path (``orchestrator._select_recon``) that had the
budget/validator divergence bug had zero test coverage, which is presumably how
it shipped unnoticed. These tests exercise it end to end with a fake planner
client, so a regression in the orchestrator's budget bookkeeping fails here
rather than surfacing as a live "recon selection exceeds the remaining tool
budget" abort.
"""

from __future__ import annotations

import json
import re

import httpx

from reachagent.scan.entrypoint import scan_target
from reachagent.scan.orchestrator import scan_all_classes

_BASE = "https://econ.test"


def _clean_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(404, text="not found")


class _FakePlannerClient:
    """Dispatches by prompt shape (plan / recon-selection / recon-selection
    FIXER-RETRY — three distinct shapes ``select_recon_tools`` can send), and
    for a normal recon-selection round always requests exactly the enforced
    remaining budget it was told about — the honest behavior a budget-aware
    model would produce. If the orchestrator's displayed budget ever diverges
    from the enforced one again, ``validate_recon_selection`` rejects this
    honest answer, ``select_recon_tools`` sends the FIXER-RETRY prompt, and
    ``fixer_rounds`` becomes nonzero — the precise regression signal, since a
    degrade-on-failure fallback elsewhere would otherwise mask the scan ever
    aborting (see ``test_recon_planner_failure_degrades_instead_of_aborting``).
    """

    def __init__(self, tool_budget: int) -> None:
        self.tool_budget = tool_budget
        self.prompts_seen: list[str] = []
        self.fixer_rounds = 0

    def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
        self.prompts_seen.append(prompt)
        if "was rejected by strict validation" in prompt:
            # The fixer-retry prompt (planner.select_recon_tools) carries no
            # Available/Remaining lines to re-parse; a validation failure
            # already happened by the time this fires, so just record it and
            # answer with the one response that is ALWAYS schema-valid.
            self.fixer_rounds += 1
            return {"tools": [], "rationale": "stopping after validation rejection", "stop": True}
        if "adaptive recon planner" in prompt:
            return self._recon_selection(prompt)
        return self._execution_plan()

    def _execution_plan(self) -> dict[str, object]:
        return {
            "rationale": "Recon first, then the deterministic classes drive confirmation.",
            "request_budget": 15,
            "tool_budget": self.tool_budget,
            "phases": [
                {"name": "recon", "rationale": "Map the read-only surface.", "tools": ["httpx"]},
                {"name": "surface", "rationale": "Parse discovered facts."},
                {"name": "insertion-points", "rationale": "No dedicated tools needed."},
                {
                    "name": "payloads",
                    "rationale": "Use only sink-matched library entries.",
                    "vuln_classes": ["sqli"],
                },
                {"name": "verification", "rationale": "No signal-gated tools needed."},
                {"name": "report", "rationale": "Render only oracle-confirmed findings."},
            ],
        }

    def _recon_selection(self, prompt: str) -> dict[str, object]:
        available = json.loads(re.search(r"Available tools: (\[.*?\])\n", prompt).group(1))
        remaining = int(re.search(r"Remaining tool budget: (\d+)", prompt).group(1))
        # Request EXACTLY the enforced remaining budget — reproduces the bug: a
        # model that trusts the displayed number and is rejected for it.
        chosen = available[:remaining] if available else []
        return {
            "tools": chosen,
            "rationale": f"selecting {len(chosen)} of {len(available)} available",
            "stop": not chosen,
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


def test_adaptive_recon_never_exceeds_its_own_displayed_budget() -> None:
    """The historical bug: prompt shows the FULL budget, validator enforces the
    SHRINKING remaining one — a model requesting exactly what it was told is
    available gets rejected. This must no longer raise."""
    client = _FakePlannerClient(tool_budget=3)
    result = scan_all_classes(
        base_url=_BASE,
        in_scope="econ.test",
        transport=httpx.MockTransport(_clean_handler),
        require_llm=True,
        planner_client=client,
        control_client=_FakeAdvisor(),
    )
    assert len(result["graph"].findings()) == 0  # clean target, no false positives
    recon_prompts = [
        p
        for p in client.prompts_seen
        if "adaptive recon planner" in p and "was rejected by strict validation" not in p
    ]
    assert recon_prompts, "the adaptive recon selector was never invoked"
    for prompt in recon_prompts:
        remaining = int(re.search(r"Remaining tool budget: (\d+)", prompt).group(1))
        assert remaining >= 1  # never a call made once genuinely exhausted
    # The real regression signal: a model that requests exactly the displayed
    # "Remaining tool budget" must never get rejected for exceeding it. A
    # degrade-on-failure fallback elsewhere (test_recon_planner_failure_*)
    # would otherwise mask this budget divergence as a silent, "successful"
    # scan — checking fixer_rounds catches it precisely.
    assert client.fixer_rounds == 0, "the displayed budget was rejected by the validator"


def test_recon_planner_failure_degrades_instead_of_aborting_the_scan() -> None:
    """A recon_selector exception (provider outage, exhausted fixer retries) must
    degrade to "stop adaptive selection" — not propagate out of scan_target and
    abort the whole scan."""

    def _boom(state: dict, available: tuple, completed: tuple) -> object:
        raise RuntimeError("planner provider unavailable")

    result = scan_target(
        base_url=_BASE,
        in_scope="econ.test",
        dry_run=False,
        transport=httpx.MockTransport(_clean_handler),
        recon_candidates=("subfinder",),
        recon_selector=_boom,
        fixtures={"subfinder": "api.econ.test\n"},
    )
    # The scan completed (did not raise) despite the selector always failing.
    assert result["dry_run"] is False


def test_content_discovery_stops_after_primary_succeeds() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return (
            httpx.Response(200, text="ok") if request.url.path == "/admin" else httpx.Response(404)
        )

    result = scan_target(
        base_url=_BASE,
        in_scope="econ.test",
        dry_run=False,
        transport=httpx.MockTransport(handler),
        fixtures={
            "ffuf": json.dumps({"results": [{"url": f"{_BASE}/admin", "status": 200}]}),
            "gobuster": "/admin (Status: 200)\n",
            "feroxbuster": json.dumps({"url": f"{_BASE}/admin", "status": 200}),
            "dirb": f"+ {_BASE}/admin (CODE:200|SIZE:1)\n",
        },
    )
    ran = {"ffuf", "gobuster", "feroxbuster", "dirb"} & set(result["recon_tools"])
    assert ran == {"ffuf"}, f"expected only the primary to fire, got {ran}"


def test_content_discovery_falls_back_when_primary_finds_nothing() -> None:
    result = scan_target(
        base_url=_BASE,
        in_scope="econ.test",
        dry_run=False,
        transport=httpx.MockTransport(_clean_handler),
        fixtures={
            "ffuf": json.dumps({"results": []}),  # primary: zero endpoints
            "gobuster": "/admin (Status: 200)\n",  # fallback: one endpoint
            "feroxbuster": json.dumps({"url": f"{_BASE}/x", "status": 200}),
            "dirb": f"+ {_BASE}/y (CODE:200|SIZE:1)\n",
        },
    )
    ran = {"ffuf", "gobuster", "feroxbuster", "dirb"} & set(result["recon_tools"])
    # Exactly the primary (empty) plus ONE fallback (which found something) —
    # feroxbuster/dirb are never reached once gobuster satisfies the family.
    assert ran == {"ffuf", "gobuster"}, f"expected primary + one fallback, got {ran}"
