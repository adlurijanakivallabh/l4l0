"""Focused safety tests for the validated LLM execution planner."""

from __future__ import annotations

import pytest

from reachagent.llm.planner import (
    PlanningContext,
    PlanValidationError,
    build_tool_catalog,
    plan_execution,
    planning_prompt,
    validate_execution_plan,
)


def _context() -> PlanningContext:
    return PlanningContext(
        target="https://api.example.test",
        target_type="url",
        in_scope=("api.example.test",),
        graph_facts={"technology": "api", "endpoint_count": "7"},
        operator_prompt="test the authenticated API safely",
        max_request_budget=30,
        max_tool_budget=6,
    )


def _plan() -> dict[str, object]:
    return {
        "rationale": "Map the API before testing the observed insertion points.",
        "request_budget": 20,
        "tool_budget": 4,
        "phases": [
            {
                "name": "recon",
                "rationale": "Fingerprint the web API and crawl its read-only surface.",
                "tools": ["httpx", "katana"],
            },
            {
                "name": "surface",
                "rationale": "Parse the discovered API surface into graph facts.",
            },
            {
                "name": "insertion-points",
                "rationale": "Find query parameters before selecting payload families.",
                "tools": ["arjun"],
            },
            {
                "name": "payloads",
                "rationale": "Use only sink-matched library entries.",
            },
            {
                "name": "verification",
                "rationale": "Use a signal-gated enrichment result only as a candidate.",
                "tools": ["nuclei"],
            },
            {
                "name": "report",
                "rationale": "Render only oracle-confirmed findings.",
            },
        ],
    }


def test_catalog_is_built_from_all_existing_runner_names() -> None:
    catalog = {entry.name: entry for entry in build_tool_catalog()}
    assert len(catalog) == 35  # three passive/event-driven recon adapters added
    assert {
        "nmap",
        "httpx",
        "arjun",
        "jwt-tool",
        "testssl",
        "bbot",
        "dnsrecon",
        "urlfinder",
    } <= set(catalog)
    assert catalog["nuclei"].signal_gated
    assert catalog["arjun"].phase == "insertion-points"


def test_validated_plan_is_immutable_and_prompt_exposes_only_catalog_names() -> None:
    context = _context()
    plan = validate_execution_plan(_plan(), context)
    assert plan.phases[0].tools == ("httpx", "katana")
    payload_phase = next(phase for phase in plan.phases if phase.name == "payloads")
    assert payload_phase.name == "payloads"
    prompt = planning_prompt(context)
    assert '"httpx"' in prompt
    assert "subprocess" not in prompt


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda raw: raw["phases"][0].update({"command": "nmap -A"}), "unsupported fields"),
        (
            lambda raw: raw["phases"][0].update({"url": "https://outside.test"}),
            "unsupported fields",
        ),
        (lambda raw: raw["phases"][0].update({"state_changing": True}), "unsupported fields"),
        (lambda raw: raw["phases"][0].update({"tools": ["not-a-tool"]}), "unknown tool"),
        (lambda raw: raw.update({"request_budget": 31}), "request_budget"),
    ],
)
def test_validator_rejects_unbounded_or_unknown_model_output(mutation, match: str) -> None:  # noqa: ANN001
    raw = _plan()
    mutation(raw)
    with pytest.raises(PlanValidationError, match=match):
        validate_execution_plan(raw, _context())


def test_validator_rejects_duplicate_tool_and_target_mismatch() -> None:
    duplicate = _plan()
    duplicate["phases"][0]["tools"] = ["httpx", "katana", "httpx"]  # type: ignore[index]
    with pytest.raises(PlanValidationError, match="must not contain duplicates"):
        validate_execution_plan(duplicate, _context())

    incompatible = _plan()
    incompatible["phases"][0]["tools"] = ["testssl"]  # type: ignore[index]
    with pytest.raises(PlanValidationError, match="not compatible"):
        validate_execution_plan(incompatible, _context())


def test_planner_propagates_model_failure_without_a_fallback() -> None:
    class FailingClient:
        def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
            raise RuntimeError("provider unavailable")

    with pytest.raises(RuntimeError, match="provider unavailable"):
        plan_execution(_context(), FailingClient())


def test_planner_retries_transient_empty_model_response() -> None:
    calls = 0

    class FlakyClient:
        def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise ValueError("LLM Responses API returned no output text")
            return _plan()

    result = plan_execution(_context(), FlakyClient())
    assert calls == 2
    assert result.phases[0].name == "recon"


def _plan_with_misplaced_tool() -> dict[str, object]:
    """A live-verification finding (v2 W16): two different real providers both
    put a recon-phase tool under a later phase on their first attempt. The
    fixer prompt must tell the model where each rejected tool actually belongs
    — repeating only the raw validation-error text was not enough for either
    model to self-correct within the 3 allotted fixer rounds."""
    plan = _plan()
    plan["phases"][2]["tools"] = ["katana"]  # katana is catalog phase "recon", not
    # "insertion-points" (phases[2])
    return plan


def test_planner_fixer_prompt_names_each_tools_required_phase() -> None:
    """The fix prompt sent after a rejection must state katana's REQUIRED phase
    (recon) explicitly — not just repeat the validation-error text — so a model
    that doesn't recall the full catalog can still self-correct."""
    seen_prompts: list[str] = []

    class RecordingClient:
        def __init__(self) -> None:
            self.calls = 0

        def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
            seen_prompts.append(prompt)
            self.calls += 1
            if self.calls == 1:
                return _plan_with_misplaced_tool()
            return _plan()  # gives up trying to fix it itself; test only inspects the prompt

    plan_execution(_context(), RecordingClient())
    fix_prompt = seen_prompts[1]
    assert '"katana": "recon"' in fix_prompt
    assert "REQUIRED phase" in fix_prompt


def test_planner_fixer_loop_recovers_once_told_the_correct_phase() -> None:
    """A client that only self-corrects once it has been told katana's real
    phase — proving the reminder actually lets the fixer loop converge, not
    just that the prompt text looks right."""
    calls = 0

    class SelfCorrectingClient:
        def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 1:
                return _plan_with_misplaced_tool()
            assert '"katana": "recon"' in prompt  # only fixes it because it was told
            return _plan()

    result = plan_execution(_context(), SelfCorrectingClient())
    assert calls == 2
    assert result.phases[0].tools == ("httpx", "katana")


def _plan_missing_surface() -> dict[str, object]:
    """A live-verification finding: a real model's first plan simply omitted the
    'surface' phase entirely (a phase-OMISSION error, not a tool-placement one) —
    the fixer prompt's tool-phase-map guidance doesn't address this failure mode
    at all, so a weaker model has no way to know it just needs to add the phase."""
    plan = _plan()
    plan["phases"] = [phase for phase in plan["phases"] if phase["name"] != "surface"]  # type: ignore[index]
    return plan


def test_planner_fixer_prompt_names_missing_required_phases() -> None:
    """The fix prompt for a missing-phase rejection must explicitly say which
    phase(s) are missing and that an empty tools list is fine for a non-recon
    phase — not just repeat the raw validation-error text."""
    seen_prompts: list[str] = []

    class RecordingClient:
        def __init__(self) -> None:
            self.calls = 0

        def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
            seen_prompts.append(prompt)
            self.calls += 1
            if self.calls == 1:
                return _plan_missing_surface()
            return _plan()

    plan_execution(_context(), RecordingClient())
    fix_prompt = seen_prompts[1]
    assert "MUST appear" in fix_prompt
    assert "surface" in fix_prompt
    assert "'tools': []" in fix_prompt


def test_planner_fixer_loop_recovers_once_told_which_phase_is_missing() -> None:
    """A client that only adds the missing 'surface' phase once its own fix
    prompt names it explicitly — proving the hint actually lets the fixer loop
    converge, not just that the prompt text looks right."""
    calls = 0

    class SelfCorrectingClient:
        def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 1:
                return _plan_missing_surface()
            assert "MUST appear" in prompt  # only fixes it because it was told
            return _plan()

    result = plan_execution(_context(), SelfCorrectingClient())
    assert calls == 2
    assert {phase.name for phase in result.phases} >= {"recon", "surface"}


def test_planner_raises_the_last_validation_error_after_exhausting_fixer_attempts() -> None:
    """A model that never listens still fails closed — no silent fallback plan,
    exactly the "provider errors propagate" design this planning boundary relies
    on (scan/orchestrator.py's one model-controlled plan boundary)."""
    calls = 0

    class StubbornClient:
        def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict[str, object]:
            nonlocal calls
            calls += 1
            return _plan_with_misplaced_tool()

    with pytest.raises(PlanValidationError, match="not valid in phase"):
        plan_execution(_context(), StubbornClient())
    assert calls == 4  # 1 initial + 3 fixer attempts, all rejected
