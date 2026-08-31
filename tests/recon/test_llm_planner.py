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
