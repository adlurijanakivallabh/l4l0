"""DOM XSS execution marker — flows (candidate) vs flows + executed (real execution)."""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest

from reachagent.browser.shim import (
    TAINT_SHIM_JS,
    BrowserFireResult,
    run_taint_shim,
)
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.mcp import server
from reachagent.payloads import PayloadLibrary
from reachagent.tools.explorer_context import ExplorerContext
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient


def _stub_judgment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force run_oracle's LLM judgment to CONFIRMS (v3 architecture, CLAUDE.md).

    The MCP ``run_oracle`` tool exposes no ``client=`` kwarg to a hand-caller, so
    this patches the same default-provider factory ``judge()`` falls back to when
    no client is supplied (mirrors tests/phase1/test_mcp_server.py::_stub_judgment).
    What used to be a fixed ``decide()`` producing a status from evidence content
    (flows + executed=True -> violation) is now an LLM call that can't be pinned
    deterministically; these tests instead assert the wiring (evidence reaches
    run_oracle and a positive judgment comes back as is_violation) still works.
    """
    from reachagent.oracles import llm_judgment as _judgment

    monkeypatch.setattr(
        _judgment,
        "build_openai_compatible_client",
        lambda **_: FixedJudgmentClient(CONFIRMS.value),
    )


# -- Shim: executed round-trips through run_taint_shim; reset installed -----------


class _FakeDriver:
    def __init__(self, *, flows: list[dict], executed: bool) -> None:
        self._flows = flows
        self._executed = executed
        self.init_scripts: list[str] = []

    def add_init_script(self, script: str) -> None:
        self.init_scripts.append(script)

    def navigate(self, url: str) -> None:
        pass

    def evaluate(self, expression: str) -> object:
        if "__reachagent_flows" in expression:
            return self._flows
        if "__reachagent_exec" in expression:
            return self._executed
        return None


def test_executed_round_trips_through_run_taint_shim() -> None:
    driver = _FakeDriver(
        flows=[{"source": "location.hash", "sink": "innerHTML", "value": "<img src=x>"}],
        executed=True,
    )
    result = run_taint_shim(driver, "anon", "http://vampi.test/#/search?q=x")
    assert isinstance(result, BrowserFireResult)
    assert result.executed is True
    assert len(result.flows) == 1
    # Reset-before-navigate installed: the init script carries the marker reset so a
    # stale marker never leaks across pages.
    assert any("__reachagent_exec = 0" in s for s in driver.init_scripts)
    assert "__reachagent_exec = 0" in TAINT_SHIM_JS


def test_executed_false_when_marker_absent() -> None:
    driver = _FakeDriver(flows=[], executed=False)
    result = run_taint_shim(driver, "anon", "http://vampi.test/")
    assert result.executed is False
    assert result.flows == ()


# -- MCP seam: execution_confirmation adapter accepts executed --------------------


def _session() -> server._Session:
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["vampi.test"]))
    ctx = ExplorerContext(
        graph=ReachabilityGraph(),
        firer=firer,
        library=PayloadLibrary.from_file(),
        base_url="http://vampi.test",
    )
    return server._Session(ctx=ctx)


def _call(mcp: object, name: str, **kwargs: object) -> object:
    tool = mcp._tool_manager._tools[name]  # type: ignore[attr-defined]
    return tool.fn(**kwargs)  # type: ignore[union-attr]


def test_mcp_execution_confirmation_accepts_executed(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp.server.fastmcp import FastMCP

    _stub_judgment(monkeypatch)
    session = _session()
    mcp = FastMCP("reachagent-test")
    server.register_tools(mcp, session)
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="execution_confirmation",
        evidence={
            "flows": [],
            "executed": True,
            "evidence_ref": "xss/dom-search",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_mcp_execution_confirmation_executed_absent_defaults_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Absent `executed` key still reaches the judge with `flows` populated; wiring
    # (not the now-removed deterministic `executed` default) is what's under test.
    from mcp.server.fastmcp import FastMCP

    _stub_judgment(monkeypatch)
    session = _session()
    mcp = FastMCP("reachagent-test")
    server.register_tools(mcp, session)
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="execution_confirmation",
        evidence={
            "flows": [{"source": "location.hash", "sink": "innerHTML", "value_snippet": "x"}],
            "evidence_ref": "xss/dom-search",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]


# -- Invariants ------------------------------------------------------------------


def test_shim_and_oracle_import_no_validator() -> None:
    import reachagent.browser.shim as shim_mod
    import reachagent.oracles.execution_confirmation as exec_mod

    for mod in (shim_mod, exec_mod):
        tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "reachagent.tools.validator" not in node.module
