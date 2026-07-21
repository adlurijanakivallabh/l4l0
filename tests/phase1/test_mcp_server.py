"""MCP server — role-bounded registration + clean startup (plan §13; Task 8).

Asserts the Task 8 DoD invariants:

  1. ``reachagent-mcp`` builds and registers exactly the Explorer + Validator
     subsets — the four Explorer tools and three Validator tools — and *no*
     Coordinator tool (``query_graph`` / ``score_and_select`` / ``check_budget``).
  2. Role boundaries survive registration: the Explorer-facing tools expose no
     ``write_finding`` (or ``run_oracle``); confirmation stays the Validator's.
  3. The server starts cleanly (build + tool introspection) and each tool is
     hand-callable, exactly as a human driving it from Claude Code would — proven
     here by invoking the registered wrappers end to end against a MockTransport
     target, including the ``fire_request`` → ``classify_response`` and
     ``run_oracle`` → ``write_finding`` handle chains.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import httpx
import pytest

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.mcp import server
from reachagent.payloads import PayloadLibrary
from reachagent.tools.explorer_context import ExplorerContext

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

EXPLORER_TOOLS = {"fingerprint_parameter", "get_payloads", "fire_request", "classify_response"}
VALIDATOR_TOOLS = {"run_oracle", "write_finding", "mark_inconclusive"}
COORDINATOR_TOOLS = {"query_graph", "score_and_select", "check_budget"}


def _tool_names(mcp: FastMCP) -> set[str]:
    return set(mcp._tool_manager._tools.keys())


def _built() -> FastMCP:
    return server.build_server(base_url="http://vampi.test", scope_hosts=["vampi.test"])


# -- Invariant 1 & 2: exactly the role-bounded set, no coordinator tool ---


def test_registers_exactly_the_explorer_and_validator_subsets() -> None:
    names = _tool_names(_built())
    assert names == EXPLORER_TOOLS | VALIDATOR_TOOLS


def test_no_coordinator_tool_is_exposed() -> None:
    names = _tool_names(_built())
    assert names.isdisjoint(COORDINATOR_TOOLS)


def test_explorer_tools_have_no_write_finding_path() -> None:
    # The four Explorer-facing tools must not include write_finding/run_oracle —
    # the same role boundary the structural module test pins, re-checked after MCP
    # registration so wiring can't leak a confirming tool onto the Explorer side.
    names = _tool_names(_built())
    explorer_side = names - VALIDATOR_TOOLS
    assert explorer_side == EXPLORER_TOOLS
    assert "write_finding" not in explorer_side
    assert "run_oracle" not in explorer_side


def test_startup_is_clean_and_tools_are_discoverable() -> None:
    # "Starts cleanly and is callable by hand": build succeeds and every tool is
    # listed with a description, which is what a client (Claude Code) sees.
    mcp = _built()
    listed = asyncio.run(mcp.list_tools())
    listed_names = {t.name for t in listed}
    assert listed_names == EXPLORER_TOOLS | VALIDATOR_TOOLS
    assert all(t.description for t in listed)


# -- Invariant 3: the registered tools are hand-callable end to end -------


def _session_on(handler: object) -> server._Session:
    """A server session whose firer is wired to a MockTransport standing in for VAmPI."""

    def _h(request: httpx.Request) -> httpx.Response:
        return handler(request)  # type: ignore[operator, no-any-return]

    client = httpx.Client(transport=httpx.MockTransport(_h))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["vampi.test"]))
    ctx = ExplorerContext(
        graph=ReachabilityGraph(),
        firer=firer,
        library=PayloadLibrary.from_file(),
        base_url="http://vampi.test",
    )
    return server._Session(ctx=ctx)


def _call(mcp: FastMCP, name: str, /, **kwargs: object) -> object:
    """Invoke a registered tool's underlying function by name (hand-call)."""
    tool = mcp._tool_manager._tools[name]
    return tool.fn(**kwargs)


def _register_on_session(session: server._Session) -> FastMCP:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("reachagent-test")
    server.register_tools(mcp, session)
    return mcp


def test_fingerprint_then_get_payloads_by_inferred_sink() -> None:
    # SQL-error canary → sink=sql → get_payloads returns only sql-matched entries.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="You have an error in your SQL syntax near ''")

    session = _session_on(handler)
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/users/v1/name"))
    param = session.graph.add_parameter(ep, Parameter(name="q", location="query"))
    mcp = _register_on_session(session)

    report = _call(
        mcp, "fingerprint_parameter", identity="user_a", endpoint_node=ep, param_node=param
    )
    assert report.inferred_sink_type == "sql"  # type: ignore[attr-defined]

    entries = _call(mcp, "get_payloads", vuln_class="sqli", sink_type="sql")
    assert entries
    assert all(e.inferred_sink_type == "sql" for e in entries)  # type: ignore[attr-defined]


def test_fire_request_returns_ref_consumed_by_classify_response() -> None:
    # The fire_ref handle chains fire_request → classify_response without the full
    # (non-serializable) response ever crossing the wire.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    session = _session_on(handler)
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/users/v1/name"))
    param = session.graph.add_parameter(ep, Parameter(name="q", location="query"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="user_a", endpoint_node=ep, param_node=param)
    fired = _call(
        mcp,
        "fire_request",
        identity="user_a",
        endpoint_node=ep,
        param_node=param,
        payload="' OR 1=1--",
    )
    ref = fired.fire_ref  # type: ignore[attr-defined]
    assert ref.startswith("fire-")

    candidate = _call(
        mcp,
        "classify_response",
        fire_ref=ref,
        identity="user_a",
        endpoint_node=ep,
        vuln_class="sqli",
        suggested_oracle="differential",
    )
    assert candidate.vuln_class == "sqli"  # type: ignore[attr-defined]
    assert candidate.status_code == 200  # type: ignore[attr-defined]
    # A candidate is inert — the serialized view carries no verdict/finding field.
    assert not hasattr(candidate, "status")
    assert not hasattr(candidate, "confirmed")


def test_classify_response_unknown_fire_ref_is_refused() -> None:
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)
    with pytest.raises(KeyError):
        _call(
            mcp,
            "classify_response",
            fire_ref="fire-does-not-exist",
            identity="user_a",
            endpoint_node="e",
            vuln_class="sqli",
            suggested_oracle="differential",
        )


def test_run_oracle_ref_chains_into_write_finding_for_a_violation() -> None:
    # A confirmed_violation verdict (BOLA: attacker gets the owner's body) minted by
    # run_oracle can be committed by write_finding via its verdict_ref.
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)

    verdict = _call(
        mcp,
        "run_oracle",
        evidence={
            "axis": "cross_identity",
            "expectation": "probe_unauthorized",
            "baseline_status": 200,
            "probe_status": 200,
            "baseline_body": '{"ssn":"1"}',
            "probe_body": '{"ssn":"1"}',
            "evidence_ref": "bola/users/1",
        },
    )
    assert verdict.status == "confirmed_violation"  # type: ignore[attr-defined]
    assert verdict.is_violation is True  # type: ignore[attr-defined]
    ref = verdict.verdict_ref  # type: ignore[attr-defined]

    finding = _call(mcp, "write_finding", verdict_ref=ref, vuln_class="bola")
    assert finding.status == "confirmed_violation"  # type: ignore[attr-defined]
    assert finding.oracle_used == "differential"  # type: ignore[attr-defined]
    assert session.graph.findings()  # persisted


def test_write_finding_refuses_a_non_violation_verdict_ref() -> None:
    # confirmed_allowed is a fact, not a finding — write_finding must refuse it,
    # even though it came from a real run_oracle handle.
    from reachagent.tools.validator_support import UnconfirmedFindingError

    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)

    verdict = _call(
        mcp,
        "run_oracle",
        evidence={
            "axis": "cross_identity",
            "expectation": "probe_authorized",
            "baseline_status": 200,
            "probe_status": 200,
            "baseline_body": "d",
            "probe_body": "d",
            "evidence_ref": "authz/ok",
        },
    )
    assert verdict.status == "confirmed_allowed"  # type: ignore[attr-defined]
    with pytest.raises(UnconfirmedFindingError):
        _call(mcp, "write_finding", verdict_ref=verdict.verdict_ref, vuln_class="bola")  # type: ignore[attr-defined]
    assert session.graph.findings() == []


def test_write_finding_cannot_be_reached_without_a_run_oracle_ref() -> None:
    # There is no way to hand write_finding a fabricated verdict: the client only
    # ever holds an opaque ref, and an unknown ref is refused outright.
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)
    with pytest.raises(KeyError):
        _call(mcp, "write_finding", verdict_ref="verdict-forged", vuln_class="bola")
    assert session.graph.findings() == []
