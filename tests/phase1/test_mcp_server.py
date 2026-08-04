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
from reachagent.payloads import MissingSlotError, PayloadLibrary
from reachagent.tools.explorer_context import ExplorerContext

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

EXPLORER_TOOLS = {
    "fingerprint_parameter",
    "get_payloads",
    "fire_request",
    "classify_response",
    "fire_browser",
}
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


def _session_on(handler: object, *, library: PayloadLibrary | None = None) -> server._Session:
    """A server session whose firer is wired to a MockTransport target."""

    def _h(request: httpx.Request) -> httpx.Response:
        return handler(request)  # type: ignore[operator, no-any-return]

    client = httpx.Client(transport=httpx.MockTransport(_h))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["vampi.test"]))
    ctx = ExplorerContext(
        graph=ReachabilityGraph(),
        firer=firer,
        library=library or PayloadLibrary.from_file(),
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
    assert all(e.resolved_value for e in entries)  # type: ignore[attr-defined]
    assert all(e.slot_kit["sleep"] == 5 for e in entries)  # type: ignore[attr-defined]
    # Oracle-confidence ordering survives MCP serialization.
    ranks = {
        "structural": 0,
        "execution_confirmation": 1,
        "oob_callback": 2,
        "differential": 3,
        "business_rule_invariant": 4,
        "timing_statistical": 5,
    }
    assert [ranks[e.oracle_type] for e in entries] == sorted(ranks[e.oracle_type] for e in entries)


def test_build_server_loads_vendored_corpus() -> None:
    mcp = _built()
    entries = _call(mcp, "get_payloads", vuln_class="sqli", sink_type="sql")
    corpus_entry = next(e for e in entries if "#L" in e.payload_ref)  # type: ignore[attr-defined]
    assert corpus_entry.resolved_value  # type: ignore[attr-defined]


def test_mcp_get_payloads_serializes_resolved_value() -> None:
    mcp = _built()
    _content, structured = asyncio.run(
        mcp.call_tool("get_payloads", {"vuln_class": "sqli", "sink_type": "sql"})
    )
    assert isinstance(structured, dict)
    results = structured["result"]
    assert isinstance(results, list) and results
    first = results[0]
    assert isinstance(first, dict)
    assert first["vuln_class"] == "sqli"
    assert isinstance(first["resolved_value"], str) and first["resolved_value"]
    assert isinstance(first["slot_kit"], dict)


def test_get_payloads_full_library_resolves_and_fires_corpus_entry() -> None:
    from reachagent.payloads import build_library

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(500, text="You have an error in your SQL syntax")

    session = _session_on(handler, library=build_library())
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/users/v1/name"))
    param = session.graph.add_parameter(ep, Parameter(name="q", location="query"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="user_a", endpoint_node=ep, param_node=param)
    entries = _call(mcp, "get_payloads", vuln_class="sqli", sink_type="sql")
    corpus_entry = next(e for e in entries if "#L" in e.payload_ref)  # type: ignore[attr-defined]

    assert corpus_entry.resolved_value  # type: ignore[attr-defined]
    fired = _call(
        mcp,
        "fire_request",
        identity="user_a",
        endpoint_node=ep,
        param_node=param,
        payload=corpus_entry.resolved_value,  # type: ignore[attr-defined]
    )
    assert fired.status_code == 500  # type: ignore[attr-defined]
    assert seen[-1].url.params["q"] == corpus_entry.resolved_value  # type: ignore[attr-defined]


def test_get_payloads_surfaces_missing_template_slots() -> None:
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)
    with pytest.raises(MissingSlotError):
        _call(mcp, "get_payloads", vuln_class="sqli_blind", sink_type="sql")


def test_get_payloads_honors_caller_slot_kit() -> None:
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)
    entries = _call(
        mcp,
        "get_payloads",
        vuln_class="xss_reflected",
        sink_type="html_reflection",
        slot_kit={"canary": "CALLER_CANARY"},
    )
    assert entries[0].slot_kit["canary"] == "CALLER_CANARY"  # type: ignore[attr-defined]
    assert entries[0].resolved_value == "<script>CALLER_CANARY</script>"  # type: ignore[attr-defined]


def test_get_payloads_mints_unique_per_fire_correlators() -> None:
    session = _session_on(lambda r: httpx.Response(200, text="<p>x</p>"))
    mcp = _register_on_session(session)
    first = _call(mcp, "get_payloads", vuln_class="xss_reflected", sink_type="html_reflection")
    second = _call(mcp, "get_payloads", vuln_class="xss_reflected", sink_type="html_reflection")
    assert first[0].slot_kit["canary"] != second[0].slot_kit["canary"]  # type: ignore[attr-defined]
    assert first[0].slot_kit["nonce"] != second[0].slot_kit["nonce"]  # type: ignore[attr-defined]
    assert first[0].slot_kit["canary"] in first[0].resolved_value  # type: ignore[attr-defined]


def test_get_payloads_mints_unique_correlators_per_entry() -> None:
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)
    entries = _call(
        mcp,
        "get_payloads",
        vuln_class="sqli_blind",
        sink_type="sql",
        slot_kit={"collab": "oob.example"},
    )
    assert len(entries) == 2  # OOB and timing templates
    assert len({e.slot_kit["nonce"] for e in entries}) == len(entries)  # type: ignore[attr-defined]
    assert len({e.slot_kit["canary"] for e in entries}) == len(entries)  # type: ignore[attr-defined]


def test_get_payloads_sink_isolation_holds_through_mcp_path() -> None:
    from reachagent.payloads import build_library

    session = _session_on(lambda r: httpx.Response(200, text="ok"), library=build_library())
    mcp = _register_on_session(session)
    html_entries = _call(mcp, "get_payloads", vuln_class="sqli", sink_type="html_reflection")
    assert html_entries == []


def test_load_library_falls_back_when_snapshot_load_fails(monkeypatch, caplog) -> None:
    def broken_loader():
        raise OSError("snapshot absent")

    monkeypatch.setattr(server, "build_library", broken_loader)
    with caplog.at_level("WARNING"):
        library = server._load_library()
    assert len(library) == len(PayloadLibrary.from_file())
    assert "falling back to base payload slice" in caplog.text


def test_explorer_resolution_wiring_has_no_validator_import() -> None:
    import ast
    from pathlib import Path

    path = Path(__file__).parents[2] / "src" / "reachagent" / "tools" / "explorer.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    imports.extend(node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom))
    assert not any("reachagent.tools.validator" in name for name in imports)


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


def test_run_oracle_structural_resolves_body_from_fire_ref() -> None:
    # Fix C: the structural oracle resolves response_body server-side from a
    # probe_fire_ref, so the response body never crosses the MCP wire. The client
    # supplies only the opaque fire handle; the sentinel match happens on the
    # body the firer captured, mirroring the differential branch.
    session = _session_on(lambda r: httpx.Response(200, text="root:x:0:0:root:/root"))
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/ftp/{filename}"))
    param = session.graph.add_parameter(ep, Parameter(name="filename", location="path"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    baseline = _call(
        mcp,
        "fire_request",
        identity="anon",
        endpoint_node=ep,
        param_node=param,
        payload="legal.md",
        method="GET",
    )
    probe = _call(
        mcp,
        "fire_request",
        identity="anon",
        endpoint_node=ep,
        param_node=param,
        payload="../../etc/passwd",
        method="GET",
    )
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "path_traversal",
            "baseline_status": baseline.status_code,  # type: ignore[attr-defined]
            "probe_status": probe.status_code,  # type: ignore[attr-defined]
            "sentinel": "root:",
            "probe_fire_ref": probe.fire_ref,  # type: ignore[attr-defined]
            "evidence_ref": "path_traversal/ftp",
        },
    )
    # No response_body key supplied — the violation can only fire if the oracle
    # resolved the body from probe_fire_ref server-side.
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_structural_union_resolves_body_from_fire_ref() -> None:
    session = _session_on(lambda r: httpx.Response(200, text='{"email":"admin@juice-sh.op"}'))
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/rest/products/search"))
    param = session.graph.add_parameter(ep, Parameter(name="q", location="query"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    probe = _call(
        mcp,
        "fire_request",
        identity="anon",
        endpoint_node=ep,
        param_node=param,
        payload="union-payload",
        method="GET",
    )
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "union_extraction",
            "probe_status": probe.status_code,  # type: ignore[attr-defined]
            "union_sentinel": "admin@juice-sh.op",
            "probe_fire_ref": probe.fire_ref,  # type: ignore[attr-defined]
            "evidence_ref": "sqli/search-union-users",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_execution_confirmation_resolves_body_from_fire_ref() -> None:
    # Fix C: the execution_confirmation oracle resolves response_body from a
    # probe_fire_ref for the stored-XSS read-back — the client passes only the
    # payload_tag and the fire handle, never the body.
    tag = "XSSTESTREACH99"
    session = _session_on(lambda r: httpx.Response(200, text=f"<b>{tag}</b> stored"))
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/api/Feedbacks"))
    param = session.graph.add_parameter(ep, Parameter(name="probe", location="query"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    readback = _call(
        mcp,
        "fire_request",
        identity="anon",
        endpoint_node=ep,
        param_node=param,
        payload="",
        method="GET",
    )
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="execution_confirmation",
        evidence={
            "payload_tag": tag,
            "probe_fire_ref": readback.fire_ref,  # type: ignore[attr-defined]
            "evidence_ref": "xss/feedback-stored",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_structural_clickjacking_violation() -> None:
    # MCP structural branch must forward x_frame_options + csp fields.
    # Both framing defenses absent → framable → violation.
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "clickjacking",
            "x_frame_options": "",
            "csp": "",
            "evidence_ref": "clickjacking/mcp",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_structural_cors_misconfig_violation() -> None:
    # MCP structural branch must forward acao, acac, probe_origin fields.
    # Origin-reflected ACAO + credentials on → violation.
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "cors_misconfig",
            "acao": "https://evil.example",
            "acac": "true",
            "probe_origin": "https://evil.example",
            "evidence_ref": "cors/mcp",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_structural_resolves_framing_headers_from_fire_ref() -> None:
    # Task D: the four framing/CORS headers resolve server-side from probe_fire_ref
    # just like the body. Here the captured response carries X-Frame-Options: DENY;
    # no x_frame_options key is passed, so the DENIED verdict can only come from the
    # oracle reading the header off the fire the firer captured. Without resolution
    # the field would default to "" and (both defenses absent) mis-fire a violation.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok", headers={"X-Frame-Options": "DENY"})

    session = _session_on(handler)
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/"))
    param = session.graph.add_parameter(ep, Parameter(name="probe", location="query"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    fired = _call(
        mcp, "fire_request", identity="anon", endpoint_node=ep, param_node=param, payload=""
    )
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "clickjacking",
            "probe_fire_ref": fired.fire_ref,  # type: ignore[attr-defined]
            "evidence_ref": "clickjacking/fire-ref",
        },
    )
    # XFO: DENY resolved from the fire_ref → defended → NOT a violation.
    assert verdict.is_violation is False  # type: ignore[attr-defined]


def test_run_oracle_structural_resolves_cors_headers_from_fire_ref() -> None:
    # Task D: ACAO/ACAC resolve server-side from probe_fire_ref. The captured
    # response reflects the attacker origin with credentials on; only probe_origin
    # crosses the wire. Without resolution acao would default to "" → inconclusive,
    # so the violation proves the headers were read off the fire.
    origin = "https://evil.example"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="ok",
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            },
        )

    session = _session_on(handler)
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/"))
    param = session.graph.add_parameter(ep, Parameter(name="Origin", location="header"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    fired = _call(
        mcp, "fire_request", identity="anon", endpoint_node=ep, param_node=param, payload=origin
    )
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "cors_misconfig",
            "probe_fire_ref": fired.fire_ref,  # type: ignore[attr-defined]
            "probe_origin": origin,
            "evidence_ref": "cors/fire-ref",
        },
    )
    # Reflected ACAO + credentials, resolved from the fire_ref → violation.
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_structural_inline_header_wins_over_fire_ref() -> None:
    # Precedence: an explicit inline header value beats what the fire_ref carries,
    # same rule as response_body. The captured response has no framing defense, but
    # an inline x_frame_options=DENY must still flip the verdict to denied.
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/"))
    param = session.graph.add_parameter(ep, Parameter(name="probe", location="query"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    fired = _call(
        mcp, "fire_request", identity="anon", endpoint_node=ep, param_node=param, payload=""
    )
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "clickjacking",
            "x_frame_options": "DENY",
            "probe_fire_ref": fired.fire_ref,  # type: ignore[attr-defined]
            "evidence_ref": "clickjacking/inline-wins",
        },
    )
    assert verdict.is_violation is False  # type: ignore[attr-defined]


def test_run_oracle_structural_resolves_set_cookie_from_fire_ref() -> None:
    # CSRF: Set-Cookie resolves server-side from probe_fire_ref, same as the
    # framing/CORS headers. The captured response ships a SameSite=None session
    # cookie; no set_cookie key is passed, so the violation can only come from
    # the oracle reading the header off the fire the firer captured.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text="ok", headers={"Set-Cookie": "session=abc; SameSite=None; Secure"}
        )

    session = _session_on(handler)
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/"))
    param = session.graph.add_parameter(ep, Parameter(name="probe", location="query"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    fired = _call(
        mcp, "fire_request", identity="anon", endpoint_node=ep, param_node=param, payload=""
    )
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "csrf_missing_protection",
            "probe_fire_ref": fired.fire_ref,  # type: ignore[attr-defined]
            "csrf_token_present": False,
            "evidence_ref": "csrf/fire-ref",
        },
    )
    # SameSite=None + no token, resolved from the fire_ref → precondition holds.
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_structural_csrf_token_present_denies() -> None:
    # An anti-CSRF token mechanism defeats the precondition even with a
    # SameSite=None cookie: csrf_token_present is a caller-supplied boolean.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text="ok", headers={"Set-Cookie": "session=abc; SameSite=None; Secure"}
        )

    session = _session_on(handler)
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/"))
    param = session.graph.add_parameter(ep, Parameter(name="probe", location="query"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    fired = _call(
        mcp, "fire_request", identity="anon", endpoint_node=ep, param_node=param, payload=""
    )
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "csrf_missing_protection",
            "probe_fire_ref": fired.fire_ref,  # type: ignore[attr-defined]
            "csrf_token_present": True,
            "evidence_ref": "csrf/token-present",
        },
    )
    assert verdict.is_violation is False  # type: ignore[attr-defined]


def test_run_oracle_structural_csrf_inline_set_cookie_wins() -> None:
    # Precedence: an inline set_cookie beats what the fire_ref carries. The
    # captured response ships SameSite=Lax (no precondition), but an inline
    # SameSite=None cookie must still flip the verdict to a violation.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok", headers={"Set-Cookie": "session=abc; SameSite=Lax"})

    session = _session_on(handler)
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/"))
    param = session.graph.add_parameter(ep, Parameter(name="probe", location="query"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    fired = _call(
        mcp, "fire_request", identity="anon", endpoint_node=ep, param_node=param, payload=""
    )
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "csrf_missing_protection",
            "set_cookie": "s=1; SameSite=None",
            "probe_fire_ref": fired.fire_ref,  # type: ignore[attr-defined]
            "csrf_token_present": False,
            "evidence_ref": "csrf/inline-wins",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]
