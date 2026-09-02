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
from tests._oracle_test_support import ALLOWS, CONFIRMS, FixedJudgmentClient

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from reachagent.graph.nodes import FindingStatus


def _stub_judgment(monkeypatch: pytest.MonkeyPatch, status: FindingStatus) -> None:
    """Force run_oracle's LLM judgment to a fixed status (v3 architecture, CLAUDE.md).

    The MCP ``run_oracle`` tool (unlike ``tools.validator.run_oracle`` directly)
    exposes no ``client=`` kwarg to a hand-caller, so these end-to-end tests can't
    inject :class:`FixedJudgmentClient` the way tests/phase3 and tests/phase6 do.
    Instead this patches the same default-provider factory ``judge()`` falls back
    to when no client is supplied — the equivalent seam at this boundary. What used
    to be a fixed per-mechanism ``decide()`` producing a status from evidence content
    is now an LLM call that can't be pinned deterministically; these tests instead
    assert the surrounding wiring (fire_ref/header resolution, control-char and
    oversized-body sanitization not crashing, and the verdict_ref chaining into
    write_finding) reacts correctly to a given verdict.
    """
    from reachagent.oracles import llm_judgment as _judgment

    monkeypatch.setattr(
        _judgment,
        "build_openai_compatible_client",
        lambda **_: FixedJudgmentClient(status.value),
    )


EXPLORER_TOOLS = {
    "fingerprint_parameter",
    "get_payloads",
    "fire_request",
    "classify_response",
    "fire_browser",
    "fire_proxy_request",
    "fire_browser_form",
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


def test_run_oracle_ref_chains_into_write_finding_for_a_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A confirmed_violation verdict (BOLA: attacker gets the owner's body) minted by
    # run_oracle can be committed by write_finding via its verdict_ref. Which status
    # a given evidence produces is now an LLM's call (v3), not something this test can
    # pin down deterministically — it fixes CONFIRMS and asserts the ref-chain wiring.
    _stub_judgment(monkeypatch, CONFIRMS)
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


def test_write_finding_refuses_a_non_violation_verdict_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # confirmed_allowed is a fact, not a finding — write_finding must refuse it,
    # even though it came from a real run_oracle handle. Fix ALLOWS via the judgment
    # seam (v3 — see _stub_judgment) since it's no longer derivable from evidence.
    from reachagent.tools.validator_support import UnconfirmedFindingError

    _stub_judgment(monkeypatch, ALLOWS)
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


def test_run_oracle_structural_resolves_body_from_fire_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Fix C: the structural oracle resolves response_body server-side from a
    # probe_fire_ref, so the response body never crosses the MCP wire. The client
    # supplies only the opaque fire handle; the resolved body reaches the (fixed,
    # v3) judgment step, mirroring the differential branch's resolution.
    _stub_judgment(monkeypatch, CONFIRMS)
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
    # No response_body key supplied and no exception raised resolving it from the
    # fire_ref — the fixed judgment status confirms the wiring end to end.
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_survives_a_control_character_in_an_inline_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A real target's response can legitimately carry a raw control byte (a
    # legacy Java/JSP error page is a common source) — this used to raise
    # ValueError deep inside StructuralEvidence's own validation and abort
    # the whole scan via "Error executing tool run_oracle: response_body
    # contains a control character". It must now be sanitized transparently
    # and the check must still run to a real verdict, not crash. Which status a
    # given evidence produces is now the LLM's call (v3) — CONFIRMS is fixed via
    # _stub_judgment so the test can assert the sanitize-then-judge path itself
    # doesn't crash and the wiring still reacts to a violation.
    _stub_judgment(monkeypatch, CONFIRMS)
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "info_disclosure",
            "probe_status": 500,
            "sentinel": "JasperException",
            "response_body": "stack trace\x00\x1bJasperException\x07 at line 1",
            "evidence_ref": "control-char-inline",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_survives_a_control_character_in_a_fire_ref_resolved_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Same failure mode, but for a body resolved server-side from a
    # probe_fire_ref (the _project() path) rather than an inline string —
    # covers both places raw body text enters evidence. CONFIRMS fixed via
    # _stub_judgment (v3): the point is the resolve-then-sanitize path doesn't crash.
    _stub_judgment(monkeypatch, CONFIRMS)
    session = _session_on(lambda r: httpx.Response(200, text="root:x:0:0\x00\x1btail"))
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/ftp/{filename}"))
    param = session.graph.add_parameter(ep, Parameter(name="filename", location="path"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
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
            "probe_status": probe.status_code,  # type: ignore[attr-defined]
            "sentinel": "root:",
            "probe_fire_ref": probe.fire_ref,  # type: ignore[attr-defined]
            "evidence_ref": "control-char-fire-ref",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_survives_an_oversized_inline_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Live-verification catch (v2 Phase 6 Stage D, against a real crAPI target): a
    # multi-megabyte JSON listing crashed the whole scan with "Error executing tool
    # run_oracle: response_body exceeds its evidence size limit" — StructuralEvidence's
    # own 1,000,000-char validation cap raising ValueError deep inside a real oracle
    # call, aborting the run instead of degrading. The body is now capped server-side
    # before the evidence object is built, so the cap itself must not raise. CONFIRMS
    # fixed via _stub_judgment (v3) — matching evidence to a status is the LLM's job.
    _stub_judgment(monkeypatch, CONFIRMS)
    session = _session_on(lambda r: httpx.Response(200, text="ok"))
    mcp = _register_on_session(session)
    oversized = "JasperException" + ("x" * 2_000_000)
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "info_disclosure",
            "probe_status": 500,
            "sentinel": "JasperException",
            "response_body": oversized,
            "evidence_ref": "oversized-inline",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_survives_an_oversized_fire_ref_resolved_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Same failure mode, but for a body resolved server-side from a probe_fire_ref —
    # covers both places raw body text enters evidence, mirroring the control-character
    # regression tests above. CONFIRMS fixed via _stub_judgment (v3).
    _stub_judgment(monkeypatch, CONFIRMS)
    session = _session_on(lambda r: httpx.Response(200, text="root:x:0:0" + ("y" * 2_000_000)))
    ep = session.graph.add_endpoint(Endpoint(method="GET", path="/ftp/{filename}"))
    param = session.graph.add_parameter(ep, Parameter(name="filename", location="path"))
    mcp = _register_on_session(session)

    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
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
            "probe_status": probe.status_code,  # type: ignore[attr-defined]
            "sentinel": "root:",
            "probe_fire_ref": probe.fire_ref,  # type: ignore[attr-defined]
            "evidence_ref": "oversized-fire-ref",
        },
    )
    assert verdict.is_violation is True  # type: ignore[attr-defined]


def test_run_oracle_structural_union_resolves_body_from_fire_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # CONFIRMS fixed via _stub_judgment (v3) — asserts the fire_ref body resolution
    # doesn't crash and the verdict wiring reacts correctly to a violation.
    _stub_judgment(monkeypatch, CONFIRMS)
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


def test_run_oracle_execution_confirmation_resolves_body_from_fire_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Fix C: the execution_confirmation oracle resolves response_body from a
    # probe_fire_ref for the stored-XSS read-back — the client passes only the
    # payload_tag and the fire handle, never the body. CONFIRMS fixed via
    # _stub_judgment (v3): asserts the resolution doesn't crash and the wiring reacts.
    _stub_judgment(monkeypatch, CONFIRMS)
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


def test_run_oracle_structural_clickjacking_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # MCP structural branch must forward x_frame_options + csp fields. Which status
    # that produces is now the LLM's call (v3) — CONFIRMS fixed via _stub_judgment.
    _stub_judgment(monkeypatch, CONFIRMS)
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


def test_run_oracle_structural_cors_misconfig_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # MCP structural branch must forward acao, acac, probe_origin fields. Which
    # status that produces is now the LLM's call (v3) — CONFIRMS fixed via
    # _stub_judgment.
    _stub_judgment(monkeypatch, CONFIRMS)
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


def test_run_oracle_structural_resolves_cors_headers_from_fire_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Task D: ACAO/ACAC resolve server-side from probe_fire_ref. The captured
    # response reflects the attacker origin with credentials on; only probe_origin
    # crosses the wire. CONFIRMS fixed via _stub_judgment (v3) — asserts the header
    # resolution doesn't crash and the wiring reacts correctly to a violation.
    _stub_judgment(monkeypatch, CONFIRMS)
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


def test_run_oracle_structural_resolves_set_cookie_from_fire_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # CSRF: Set-Cookie resolves server-side from probe_fire_ref, same as the
    # framing/CORS headers. The captured response ships a SameSite=None session
    # cookie; no set_cookie key is passed. CONFIRMS fixed via _stub_judgment (v3) —
    # asserts the header resolution doesn't crash and the wiring reacts correctly.
    _stub_judgment(monkeypatch, CONFIRMS)

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


def test_run_oracle_structural_csrf_inline_set_cookie_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Precedence: an inline set_cookie beats what the fire_ref carries. CONFIRMS
    # fixed via _stub_judgment (v3) — asserts the inline-wins resolution doesn't
    # crash and the wiring reacts correctly to a violation.
    _stub_judgment(monkeypatch, CONFIRMS)

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
