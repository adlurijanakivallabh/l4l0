"""Big Task 19 generic payload-library chain tests."""

from __future__ import annotations

import httpx

from reachagent.execution import AuditLog, RequestFirer, ScopeGuard
from reachagent.graph.nodes import AuthState, Endpoint, Identity, Parameter, Provenance, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.mcp import server
from reachagent.oracles import OracleMechanism
from reachagent.payloads import PayloadEntry, PayloadLibrary, build_library, resolve_entry
from reachagent.tools.explorer_context import ExplorerContext
from reachagent.tools.payload_chain import (
    audit_failure_callback,
    call_tool_sync,
    run_coordinator_payload_step,
    run_payload_chain,
)


def _session(handler, *, library: PayloadLibrary | None = None) -> tuple[server._Session, object]:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    audit = AuditLog()
    firer = RequestFirer(client, ScopeGuard.from_hosts(["vampi.test"]), audit)
    graph = ReachabilityGraph()
    context = ExplorerContext(
        graph=graph,
        firer=firer,
        library=library or PayloadLibrary.from_file(),
        base_url="http://vampi.test",
    )
    session = server._Session(ctx=context)
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("payload-chain-test")
    server.register_tools(mcp, session)
    return session, mcp


def _surface(mcp: object) -> object:
    return mcp


def test_generic_chain_uses_real_library_payload_over_mcp() -> None:
    seen: list[httpx.Request] = []

    corpus_entry = next(
        entry
        for entry in build_library().get_payloads("sqli", SinkType.SQL)
        if "#L" in entry.payload_ref
    )
    corpus_value = resolve_entry(corpus_entry)
    assert corpus_value
    assert corpus_entry.payload_ref.startswith("PayloadsAllTheThings/")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        value = request.url.params.get("q", "")
        if value == "baseline":
            return httpx.Response(200, text="safe")
        if value == corpus_value or value.startswith("reachagent-canary-"):
            return httpx.Response(500, text="You have an error in your SQL syntax")
        return httpx.Response(200, text="safe")

    session, mcp = _session(handler, library=PayloadLibrary([corpus_entry]))
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/users/v1/name"))
    parameter = session.graph.add_parameter(endpoint, Parameter("q", "query"))
    assert session.ctx.graph.parameter_sink(parameter) is None
    assert session.ctx.is_fingerprinted(parameter) is False
    audit_failure = audit_failure_callback(
        session.ctx.firer.audit,
        identity="anonymous",
        base_url=session.ctx.base_url,
        endpoint_path="/users/v1/name",
    )

    result = run_payload_chain(
        lambda name, arguments: call_tool_sync(_surface(mcp), name, arguments),
        identity="anonymous",
        endpoint_node=endpoint,
        param_node=parameter,
        vuln_class="sqli",
        baseline_payload="baseline",
        audit_failure=audit_failure,
    )

    assert result.confirmed is True
    assert result.attempted == 1
    assert result.finding_node is not None
    assert result.payload_ref == corpus_entry.payload_ref
    assert session.graph.findings()
    assert seen[0].url.params["q"]
    assert seen[1].url.params["q"] == "baseline"
    assert seen[2].url.params["q"] == corpus_value
    expected_raw_path = httpx.URL(
        "http://vampi.test/users/v1/name", params={"q": corpus_value}
    ).raw_path
    assert seen[2].url.raw_path == expected_raw_path
    assert all(
        entry.target == "http://vampi.test/users/v1/name"
        for entry in session.ctx.firer.audit.entries
    )
    assert all("'" not in entry.target for entry in session.ctx.firer.audit.entries)
    assert not any(
        entry.outcome == "payload_chain_failure" for entry in session.ctx.firer.audit.entries
    )


def test_payload_exhaustion_is_audited() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("q", "").startswith("reachagent-canary-"):
            return httpx.Response(500, text="You have an error in your SQL syntax")
        return httpx.Response(200, text="safe")

    session, mcp = _session(handler)
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/public"))
    parameter = session.graph.add_parameter(endpoint, Parameter("q", "query"))
    failures: list[str] = []
    result = run_payload_chain(
        lambda name, arguments: call_tool_sync(mcp, name, arguments),
        identity="anonymous",
        endpoint_node=endpoint,
        param_node=parameter,
        vuln_class="sqli",
        baseline_payload="baseline",
        max_attempts=1,
        audit_failure=failures.append,
    )
    assert result.failure and "payloads exhausted" in result.failure
    assert failures == [result.failure]


def test_empty_sink_is_explicit_and_audited() -> None:
    session, mcp = _session(lambda request: httpx.Response(200, text="safe"))
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/public"))
    parameter = session.graph.add_parameter(endpoint, Parameter("q", "query"))
    failures: list[str] = []

    result = run_payload_chain(
        lambda name, arguments: call_tool_sync(mcp, name, arguments),
        identity="anonymous",
        endpoint_node=endpoint,
        param_node=parameter,
        vuln_class="sqli",
        baseline_payload="baseline",
        audit_failure=failures.append,
    )

    assert result.confirmed is False
    assert result.attempted == 0
    assert result.failure and "no payloads matched" in result.failure
    assert failures == [result.failure]
    assert session.graph.findings() == []


def test_missing_payload_slot_is_loud_and_audited() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("q", "").startswith("reachagent-canary-"):
            return httpx.Response(500, text="You have an error in your SQL syntax")
        return httpx.Response(200, text="safe")

    session, mcp = _session(handler)
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/users/v1/name"))
    parameter = session.graph.add_parameter(endpoint, Parameter("q", "query"))
    failures: list[str] = []

    # The full library's sqli_blind/sql bucket carries a timing_statistical entry
    # whose evidence needs the dedicated blind-SQLi prober. The generic chain has
    # no safe adapter for it, so the entry is SKIPPED with a loud audit — never
    # fired, never silently clean — and the explicit failed result reports why.
    result = run_payload_chain(
        lambda name, arguments: call_tool_sync(mcp, name, arguments),
        identity="anonymous",
        endpoint_node=endpoint,
        param_node=parameter,
        vuln_class="sqli_blind",
        baseline_payload="baseline",
        audit_failure=failures.append,
    )

    assert result.confirmed is False
    assert any("no safe evidence adapter" in f for f in failures)
    assert "timing_statistical" in failures[0]
    assert result.failure and "payloads exhausted" in result.failure
    assert session.graph.findings() == []


def test_dead_payload_ref_is_loud_and_audited() -> None:
    entry = PayloadEntry(
        vuln_class="sqli",
        context="dead ref test",
        inferred_sink_type=SinkType.SQL,
        oracle_type=OracleMechanism.DIFFERENTIAL,
        payload_ref="SecLists/does-not-exist.txt#L999999",
        graph_edge_on_success="enables",
    )
    session, mcp = _session(
        lambda request: httpx.Response(500, text="You have an error in your SQL syntax"),
        library=PayloadLibrary([entry]),
    )
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/users/v1/name"))
    parameter = session.graph.add_parameter(endpoint, Parameter("q", "query"))
    failures: list[str] = []

    # The MCP get_payloads layer skips unresolvable refs (dead handles) rather
    # than crashing the whole chain; the explicit failed result is still loud:
    # it says the bucket was exhausted and nothing was confirmed.
    result = run_payload_chain(
        lambda name, arguments: call_tool_sync(mcp, name, arguments),
        identity="anonymous",
        endpoint_node=endpoint,
        param_node=parameter,
        vuln_class="sqli",
        baseline_payload="baseline",
        audit_failure=failures.append,
    )

    assert result.confirmed is False
    assert result.attempted == 0
    # Every entry skipped -> the earlier, equally-explicit empty-bucket failure.
    assert result.failure and "no payloads matched" in result.failure
    assert session.graph.findings() == []


def test_unsupported_oracle_is_loud_and_audited() -> None:
    entry = PayloadEntry(
        vuln_class="sqli",
        context="unsupported test",
        inferred_sink_type=SinkType.SQL,
        oracle_type=OracleMechanism.TIMING_STATISTICAL,
        payload_ref="sqli/error-based/quote-break",
        graph_edge_on_success="enables",
    )
    session, mcp = _session(
        lambda request: httpx.Response(500, text="You have an error in your SQL syntax"),
        library=PayloadLibrary([entry]),
    )
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/users/v1/name"))
    parameter = session.graph.add_parameter(endpoint, Parameter("q", "query"))
    failures: list[str] = []

    # An unsupported oracle family is skipped with a loud audit; the chain
    # continues past it and the explicit failure names the reason.
    result = run_payload_chain(
        lambda name, arguments: call_tool_sync(mcp, name, arguments),
        identity="anonymous",
        endpoint_node=endpoint,
        param_node=parameter,
        vuln_class="sqli",
        baseline_payload="baseline",
        audit_failure=failures.append,
    )
    assert failures and "no safe evidence adapter" in failures[0]
    assert result.confirmed is False
    assert session.graph.findings() == []


def test_success_mcp_sequence_includes_validator_calls() -> None:
    seen: list[str] = []
    corpus_entry = next(
        entry
        for entry in build_library().get_payloads("sqli", SinkType.SQL)
        if "#L" in entry.payload_ref
    )
    corpus_value = resolve_entry(corpus_entry)

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        if value.startswith("reachagent-canary-") or value == corpus_value:
            return httpx.Response(500, text="You have an error in your SQL syntax")
        return httpx.Response(200, text="safe")

    session, mcp = _session(handler, library=PayloadLibrary([corpus_entry]))
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/users/v1/name"))
    parameter = session.graph.add_parameter(endpoint, Parameter("q", "query"))

    def caller(name: str, arguments: dict[str, object]) -> object:
        seen.append(name)
        return call_tool_sync(mcp, name, arguments)

    result = run_payload_chain(
        caller,
        identity="anonymous",
        endpoint_node=endpoint,
        param_node=parameter,
        vuln_class="sqli",
        baseline_payload="baseline",
    )
    assert result.confirmed is True
    assert seen == [
        "fingerprint_parameter",
        "get_payloads",
        "fire_request",
        "fire_request",
        "classify_response",
        "run_oracle",
        "write_finding",
    ]


def test_real_mcp_call_tool_boundary_is_used() -> None:
    session, mcp = _session(lambda request: httpx.Response(200, text="safe"))
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/public"))
    parameter = session.graph.add_parameter(endpoint, Parameter("q", "query"))
    names: list[str] = []

    def caller(name: str, arguments: dict[str, object]) -> object:
        names.append(name)
        return call_tool_sync(mcp, name, arguments)

    run_payload_chain(
        caller,
        identity="anonymous",
        endpoint_node=endpoint,
        param_node=parameter,
        vuln_class="sqli",
        baseline_payload="baseline",
    )
    assert names[:2] == ["fingerprint_parameter", "get_payloads"]
    assert "fire_request" not in names
    assert session.ctx.firer.audit.entries


def test_coordinator_selection_drives_generic_chain() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        if value.startswith("reachagent-canary-") or value == "'":
            return httpx.Response(500, text="You have an error in your SQL syntax")
        return httpx.Response(200, text="safe")

    session, mcp = _session(handler)
    identity = session.graph.add_identity(
        "anonymous",
        Identity(role="user", auth_state=AuthState.UNAUTH, provenance=Provenance.SEEDED),
    )
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/users/v1/name"))
    session.graph.add_parameter(endpoint, Parameter("q", "query"))
    from reachagent.graph.chain_solver import ChainSolver
    from reachagent.tools.coordinator_support import CoordinatorContext

    context = CoordinatorContext(session.graph, ChainSolver(session.graph), run_id="task19")
    result = run_coordinator_payload_step(
        lambda name, arguments: call_tool_sync(mcp, name, arguments),
        {"context": context, "identity_node": identity, "endpoint_node": endpoint},
        vuln_class="sqli",
        baseline_payload="baseline",
    )

    assert result.confirmed is True
    assert result.finding_node is not None
    assert session.graph.findings()

    audit = AuditLog()
    callback = audit_failure_callback(
        audit,
        identity="anonymous",
        base_url="http://vampi.test",
        endpoint_path="/users?secret=payload",
    )
    callback("no payloads matched")
    assert audit.entries[0].target == "http://vampi.test/users"
    assert "secret" not in audit.entries[0].target
    assert "payload" not in audit.entries[0].target


def test_ssti_payload_fires_end_to_end_through_execution_confirmation_chain() -> None:
    """Prove a NEW honest-mapped class (SSTI) resolves and fires, not just sitting."""
    corpus_entry = next(
        entry
        for entry in build_library().get_payloads("ssti", SinkType.TEMPLATE)
        if "#L" in entry.payload_ref
    )
    assert corpus_entry.vuln_class == "ssti"
    assert corpus_entry.inferred_sink_type is SinkType.TEMPLATE
    assert corpus_entry.oracle_type is OracleMechanism.EXECUTION_CONFIRMATION
    corpus_value = resolve_entry(corpus_entry)
    assert (
        "{{" in corpus_value or "${" in corpus_value or "<%" in corpus_value or "#{" in corpus_value
    )

    from reachagent.payloads import expected_execution_output

    expected = expected_execution_output(corpus_value)
    assert expected is not None

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        # Plain-text reflection with the expected rendered value injected — proves
        # execution confirmation fires over the real wire (not a faked status).
        if request.url.params.get("_q") == corpus_value:
            return httpx.Response(
                200, text=f"rendered {expected}", headers={"content-type": "text/plain"}
            )
        if request.url.params.get("_q", "").startswith("reachagent-canary-"):
            # Benign canary reflects in plain text — required for template hint gate.
            return httpx.Response(
                200, text=request.url.params.get("_q", ""), headers={"content-type": "text/plain"}
            )
        return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

    session, mcp = _session(handler, library=PayloadLibrary([corpus_entry]))
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/users/v1/name"))
    parameter = session.graph.add_parameter(endpoint, Parameter("_q", "query"))

    result = run_payload_chain(
        lambda name, arguments: call_tool_sync(_surface(mcp), name, arguments),
        identity="anonymous",
        endpoint_node=endpoint,
        param_node=parameter,
        vuln_class="ssti",
        baseline_payload="baseline",
    )

    assert result.confirmed is True
    assert result.payload_ref == corpus_entry.payload_ref
    assert session.graph.findings()
    # The attack payload actually crossed the wire as a value (not a status fake).
    assert any(r.url.params.get("_q") == corpus_value for r in seen)


def test_non_arithmetic_ssti_payload_is_rejected_before_any_attack_fire() -> None:
    """Preflight: a non-arithmetic SSTI payload never fires an attack request."""
    entry = PayloadEntry(
        vuln_class="ssti",
        context="non-arithmetic ssti test",
        inferred_sink_type=SinkType.TEMPLATE,
        oracle_type=OracleMechanism.EXECUTION_CONFIRMATION,
        payload_ref="PayloadsAllTheThings/Server Side Template Injection/Intruder/ssti.fuzz#L12",
        graph_edge_on_success="enables",
    )
    # Lines that aren't simple arithmetic survive the corpus semantic guard only when they
    # actually have a sink match; the test uses one that won't resolve to an arithmetic value.
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        q = request.url.params.get("_q", "")
        if q.startswith("reachagent-canary-"):
            return httpx.Response(200, text=q, headers={"content-type": "text/plain"})
        return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

    session, mcp = _session(handler, library=PayloadLibrary([entry]))
    endpoint = session.graph.add_endpoint(Endpoint("GET", "/users/v1/name"))
    parameter = session.graph.add_parameter(endpoint, Parameter("_q", "query"))
    failures: list[str] = []

    # The unsafe payload is SKIPPED with a loud audit before any attack fire —
    # the safety guarantee is unchanged (nothing non-deterministic crosses the
    # wire); the mechanism is a per-entry skip instead of a chain-wide abort.
    result = run_payload_chain(
        lambda name, arguments: call_tool_sync(_surface(mcp), name, arguments),
        identity="anonymous",
        endpoint_node=endpoint,
        param_node=parameter,
        vuln_class="ssti",
        baseline_payload="baseline",
        audit_failure=failures.append,
    )
    assert failures and "no deterministic rendered" in failures[0]
    assert result.confirmed is False and result.attempted == 0
    # Only canary fired — no attack fire reached the wire.
    assert not any(
        r.url.params.get("_q")
        for r in seen
        if not r.url.params.get("_q", "").startswith("reachagent")
    )
