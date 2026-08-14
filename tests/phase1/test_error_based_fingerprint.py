"""Error-triggering fingerprint probe for quoted error-based sinks (closes live E2E)."""

from __future__ import annotations

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Finding, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
)
from reachagent.payloads import PayloadLibrary
from reachagent.tools import explorer, validator
from reachagent.tools.candidate import FingerprintReport
from reachagent.tools.explorer_context import ExplorerContext

BASE_URL = "https://target.test"
_CANARY = "reachagent-canary-7f3a2b"


def _graph_with_param() -> tuple[ReachabilityGraph, str, str]:
    graph = ReachabilityGraph()
    endpoint_node = graph.add_endpoint(Endpoint(method="GET", path="/users/v1/name"))
    param_node = graph.add_parameter(endpoint_node, Parameter(name="q", location="query"))
    return graph, endpoint_node, param_node


def _context(
    graph: ReachabilityGraph, handler: object
) -> tuple[ExplorerContext, list[httpx.Request]]:
    calls: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)  # type: ignore[operator, no-any-return]

    client = httpx.Client(transport=httpx.MockTransport(recording))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["target.test"]))
    return (
        ExplorerContext(
            graph=graph, firer=firer, library=PayloadLibrary.from_file(), base_url=BASE_URL
        ),
        calls,
    )


def _q(request: httpx.Request) -> str:
    return request.url.params.get("q", "")


# -- The live-VAmPI case: benign canary 404 clean, diagnostic canary' → SQL --------


def test_diagnostic_infers_sql_for_quoted_error_sink() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _q(request) == f"{_CANARY}'":
            return httpx.Response(500, text="sqlalchemy.exc.OperationalError: unrecognized token")
        return httpx.Response(404, text='{"status":"fail","message":"User not found"}')

    graph, ep, pn = _graph_with_param()
    ctx, calls = _context(graph, handler)
    report = explorer.fingerprint_parameter(ctx, "user_a", ep, pn)

    assert isinstance(report, FingerprintReport)
    assert report.inferred_sink_type is SinkType.SQL
    assert graph.parameter_sink(pn) is SinkType.SQL
    # Benign canary first, then one diagnostic probe — exactly two requests.
    assert len(calls) == 2
    assert _q(calls[0]) == _CANARY
    assert _q(calls[1]) == f"{_CANARY}'"
    # The diagnostic's sql signature is the provenance.
    assert "sqlalchemy" in (report.error_signature or "")
    # get_payloads now matches the error-based SQLi payload set.
    entries = explorer.get_payloads(ctx, "sqli", SinkType.SQL)
    assert entries
    assert any("quote-break" in e.payload_ref for e in entries)


# -- E2E: fingerprint → get_payloads → fire quote-break → run_oracle → write_finding --


def test_end_to_end_quoted_sqli_to_confirmed_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        q = _q(request)
        if q == "'":
            return httpx.Response(500, text="sqlalchemy.exc.OperationalError: unrecognized token")
        if q == f"{_CANARY}'":
            return httpx.Response(500, text="sqlalchemy.exc.OperationalError: unrecognized token")
        return httpx.Response(404, text="User not found")

    graph, ep, pn = _graph_with_param()
    ctx, _calls = _context(graph, handler)

    # 1. fingerprint → SQL via the diagnostic.
    report = explorer.fingerprint_parameter(ctx, "user_a", ep, pn)
    assert report.inferred_sink_type is SinkType.SQL

    # 2. sink-matched payloads include the error-based quote-break.
    entries = explorer.get_payloads(ctx, "sqli", SinkType.SQL)
    quote_entry = next(e for e in entries if "quote-break" in e.payload_ref)

    # 3. fire the quote-break payload through the (now fingerprinted) param.
    from reachagent.payloads.payload_resolver import resolve_entry

    payload = resolve_entry(quote_entry)
    assert payload == "'"
    fire_result = explorer.fire_request(ctx, "user_a", ep, pn, payload)
    assert fire_result.status_code == 500
    assert "sqlalchemy" in fire_result.body.decode("utf-8", errors="replace").lower()

    # 4. run_oracle differential DATABASE_ERROR: baseline served (2xx), probe 500 + sig.
    evidence = DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.DATABASE_ERROR,
        baseline=Observation(label="baseline", status_code=200, body="User not found"),
        probe=Observation(
            label="probe",
            status_code=fire_result.status_code,
            body=fire_result.body.decode("utf-8", errors="replace"),
        ),
        error_signatures=("sqlalchemy",),
        evidence_ref="generic/payload-chain",
    )
    verdict = validator.run_oracle(OracleMechanism.DIFFERENTIAL, evidence)
    assert verdict.is_violation

    # 5. write_finding commits the Finding.
    node = validator.write_finding(
        graph, Finding(vuln_class="sqli", severity="high", oracle_used="", evidence_ref=""), verdict
    )
    assert node
    assert len(graph.findings()) == 1
    assert graph.findings()[0][1].vuln_class == "sqli"


# -- Negative: HTML reflection — diagnostic must not override an observed sink ----


def test_html_reflection_diagnostic_does_not_override() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text=f"<html>{_q(request)}</html>", headers={"content-type": "text/html"}
        )

    graph, ep, pn = _graph_with_param()
    ctx, calls = _context(graph, handler)
    report = explorer.fingerprint_parameter(ctx, "user_a", ep, pn)
    # Observed HTML reflection wins; the diagnostic never fires (observed != None).
    assert report.inferred_sink_type is SinkType.HTML_REFLECTION
    assert graph.parameter_sink(pn) is SinkType.HTML_REFLECTION
    assert len(calls) == 1  # benign canary only — no diagnostic probe


# -- Hint interplay: a sink_hint skips the diagnostic entirely --------------------


def test_sink_hint_skips_diagnostic() -> None:
    graph = ReachabilityGraph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/file"))
    pn = graph.add_parameter(ep, Parameter(name="f", location="path"))
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(404, text="nope")

    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    firer = RequestFirer(client, ScopeGuard.from_hosts(["target.test"]))
    ctx = ExplorerContext(
        graph=graph, firer=firer, library=PayloadLibrary.from_file(), base_url=BASE_URL
    )
    report = explorer.fingerprint_parameter(
        ctx, "user_a", ep, pn, sink_hint=SinkType.FILE_PATH, vuln_class="path_traversal"
    )
    assert report.inferred_sink_type is SinkType.FILE_PATH
    assert len(calls) == 1  # hint present → no diagnostic probe


# -- Diagnostic fires at most once, read-only GET, scope held ---------------------


def test_diagnostic_fires_at_most_once_read_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="nope")

    graph, ep, pn = _graph_with_param()
    ctx, calls = _context(graph, handler)
    report = explorer.fingerprint_parameter(ctx, "user_a", ep, pn)
    assert report.inferred_sink_type is None  # no SQL error → sink stays None
    assert len(calls) == 2  # canary + one diagnostic, at most one diagnostic
    assert all(c.method == "GET" for c in calls)


# -- Invariants -------------------------------------------------------------------


def test_six_oracle_families_unchanged() -> None:
    assert set(OracleMechanism) == {
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.STRUCTURAL,
        OracleMechanism.TIMING_STATISTICAL,
        OracleMechanism.OOB_CALLBACK,
        OracleMechanism.EXECUTION_CONFIRMATION,
        OracleMechanism.BUSINESS_RULE_INVARIANT,
    }


def test_explorer_tool_surface_unchanged() -> None:
    # The diagnostic is a private branch inside fingerprint_parameter — it adds no
    # public callable, so the role-boundary test's four-tool surface still holds.
    public = {
        n
        for n, obj in vars(explorer).items()
        if not n.startswith("_") and callable(obj) and not isinstance(obj, type)
    }
    assert public == {
        "fingerprint_parameter",
        "get_payloads",
        "fire_request",
        "classify_response",
        "fire_browser",
    }
