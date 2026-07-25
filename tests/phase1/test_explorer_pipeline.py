"""Explorer tool pipeline — the §9 sequence as real functions (plan §9, §13; Task 5).

Asserts the Task 5 DoD invariants:

  1. ``fingerprint_parameter`` sends a benign canary first and sets
     ``inferred_sink_type`` on the ``Parameter`` node; nothing downstream fires
     before it completes (``fire_request`` refuses an un-fingerprinted param).
  2. ``classify_response`` emits a *candidate* record only — it has no code path
     to ``write_finding``.
  3. All four Explorer tools are real functions routing through Task 1's firer
     (here wired to an ``httpx.MockTransport`` standing in for the target).

The candidate → oracle → finding gate is one-way: the Explorer produces an inert
``Candidate`` and can never confirm it. That the module also cannot even *reach*
``write_finding`` is asserted structurally.
"""

from __future__ import annotations

import httpx
import pytest

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.payloads import PayloadLibrary
from reachagent.tools import explorer
from reachagent.tools.candidate import Candidate, FingerprintReport
from reachagent.tools.explorer_context import ExplorerContext, FingerprintRequiredError

BASE_URL = "https://target.test"


def _graph_with_param(
    *, path: str = "/users/v1/name", location: str = "query", name: str = "q"
) -> tuple[ReachabilityGraph, str, str]:
    """A graph holding one endpoint + one parameter; returns their node ids."""
    graph = ReachabilityGraph()
    endpoint_node = graph.add_endpoint(Endpoint(method="GET", path=path))
    param_node = graph.add_parameter(endpoint_node, Parameter(name=name, location=location))
    return graph, endpoint_node, param_node


def _context(
    graph: ReachabilityGraph,
    handler: object,
    *,
    calls: list[httpx.Request] | None = None,
) -> ExplorerContext:
    """An ExplorerContext whose firer is wired to a recording MockTransport."""

    def recording(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        return handler(request)  # type: ignore[operator, no-any-return]

    client = httpx.Client(transport=httpx.MockTransport(recording))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["target.test"]))
    return ExplorerContext(
        graph=graph,
        firer=firer,
        library=PayloadLibrary.from_file(),
        base_url=BASE_URL,
    )


# -- Invariant 1: fingerprint canary-first, sets sink, gates downstream ---


def test_fingerprint_sends_canary_and_sets_sql_sink() -> None:
    # The canary provokes a SQL error → the parameter is fingerprinted as SQL.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="You have an error in your SQL syntax near ''")

    graph, endpoint_node, param_node = _graph_with_param()
    calls: list[httpx.Request] = []
    ctx = _context(graph, handler, calls=calls)

    report = explorer.fingerprint_parameter(ctx, "user_a", endpoint_node, param_node)

    assert isinstance(report, FingerprintReport)
    assert report.inferred_sink_type is SinkType.SQL
    # The sink is written onto the Parameter node, not just returned.
    assert graph.parameter_sink(param_node) is SinkType.SQL
    # Exactly one request fired — the canary — and it carried the canary marker.
    assert len(calls) == 1
    assert ctx.canary in (calls[0].url.query.decode() or "")


def test_fingerprint_of_html_reflection_sets_html_sink() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        canary = request.url.params.get("q", "")
        return httpx.Response(200, text=f"<p>{canary}</p>", headers={"content-type": "text/html"})

    graph, endpoint_node, param_node = _graph_with_param()
    ctx = _context(graph, handler)

    report = explorer.fingerprint_parameter(ctx, "user_a", endpoint_node, param_node)
    assert report.reflected is True
    assert report.inferred_sink_type is SinkType.HTML_REFLECTION
    assert graph.parameter_sink(param_node) is SinkType.HTML_REFLECTION


def test_fingerprint_may_infer_no_sink() -> None:
    # A clean JSON response with no reflection and no SQL error → no sink. This
    # is a legitimate result (authz classes have no injection sink), and it must
    # still count as "fingerprinted" so downstream isn't blocked forever.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"users": []})

    graph, endpoint_node, param_node = _graph_with_param()
    ctx = _context(graph, handler)

    report = explorer.fingerprint_parameter(ctx, "user_a", endpoint_node, param_node)
    assert report.inferred_sink_type is None
    assert graph.parameter_sink(param_node) is None
    assert ctx.is_fingerprinted(param_node) is True


def test_fire_request_refused_before_fingerprint() -> None:
    # Nothing downstream fires before fingerprint completes: fire_request on an
    # un-fingerprinted parameter raises before any I/O.
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("fire_request must not reach the network pre-fingerprint")

    graph, endpoint_node, param_node = _graph_with_param()
    calls: list[httpx.Request] = []
    ctx = _context(graph, handler, calls=calls)

    with pytest.raises(FingerprintRequiredError):
        explorer.fire_request(ctx, "user_a", endpoint_node, param_node, "' OR 1=1--")
    assert calls == []  # no packet left the process


def test_fire_request_allowed_after_fingerprint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    graph, endpoint_node, param_node = _graph_with_param()
    calls: list[httpx.Request] = []
    ctx = _context(graph, handler, calls=calls)

    explorer.fingerprint_parameter(ctx, "user_a", endpoint_node, param_node)
    result = explorer.fire_request(ctx, "user_a", endpoint_node, param_node, "' OR 1=1--")
    assert result.status_code == 200
    # Two requests fired: the canary, then the payload.
    assert len(calls) == 2


# -- Invariant 2: get_payloads routes sink-matched entries ----------------


def test_get_payloads_routes_by_inferred_sink() -> None:
    graph, endpoint_node, param_node = _graph_with_param()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text='sqlite3.OperationalError: near "\'": syntax error')

    ctx = _context(graph, handler)
    explorer.fingerprint_parameter(ctx, "user_a", endpoint_node, param_node)

    sink = graph.parameter_sink(param_node)
    entries = explorer.get_payloads(ctx, "sqli", sink)
    assert entries  # sink-matched entries exist for sqli@sql
    assert all(e.inferred_sink_type is SinkType.SQL for e in entries)


# -- Invariant 3: classify_response emits a candidate, never a finding ----


def test_classify_response_emits_candidate_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    graph, endpoint_node, param_node = _graph_with_param()
    ctx = _context(graph, handler)
    explorer.fingerprint_parameter(ctx, "user_a", endpoint_node, param_node)
    result = explorer.fire_request(ctx, "user_a", endpoint_node, param_node, "payload")

    candidate = explorer.classify_response(
        result,
        identity="user_a",
        endpoint_node=endpoint_node,
        param_node=param_node,
        vuln_class="sqli",
        suggested_oracle=OracleMechanism.DIFFERENTIAL,
        payload_ref="sqli/error-based/quote-break",
    )
    assert isinstance(candidate, Candidate)
    # A candidate carries no verdict/status field and no confirm method.
    assert not hasattr(candidate, "status")
    assert not hasattr(candidate, "confirmed")
    assert not hasattr(candidate, "confirm")
    assert not hasattr(candidate, "write_finding")
    # It names which oracle *should* judge it — but does not judge.
    assert candidate.suggested_oracle is OracleMechanism.DIFFERENTIAL


def test_explorer_module_has_no_path_to_write_finding() -> None:
    # Structural proof the DoD asks for: classify_response (and the whole Explorer
    # module) cannot reach write_finding. The module exposes exactly the five
    # tools (fire_browser added Phase 3 Task 5) and imports no validator symbol.
    public = {
        name
        for name in vars(explorer)
        if callable(getattr(explorer, name)) and not name.startswith("_")
    }
    assert public == {
        "fingerprint_parameter",
        "get_payloads",
        "fire_request",
        "classify_response",
        "fire_browser",
    }
    assert "write_finding" not in vars(explorer)
    assert "run_oracle" not in vars(explorer)
    # No validator module was imported into the Explorer's namespace.
    import sys

    src = sys.modules["reachagent.tools.explorer"]
    assert not hasattr(src, "validator")


def test_classify_response_signal_is_raw_and_non_judgmental() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="You have an error in your SQL syntax; check the manual")

    graph, endpoint_node, param_node = _graph_with_param()
    ctx = _context(graph, handler)
    explorer.fingerprint_parameter(ctx, "user_a", endpoint_node, param_node)
    result = explorer.fire_request(ctx, "user_a", endpoint_node, param_node, "'")

    candidate = explorer.classify_response(
        result,
        identity="user_a",
        endpoint_node=endpoint_node,
        param_node=param_node,
        vuln_class="sqli",
        suggested_oracle=OracleMechanism.DIFFERENTIAL,
    )
    # Raw signal only: status, length, timing, matched error strings.
    assert candidate.signal.status_code == 500
    assert candidate.signal.body_length > 0
    assert candidate.signal.elapsed_seconds >= 0
    assert any("sql syntax" in s for s in candidate.signal.error_strings)


# -- Sanity: scope gate still applies to the Explorer's requests ----------


def test_fingerprint_out_of_scope_target_never_fires() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("scope gate should refuse before any I/O")

    graph, endpoint_node, param_node = _graph_with_param()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["in-scope.test"]))
    ctx = ExplorerContext(
        graph=graph, firer=firer, library=PayloadLibrary.from_file(), base_url=BASE_URL
    )
    from reachagent.execution import OutOfScopeError

    with pytest.raises(OutOfScopeError):
        explorer.fingerprint_parameter(ctx, "user_a", endpoint_node, param_node)
    # And the parameter was not marked fingerprinted, so it stays gated.
    assert ctx.is_fingerprinted(param_node) is False
