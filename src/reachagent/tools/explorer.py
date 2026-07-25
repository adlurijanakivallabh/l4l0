"""Explorer tool subset (plan §13, §4, §9).

Highest call volume, Haiku-tier (§4). The four tools below are the §9 pipeline as
real functions, routing through Task 1's firer and Task 4's payload library:

    fingerprint_parameter → get_payloads → fire_request → classify_response

The pipeline only ever produces a :class:`~reachagent.tools.candidate.Candidate`
— an inert lead. The Explorer generates candidates; it can never confirm one and
has no ``write_finding`` under any circumstance (§13, CLAUDE.md non-negotiable).
Confirmation is the Validator's ``run_oracle``/``write_finding`` alone (§7, §13).

**Module surface is load-bearing.** ``tests/phase1/test_tool_boundaries.py``
asserts this module exposes *exactly* these four tool names among non-underscore
callables. Records, context, and errors therefore live in sibling modules
(``candidate``, ``explorer_context``) imported as modules, and every helper is
underscore-prefixed — so nothing but the four tools appears in the manifest.

Each tool takes an :class:`ExplorerContext` first (its firer/library/graph
collaborators). The §13 manifest signatures — ``fingerprint_parameter(endpoint,
param)`` etc. — are what the MCP layer (Task 8) exposes once it binds a context;
the contract a human or the Phase 5 Coordinator calls is unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Imported as modules, never as names: the role-boundary test asserts this module
# exposes exactly the four tool callables, and ``SinkType``/``OracleMechanism``
# are classes (callable) that would leak into that surface if bound here directly.
# ``_nodes`` is needed at runtime (``_infer_sink_type`` returns real ``SinkType``
# values); the bare names below are annotation-only under ``TYPE_CHECKING``.
from reachagent.browser import shim as _shim
from reachagent.graph import nodes as _nodes
from reachagent.tools import candidate as _candidate
from reachagent.tools import explorer_context as _ctx

if TYPE_CHECKING:
    from reachagent.browser.shim import BrowserDriver, BrowserFireResult
    from reachagent.execution.firer import FireResult
    from reachagent.graph.nodes import SinkType
    from reachagent.oracles import OracleMechanism
    from reachagent.payloads.library import PayloadEntry

# SQL error fragments a benign canary can surface when it lands in a SQL sink —
# the classic sign that a string parameter is concatenated into a query. Matched
# case-insensitively against the response body (§9 fingerprint step).
_SQL_ERROR_SIGNATURES = (
    "sql syntax",
    "sqlite3.operationalerror",
    "psycopg2",
    "you have an error in your sql",
    "unclosed quotation mark",
    "sqlalchemy",
    'near "',
)

# Content types whose responses render the canary as markup — a reflected canary
# here means an HTML-reflection sink, not a data echo.
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")


def _decode_body(body: bytes) -> str:
    """Best-effort text view of a response body for signature matching."""
    return body.decode("utf-8", errors="replace")


def _fire_with_value(
    ctx: _ctx.ExplorerContext,
    identity: str,
    method: str,
    url: str,
    location: str,
    name: str,
    value: str,
    *,
    state_changing: bool,
) -> FireResult:
    """Fire ``value`` into a parameter's location through Task 1's firer.

    Passes httpx kwargs by explicit name rather than unpacking an untyped dict,
    so ``state_changing`` can never be shadowed by a caller-supplied key. A path
    parameter is already baked into ``url`` by recon, so it needs no injection —
    the request still fires to read the endpoint's behaviour.
    """
    if location == "query":
        return ctx.firer.fire(
            identity, method, url, state_changing=state_changing, params={name: value}
        )
    if location == "header":
        return ctx.firer.fire(
            identity, method, url, state_changing=state_changing, headers={name: value}
        )
    if location == "body":
        return ctx.firer.fire(
            identity, method, url, state_changing=state_changing, json={name: value}
        )
    return ctx.firer.fire(identity, method, url, state_changing=state_changing)


def _match_sql_errors(body_lower: str) -> tuple[str, ...]:
    """SQL error fragments present in the (lower-cased) body, in listed order."""
    return tuple(sig for sig in _SQL_ERROR_SIGNATURES if sig in body_lower)


def _infer_sink_type(
    *, reflected: bool, sql_errors: tuple[str, ...], content_type: str | None
) -> SinkType | None:
    """Map benign-canary observations to an inferred sink (§9 step 1).

    Deliberately conservative: it returns a sink only on positive evidence, and
    ``None`` otherwise. ``None`` is a legitimate result — the VAmPI toggle's core
    classes (BOLA/IDOR/mass-assignment) are authorization classes with no
    injection sink — so "no sink inferred" is a real state, not a failure. Deeper
    fingerprinting (nosql/shell/ldap/template probes) is a later-phase concern;
    this Phase 1 heuristic covers the sinks the shipped payload slice tags.
    """
    if sql_errors:
        # A canary that provokes a SQL error is concatenated into a query.
        return _nodes.SinkType.SQL
    if reflected and content_type is not None:
        if any(content_type.startswith(ct) for ct in _HTML_CONTENT_TYPES):
            return _nodes.SinkType.HTML_REFLECTION
    return None


def fingerprint_parameter(
    ctx: _ctx.ExplorerContext,
    identity: str,
    endpoint_node: str,
    param_node: str,
    *,
    method: str = "GET",
) -> _candidate.FingerprintReport:
    """Send a benign canary, infer the sink, and set it on the Parameter node (§9).

    This is step 1 of the pipeline and a hard precondition for everything after
    it: it fires *only* the benign canary (never an attack payload), reads
    reflection / error-signature / content-type behaviour, writes the inferred
    ``inferred_sink_type`` onto the ``Parameter`` graph node, and marks the
    parameter fingerprinted. ``fire_request`` refuses any parameter that has not
    been through here, so nothing downstream fires before this completes (§9).

    The canary request goes through Task 1's firer, so it is still scope- and
    read-only-first-gated like any other request.
    """
    endpoint = ctx.graph.endpoint(endpoint_node)
    param = ctx.graph.parameter(param_node)
    url = f"{ctx.target_base}{endpoint.path}"

    # Inject the canary in the parameter's location. Only the benign canary fires
    # here; the firer enforces read-only-first regardless.
    result = _fire_with_value(
        ctx, identity, method, url, param.location, param.name, ctx.canary, state_changing=False
    )

    body_text = _decode_body(result.body)
    reflected = ctx.canary in body_text
    sql_errors = _match_sql_errors(body_text.lower())
    content_type = result.headers.get("content-type")
    sink = _infer_sink_type(reflected=reflected, sql_errors=sql_errors, content_type=content_type)

    # The single graph mutation: record the inferred sink, then mark done.
    ctx.graph.set_parameter_sink_type(param_node, sink)
    ctx.mark_fingerprinted(param_node)

    return _candidate.FingerprintReport(
        endpoint_node=endpoint_node,
        param_node=param_node,
        inferred_sink_type=sink,
        reflected=reflected,
        error_signature=sql_errors[0] if sql_errors else None,
        observed_content_type=content_type,
    )


def get_payloads(
    ctx: _ctx.ExplorerContext,
    vuln_class: str,
    sink_type: SinkType | None,
) -> list[PayloadEntry]:
    """Sink-matched lookup from the tagged library, ordered by oracle confidence (§9, §13).

    A thin routing layer over Task 4's :class:`PayloadLibrary`: it returns only
    entries whose ``inferred_sink_type`` matches ``sink_type`` exactly, so a
    parameter fingerprinted as ``html_reflection`` never receives a SQL payload
    and vice versa. ``sink_type`` should be the value ``fingerprint_parameter``
    wrote — read it from the graph via :meth:`ReachabilityGraph.parameter_sink`.
    """
    return ctx.library.get_payloads(vuln_class, sink_type)


def fire_request(
    ctx: _ctx.ExplorerContext,
    identity: str,
    endpoint_node: str,
    param_node: str,
    payload: str,
    *,
    method: str = "GET",
    state_changing: bool = False,
) -> FireResult:
    """Execute one payload-bearing request through Task 1's firer (§13).

    Refuses — before any I/O — to fire against a parameter that has not been
    fingerprinted (:class:`FingerprintRequiredError`), enforcing the §9 rule that
    the benign canary precedes any attack payload. Beyond that it delegates to the
    firer, so scope and read-only-first still gate every request (§10).
    """
    if not ctx.is_fingerprinted(param_node):
        raise _ctx.FingerprintRequiredError(
            f"parameter {param_node!r} must be fingerprinted before fire_request (§9)"
        )

    endpoint = ctx.graph.endpoint(endpoint_node)
    param = ctx.graph.parameter(param_node)
    url = f"{ctx.target_base}{endpoint.path}"

    return _fire_with_value(
        ctx,
        identity,
        method,
        url,
        param.location,
        param.name,
        payload,
        state_changing=state_changing,
    )


def classify_response(
    result: FireResult,
    *,
    identity: str,
    endpoint_node: str,
    param_node: str | None,
    vuln_class: str,
    suggested_oracle: OracleMechanism,
    payload_ref: str | None = None,
    notes: tuple[str, ...] = (),
) -> _candidate.Candidate:
    """Extract raw signal from a response and emit a *candidate* — never a finding (§13).

    This is the Explorer's terminal step. It pulls only measurable, non-judgmental
    signal (status, body length, timing, matched error strings) into a
    :class:`ResponseSignal`, and bundles it into a :class:`Candidate` tagged with
    the oracle family that *should* judge it. That is the whole output: an inert
    handoff.

    There is intentionally no path from here to ``write_finding``. This function
    imports no validator tool, constructs no ``Finding``, and returns a type with
    no confirm method — the only way the candidate's evidence becomes a finding is
    the Validator running ``run_oracle`` and getting a ``confirmed`` verdict (§7,
    §13). The one-way candidate → oracle → finding gate lives here by omission.
    """
    body_text = _decode_body(result.body)
    signal = _candidate.ResponseSignal(
        status_code=result.status_code,
        body_length=len(result.body),
        elapsed_seconds=result.elapsed_seconds,
        error_strings=_match_sql_errors(body_text.lower()),
    )
    return _candidate.Candidate(
        identity=identity,
        endpoint_node=endpoint_node,
        param_node=param_node,
        vuln_class=vuln_class,
        suggested_oracle=suggested_oracle,
        payload_ref=payload_ref,
        signal=signal,
        notes=notes,
    )


def fire_browser(
    driver: BrowserDriver,
    identity: str,
    url: str,
    *,
    inject_shim: bool = True,
) -> BrowserFireResult:
    """Install the taint-tracking shim and navigate to ``url`` (§13, Phase 3 Task 5).

    Explorer-owned transport for browser-side DOM XSS discovery. Installs the
    JavaScript shim via ``addInitScript``, navigates, and returns a
    :class:`~reachagent.browser.shim.BrowserFireResult` carrying any source→sink
    flows the shim recorded. Each flow is a candidate for the
    ``EXECUTION_CONFIRMATION`` oracle (deferred to Task 6 / #24).

    Role boundary: this tool is Explorer-only. It has no path to ``write_finding``
    or ``run_oracle`` — the same invariant as the other four Explorer tools, proven
    structurally in ``tests/phase*/test_tool_boundaries.py``.
    """
    return _shim.run_taint_shim(driver, identity, url, inject_shim=inject_shim)
