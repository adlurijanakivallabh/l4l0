"""Explorer tool subset (plan §13, §4, §9).

Highest call volume, Haiku-tier (§4). The four tools below are the §9 pipeline as
real functions, routing through Task 1's firer and Task 4's payload library:

    fingerprint_parameter → get_payloads → fire_request → classify_response

The pipeline only ever produces a :class:`~reachagent.tools.candidate.Candidate`
— an inert lead. The Explorer generates candidates; it can never confirm one and
has no ``write_finding`` under any circumstance (§13 safety invariant).
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

import json
import re
import urllib.parse
from collections.abc import Mapping as _Mapping
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
    "sqlite_error",
    "psycopg2",
    "you have an error in your sql",
    "unclosed quotation mark",
    "sqlalchemy",
    'near "',
)

# Content types whose responses render the canary as markup — a reflected canary
# here means an HTML-reflection sink, not a data echo.
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")

# Explicit sink contract for generic payload classes. A hint is accepted only when
# it matches a known class family; callers cannot select an arbitrary sink.
_CLASS_SINKS = {
    "sqli": _nodes.SinkType.SQL,
    "nosqli": _nodes.SinkType.NOSQL,
    "command_injection": _nodes.SinkType.SHELL,
    "path_traversal": _nodes.SinkType.FILE_PATH,
    "ssti": _nodes.SinkType.TEMPLATE,
    "ldap_injection": _nodes.SinkType.LDAP,
    "xss_reflected": _nodes.SinkType.HTML_REFLECTION,
}


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
    extra_fields: dict[str, object] | None = None,
    upload: _ctx.UploadSpec | None = None,
) -> FireResult:
    """Fire ``value`` into a parameter's location through Task 1's firer.

    Passes httpx kwargs by explicit name rather than unpacking an untyped dict,
    so ``state_changing`` can never be shadowed by a caller-supplied key.

    Injection per ``location``:

    * ``query`` / ``header`` — single key/value in the query string or headers.
    * ``body`` / ``json`` — a JSON object. ``extra_fields`` merges sibling keys so a body
      that needs more than the one injected field (e.g. a feedback POST needing
      ``rating`` alongside ``comment``) can be formed; the injected ``{name: value}``
      always wins on key collision.
    * ``form`` — an ``application/x-www-form-urlencoded`` body.
    * ``cookie`` — one cookie value.
    * ``graphql`` — a read-only GraphQL document; ``field.argument`` names inject
      a JSON-string argument while a bare field is selected without arguments.
    * ``path`` — the payload is substituted into the ``{name}`` placeholder in the
      URL (percent-encoded), so a traversal/injection value actually lands in the
      path segment. A path with no matching placeholder fires unchanged (recon
      already baked a concrete value), preserving prior behaviour.

    ``upload`` selects a ``multipart/form-data`` request: the injected value names
    the file (``filename``/``content_type``/``content``) and ``extra_fields`` become
    form fields — the firer's one-param JSON default cannot form a multipart body.
    """
    if upload is not None:
        files = {name: (upload.filename, upload.content, upload.content_type)}
        return ctx.firer.fire(
            identity,
            method,
            url,
            state_changing=state_changing,
            files=files,
            data=dict(extra_fields or {}),
        )
    if location == "query":
        return ctx.firer.fire(
            identity, method, url, state_changing=state_changing, params={name: value}
        )
    if location == "header":
        return ctx.firer.fire(
            identity, method, url, state_changing=state_changing, headers={name: value}
        )
    if location in {"body", "json"}:
        body: dict[str, object] = dict(extra_fields or {})
        body[name] = value
        return ctx.firer.fire(identity, method, url, state_changing=state_changing, json=body)
    if location == "form":
        body = {str(k): str(v) for k, v in (extra_fields or {}).items()}
        body[name] = value
        return ctx.firer.fire(identity, method, url, state_changing=state_changing, data=body)
    if location == "cookie":
        cookies = {str(k): str(v) for k, v in (extra_fields or {}).items()}
        cookies[name] = value
        return ctx.firer.fire(identity, method, url, state_changing=state_changing, cookies=cookies)
    if location == "multipart":
        files = {name: ("probe.txt", value.encode("utf-8"), "text/plain")}
        return ctx.firer.fire(
            identity,
            method,
            url,
            state_changing=state_changing,
            files=files,
            data=dict(extra_fields or {}),
        )
    if location == "graphql":
        field, _, argument = name.partition(".")
        if not field or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field):
            raise ValueError(f"invalid GraphQL field insertion point: {name!r}")
        if argument:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", argument):
                raise ValueError(f"invalid GraphQL argument insertion point: {name!r}")
            document = f"query ReachAgentProbe {{ {field}({argument}: {json.dumps(value)}) }}"
        else:
            document = f"query ReachAgentProbe {{ {field} }}"
        return ctx.firer.fire(
            identity,
            method,
            url,
            state_changing=state_changing,
            json={"query": document},
        )
    if location == "path":
        injected = url.replace(f"{{{name}}}", urllib.parse.quote(value, safe=""))
        return ctx.firer.fire(identity, method, injected, state_changing=state_changing)
    raise ValueError(f"unsupported parameter location: {location!r}")


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
    sink_hint: SinkType | None = None,
    vuln_class: str | None = None,
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

    Diagnostic error-triggering probe (§9 step 1 exists to read error behaviour):
    a benign canary that sits *safely inside* SQL quotes (``WHERE username =
    '<canary>'``) returns a clean 404 — no SQL error — so the error-based sink is
    invisible to it. The canary alone cannot surface quoted-param error-based
    SQLi. When the canary inferred NO sink and no ``sink_hint`` was supplied, one
    additional read-only probe fires with the quote-appended value
    ``"<canary>'"`` — a *fingerprinting primitive*, the same class as the canary,
    NOT a corpus payload — and its body is matched against the SQL error
    signatures. A match infers ``SQL``; no match leaves the sink ``None``
    (conservative — an HTML/NoSQL/template param that merely reflects the quote
    never becomes sql; no false sink). The benign canary still precedes it, so the
    §9 ordering invariant holds.
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
    # Explicit sink contract for generic payload classes. A hint is allowed only
    # for sinks with no observational fingerprint path (a path placeholder yields
    # no reflection; a template sink reflects the canary in plain text, which the
    # HTML heuristic cannot distinguish) — and only when it matches the class the
    # caller named. It never overrides positive evidence: an observed SQL error
    # or HTML reflection always wins.
    _HINTABLE_SINKS = {_nodes.SinkType.FILE_PATH, _nodes.SinkType.TEMPLATE}

    observed = _infer_sink_type(
        reflected=reflected, sql_errors=sql_errors, content_type=content_type
    )
    if sink_hint is not None:
        if sink_hint not in _HINTABLE_SINKS:
            raise ValueError(
                f"sink hint {sink_hint.value!r} is not accepted — only "
                f"{sorted(s.value for s in _HINTABLE_SINKS)} have no observational "
                "fingerprint path; all other sinks must be observed"
            )
        if vuln_class is not None and _CLASS_SINKS.get(vuln_class) is not sink_hint:
            raise ValueError(
                f"sink hint {sink_hint.value!r} is not valid for vuln_class {vuln_class!r}"
            )
        if observed is not None and observed is not sink_hint:
            raise ValueError(
                f"sink hint {sink_hint.value!r} conflicts with observed evidence "
                f"({observed.value!r}) — observed signal wins"
            )
        if sink_hint is _nodes.SinkType.TEMPLATE and not reflected:
            raise ValueError("template sink hint requires reflected benign canary")

    # Diagnostic error-triggering probe: only when the benign canary inferred no
    # sink AND no hint was supplied. One quote-appended read-only probe reads the
    # error behaviour a quoted-param SQLi sink hides from the benign canary. A SQL
    # error match infers SQL; no match leaves the sink None (conservative).
    if observed is None and sink_hint is None:
        diag_value = f"{ctx.canary}'"
        diag_result = _fire_with_value(
            ctx, identity, method, url, param.location, param.name, diag_value, state_changing=False
        )
        diag_errors = _match_sql_errors(_decode_body(diag_result.body).lower())
        if diag_errors:
            sql_errors = diag_errors
            observed = _nodes.SinkType.SQL

    sink = observed if observed is not None else sink_hint

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
    *,
    context: _Mapping[str, object] | None = None,
    max_mutations: int = 0,
    slot_kit: _Mapping[str, object] | None = None,
) -> list[PayloadEntry]:
    """Sink-matched lookup from the tagged library, ordered by oracle confidence (§9, §13).

    A thin routing layer over :class:`PayloadLibrary`: it returns only
    entries whose ``inferred_sink_type`` matches ``sink_type`` exactly, so a
    parameter fingerprinted as ``html_reflection`` never receives a SQL payload
    and vice versa. ``sink_type`` should be the value ``fingerprint_parameter``
    wrote — read it from the graph via :meth:`ReachabilityGraph.parameter_sink`.
    Context dimensions are filtered before bounded parent-preserving mutations
    are expanded.
    """
    entries = ctx.library.get_payloads(vuln_class, sink_type, context=context)
    from reachagent.payloads.encoding import expand_payload_mutations

    return expand_payload_mutations(
        entries,
        max_per_parent=max_mutations,
        slot_kit=slot_kit,
    )


def fire_request(
    ctx: _ctx.ExplorerContext,
    identity: str,
    endpoint_node: str,
    param_node: str,
    payload: str,
    *,
    method: str = "GET",
    state_changing: bool = False,
    extra_fields: dict[str, object] | None = None,
    upload: _ctx.UploadSpec | None = None,
) -> FireResult:
    """Execute one payload-bearing request through Task 1's firer (§13).

    Refuses — before any I/O — to fire against a parameter that has not been
    fingerprinted (:class:`FingerprintRequiredError`), enforcing the §9 rule that
    the benign canary precedes any attack payload. Beyond that it delegates to the
    firer, so scope and read-only-first still gate every request (§10).

    ``extra_fields`` supplies sibling body/form keys when the one injected field
    is not a complete request (multi-field JSON, or the non-file parts of a
    multipart form). ``upload`` selects a ``multipart/form-data`` fire whose file
    part carries ``payload`` as the injected value's file spec.
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
        extra_fields=extra_fields,
        upload=upload,
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
