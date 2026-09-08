"""The ``http`` agent tool — a scope-checked, pinned-IP-dialed request, with its capture returned.

Wraps Phase 3's :class:`~lalo.execution.firer.HttpFirer`/
:class:`~lalo.execution.scope.ScopeGuard`, whose design (resolve-once-pin-IP,
metadata denial, manual redirect re-validation) was already fully
reference-informed when built. This is tool-interface wiring — what an
agent passes in and gets back — not a new safety/design decision, so it
needs no fresh reference reading; the interface is a plain, obvious
request/response shape.
"""

from __future__ import annotations

import asyncio
import difflib
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import websockets

from ..agent.tools import FunctionTool, ToolResult, str_arg
from ..identity.role_matrix import RoleMatrixEntry, build_role_matrix
from .firer import FireResult, HttpFirer
from .rawsock import tcp_send_recv
from .scope import ScopeGuard

_MAX_BODY_CHARS = 4000


def _headers_arg(args: dict[str, object], key: str) -> dict[str, str] | None:
    raw = args.get(key)
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else None


def build_http_tool(firer: HttpFirer) -> FunctionTool:
    def _http(args: dict[str, object]) -> ToolResult:
        url = args.get("url")
        if not isinstance(url, str) or not url:
            return ToolResult(observation="error: 'url' is required", ok=False)
        method = str_arg(args, "method", "GET").upper()
        headers = _headers_arg(args, "headers")
        body = args.get("body")
        content = body.encode("utf-8") if isinstance(body, str) else None

        result = firer.fire(method, url, headers=headers, content=content)
        if not result.fired:
            reason = result.scope_reason
            if result.error:
                reason += f" ({result.error})"
            return ToolResult(observation=f"not fired: {reason}", ok=False)

        body_text = result.body[:_MAX_BODY_CHARS].decode("utf-8", errors="replace")
        observation = (
            f"status={result.status} elapsed_ms={result.elapsed_ms:.0f}\n"
            f"headers={dict(result.headers)}\n\n{body_text}"
        )
        ok = result.error is None and result.status is not None and result.status < 500
        return ToolResult(observation=observation, ok=ok)

    return FunctionTool(
        name="http",
        description=(
            "Fire a scope-checked HTTP(S) request against your declared engagement. "
            'args: {"method": str (default GET), "url": str, "headers": dict (optional), '
            '"body": str (optional)}'
        ),
        func=_http,
    )


def _count_arg(args: dict[str, object], *, default: int, max_count: int) -> int | str:
    """The ``count`` arg clamped to ``[1, max_count]``, or an error string.

    An absent key or an explicit JSON ``null`` means "use the default" (same
    distinction ``str_arg`` makes for string args) -- ``raw or default`` would
    ALSO swallow an explicit, legitimate ``0``, silently turning it into
    ``default`` instead of the floor of 1. ``bool`` is a subclass of ``int`` in
    Python, so it's excluded explicitly too (mirrors ``run_command``'s own
    timeout-arg parsing).
    """
    raw = args.get("count", default)
    if raw is None:
        raw = default
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return "'count' must be a number"
    return max(1, min(int(raw), max_count))


def build_fire_concurrent_tool(firer: HttpFirer) -> FunctionTool:
    """Fire N near-identical requests as close to simultaneously as
    possible, for race-condition testing - the one wire-level-simultaneity
    gap the agent's single-request-per-tool-call loop can't otherwise reach.
    """

    def _describe(i: int, result: FireResult | str) -> str:
        if isinstance(result, str):  # a raised exception, stringified by _fire_one
            return f"[{i}] {result}"
        if not result.fired:
            reason = result.scope_reason
            if result.error:
                reason += f" ({result.error})"
            return f"[{i}] not fired: {reason}"
        return (
            f"[{i}] status={result.status} elapsed_ms={result.elapsed_ms:.0f} "
            f"len={len(result.body)}"
        )

    def _fire_concurrent(args: dict[str, object]) -> ToolResult:
        url = str_arg(args, "url", "")
        if not url:
            return ToolResult(observation="error: 'url' is required", ok=False)
        method = str_arg(args, "method", "GET").upper()
        count = _count_arg(args, default=10, max_count=50)
        if isinstance(count, str):
            return ToolResult(observation=f"error: {count}", ok=False)
        headers = _headers_arg(args, "headers")
        content_raw = args.get("content")
        content = content_raw.encode("utf-8") if isinstance(content_raw, str) else None

        def _fire_one() -> FireResult | str:
            try:
                return firer.fire(method, url, headers=headers, content=content)
            except Exception as exc:  # noqa: BLE001 - report every failure, never drop one
                return f"exception: {type(exc).__name__}: {exc}"

        # Submitted up front in one batch so all `count` requests are in
        # flight together (as close to simultaneous as a thread pool gets);
        # gathering `.result()` in submission order afterwards doesn't
        # change when they fired, only the order they're reported in.
        with ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(_fire_one) for _ in range(count)]
            results = [future.result() for future in futures]

        lines = [_describe(i, r) for i, r in enumerate(results)]
        ok = any(not isinstance(r, str) for r in results)
        return ToolResult(observation="\n".join(lines)[:_MAX_BODY_CHARS], ok=ok)

    return FunctionTool(
        name="fire_concurrent",
        description=(
            "Fire the same request N times (default 10, max 50) as close to simultaneously "
            "as possible via a thread pool, for race-condition testing. args: "
            '{"method": str (default GET), "url": str, "count": int (optional), '
            '"headers": dict (optional), "content": str (optional)}'
        ),
        func=_fire_concurrent,
    )


def build_diff_responses_tool(firer: HttpFirer) -> FunctionTool:
    """Fire two requests (e.g. as user A vs user B) and return a real line
    diff of status + body, instead of eyeballing two independently
    head+tail-truncated observations where the one differing field can
    fall inside the dropped middle of one but not the other.
    """

    def _status_line(label: str, result: FireResult) -> str:
        if not result.fired:
            reason = result.scope_reason
            if result.error:
                reason += f" ({result.error})"
            return f"{label}: not fired: {reason}"
        return f"{label}: status={result.status}"

    def _diff(args: dict[str, object]) -> ToolResult:
        url_a = str_arg(args, "url_a", "")
        url_b = str_arg(args, "url_b", "")
        if not url_a or not url_b:
            return ToolResult(observation="error: 'url_a' and 'url_b' are required", ok=False)
        method_a = str_arg(args, "method_a", "GET").upper()
        method_b = str_arg(args, "method_b", method_a).upper()
        headers_a = _headers_arg(args, "headers_a")
        headers_b = _headers_arg(args, "headers_b")

        result_a = firer.fire(method_a, url_a, headers=headers_a)
        result_b = firer.fire(method_b, url_b, headers=headers_b)

        body_a_text = result_a.body.decode("utf-8", errors="replace")
        body_b_text = result_b.body.decode("utf-8", errors="replace")
        diff = list(
            difflib.unified_diff(
                body_a_text.splitlines(),
                body_b_text.splitlines(),
                fromfile="a",
                tofile="b",
                lineterm="",
                n=1,
            )
        )
        lines = [
            _status_line("a", result_a),
            _status_line("b", result_b),
            f"body diff ({len(diff)} changed line(s)):",
            *diff[:200],
        ]
        return ToolResult(observation="\n".join(lines)[:_MAX_BODY_CHARS], ok=True)

    return FunctionTool(
        name="diff_responses",
        description=(
            "Fire two requests (e.g. as user A vs user B) and return a structural diff of "
            "status + body - a real line diff, not truncated eyeballing. Use for "
            "differential-oracle testing (e.g. IDOR: does another user's resource actually "
            'differ from your own?). args: {"method_a": str (default GET), "url_a": str, '
            '"headers_a": dict (optional), "method_b": str (optional, defaults to method_a), '
            '"url_b": str, "headers_b": dict (optional)}'
        ),
        func=_diff,
    )


@dataclass
class _MatrixCell:
    entry: RoleMatrixEntry
    tested: bool = False
    observed_status: str | None = None


def build_access_control_matrix_tool() -> FunctionTool:
    """Track access-control test coverage as an identity x endpoint matrix,
    so coverage is machine-observed (queryable untested cells) rather than
    the agent's own self-reported todo list.

    `build_role_matrix` produces immutable cells with no "tested" state; the
    state dict closed over here owns that, one instance per scan (the caller
    builds this tool once and shares the same instance across every agent in
    the hierarchy, the same way `firer`/`scope` are single-instances-per-scan).
    """
    state: dict[tuple[str, str], _MatrixCell] = {}
    # spawn_agents runs siblings on real OS threads, all sharing this one
    # tool instance (see build_access_control_matrix_tool's docstring) -
    # without this, a concurrent `build` can `state.clear()` mid-iteration
    # of another thread's `query_untested` (RuntimeError) or silently wipe
    # cells another agent already marked tested. One lock held for the
    # whole dispatch is enough: no branch below does I/O or calls back out,
    # so there's no deadlock/starvation risk to trade against a finer-grained
    # per-branch lock.
    lock = threading.Lock()

    def _run(args: dict[str, object]) -> ToolResult:
        action = str_arg(args, "action", "")
        with lock:
            if action == "build":
                identity_ids = args.get("identity_ids")
                endpoint_ids = args.get("endpoint_ids")
                if not isinstance(identity_ids, list) or not isinstance(endpoint_ids, list):
                    return ToolResult(
                        observation="error: 'identity_ids' and 'endpoint_ids' must be lists",
                        ok=False,
                    )
                state.clear()
                for entry in build_role_matrix(
                    [str(i) for i in identity_ids], [str(e) for e in endpoint_ids]
                ):
                    state[(entry.identity_id, entry.endpoint_id)] = _MatrixCell(entry=entry)
                return ToolResult(observation=f"built {len(state)} cells", ok=True)
            if action == "mark_tested":
                key = (str_arg(args, "identity_id", ""), str_arg(args, "endpoint_id", ""))
                cell = state.get(key)
                if cell is None:
                    return ToolResult(
                        observation=f"error: no cell for {key} - call action=build first",
                        ok=False,
                    )
                cell.tested = True
                cell.observed_status = str_arg(args, "observed_status", "")
                return ToolResult(observation="marked", ok=True)
            if action == "query_untested":
                untested = [
                    f"{c.entry.identity_id} x {c.entry.endpoint_id}"
                    for c in state.values()
                    if not c.tested
                ]
                return ToolResult(
                    observation="\n".join(untested) if untested else "all cells tested", ok=True
                )
            return ToolResult(
                observation=(
                    f"error: unknown action {action!r} - use build|mark_tested|query_untested"
                ),
                ok=False,
            )

    return FunctionTool(
        name="access_control_matrix",
        description=(
            "Track access-control test coverage as an identity x endpoint matrix. args: "
            '{"action": "build"|"mark_tested"|"query_untested", ...}. build: '
            '{"identity_ids": [str], "endpoint_ids": [str]}. mark_tested: {"identity_id": str, '
            '"endpoint_id": str, "observed_status": str}. query_untested: {}.'
        ),
        func=_run,
    )


def build_raw_tcp_tool(scope: ScopeGuard) -> FunctionTool:
    """Wrap the scope-checked, pinned-IP `tcp_send_recv` primitive for direct
    non-web service interaction (raw TCP payloads: SMTP/LDAP/custom protocol
    probing, not just HTTP).
    """

    def _raw_tcp(args: dict[str, object]) -> ToolResult:
        host = str_arg(args, "host", "")
        port_raw = args.get("port")
        if not host or port_raw is None:
            return ToolResult(observation="error: 'host' and 'port' are required", ok=False)
        try:
            port = int(port_raw)  # type: ignore[call-overload]
        except (TypeError, ValueError):
            return ToolResult(observation="error: 'port' must be an integer", ok=False)
        payload = str_arg(args, "payload", "").encode()
        timeout = float(args.get("timeout", 5.0) or 5.0)  # type: ignore[arg-type]

        result = tcp_send_recv(scope, host, port, payload, timeout=timeout)
        if not result.fired:
            return ToolResult(observation=f"error: {result.scope_reason}", ok=False)
        elapsed = result.elapsed_ms if result.elapsed_ms is not None else 0.0
        observation = (
            f"received {len(result.data)} bytes in {elapsed:.0f}ms\n"
            f"{result.data[:_MAX_BODY_CHARS]!r}"
        )
        return ToolResult(observation=observation, ok=result.error is None)

    return FunctionTool(
        name="raw_tcp",
        description=(
            "Send raw bytes over a scope-checked, pinned-IP TCP connection and return "
            'whatever comes back. args: {"host": str, "port": int, "payload": str '
            '(optional, sent as raw bytes), "timeout": number (optional, seconds, default 5.0)}'
        ),
        func=_raw_tcp,
    )


def build_ws_fire_tool(scope: ScopeGuard) -> FunctionTool:
    """Connect to a WebSocket endpoint, send one message, read back whatever
    arrives - many modern API targets (chat, live dashboards, GraphQL
    subscriptions) are WebSocket-native and were previously only reachable
    via the free shell writing a throwaway client script.

    Scope-checked the same way ``HttpFirer.fire()`` checks a URL, but NOT
    pinned-IP-dialed the way HTTP is: ``websockets.connect`` doesn't expose
    the same low-level socket-injection seam ``httpx`` does. The URL-level
    ``scope.check()`` still blocks an out-of-scope host from ever being
    dialed - it just lacks HTTP's TOCTOU-closing pinned-IP guarantee against
    DNS rebinding between the check and the connect. A real, honestly
    smaller guarantee than HTTP gets, not a silent gap.
    """

    def _ws_fire(args: dict[str, object]) -> ToolResult:
        url = str_arg(args, "url", "")
        message = str_arg(args, "message", "")
        if not url:
            return ToolResult(observation="error: 'url' is required", ok=False)
        decision = scope.check(url.replace("ws://", "http://").replace("wss://", "https://"))
        if not decision.allowed:
            return ToolResult(observation=f"error: scope {decision.reason}", ok=False)
        timeout = float(args.get("timeout", 5.0) or 5.0)  # type: ignore[arg-type]

        async def _run() -> str:
            async with websockets.connect(url, open_timeout=timeout) as conn:
                if message:
                    await conn.send(message)
                try:
                    return str(await asyncio.wait_for(conn.recv(), timeout=timeout))
                except TimeoutError:
                    return "(no response within timeout)"

        try:
            response = asyncio.run(_run())
        except Exception as exc:  # noqa: BLE001 - report every connection failure, never crash the agent
            return ToolResult(observation=f"error: {type(exc).__name__}: {exc}", ok=False)
        return ToolResult(observation=response[:_MAX_BODY_CHARS], ok=True)

    return FunctionTool(
        name="ws_fire",
        description=(
            "Connect to a WebSocket endpoint, send one message, and return whatever comes "
            'back. args: {"url": str (ws:// or wss://), "message": str (optional), '
            '"timeout": number (optional, seconds, default 5.0)}'
        ),
        func=_ws_fire,
    )
