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

from ..agent.tools import FunctionTool, ToolResult
from .firer import HttpFirer

_MAX_BODY_CHARS = 4000


def build_http_tool(firer: HttpFirer) -> FunctionTool:
    def _http(args: dict[str, object]) -> ToolResult:
        url = args.get("url")
        if not isinstance(url, str) or not url:
            return ToolResult(observation="error: 'url' is required", ok=False)
        method = str(args.get("method", "GET")).upper()
        headers_raw = args.get("headers")
        headers = (
            {str(k): str(v) for k, v in headers_raw.items()}
            if isinstance(headers_raw, dict)
            else None
        )
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
