"""Phase 9 transport, evidence, and execution-boundary checks."""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from reachagent.browser.shim import BrowserFireResult, TaintFlow, run_taint_shim
from reachagent.execution import (
    AuditLog,
    ProgressEvent,
    RequestFirer,
    ScopeGuard,
    TransportCancelledError,
    TransportControl,
    TransportDispatcher,
    TransportRequest,
)
from reachagent.graph.store import ReachabilityGraph
from reachagent.mcp import server
from reachagent.oracles import OracleMechanism
from reachagent.payloads import PayloadLibrary
from reachagent.tools.explorer_context import ExplorerContext


class _Request:
    def __init__(self, url: str, redirected_from: _Request | None = None) -> None:
        self.url = url
        self.redirected_from = redirected_from


class _Response:
    def __init__(self) -> None:
        self.status = 200
        self.url = "http://target.test/final"
        self.request = _Request("http://target.test/final", _Request("http://target.test/start"))


class _Browser:
    def __init__(self) -> None:
        self.scripts: list[str] = []
        self.urls: list[str] = []

    def add_init_script(self, script: str) -> None:
        self.scripts.append(script)

    def navigate(self, url: str) -> object:
        self.urls.append(url)
        return _Response()

    def evaluate(self, expression: str) -> object:
        if "reachagent_flows" in expression:
            return [{"source": "location.hash", "sink": "innerHTML", "value": "marker"}]
        if "reachagent_exec" in expression:
            return True
        return 42

    def get_cookies(self) -> object:
        return [{"name": "sid", "value": "cookie-secret"}]


def _session(handler: Callable[[httpx.Request], httpx.Response]) -> server._Session:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["target.test"]))
    ctx = ExplorerContext(
        graph=ReachabilityGraph(),
        firer=firer,
        library=PayloadLibrary.from_file(),
        base_url="http://target.test",
    )
    return server._Session(ctx=ctx)


def _call(mcp: Any, name: str, **kwargs: object) -> Any:
    tool = mcp._tool_manager._tools[name]
    return tool.fn(**kwargs)


def test_browser_navigation_projection_captures_status_redirects_and_cookie_names() -> None:
    result = run_taint_shim(_Browser(), "user", "http://target.test/start")
    assert result.status_code == 200
    assert result.final_url == "http://target.test/final"
    assert result.redirects == ("http://target.test/start",)
    assert result.cookies == (("sid", "cookie-secret"),)
    assert result.body_length == 42
    assert "cookie-secret" not in repr(result)


def test_http_dispatch_keeps_oracle_agnostic_and_audited() -> None:
    audit = AuditLog()
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(handler)),
        ScopeGuard.from_hosts(["target.test"]),
        audit,
    )
    result = TransportDispatcher(firer).fire(
        TransportRequest(identity="anon", url="http://target.test/ping")
    )
    assert result.transport == "http"
    assert result.final_url == "http://target.test/ping"
    assert len(seen) == 1
    assert audit.entries[-1].outcome == "fired:200"


def test_proxy_dispatch_requires_a_real_proxy_and_does_not_fallback_to_http() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, text="ok")

    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(handler)),
        ScopeGuard.from_hosts(["target.test"]),
    )
    with pytest.raises(ValueError, match="proxy transport requires"):
        TransportDispatcher(firer).fire(
            TransportRequest(identity="anon", url="http://target.test/ping"), "proxy"
        )
    assert sent == []


def test_proxy_dispatch_uses_proxy_client_after_scope_and_clearance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_client = httpx.Client
    requests: list[httpx.Request] = []
    clients: list[httpx.Client] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, text="ok")

    def factory(**kwargs: object) -> httpx.Client:
        client = real_client(transport=httpx.MockTransport(handler))
        clients.append(client)
        return client

    monkeypatch.setattr(httpx, "Client", factory)
    firer = RequestFirer(
        real_client(transport=httpx.MockTransport(handler)),
        ScopeGuard.from_hosts(["target.test"]),
    )
    dispatcher = TransportDispatcher(firer)
    result = dispatcher.fire(
        TransportRequest(identity="anon", url="http://target.test/ping"),
        "proxy",
        proxy_url="http://proxy.test:8080",
    )
    assert result.transport == "proxy"
    assert requests
    assert len(clients) == 1


def test_browser_preflight_and_cancellation_emit_bounded_progress() -> None:
    events: list[ProgressEvent] = []
    control = TransportControl("browser-1", progress=events.append)
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, text="ok"))),
        ScopeGuard.from_hosts(["target.test"]),
    )
    TransportDispatcher(firer).prepare_browser("anon", "http://target.test/page", control=control)
    assert events[-1].stage == "preflight"
    assert events[-1].transport == "browser"
    control.cancel_event.set()
    with pytest.raises(TransportCancelledError):
        control.check()


def test_mcp_annotations_are_conservative_for_mutating_request_tools() -> None:
    mcp = server.build_server(base_url="http://target.test", scope_hosts=["target.test"])
    request_annotations = mcp._tool_manager._tools["fire_request"].annotations
    proxy_annotations = mcp._tool_manager._tools["fire_proxy_request"].annotations
    assert request_annotations is not None
    assert proxy_annotations is not None
    assert request_annotations.readOnlyHint is False
    assert request_annotations.destructiveHint is True
    assert proxy_annotations.readOnlyHint is False
    assert proxy_annotations.destructiveHint is True


def test_browser_handle_is_server_side_and_only_oracle_can_consume_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp.server.fastmcp import FastMCP

    import reachagent.oracles.llm_judgment as _llm_judgment
    from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

    # v3 (CLAUDE.md): confirmation is an LLM judgment, not the removed decide()
    # logic. The run_oracle MCP tool has no client= seam, so fix the provider
    # factory judge() falls back to and assert wiring: does a confirmed verdict
    # flow through the server-side browser handle to is_violation=True.
    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    session = _session(lambda _: httpx.Response(200, text="ok"))
    flow = TaintFlow(source="location.hash", sink="innerHTML", value_snippet="marker")
    browser_ref = session.put_browser(
        BrowserFireResult(
            url="http://target.test/page",
            identity="anon",
            flows=(flow,),
            executed=True,
            status_code=200,
        )
    )
    mcp = FastMCP("phase9")
    server.register_tools(mcp, session)
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism=OracleMechanism.EXECUTION_CONFIRMATION.value,
        evidence={"browser_ref": browser_ref, "evidence_ref": "browser/marker"},
    )
    assert verdict.is_violation is True


def test_browser_cookie_binding_keeps_value_out_of_graph_projection() -> None:
    from reachagent.graph.nodes import AuthState
    from reachagent.identity.store import Credential, IdentityStore

    identities = IdentityStore()
    identities.add(Credential("user", "u", "p", "user", AuthState.USER))
    identities.token_store("user").merge_cookies({"sid": "cookie-secret"})
    session = identities.ensure_session("user")
    assert session is not None
    assert session.token_ref == "token:user"
    assert "cookie-secret" not in repr(session)
    assert identities.token_store("user").safe_summary()["cookie_names"] == ["sid"]


def test_transport_modules_have_no_oracle_or_finding_authority() -> None:
    root = Path("src/reachagent")
    for relative in ("execution/transports.py", "browser/shim.py", "browser/playwright_driver.py"):
        tree = ast.parse((root / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert "oracles" not in (node.module or "")
                assert "validator" not in (node.module or "")
            if isinstance(node, ast.Import):
                assert all("oracles" not in alias.name for alias in node.names)
                assert all("validator" not in alias.name for alias in node.names)


def test_model_url_projection_removes_query_fragment_and_userinfo() -> None:
    safe = server._safe_target_url("https://alice:secret@target.test/path?q=secret#frag")
    assert safe == "https://target.test/path"


def test_mcp_transport_callers_do_not_construct_verdicts_or_findings() -> None:
    tree = ast.parse(Path("src/reachagent/mcp/server.py").read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in ("fire_request", "fire_browser_form", "fire_browser", "fire_proxy_request"):
        node = functions[name]
        body = ast.unparse(node)
        assert "_validator.run_oracle" not in body
        assert "_validator.write_finding" not in body
        assert "_nodes.Finding" not in body
