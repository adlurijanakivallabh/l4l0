"""End-to-end test: the agent itself decides to spawn_agent (an agent-callable
tool, not just a host-orchestrated API), the child records a finding via a real
firer, and the authoritative finding is merged back automatically."""

from __future__ import annotations

import http.server
import threading

from lalo.core.model_router import CompletionRequest, CompletionResponse, ModelRouter
from lalo.scan import run_scan


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<html>ok</html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


def _server() -> tuple[http.server.HTTPServer, str]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


class _ScriptedProvider:
    """A provider whose reply depends on whether it's the root or a spawned child.

    Distinguishes by looking for the child-only marker text ("SPECIALIST TASK")
    injected into the child's mission.
    """

    name = "scripted"

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        # Detect child-vs-root by prompt POSITION (MISSION is always the first
        # line), not by a plain substring: the root's own history re-quotes the
        # child's task argument verbatim, so a naive `"SPECIALIST TASK" in prompt`
        # check would false-positive on the root's second turn once it has
        # spawned. The loop renders history as "called <tool>(<args>) ->
        # <observation>" — used below to detect prior steps by tool name.
        if request.prompt.startswith("MISSION:\nSPECIALIST TASK"):
            # Child: record a finding then finish.
            if "called record_finding" not in request.prompt:
                text = (
                    '{"tool":"record_finding","args":{"title":"child found it",'
                    '"vuln_class":"xss","severity":"medium","target":"x"}}'
                )
            else:
                text = '{"tool":"finish","args":{"summary":"child done"}}'
        else:
            # Root: spawn a child, then finish once the child reports back.
            if "called spawn_agent" not in request.prompt:
                text = (
                    '{"tool":"spawn_agent","args":{"name":"XSS Specialist",'
                    '"task":"SPECIALIST TASK: find xss","skills":["xss"]}}'
                )
            else:
                text = '{"tool":"finish","args":{"summary":"root done"}}'
        return CompletionResponse(text=text, provider=self.name, model="scripted")


def test_root_agent_spawns_child_via_tool_and_merges_finding() -> None:
    srv, base = _server()
    try:
        router = ModelRouter(
            providers={"scripted": _ScriptedProvider()},
            routes={"reasoning": ("scripted",)},
        )
        result = run_scan(targets=["127.0.0.1"], objective=f"test {base}", router=router)
    finally:
        srv.shutdown()

    assert result.stop_reason == "finished"
    assert len(result.findings) == 1
    assert result.findings[0].title == "child found it"
    assert result.agent_registry is not None
    nodes = result.agent_registry.snapshot()
    assert len(nodes) == 1
    assert nodes[0].status == "completed"
    assert nodes[0].finding_ids == [result.findings[0].id]
    assert "XSS Specialist" in result.agent_registry.render_tree()


def test_spawn_depth_ceiling_refuses_beyond_max_depth() -> None:
    from lalo.agents.registry import AgentRegistry
    from lalo.execution.firer import HttpFirer
    from lalo.execution.scope import ScopeGuard
    from lalo.execution.target import Engagement
    from lalo.graph.store import ReachGraph
    from lalo.knowledge import SkillLibrary
    from lalo.scan.tools import ScanContext, build_registry

    scope = ScopeGuard(engagement=Engagement.from_specs(["127.0.0.1"]))
    router = ModelRouter(providers={}, routes={})
    ctx = ScanContext(
        graph=ReachGraph(),
        firer=HttpFirer(scope),
        router=router,
        agent_registry=AgentRegistry(),
        skill_library=SkillLibrary(),
        depth=3,
        max_depth=3,
    )
    registry = build_registry(ctx)
    result = registry.dispatch("spawn_agent", {"name": "x", "task": "y"})
    assert result.ok is False
    assert "max spawn depth" in result.observation
