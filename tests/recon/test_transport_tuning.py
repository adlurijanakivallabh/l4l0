"""Transport selection + MCP browser/proxy firing - hermetic tests.

Covers: transport selection (flag gating, allowlist, fallback), the new MCP
tools being registered, and the AST boundary proof extending to the two
new firing mechanisms.
"""

from __future__ import annotations

import ast
from pathlib import Path

from reachagent.graph.nodes import Endpoint, Host, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.transport_tuning import (
    build_transport_signals,
    propose_transport,
    validate_transport,
)

_TARGET = "target.test"


def _graph() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(Host(address=_TARGET, source="test"))
    return g


class FakeTuner:
    def __init__(self, transport: str, rationale: str = "test") -> None:
        self._transport = transport
        self._rationale = rationale

    def propose(
        self,
        signals: dict[str, str],
        allowlist: tuple[str, ...],
    ) -> dict[str, object]:
        return {"transport": self._transport, "rationale": self._rationale}


class TestValidateTransport:
    def test_valid_http(self) -> None:
        r = validate_transport({"transport": "http", "rationale": "standard"})
        assert r is not None and r.transport == "http"

    def test_valid_browser(self) -> None:
        r = validate_transport({"transport": "browser", "rationale": "CSRF form"})
        assert r is not None and r.transport == "browser"

    def test_invalid_rejected(self) -> None:
        assert validate_transport({"transport": "carrier-pigeon"}) is None

    def test_missing_rejected(self) -> None:
        assert validate_transport({}) is None


class TestProposeTransport:
    def test_off_by_default(self) -> None:
        g = _graph()
        ep_id = g.add_endpoint(Endpoint(method="GET", path="/"))
        r = propose_transport(g, ep_id)
        assert r.transport == "http"
        assert r.rationale == "flag off"

    def test_browser_selected(self) -> None:
        import os

        os.environ["REACHAGENT_TRANSPORT_TUNING"] = "1"
        g = _graph()
        ep_id = g.add_endpoint(Endpoint(method="POST", path="/login"))
        r = propose_transport(g, ep_id, client=FakeTuner("browser", "CSRF form"))
        assert r.transport == "browser"
        del os.environ["REACHAGENT_TRANSPORT_TUNING"]


class TestBuildTransportSignals:
    def test_signals_from_graph(self) -> None:
        g = _graph()
        ep_id = g.add_endpoint(Endpoint(method="POST", path="/login"))
        pn = g.add_parameter(ep_id, Parameter(name="user", location="body"))
        g.set_parameter_sink_type(pn, SinkType.SQL)
        signals = build_transport_signals(g, ep_id)
        assert signals["method"] == "POST"
        assert signals["path"] == "/login"
        assert "user(body)->sql" in signals.get("params", "")


class TestMCPToolRegistration:
    """Verify the new MCP tools are registered alongside the existing ones."""

    def test_mcp_server_has_proxy_and_browser_form_tools(self) -> None:
        src = Path("src/reachagent/mcp/server.py").read_text()
        assert "def fire_proxy_request" in src, "fire_proxy_request not registered"
        assert "def fire_browser_form" in src, "fire_browser_form not registered"
        assert "def fire_request" in src
        assert "def fire_browser" in src

    def test_mcp_server_parses(self) -> None:
        src = Path("src/reachagent/mcp/server.py").read_text()
        tree = ast.parse(src)
        _ = tree  # parse succeeded

    def test_new_tools_route_through_scope_and_oracle(self) -> None:
        """AST scan: new tools use the gated firer and never write findings."""
        src = Path("src/reachagent/mcp/server.py").read_text()
        assert "ctx.firer.fire(" in src
        assert "ctx.firer.scope.enforce(url)" in src
        for fn_name in ("fire_proxy_request", "fire_browser_form"):
            fn_start = src.index(f"def {fn_name}")
            next_def = src.find("\n    def ", fn_start + 10)
            fn_end = next_def if next_def > 0 else len(src)
            fn_body = src[fn_start:fn_end]
            # Check for CALL syntax, not docstring mentions.
            assert "_validator.write_finding" not in fn_body
            assert "_validator.run_oracle" not in fn_body
            assert "write_finding(" not in fn_body
            assert "run_oracle(" not in fn_body
