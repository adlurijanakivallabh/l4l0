"""Tests for recon: runner parsers, JS mining, spec ingestion, orchestration."""

from __future__ import annotations

from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement
from lalo.graph.store import ReachGraph
from lalo.recon import ingest_openapi, mine_javascript, run_recon
from lalo.recon.executor import ExecOutput
from lalo.recon.runners import ReconRunner, _parse_httpx, _parse_naabu, _parse_subfinder


def test_parse_httpx_extracts_endpoints_and_tech() -> None:
    out = (
        '{"url":"https://app.example.com/","status_code":200,"tech":["nginx","php"]}\n'
        '{"url":"https://app.example.com/login","status_code":200}\n'
    )
    facts = _parse_httpx(out)
    kinds = [(f.kind, f.value) for f in facts]
    assert ("endpoint", "https://app.example.com/") in kinds
    assert ("fingerprint", "nginx") in kinds


def test_parse_subfinder_and_naabu() -> None:
    assert _parse_subfinder('{"host":"api.example.com"}')[0].value == "api.example.com"
    svc = _parse_naabu('{"host":"app.example.com","port":5432}')[0]
    assert svc.kind == "service" and svc.metadata["port"] == 5432


def test_mine_javascript() -> None:
    js = """
    const API = "https://api.example.com/v2";
    fetch('/internal/admin/users');
    const key = "AKIAIOSFODNN7EXAMPLE";
    const x = "hello";
    """
    found = mine_javascript(js)
    assert "https://api.example.com/v2" in found.endpoints
    assert "/internal/admin/users" in found.endpoints
    assert "AKIAIOSFODNN7EXAMPLE" in found.secrets
    assert "hello" not in found.endpoints


def test_ingest_openapi_scope_validates_base_urls() -> None:
    spec = {
        "servers": [{"url": "https://app.example.com"}, {"url": "https://evil.com"}],
        "paths": {"/users/{id}": {"get": {}}, "/admin": {"post": {}}},
    }
    scope = ScopeGuard(
        engagement=Engagement.from_specs(["app.example.com"]),
        resolver=lambda h: frozenset({"93.184.216.34"}),
    )
    facts = ingest_openapi(spec, scope=scope)
    urls = {f.value for f in facts}
    assert any("app.example.com/users/" in u for u in urls)
    # The out-of-engagement server's endpoints were dropped.
    assert not any("evil.com" in u for u in urls)


class _FakeExecutor:
    def __init__(self, available: set[str], outputs: dict[str, str]) -> None:
        self._available = available
        self._outputs = outputs

    def has_binary(self, name: str) -> bool:
        return name in self._available

    def run(self, argv: list[str], *, timeout: float = 120.0) -> ExecOutput:
        return ExecOutput(0, self._outputs.get(argv[0], ""), "")


def test_run_recon_merges_scope_valid_facts() -> None:
    executor = _FakeExecutor(
        available={"httpx"},
        outputs={"httpx": '{"url":"https://app.example.com/","status_code":200,"tech":["nginx"]}'},
    )
    scope = ScopeGuard(
        engagement=Engagement.from_specs(["app.example.com"]),
        resolver=lambda h: frozenset({"93.184.216.34"}),
    )
    graph = ReachGraph()
    runners = [
        ReconRunner("httpx", "httpx", lambda t: ["httpx", t], _parse_httpx),
        ReconRunner("subfinder", "subfinder", lambda t: ["subfinder", t], _parse_subfinder),
    ]
    report = run_recon("https://app.example.com", executor, scope, graph, runners=runners)
    assert "httpx" in report.runners_ran
    assert "subfinder" in report.runners_skipped  # binary not available -> no-op
    assert report.added >= 1
    assert graph.summary().get("endpoint", 0) >= 1
