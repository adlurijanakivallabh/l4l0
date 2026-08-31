"""Sibling-list baseline + template-first ordering + budget 20 (closes live E2E)."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.payloads import PayloadLibrary
from reachagent.payloads.payload_resolver import template_refs
from reachagent.scan.entrypoint import _harvest_baseline_value, scan_target

BASE_URL = "https://target.test"


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["target.test"]))


# -- Fix 1: sibling-list baseline harvest ----------------------------------------


def _sibling_graph() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_endpoint(Endpoint(method="GET", path="/users/v1"))
    ep = g.add_endpoint(Endpoint(method="GET", path="/users/v1/{username}"))
    g.add_parameter(ep, Parameter(name="username", location="path"))
    return g


def test_sibling_harvest_returns_valid_username() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"username": "name1"}, {"username": "name2"}])

    g = _sibling_graph()
    firer = _firer(handler)
    value = _harvest_baseline_value(g, firer, "u", BASE_URL, "/users/v1/{username}", "username")
    assert value == "name1"


def test_no_sibling_falls_back_none() -> None:
    g = ReachabilityGraph()
    ep = g.add_endpoint(Endpoint(method="GET", path="/users/v1/{username}"))
    g.add_parameter(ep, Parameter(name="username", location="path"))
    firer = _firer(lambda r: httpx.Response(200, json=[]))
    assert (
        _harvest_baseline_value(g, firer, "u", BASE_URL, "/users/v1/{username}", "username") is None
    )


def test_sibling_non_2xx_falls_back_none() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="nope")

    g = _sibling_graph()
    firer = _firer(handler)
    assert (
        _harvest_baseline_value(g, firer, "u", BASE_URL, "/users/v1/{username}", "username") is None
    )


def test_sibling_json_without_field_falls_back_none() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"id": 1}, {"id": 2}])

    g = _sibling_graph()
    firer = _firer(handler)
    assert (
        _harvest_baseline_value(g, firer, "u", BASE_URL, "/users/v1/{username}", "username") is None
    )


def test_sibling_plural_key_wrapper_harvests_first_item() -> None:
    # The exact live VAmPI shape: {"users": [...]} — a dict wrapping the list
    # under a plural key, not a bare array.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"users": [{"username": "name1"}, {"username": "name2"}]})

    g = _sibling_graph()
    firer = _firer(handler)
    value = _harvest_baseline_value(g, firer, "u", BASE_URL, "/users/v1/{username}", "username")
    assert value == "name1"


def test_sibling_items_key_wrapper_harvests_first_item() -> None:
    # Generic plural-key shape under a different key ("items").
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": [{"name": "book1"}]})

    g = _sibling_graph()
    firer = _firer(handler)
    value = _harvest_baseline_value(g, firer, "u", BASE_URL, "/users/v1/{username}", "username")
    assert value == "book1"


# -- Fix 2: template-first ordering ----------------------------------------------


def test_template_first_ordering_sqli() -> None:
    lib = PayloadLibrary.from_file()
    entries = lib.get_payloads("sqli", SinkType.SQL)
    assert entries, "expected sqli entries"
    templates = template_refs()
    # The first entry is a hand-authored template (quote-break), corpus after.
    assert entries[0].payload_ref in templates
    assert "quote-break" in entries[0].payload_ref
    # Every hand-authored template sorts before every corpus line-locator.
    template_positions = [i for i, e in enumerate(entries) if e.payload_ref in templates]
    corpus_positions = [i for i, e in enumerate(entries) if e.payload_ref not in templates]
    if template_positions and corpus_positions:
        assert max(template_positions) < min(corpus_positions)


def test_template_first_within_every_confidence_rank() -> None:
    lib = PayloadLibrary.from_file()
    templates = template_refs()
    # For any vuln_class/sink with mixed template+corpus entries, templates sort first.
    for vuln_class in ("sqli", "xss_reflected", "command_injection", "path_traversal", "ssti"):
        for sink in (
            None,
            SinkType.SQL,
            SinkType.HTML_REFLECTION,
            SinkType.SHELL,
            SinkType.FILE_PATH,
            SinkType.TEMPLATE,
        ):
            entries = lib.get_payloads(vuln_class, sink)
            if not entries:
                continue
            seen_corpus = False
            for e in entries:
                if e.payload_ref not in templates:
                    seen_corpus = True
                else:
                    assert not seen_corpus, f"{vuln_class}/{sink}: template after corpus"


# -- Fix 3: max_attempts default 20 ----------------------------------------------


def test_max_attempts_default_20() -> None:
    sig = inspect.signature(scan_target)
    assert sig.parameters["max_attempts"].default == 20


# -- E2E acceptance proof: fingerprint → baseline harvest → quote-break → finding --


_VAMPI_SURFACE = """\
endpoints:
  - method: GET
    path: /users/v1
  - method: GET
    path: /users/v1/{username}
    parameters:
      - name: username
        location: path
"""


def _vampi_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/users/v1":
        return httpx.Response(200, json=[{"username": "name1"}, {"username": "name2"}])
    if path == "/users/v1/name1":
        return httpx.Response(200, json={"username": "name1", "email": "a@b.c"})
    if path == "/users/v1/reachagent-canary-7f3a2b":
        return httpx.Response(404, json={"status": "fail", "message": "User not found"})
    if path.endswith("'"):
        # Diagnostic (canary') and quote-break ('): both break the SQL.
        return httpx.Response(500, text="sqlalchemy.exc.OperationalError: unrecognized token")
    return httpx.Response(404, text="not found")


def test_e2e_error_based_sqli_to_finding(tmp_path: Path) -> None:
    surface = tmp_path / "surface.yaml"
    surface.write_text(_VAMPI_SURFACE)
    result = scan_target(
        base_url=BASE_URL,
        in_scope="target.test",
        dry_run=False,
        transport=httpx.MockTransport(_vampi_handler),
        surface_path=str(surface),
    )
    findings = result["graph"].findings()
    assert len(findings) >= 1, "expected at least one confirmed finding"
    assert any(f.vuln_class == "sqli" for _, f in findings)


# -- Negative: clean target → zero findings --------------------------------------


def test_clean_target_zero_findings(tmp_path: Path) -> None:
    surface = tmp_path / "surface.yaml"
    surface.write_text(_VAMPI_SURFACE)

    def clean_handler(request: httpx.Request) -> httpx.Response:
        # No SQL error on the diagnostic, no harvestable sibling value.
        return httpx.Response(404, json={"status": "fail", "message": "not found"})

    result = scan_target(
        base_url=BASE_URL,
        in_scope="target.test",
        dry_run=False,
        transport=httpx.MockTransport(clean_handler),
        surface_path=str(surface),
    )
    assert result["graph"].findings() == []


# -- Invariants ------------------------------------------------------------------


def test_explorer_tool_surface_unchanged() -> None:
    import reachagent.tools.explorer as explorer

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


def test_library_imports_no_validator() -> None:
    import reachagent.payloads.library as mod

    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "reachagent.tools.validator" not in node.module
            assert "reachagent.tools.candidate" not in node.module
