"""Wildcard/catch-all calibration (D5 deferred FP item) — hermetic, MockTransport only."""

from __future__ import annotations

import json

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.calibration import CalibrationResult, CalibrationRunner
from reachagent.recon.tools.dirb import DirbRunner
from reachagent.recon.tools.feroxbuster import FeroxbusterRunner
from reachagent.recon.tools.ffuf import FfufRunner
from reachagent.recon.tools.gobuster import GobusterRunner
from reachagent.scan.entrypoint import scan_target

_TARGET = "target.test"
_CATCHALL_BODY = b"catchall-page"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET, "example.com"])


def _firer(handler: object, audit: AuditLog | None = None) -> tuple[RequestFirer, AuditLog]:
    a = audit or AuditLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, _scope(), a), a


# -- D1 wildcard detection: 3 same-shape 2xx probes = catch-all -----------------


def test_calibration_detects_wildcard_catch_all() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_CATCHALL_BODY)

    firer, _a = _firer(handler)
    result = CalibrationRunner(firer, f"https://{_TARGET}").run()
    assert result.wildcard is True
    assert result.shape_label == f"200/size:{len(_CATCHALL_BODY)}"
    assert len(result.statuses) == 3
    assert all(s == 200 for s in result.statuses)


def test_calibration_no_wildcard_on_404() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"missing")

    firer, _a = _firer(handler)
    result = CalibrationRunner(firer, f"https://{_TARGET}").run()
    assert result.wildcard is False
    assert result.shape_label == "none"


def test_calibration_no_wildcard_on_differing_sizes() -> None:
    # Same 2xx but different bodies → the target distinguishes paths.
    bodies = [b"aaaa", b"bbbbbb", b"cccc"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=bodies.pop(0))

    firer, _a = _firer(handler)
    result = CalibrationRunner(firer, f"https://{_TARGET}").run()
    assert result.wildcard is False


# -- D1 probe discipline: distinct paths, read-only GETs, firer gates -----------


def test_probe_paths_distinct_and_read_only() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        return httpx.Response(200, content=_CATCHALL_BODY)

    firer, _a = _firer(handler)
    CalibrationRunner(firer, f"https://{_TARGET}").run()
    assert len(seen) == 3
    assert all(m == "GET" for m, _u in seen)
    paths = {u.split(f"https://{_TARGET}", 1)[1] for _m, u in seen}
    assert len(paths) == 3  # distinct
    assert all(p.startswith("/reachagent-cal-") for p in paths)


def test_probe_through_firer_enforces_scope() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        raise AssertionError("must not fire out-of-scope")

    a = AuditLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    firer = RequestFirer(client, ScopeGuard.from_hosts(["in-scope.test"]), a)
    # target.test is out of the firer's scope → probes refused, none fired.
    result = CalibrationRunner(firer, f"https://{_TARGET}").run()
    assert result.wildcard is False
    assert any(e.outcome == "refused_out_of_scope" for e in a.entries)


# -- D2 suppression in the content wrappers --------------------------------------


def test_wildcard_suppresses_gobuster_endpoints() -> None:
    cal = CalibrationResult(
        statuses=(200, 200, 200),
        sizes=(14, 14, 14),
        body_hashes=("a", "a", "a"),
        content_types=("text/html",) * 3,
        wildcard=True,
    )
    graph = ReachabilityGraph()
    audit = AuditLog()
    runner = GobusterRunner(graph=graph, scope=_scope(), audit=audit)
    runner.calibration = cal  # D3 pass-through (entrypoint sets this before ingest)
    runner.ingest(f"https://{_TARGET}", "/admin (Status: 200)\n/login (Status: 200)\n")
    # Zero Endpoints asserted — the paths are untrustworthy catch-all hits.
    assert list(graph.endpoints()) == []
    assert len([e for e in audit.entries if e.outcome == "refused_wildcard_catchall"]) == 2
    # The calibration fact itself IS recorded on the Host.
    host = next(iter(graph.hosts()))[1]
    assert host.technology is not None and "wildcard_shape:200/size:14" in host.technology


def test_no_wildcard_passes_through_gobuster() -> None:
    cal = CalibrationResult(
        statuses=(404, 404, 404),
        sizes=(7, 7, 7),
        body_hashes=("b", "b", "b"),
        content_types=("text/html",) * 3,
        wildcard=False,
    )
    graph = ReachabilityGraph()
    audit = AuditLog()
    runner = GobusterRunner(graph=graph, scope=_scope(), audit=audit)
    runner.calibration = cal
    runner.ingest(f"https://{_TARGET}", "/admin (Status: 200)\n/login (Status: 200)\n")
    paths = {ep.path for _, ep in graph.endpoints()}
    assert "/admin" in paths and "/login" in paths
    assert not any(e.outcome == "refused_wildcard_catchall" for e in audit.entries)


def test_wildcard_suppresses_ffuf_ferox_dirb() -> None:
    cal = CalibrationResult(
        statuses=(200, 200, 200),
        sizes=(14, 14, 14),
        body_hashes=("a", "a", "a"),
        content_types=("text/html",) * 3,
        wildcard=True,
    )
    fixtures: list[tuple[object, str]] = [
        (FfufRunner, json.dumps({"results": [{"url": f"https://{_TARGET}/api", "status": 200}]})),
        (FeroxbusterRunner, f'{{"url":"https://{_TARGET}/x","status":200}}\n'),
        (DirbRunner, f"+ https://{_TARGET}/y (CODE:200|SIZE:1)\n"),
    ]
    for cls, fixture in fixtures:
        graph = ReachabilityGraph()
        audit = AuditLog()
        runner = cls(graph=graph, scope=_scope(), audit=audit)
        runner.calibration = cal
        runner.ingest(f"https://{_TARGET}", fixture)
        assert list(graph.endpoints()) == [], f"{cls.__name__} suppressed nothing"
        assert any(e.outcome == "refused_wildcard_catchall" for e in audit.entries)


def test_wildcard_suppress_is_recon_facts_only() -> None:
    # After suppression the graph holds a Host but zero Endpoint / Finding / can_call.
    cal = CalibrationResult(
        statuses=(200, 200, 200),
        sizes=(14, 14, 14),
        body_hashes=("a", "a", "a"),
        content_types=("text/html",) * 3,
        wildcard=True,
    )
    graph = ReachabilityGraph()
    audit = AuditLog()
    runner = GobusterRunner(graph=graph, scope=_scope(), audit=audit)
    runner.calibration = cal
    runner.ingest(f"https://{_TARGET}", "/admin (Status: 200)\n")
    assert list(graph.hosts())
    assert list(graph.endpoints()) == []
    assert graph.findings() == []
    assert graph.can_call_edges() == []


# -- D3 wiring through scan_target -----------------------------------------------


def test_wiring_passes_through_without_wildcard() -> None:
    # Dry-run: no calibration probe fired → content discovery passes through.
    result = scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=True,
        fixtures={"gobuster": "/items (Status: 200)\n"},
    )
    assert result["dry_run"] is True
    paths = {ep.path for _, ep in result["graph"].endpoints()}
    assert "/items" in paths
    assert not any(e.outcome == "refused_wildcard_catchall" for e in result["audit"].entries)


def test_wiring_suppresses_content_discovery_on_wildcard() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Catch-all: any path (probe or content) returns the same body.
        return httpx.Response(200, content=_CATCHALL_BODY)

    result = scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=False,
        transport=httpx.MockTransport(handler),
        fixtures={
            "gobuster": "/admin (Status: 200)\n",
            "ffuf": json.dumps({"results": [{"url": "https://example.com/api", "status": 200}]}),
            "feroxbuster": '{"url":"https://example.com/x","status":200}\n',
            "dirb": "+ https://example.com/y (CODE:200|SIZE:1)\n",
        },
    )
    g = result["graph"]
    paths = {ep.path for _, ep in g.endpoints()}
    # All four content-discovery paths suppressed by the catch-all verdict.
    assert not (paths & {"/admin", "/api", "/x", "/y"})
    assert any(e.outcome == "refused_wildcard_catchall" for e in result["audit"].entries)
    # Calibration fact recorded on the host.
    assert any(
        (h.technology or "") and "wildcard_shape:200/size:" in h.technology for _, h in g.hosts()
    )


def test_wiring_never_fires_calibration_in_dry_run() -> None:
    # Dry-run asserts zero fired — calibration must not run (it fires probes).
    result = scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=True,
        fixtures={"gobuster": "/a (Status: 200)\n"},
    )
    assert not any(e.outcome.startswith("fired:") for e in result["audit"].entries)
