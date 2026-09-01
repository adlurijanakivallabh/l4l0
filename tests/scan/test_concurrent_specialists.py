"""Build Order 2c: concurrent specialist spawning.

Three layers, matching the design: (1) _dispatch_classes in isolation
(the shared loop both the sequential path and each specialist child use),
(2) _run_phase3_concurrent's scheduling/merge/crash-isolation/cancellation
mechanics against FAKE drivers (fast, deterministic, and able to prove
genuine thread overlap via timestamps), (3) one real end-to-end scan
through scan_all_classes(concurrent_specialists=True) against the same
fixture test_orchestrator.py's sequential-path test already uses, to prove
parity of the actual finding set.
"""

from __future__ import annotations

import threading
import time
import types

import httpx
import pytest

import reachagent.scan.orchestrator as _orchestrator
from reachagent.graph.nodes import Finding, FindingStatus
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.agentic_loop import ScanCancelled
from reachagent.scan.orchestrator import (
    _PHASE3_CLASS_ORDER,
    _SPECIALIST_OF_CLASS,
    _dispatch_classes,
    _run_phase3_concurrent,
    _ValidatorSeam,
    scan_all_classes,
)

_SQL_ERROR = 'You have an error in your SQL syntax; near "\'"'


def _finding(vuln_class: str, evidence_ref: str) -> Finding:
    return Finding(
        vuln_class=vuln_class,
        severity="high",
        oracle_used="structural",
        evidence_ref=evidence_ref,
        status=FindingStatus.CONFIRMED_VIOLATION,
    )


def _control_state(touches: list[int] | None = None) -> object:
    log = touches if touches is not None else []
    return types.SimpleNamespace(touch=lambda: log.append(1))


# === _dispatch_classes — the shared loop ====================================


def test_dispatch_classes_calls_every_driver_and_touches_once_each() -> None:
    graph = ReachabilityGraph()
    calls: list[str] = []
    touches: list[int] = []
    drivers = {"a": lambda: calls.append("a"), "b": lambda: calls.append("b")}

    _dispatch_classes(
        ("a", "b"),
        graph=graph,
        drivers=drivers,
        events=[],
        operator_prompt=None,
        cancel_check=None,
        check_cancel=lambda _c: None,
        touch=lambda: touches.append(1),
    )

    assert calls == ["a", "b"]  # REACHAGENT_VULN_TUNING unset -> default order preserved
    assert len(touches) == 2


def test_dispatch_classes_propagates_cancellation() -> None:
    def _cancel(_c: object) -> None:
        raise ScanCancelled("stop")

    with pytest.raises(ScanCancelled):
        _dispatch_classes(
            ("a",),
            graph=ReachabilityGraph(),
            drivers={"a": lambda: None},
            events=[],
            operator_prompt=None,
            cancel_check=None,
            check_cancel=_cancel,
            touch=lambda: None,
        )


def test_dispatch_classes_label_prefixes_its_narration_events() -> None:
    events: list = []
    _dispatch_classes(
        ("jwt_forgery",),
        graph=ReachabilityGraph(),
        drivers={"jwt_forgery": lambda: None},
        events=events,
        operator_prompt=None,
        cancel_check=None,
        check_cancel=lambda _c: None,
        touch=lambda: None,
        label="auth",
    )
    assert any(e.message.startswith("[auth]") for e in events)


# === _run_phase3_concurrent — scheduling/merge/crash-isolation/cancellation =


def _patch_fake_drivers(monkeypatch, *, run: object) -> None:
    """Replace _build_phase3_drivers with one returning `run(class_name)`
    closures bound to whatever graph THIS call was built for (the parent's
    for the sequential auth phase, each child's own for the concurrent fan-out)."""

    def fake_build(*, graph, **_kw):  # noqa: ANN001
        return {c: (lambda c=c: run(c, graph)) for c in _PHASE3_CLASS_ORDER}

    monkeypatch.setattr(_orchestrator, "_build_phase3_drivers", fake_build)


def _run_concurrent(*, run: object, graph: ReachabilityGraph, control_state: object, events: list):
    _run_phase3_concurrent(
        graph=graph,
        seam=_ValidatorSeam(graph),
        firer=None,
        base_url="http://x.test",
        identity="anon",
        auth_headers={},
        identities=None,
        transport=None,
        library=None,
        allow_cross_user_writes=False,
        events=events,
        operator_prompt=None,
        cancel_check=None,
        check_cancel=lambda _c: None,
        control_state=control_state,
    )


def test_auth_runs_before_the_concurrent_fan_out_is_announced(monkeypatch) -> None:  # noqa: ANN001
    order: list[str] = []

    def run(class_name: str, graph: ReachabilityGraph) -> None:
        order.append(class_name)

    _patch_fake_drivers(monkeypatch, run=run)
    graph = ReachabilityGraph()
    events: list = []
    _run_concurrent(run=run, graph=graph, control_state=_control_state(), events=events)

    auth_classes = [c for c in _PHASE3_CLASS_ORDER if _SPECIALIST_OF_CLASS.get(c) == "auth"]
    fan_out_index = next(i for i, e in enumerate(events) if "fanning out" in e.message)
    fan_out_call_count = order[: len(auth_classes)]
    assert set(fan_out_call_count) == set(auth_classes)  # every auth class ran first
    assert any("sequential, runs first" in e.message for e in events[:fan_out_index])


def test_non_auth_specialists_genuinely_overlap_in_wall_clock_time(monkeypatch) -> None:  # noqa: ANN001
    timeline: list[tuple[str, str, float]] = []
    lock = threading.Lock()

    def run(class_name: str, graph: ReachabilityGraph) -> None:
        specialist = _SPECIALIST_OF_CLASS.get(class_name, "general")
        if specialist == "auth":
            return  # keep the sequential prelude fast
        with lock:
            timeline.append((specialist, "start", time.monotonic()))
        time.sleep(0.05)
        with lock:
            timeline.append((specialist, "end", time.monotonic()))

    _patch_fake_drivers(monkeypatch, run=run)
    graph = ReachabilityGraph()
    _run_concurrent(run=run, graph=graph, control_state=_control_state(), events=[])

    specialists = {s for s, _kind, _t in timeline}
    assert len(specialists) >= 2  # client_side/injection/protocol/api_logic all present
    starts = {s: min(t for sp, k, t in timeline if sp == s and k == "start") for s in specialists}
    ends = {s: max(t for sp, k, t in timeline if sp == s and k == "end") for s in specialists}
    overlap = any(
        a != b and starts[a] < ends[b] and starts[b] < ends[a]
        for a in specialists
        for b in specialists
    )
    assert overlap, f"no wall-clock overlap observed between specialists: {timeline}"


def test_findings_from_every_specialist_are_merged_into_the_parent_graph(monkeypatch) -> None:  # noqa: ANN001
    def run(class_name: str, graph: ReachabilityGraph) -> None:
        if class_name == "structural_headers":  # client_side
            graph.add_finding(_finding("clickjacking", "ref-headers"))
        elif class_name == "sqli_blind":  # injection
            graph.add_finding(_finding("sqli_blind", "ref-sqli"))
        elif class_name == "graphql":  # api_logic
            graph.add_finding(_finding("graphql", "ref-graphql"))

    _patch_fake_drivers(monkeypatch, run=run)
    graph = ReachabilityGraph()
    _run_concurrent(run=run, graph=graph, control_state=_control_state(), events=[])

    classes = {f.vuln_class for _fid, f in graph.findings()}
    assert classes == {"clickjacking", "sqli_blind", "graphql"}


def test_one_specialist_crashing_never_aborts_its_siblings(monkeypatch) -> None:  # noqa: ANN001
    def run(class_name: str, graph: ReachabilityGraph) -> None:
        if class_name == "sqli_blind":  # injection specialist
            raise RuntimeError("boom")
        if class_name == "structural_headers":  # client_side specialist
            graph.add_finding(_finding("clickjacking", "ref-headers"))

    _patch_fake_drivers(monkeypatch, run=run)
    graph = ReachabilityGraph()
    events: list = []
    _run_concurrent(run=run, graph=graph, control_state=_control_state(), events=events)

    classes = {f.vuln_class for _fid, f in graph.findings()}
    assert "clickjacking" in classes  # the surviving specialist's work still landed
    assert any("crashed" in e.message and "RuntimeError" in e.message for e in events)
    assert any("done" in e.message for e in events)  # a sibling completed cleanly


def test_cancellation_mid_fanout_still_merges_partial_work_then_raises(monkeypatch) -> None:  # noqa: ANN001
    def run(class_name: str, graph: ReachabilityGraph) -> None:
        if class_name == "sqli_blind":  # injection specialist
            raise ScanCancelled("operator cancelled")
        if class_name == "structural_headers":  # client_side specialist
            graph.add_finding(_finding("clickjacking", "ref-headers"))

    _patch_fake_drivers(monkeypatch, run=run)
    graph = ReachabilityGraph()
    events: list = []

    with pytest.raises(ScanCancelled):
        _run_concurrent(run=run, graph=graph, control_state=_control_state(), events=events)

    # The cancelled specialist raised before finding anything, but the
    # sibling that finished cleanly first must still have been merged.
    classes = {f.vuln_class for _fid, f in graph.findings()}
    assert "clickjacking" in classes


def test_control_state_touched_for_every_class_plus_once_per_specialist_merge(
    monkeypatch,  # noqa: ANN001
) -> None:
    """Touch fires: once per auth class (sequential _dispatch_classes), once
    per non-auth class INSIDE each specialist's own _dispatch_classes (via
    the lock-wrapped _safe_touch), and once more per specialist when the
    parent merges its result -- the idle-timeout clock must never go quiet
    for as long as any specialist, not just the coarse phase boundary."""

    def run(class_name: str, graph: ReachabilityGraph) -> None:
        return None

    _patch_fake_drivers(monkeypatch, run=run)
    graph = ReachabilityGraph()
    touches: list[int] = []
    _run_concurrent(run=run, graph=graph, control_state=_control_state(touches), events=[])

    auth_count = sum(1 for c in _PHASE3_CLASS_ORDER if _SPECIALIST_OF_CLASS.get(c) == "auth")
    non_auth_specialists = {
        s for c in _PHASE3_CLASS_ORDER if (s := _SPECIALIST_OF_CLASS.get(c, "general")) != "auth"
    }
    non_auth_class_count = len(_PHASE3_CLASS_ORDER) - auth_count
    expected = auth_count + non_auth_class_count + len(non_auth_specialists)
    assert len(touches) == expected


# === End-to-end parity: concurrent_specialists=True matches the sequential path ===


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    origin = request.headers.get("origin", "")
    if path == "/":
        headers = {
            "content-type": "text/html",
            "set-cookie": "session=abc; Path=/; SameSite=None; Secure",
            "access-control-allow-origin": origin or "*",
            "access-control-allow-credentials": "true",
        }
        return httpx.Response(200, text="<html>reachagent</html>", headers=headers)
    if path in ("/users/v1", "/items"):
        return httpx.Response(200, json={"users": [{"username": "name1"}]})
    if path.startswith("/users/v1/"):
        seg = path.rsplit("/", 1)[-1]
        if seg.endswith("'"):
            return httpx.Response(500, text=_SQL_ERROR)
        if seg.startswith("reachagent-canary-"):
            return httpx.Response(404, text="not found")
        return httpx.Response(200, json={"username": "name1"})
    return httpx.Response(404, text="not found")


def _surface(tmp_path) -> str:  # noqa: ANN001
    surface = tmp_path / "surface.yaml"
    surface.write_text(
        "endpoints:\n"
        "  - method: GET\n    path: /\n"
        "  - method: GET\n    path: /users/v1\n"
        "  - method: GET\n    path: /users/v1/{username}\n"
        "    parameters:\n      - name: username\n        location: path\n"
    )
    return str(surface)


def test_concurrent_scan_finds_the_same_classes_as_the_sequential_scan(tmp_path) -> None:  # noqa: ANN001
    from reachagent.payloads import PayloadLibrary

    result = scan_all_classes(
        base_url="https://example.com",
        in_scope="example.com",
        transport=httpx.MockTransport(_handler),
        surface_path=_surface(tmp_path),
        library=PayloadLibrary.from_file(),
        concurrent_specialists=True,
    )
    classes = {f.vuln_class for _fid, f in result["graph"].findings()}
    assert "sqli" in classes
    assert {"clickjacking", "cors_misconfig", "csrf_missing_protection"} <= classes
    for _fid, f in result["graph"].findings():
        assert f.status.value == "confirmed_violation"


def test_concurrent_scan_on_a_clean_target_yields_zero_findings(tmp_path) -> None:  # noqa: ANN001
    from reachagent.payloads import PayloadLibrary

    def clean_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    result = scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(clean_handler),
        surface_path=_surface(tmp_path),
        library=PayloadLibrary.from_file(),
        concurrent_specialists=True,
    )
    assert result["graph"].findings() == []
