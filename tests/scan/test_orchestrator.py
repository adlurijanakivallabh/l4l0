"""Hermetic test for the all-class orchestrator (plan v2)."""

from __future__ import annotations

import httpx

from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import (
    _PHASE3_CLASS_ORDER,
    _SPECIALIST_OF_CLASS,
    ALL_CLASSES,
    ScanEvent,
    rank_vuln_classes,
    scan_all_classes,
)

_SQL_ERROR = 'You have an error in your SQL syntax; near "\'"'


def _handler(request: httpx.Request) -> httpx.Response:
    """A small target: SQLi on /users/v1/{username} + a clickjacking/cors/csrf-prone /."""
    path = request.url.path
    origin = request.headers.get("origin", "")
    # The root page ships no framing defense, a SameSite=None session cookie, and
    # reflects any Origin with credentials — the three structural findings.
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
    if path.startswith("/items/"):
        q = request.url.params.get("probe", "")
        if q.endswith("'"):
            return httpx.Response(500, text=_SQL_ERROR)
        if q.startswith("reachagent-canary-"):
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


def test_scan_all_classes_detects_sqli_and_structural(tmp_path) -> None:  # noqa: ANN001
    from reachagent.payloads import PayloadLibrary

    events: list[ScanEvent] = []
    result = scan_all_classes(
        base_url="https://example.com",
        in_scope="example.com",
        transport=httpx.MockTransport(_handler),
        surface_path=_surface(tmp_path),
        events=events,
        library=PayloadLibrary.from_file(),
    )
    classes = {f.vuln_class for _fid, f in result["graph"].findings()}
    # The generic sink loop confirms sqli; the structural-header pass confirms the
    # three client-side classes from the root page headers.
    assert "sqli" in classes
    assert {"clickjacking", "cors_misconfig", "csrf_missing_protection"} <= classes
    # Every finding carries deterministic oracle provenance.
    for _fid, f in result["graph"].findings():
        assert f.status.value == "confirmed_violation"
        assert f.oracle_used
    # The phase timeline captured the three phases.
    assert any(e.phase == "recon" for e in result["events"])
    assert any(e.phase == "payloads" for e in result["events"])


def test_all_classes_enum_is_stable() -> None:
    # The orchestrator dispatches every class in the §9 coverage target.
    assert "sqli" in ALL_CLASSES
    assert "race" in ALL_CLASSES


def test_tls_insecure_env_flag_disables_cert_verification(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    """REACHAGENT_TLS_INSECURE is opt-in only — never a silent default. A target
    with an expired/self-signed cert (a legacy or intentionally-vulnerable demo
    app) otherwise fails every single request at the transport layer."""
    import reachagent.scan.orchestrator as orch

    captured: list[dict[str, object]] = []
    real_client = httpx.Client

    class _CapturingClient(real_client):  # type: ignore[misc]
        def __init__(self, *args: object, **kwargs: object) -> None:
            captured.append(dict(kwargs))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(orch.httpx, "Client", _CapturingClient)

    # A full scan constructs more than one httpx.Client: the main firer's
    # (which must track REACHAGENT_TLS_INSECURE), plus side-channel clients
    # for classes that deliberately probe third-party infrastructure with
    # real, valid certs outside the target's own scope (subdomain_takeover,
    # cloud_bucket_exposure) — those never pass verify= at all, by design,
    # since there's no reason to disable cert checking against
    # s3.amazonaws.com just because the target site has a bad cert. So the
    # property under test is "at least one captured client reflects the
    # flag", not "the last one captured does" — the latter depends on
    # incidental class-dispatch ordering, not on what this test actually
    # cares about.
    monkeypatch.delenv("REACHAGENT_TLS_INSECURE", raising=False)
    scan_all_classes(
        base_url="https://example.com",
        in_scope="example.com",
        transport=httpx.MockTransport(_handler),
        surface_path=_surface(tmp_path),
        events=[],
    )
    assert all(kwargs.get("verify", True) is not False for kwargs in captured)

    captured.clear()
    monkeypatch.setenv("REACHAGENT_TLS_INSECURE", "1")
    scan_all_classes(
        base_url="https://example.com",
        in_scope="example.com",
        transport=httpx.MockTransport(_handler),
        surface_path=_surface(tmp_path),
        events=[],
    )
    assert any(kwargs.get("verify") is False for kwargs in captured)
    assert len(ALL_CLASSES) >= 22


def _clean_handler(request: httpx.Request) -> httpx.Response:
    """A properly-hardened target: no SQL errors, full framing/CORS/CSRF defenses."""
    path = request.url.path
    headers = {
        "x-frame-options": "DENY",
        "content-security-policy": "frame-ancestors 'self'",
        "set-cookie": "session=abc; Path=/; SameSite=Strict",
        "access-control-allow-origin": "https://trusted.example",
    }
    if path in ("/users/v1", "/items"):
        return httpx.Response(200, json={"users": [{"username": "name1"}]}, headers=headers)
    if path.startswith("/users/v1/") or path.startswith("/items/"):
        return httpx.Response(200, json={"username": "name1"}, headers=headers)
    if path == "/":
        return httpx.Response(200, text="<html>safe</html>", headers=headers)
    return httpx.Response(404, text="not found")


def test_clean_target_zero_findings(tmp_path) -> None:  # noqa: ANN001
    """The orchestrator reports no findings on a hardened target (FP honesty)."""
    from reachagent.payloads import PayloadLibrary

    result = scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        surface_path=_surface(tmp_path),
        library=PayloadLibrary.from_file(),
    )
    assert result["graph"].findings() == []
    assert result["findings"] == []


# === rank_vuln_classes — LLM-advised Phase 3 dispatch order ================
# Order only: every input class must still appear in the output, regardless
# of what the (fake) LLM proposes. This is a strategy convenience, never a
# coverage gate.

_CLASSES = ("jwt_forgery", "xxe", "graphql")


class _FakeRankClient:
    def __init__(self, response: dict) -> None:  # noqa: ANN001
        self._response = response

    def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict:  # noqa: ANN001
        return self._response


def test_rank_vuln_classes_disabled_by_default_returns_original_order() -> None:
    order, reason = rank_vuln_classes(_CLASSES, ReachabilityGraph())
    assert order == _CLASSES
    assert "disabled" in reason


def test_phase3_dispatch_re_ranks_after_every_class_not_just_once(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    """Build Order 2: continuous replanning, not a one-shot upfront order.

    Patches rank_vuln_classes itself to a spy that records the class-name
    tuple it's asked to rank on every call. If the dispatch loop still made
    one upfront call, this would record exactly 1 call with the full
    _PHASE3_CLASS_ORDER. The new per-step loop must call it once per
    remaining class, each call's tuple one shorter than the last.
    """
    from reachagent.payloads import PayloadLibrary
    from reachagent.scan import orchestrator as _orchestrator

    calls: list[tuple[str, ...]] = []

    def _spy_rank(class_names, graph, *, operator_prompt=None, client=None):  # noqa: ANN001
        calls.append(tuple(class_names))
        return tuple(class_names), "spy"

    monkeypatch.setattr(_orchestrator, "rank_vuln_classes", _spy_rank)
    scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        surface_path=_surface(tmp_path),
        library=PayloadLibrary.from_file(),
    )
    assert len(calls) == len(_PHASE3_CLASS_ORDER)
    # Each call's remaining set is exactly one shorter than the previous.
    for earlier, later in zip(calls, calls[1:], strict=False):
        assert len(later) == len(earlier) - 1
    assert calls[0] == _PHASE3_CLASS_ORDER
    assert calls[-1] == (_PHASE3_CLASS_ORDER[-1],)


def test_phase3_dispatch_refreshes_the_idle_clock_once_per_class(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    """Bug found live (Build Order 2 follow-up): AdaptiveControlState's idle
    clock was only refreshed at the 5 coarse phase boundaries
    (recon/endpoints/payloads/verification/report) via a single touch()
    call after ALL of Phase 3 finishes. Once Phase 3 became ~22 per-class
    re-ranking calls instead of one upfront call, a real scan's cumulative
    Phase-3 wall-clock time could exceed idle_timeout even while making
    continuous real progress throughout (confirmed live: a genuine finding
    landed mid-phase, then the very next coarse-phase check raised
    IdleTimeout anyway). Spies on AdaptiveControlState.touch directly
    (patched on the source class, since orchestrator.py imports it locally
    inside scan_all_classes) to prove it's called at least once per
    dispatched class, not just once at the end.
    """
    from reachagent.payloads import PayloadLibrary
    from reachagent.scan import agentic_loop as _agentic_loop

    calls = {"n": 0}
    real_touch = _agentic_loop.AdaptiveControlState.touch

    def _spy_touch(self: object) -> None:
        calls["n"] += 1
        real_touch(self)  # type: ignore[arg-type]

    monkeypatch.setattr(_agentic_loop.AdaptiveControlState, "touch", _spy_touch)
    scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        surface_path=_surface(tmp_path),
        library=PayloadLibrary.from_file(),
    )
    # At least one touch() per dispatched Phase-3 class, on top of whatever
    # coarse-phase touches already happened (recon/endpoints/etc.) — the
    # old behavior would have left this at just the coarse-phase count,
    # far below len(_PHASE3_CLASS_ORDER).
    assert calls["n"] >= len(_PHASE3_CLASS_ORDER)


def test_rank_vuln_classes_applies_a_valid_llm_order(monkeypatch) -> None:  # noqa: ANN001
    from reachagent.llm import runtime as _runtime

    monkeypatch.setattr(_runtime, "flag_enabled", lambda _name: True)
    client = _FakeRankClient({"order": ["xxe", "graphql", "jwt_forgery"], "reason": "test"})
    order, reason = rank_vuln_classes(_CLASSES, ReachabilityGraph(), client=client)
    assert order == ("xxe", "graphql", "jwt_forgery")
    assert reason == "test"


def test_rank_vuln_classes_never_drops_a_hallucinated_or_missing_class(monkeypatch) -> None:  # noqa: ANN001
    from reachagent.llm import runtime as _runtime

    monkeypatch.setattr(_runtime, "flag_enabled", lambda _name: True)
    # "sqli" isn't in _CLASSES (hallucinated); "graphql" is silently omitted.
    client = _FakeRankClient({"order": ["xxe", "sqli", "jwt_forgery"], "reason": "test"})
    order, _reason = rank_vuln_classes(_CLASSES, ReachabilityGraph(), client=client)
    assert set(order) == set(_CLASSES)
    assert order[0] == "xxe"
    assert order[1] == "jwt_forgery"
    assert order[2] == "graphql"  # appended back in original relative order


def test_rank_vuln_classes_falls_back_on_malformed_response(monkeypatch) -> None:  # noqa: ANN001
    from reachagent.llm import runtime as _runtime

    monkeypatch.setattr(_runtime, "flag_enabled", lambda _name: True)
    client = _FakeRankClient({"order": "not-a-list"})
    order, reason = rank_vuln_classes(_CLASSES, ReachabilityGraph(), client=client)
    assert order == _CLASSES
    assert "unavailable" in reason


def test_rank_vuln_classes_falls_back_when_client_raises(monkeypatch) -> None:  # noqa: ANN001
    from reachagent.llm import runtime as _runtime

    monkeypatch.setattr(_runtime, "flag_enabled", lambda _name: True)

    class _BoomClient:
        def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict:  # noqa: ANN001
            raise RuntimeError("provider down")

    order, reason = rank_vuln_classes(_CLASSES, ReachabilityGraph(), client=_BoomClient())
    assert order == _CLASSES
    assert "unavailable" in reason


class _PromptCapturingClient:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    def propose_json(self, prompt: str, *, max_tokens: int = 512) -> dict:  # noqa: ANN001
        self.prompts.append(prompt)
        return {"order": [], "reason": "test"}


def test_rank_vuln_classes_surfaces_pattern_memory_as_a_signal(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    """Cross-engagement pattern memory ("My additions") reaches the ranking
    prompt as one more bounded, fixed-vocabulary signal — order-only, never
    a coverage gate; the class list itself is unaffected either way."""
    from reachagent.graph.nodes import Host
    from reachagent.llm import runtime as _runtime
    from reachagent.memory.pattern_db import record_confirmed_pattern

    monkeypatch.setattr(_runtime, "flag_enabled", lambda _name: True)
    pattern_path = tmp_path / "patterns.jsonl"
    record_confirmed_pattern("sqli", "WordPress, PHP", "differential", "high", path=pattern_path)
    monkeypatch.setattr("reachagent.memory.pattern_db._DEFAULT_PATH", pattern_path)

    graph = ReachabilityGraph()
    graph.add_host(Host(address="1.2.3.4", hostname="t.test", technology="WordPress, PHP"))
    client = _PromptCapturingClient()

    order, _reason = rank_vuln_classes(_CLASSES, graph, client=client)

    assert order == _CLASSES  # order-only signal, never drops/adds a class
    assert client.prompts
    assert "past_confirmed_for_similar_stack: sqli" in client.prompts[0]


def test_rank_vuln_classes_omits_pattern_signal_with_no_tech_or_no_history(
    monkeypatch, tmp_path
) -> None:  # noqa: ANN001
    from reachagent.llm import runtime as _runtime

    monkeypatch.setattr(_runtime, "flag_enabled", lambda _name: True)
    monkeypatch.setattr("reachagent.memory.pattern_db._DEFAULT_PATH", tmp_path / "empty.jsonl")
    client = _PromptCapturingClient()

    rank_vuln_classes(_CLASSES, ReachabilityGraph(), client=client)

    assert "past_confirmed_for_similar_stack" not in client.prompts[0]


def test_rank_vuln_classes_surfaces_white_box_facts_as_signals(monkeypatch) -> None:  # noqa: ANN001
    """Build Order 7: SAST hits and known-vulnerable dependencies steer
    priority the same order-only way every other signal already does."""
    from reachagent.graph.nodes import SourceFile, StaticAdvisory
    from reachagent.llm import runtime as _runtime

    monkeypatch.setattr(_runtime, "flag_enabled", lambda _name: True)
    graph = ReachabilityGraph()
    graph.add_source_file(
        SourceFile(path="app/db.py", rule_id="python.sql-injection", line=42, message="x")
    )
    graph.add_static_advisory(
        StaticAdvisory(
            ecosystem="pypi",
            package="requests",
            version="2.6.0",
            cve_id="CVE-2015-2296",
            manifest="requirements.txt",
        )
    )
    client = _PromptCapturingClient()

    order, _reason = rank_vuln_classes(_CLASSES, graph, client=client)

    assert order == _CLASSES  # order-only signal, never drops/adds a class
    assert "static_analysis_hits: python.sql-injection" in client.prompts[0]
    assert "known_vulnerable_dependencies: requests:CVE-2015-2296" in client.prompts[0]


def test_rank_vuln_classes_omits_white_box_signals_with_no_static_facts(monkeypatch) -> None:  # noqa: ANN001
    from reachagent.llm import runtime as _runtime

    monkeypatch.setattr(_runtime, "flag_enabled", lambda _name: True)
    client = _PromptCapturingClient()

    rank_vuln_classes(_CLASSES, ReachabilityGraph(), client=client)

    assert "static_analysis_hits" not in client.prompts[0]
    assert "known_vulnerable_dependencies" not in client.prompts[0]


# === Named specialist personas — hand-off narration (Agentic Coordinator, Phase 2) ===


def test_every_phase3_class_has_a_named_specialist() -> None:
    # A class silently falling back to "general" would mean it never gets a
    # named hand-off in the live event feed -- a data-integrity gap, not
    # just cosmetic.
    missing = [c for c in _PHASE3_CLASS_ORDER if c not in _SPECIALIST_OF_CLASS]
    assert missing == []


def test_scan_emits_specialist_handoff_events(tmp_path) -> None:  # noqa: ANN001
    from reachagent.payloads import PayloadLibrary

    result = scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        surface_path=_surface(tmp_path),
        library=PayloadLibrary.from_file(),
    )
    specialist_events = [
        e for e in result["events"] if "specialist" in e.details and "— starting" in e.message
    ]
    assert specialist_events, "at least one specialist hand-off event must be emitted"
    # Hand-offs must be visibly distinct personas, not one giant undifferentiated block.
    assert len({e.details["specialist"] for e in specialist_events}) > 1
