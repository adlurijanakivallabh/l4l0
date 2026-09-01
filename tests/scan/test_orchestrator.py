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

    monkeypatch.delenv("REACHAGENT_TLS_INSECURE", raising=False)
    scan_all_classes(
        base_url="https://example.com",
        in_scope="example.com",
        transport=httpx.MockTransport(_handler),
        surface_path=_surface(tmp_path),
        events=[],
    )
    assert captured[-1].get("verify", True) is not False

    captured.clear()
    monkeypatch.setenv("REACHAGENT_TLS_INSECURE", "1")
    scan_all_classes(
        base_url="https://example.com",
        in_scope="example.com",
        transport=httpx.MockTransport(_handler),
        surface_path=_surface(tmp_path),
        events=[],
    )
    assert captured[-1]["verify"] is False
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
