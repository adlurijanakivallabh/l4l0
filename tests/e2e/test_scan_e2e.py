"""E2E: generic scan_target confirms findings via payload_chain, hermetic."""

from __future__ import annotations

import httpx

from reachagent.scan.entrypoint import scan_target
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    q = request.url.params.get("probe", "") or request.url.params.get("q", "")
    # sibling list harvest
    if path in ("/users/v1", "/items"):
        return httpx.Response(200, json={"users": [{"username": "name1"}]})
    if path.startswith("/users/v1/") or path.startswith("/items/"):
        # baseline vs probe: canary 404 vs quote 500 with sql error
        if q.endswith("'"):
            return httpx.Response(500, text='You have an error in your SQL syntax; near "\'"')
        if q.startswith("reachagent-canary-"):
            return httpx.Response(404, text="not found")
        return httpx.Response(200, json={"username": "name1"})
    if q.startswith("reachagent-canary-"):
        return httpx.Response(500, text="You have an error in your SQL syntax")
    if q == "'":
        return httpx.Response(500, text="You have an error in your SQL syntax")
    return httpx.Response(200, text="safe")


def test_scan_e2e_generic_sqli(tmp_path, monkeypatch):  # noqa: ANN001
    # v3 (CLAUDE.md): confirmation is now an LLM judgment, not the removed
    # decide() logic, and scan_target's full pipeline has no client= seam to
    # inject through. Fix the LLM provider factory judge() falls back to, so
    # this test asserts WIRING (evidence -> confirmed verdict -> finding),
    # not judgment itself.
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment,
        "build_openai_compatible_client",
        lambda **kw: FixedJudgmentClient(CONFIRMS.value),
    )
    surface = tmp_path / "surface.yaml"
    surface.write_text(
        "endpoints:\n"
        "  - method: GET\n    path: /users/v1\n"
        "  - method: GET\n    path: /users/v1/{username}\n"
        "    parameters:\n      - name: username\n        location: path\n"
    )
    result = scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=False,
        transport=httpx.MockTransport(_handler),
        surface_path=str(surface),
    )
    findings = result.get("findings", [])
    assert len(findings) >= 1
    # Evidence must be generic payload-chain shaped, no hardcoded endpoint literal.
    assert result["graph"].findings()
    for _fid, f in result["graph"].findings():
        assert "generic/payload-chain" in f.evidence_ref or "generic/" in f.evidence_ref


def test_scan_e2e_findings_dedup(tmp_path):  # noqa: ANN001
    surface = tmp_path / "surface.yaml"
    surface.write_text(
        "endpoints:\n"
        "  - method: GET\n    path: /items\n"
        "  - method: GET\n    path: /items/{probe}\n"
        "    parameters:\n      - name: probe\n        location: query\n"
    )
    result = scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=False,
        transport=httpx.MockTransport(_handler),
        surface_path=str(surface),
    )
    # Dedup: findings list length matches graph node count.
    assert len(result["findings"]) == len(result["graph"].findings())
