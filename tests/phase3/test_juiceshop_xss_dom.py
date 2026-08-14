"""Browser-attributed localXssChallenge — fire_browser + EXECUTION_CONFIRMATION (hermetic)."""

from __future__ import annotations

import ast
from pathlib import Path

from reachagent.eval import juiceshop_live as jl
from reachagent.eval.juiceshop_harness import (
    VERIFIED_CHALLENGE_SCOPE,
    claim_scope_class,
)
from reachagent.oracles import OracleMechanism


def _target() -> jl.JuiceshopTarget:
    return jl.JuiceshopTarget(base_url="http://juice-sh.op")


def _fake_call(monkeypatch, *, flows: list[dict] | None, raise_on_browser: bool = False):  # noqa: ANN001
    """Install a canned `_call` dispatcher; return the recorded call list."""
    calls: list[tuple[str, dict]] = []

    def dispatcher(mcp: object, name: str, **arguments: object) -> dict[str, object]:
        calls.append((name, dict(arguments)))
        if name == "fire_browser":
            if raise_on_browser:
                raise RuntimeError("browser unavailable")
            return {"flows": flows or []}
        if name == "run_oracle":
            return {"is_violation": True, "verdict_ref": "verdict-1"}
        if name == "write_finding":
            return {"finding": "f1"}
        raise AssertionError(f"unexpected call {name}")

    monkeypatch.setattr(jl, "_call", dispatcher)
    return calls


def test_one_flow_confirms_local_xss_claim(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_JUICESHOP_BROWSER", "1")
    calls = _fake_call(
        monkeypatch,
        flows=[{"source": "location.hash", "sink": "innerHTML", "value_snippet": "x"}],
    )
    claims = jl._detect_xss_dom(_target(), None)
    assert any(c.challenge_key == "localXssChallenge" and c.vuln_class == "xss" for c in claims)
    # fire_browser hit the documented search surface with the DOM canary.
    fb = next(c for c in calls if c[0] == "fire_browser")
    assert "/#/search?q=reachagent-dom-canary" in fb[1]["url"]
    # run_oracle used execution_confirmation with the flows.
    ro = next(c for c in calls if c[0] == "run_oracle")
    assert ro[1]["mechanism"] == "execution_confirmation"
    assert ro[1]["evidence"]["flows"]  # type: ignore[attr-defined]
    # write_finding committed an xss finding.
    wf = next(c for c in calls if c[0] == "write_finding")
    assert wf[1]["vuln_class"] == "xss"


def test_zero_flows_no_claim_no_finding(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_JUICESHOP_BROWSER", "1")
    calls = _fake_call(monkeypatch, flows=[])
    claims = jl._detect_xss_dom(_target(), None)
    assert claims == set()
    assert not any(c[0] in ("run_oracle", "write_finding") for c in calls)


def test_fire_browser_raises_returns_empty_and_audits(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_JUICESHOP_BROWSER", "1")
    _fake_call(monkeypatch, flows=None, raise_on_browser=True)
    captured: dict[str, object] = {}
    real_session_as = jl._session_as

    def capturing(target, token, shared):
        sess = real_session_as(target, token, shared)
        captured["sess"] = sess
        return sess

    monkeypatch.setattr(jl, "_session_as", capturing)
    claims = jl._detect_xss_dom(_target(), None)
    assert claims == set()  # no crash, no fabricated claim
    sess = captured["sess"]
    assert any("error:RuntimeError" in e.outcome for e in sess.ctx.firer.audit.entries)


def test_browser_flag_off_skips(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.delenv("REACHAGENT_JUICESHOP_BROWSER", raising=False)
    calls = _fake_call(monkeypatch, flows=[])
    claims = jl._detect_xss_dom(_target(), None)
    assert claims == set()
    assert calls == []  # no fire_browser, nothing dispatched


def test_xss_scope_credits_local_xss_challenge() -> None:
    # "xss" maps to scope "xss"; localXssChallenge is in that scope, so a
    # tracker-delta flip credits exactly this challenge.
    assert claim_scope_class("xss", "localXssChallenge", None) == "xss"
    assert VERIFIED_CHALLENGE_SCOPE["localXssChallenge"] == "xss"


def test_six_oracle_families_unchanged() -> None:
    assert set(OracleMechanism) == {
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.STRUCTURAL,
        OracleMechanism.TIMING_STATISTICAL,
        OracleMechanism.OOB_CALLBACK,
        OracleMechanism.EXECUTION_CONFIRMATION,
        OracleMechanism.BUSINESS_RULE_INVARIANT,
    }


def test_juiceshop_live_imports_no_validator_directly() -> None:
    src = Path(jl.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "reachagent.tools.validator" not in node.module
