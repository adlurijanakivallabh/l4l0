"""Hermetic E2E for the jwt_forgery driver: baseline-valid-token + forged-token
probes -> STRUCTURAL JWT_FORGERY confirmation.

No dedicated driver test existed for run_jwt_forgery before — the payload
catalog (tests/recon/test_phase2a_fixes.py) only proved the four forged
tokens resolve and are catalogued correctly, never that the driver loop
actually fires all four against a token-bearing endpoint and reaches the
oracle. Added alongside the new kid-injection template to prove the fourth
variant is wired end to end, not just resolvable.
"""

from __future__ import annotations

import httpx

from reachagent.detection.oracle_gateway import OracleOutcome
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles.base import OracleVerdict
from reachagent.scan.orchestrator import _ValidatorSeam, run_jwt_forgery
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE

_BASE = "http://jwt.test"
_VALID_TOKEN = "a-valid-session-token"


def _real_evidence_run(self: _ValidatorSeam, mechanism: object, evidence: object) -> OracleOutcome:
    """v3 (CLAUDE.md): confirmation is now an LLM judgment, not the removed
    decide() logic. A blanket fixed verdict (FixedJudgmentClient) would confirm
    on the FIRST forged variant tried (none-alg) regardless of its real probe
    status, since run_jwt_forgery breaks its loop on the first is_violation —
    defeating the point of this test, which is that only the kid-injection
    variant actually gets accepted (200) by the broken verifier. So this stand-in
    for _ValidatorSeam.run still looks at the real StructuralEvidence.probe_status
    to decide, letting the test assert on real HTTP-response-driven wiring instead
    of a specific LLM judgment.
    """
    status = CONFIRMS if evidence.probe_status == 200 else INCONCLUSIVE  # type: ignore[attr-defined]
    ref = str(getattr(evidence, "evidence_ref", "") or "")
    verdict = OracleVerdict(
        mechanism=mechanism, status=status, evidence_ref=ref, reason="test-fixed-verdict"
    )
    self._last = verdict
    return OracleOutcome(verdict)


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/api/user/profile"))
    return graph


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["jwt.test"]))


def _run(handler: object, graph: ReachabilityGraph | None = None) -> list:
    graph = graph or _graph()
    seam = _ValidatorSeam(graph)
    run_jwt_forgery(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={"Authorization": f"Bearer {_VALID_TOKEN}"},
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_all_four_forged_variants_are_attempted() -> None:
    seen_tokens: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        seen_tokens.append(auth.removeprefix("Bearer "))
        # Everything refused except the real, valid token — a correct verifier.
        return httpx.Response(200 if auth == f"Bearer {_VALID_TOKEN}" else 401, text="{}")

    assert _run(handler) == []
    assert _VALID_TOKEN in seen_tokens
    # All four precomputed forged shapes must have been fired, not just some.
    assert sum(1 for t in seen_tokens if t != _VALID_TOKEN) == 4


def test_kid_injection_token_accepted_confirms_a_finding(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(_ValidatorSeam, "run", _real_evidence_run)

    from reachagent.payloads.payload_resolver import resolve

    kid_token = resolve("jwt_forgery/kid-injection")

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        # A broken verifier accepts the valid token AND the kid-forged one.
        if auth in (f"Bearer {_VALID_TOKEN}", f"Bearer {kid_token}"):
            return httpx.Response(200, text="{}")
        return httpx.Response(401, text="{}")

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    metadata = {f.metadata.get("forged") for _fid, f in findings}
    assert "jwt_forgery" in classes
    assert "kid-injection" in metadata


def test_no_valid_baseline_token_never_fires() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text="{}")

    graph = _graph()
    seam = _ValidatorSeam(graph)
    run_jwt_forgery(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},  # no bearer token to baseline against
        seam=seam,
        events=[],
    )
    assert seen == []
    assert graph.findings() == []
