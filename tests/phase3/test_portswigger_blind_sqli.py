"""Hermetic PortSwigger time-delay blind-SQLi runner tests (Task 9a)."""

from __future__ import annotations

import functools

import httpx
import pytest

from reachagent.eval.juiceshop_harness import PortswiggerResult
from reachagent.eval.portswigger_blind_sqli import (
    PortswiggerBlindSqliRunner,
    PortswiggerLabConfig,
    build_configured_runner,
    run_vulnerable_and_clean,
)
from reachagent.execution.firer import FireResult
from reachagent.graph.nodes import FindingStatus
from reachagent.graph.store import ReachabilityGraph
from reachagent.identity.store import IdentityConfigError
from reachagent.tools import validator
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient


class _MockLabFirer:
    """Mock GET execution layer: vulnerable variant delays only tagged payloads."""

    def __init__(
        self,
        *,
        delayed: bool,
        baseline_status: int = 200,
        probe_status: int = 200,
    ) -> None:
        self.delayed = delayed
        self.baseline_status = baseline_status
        self.probe_status = probe_status
        self.calls: list[tuple[str, str, str, str]] = []

    def fire(self, identity: str, method: str, url: str, **kwargs: object) -> FireResult:
        headers = kwargs.get("headers", {})
        cookie = str(headers.get("Cookie", "")) if isinstance(headers, dict) else ""
        assert identity == "portswigger"
        assert method == "GET"
        assert url == "https://lab.test/filter?category=Gifts"
        assert cookie.startswith("TrackingId=")
        assert "; session=session-token" in cookie
        self.calls.append((identity, method, url, cookie))
        is_probe = "x'||pg_sleep(10)--" in cookie
        delayed = self.delayed and is_probe
        return FireResult(
            status_code=self.probe_status if is_probe else self.baseline_status,
            elapsed_seconds=5.0 if delayed else 0.1,
            body=b"mock lab response",
            headers=httpx.Headers({"content-type": "text/html"}),
        )


def _runner(
    *,
    delayed: bool,
    graph: ReachabilityGraph,
    firer: _MockLabFirer,
    client: object | None = None,
) -> PortswiggerBlindSqliRunner:
    # v3 (CLAUDE.md): confirmation is an LLM judgment now, not a deterministic
    # decide(). Tests that need a specific verdict inject a FixedJudgmentClient
    # through validator.run_oracle's client= seam; tests that don't care leave
    # client=None and get the real (fail-closed, no-provider) INCONCLUSIVE path.
    oracle_runner = (
        validator.run_oracle
        if client is None
        else functools.partial(validator.run_oracle, client=client)
    )
    return PortswiggerBlindSqliRunner(
        config=PortswiggerLabConfig(
            base_url="https://lab.test",
            session_token="session-token",
            enabled=True,
        ),
        graph=graph,
        oracle_runner=oracle_runner,
        write_finding=lambda finding, verdict: validator.write_finding(graph, finding, verdict),
        firer=firer,
    )


def test_time_delay_runner_confirms_vulnerable_and_clean_variants() -> None:
    vulnerable_graph = ReachabilityGraph()
    clean_graph = ReachabilityGraph()
    vulnerable_firer = _MockLabFirer(delayed=True)
    clean_firer = _MockLabFirer(delayed=False)

    result = run_vulnerable_and_clean(
        _runner(
            delayed=True,
            graph=vulnerable_graph,
            firer=vulnerable_firer,
            client=FixedJudgmentClient(CONFIRMS.value),
        ),
        _runner(delayed=False, graph=clean_graph, firer=clean_firer),
    )

    assert isinstance(result, PortswiggerResult)
    assert result.available is True
    assert result.vuln_lab_confirmed is True
    assert result.clean_lab_fp_count == 0
    assert result.clean_variant_tested is True
    assert result.lab_type == "portswigger-time-delay"
    assert result.mechanism == "timing_statistical"
    assert result.evidence_ref == "portswigger/blind-sqli/time-delay"
    assert len(vulnerable_firer.calls) == 20  # ten baseline + ten delay GETs
    assert len(clean_firer.calls) == 20
    assert all(method == "GET" for _, method, _, _ in vulnerable_firer.calls + clean_firer.calls)
    assert ["pg_sleep(10)" in cookie for _, _, _, cookie in vulnerable_firer.calls] == [
        False,
        True,
    ] * 10

    vulnerable_findings = vulnerable_graph.findings()
    clean_findings = clean_graph.findings()
    assert len(vulnerable_findings) == 1
    assert vulnerable_findings[0][1].vuln_class == "sqli_blind"
    assert vulnerable_findings[0][1].status is FindingStatus.CONFIRMED_VIOLATION
    assert vulnerable_findings[0][1].oracle_used == "timing_statistical"
    assert clean_findings == []


def test_time_delay_runner_rejects_non_success_statuses() -> None:
    for baseline_status, probe_status in ((403, 200), (200, 500), (200, 504), (200, 302)):
        graph = ReachabilityGraph()
        firer = _MockLabFirer(
            delayed=True,
            baseline_status=baseline_status,
            probe_status=probe_status,
        )
        result = _runner(delayed=True, graph=graph, firer=firer).run()

        assert result.available is True
        assert result.vuln_lab_confirmed is False
        assert result.mechanism == ""
        assert result.passes is False
        assert graph.findings() == []
        assert len(firer.calls) == 20


def test_time_delay_runner_clean_variant_stays_inconclusive() -> None:
    graph = ReachabilityGraph()
    firer = _MockLabFirer(delayed=False)
    result = _runner(delayed=False, graph=graph, firer=firer).run()

    assert result.available is True
    assert result.vuln_lab_confirmed is False
    assert graph.findings() == []
    assert len(firer.calls) == 20


def test_live_config_requires_only_three_values_when_enabled() -> None:
    config = PortswiggerLabConfig.from_env(
        {
            "REACHAGENT_PORTSWIGGER_LIVE": "1",
            "REACHAGENT_PORTSWIGGER_LAB_URL": "https://lab.test",
            "REACHAGENT_PORTSWIGGER_SESSION_TOKEN": "token",
        }
    )
    assert config.enabled is True
    assert config.base_url == "https://lab.test"
    assert config.session_token == "token"


def test_live_config_fails_loudly_when_enabled_credentials_missing() -> None:
    with pytest.raises(IdentityConfigError, match="REACHAGENT_PORTSWIGGER_LAB_URL"):
        PortswiggerLabConfig.from_env(
            {
                "REACHAGENT_PORTSWIGGER_LIVE": "1",
                "REACHAGENT_PORTSWIGGER_SESSION_TOKEN": "token",
            }
        )


def test_live_builder_is_dormant_without_explicit_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_PORTSWIGGER_LIVE", raising=False)
    monkeypatch.delenv("REACHAGENT_PORTSWIGGER_LAB_URL", raising=False)
    monkeypatch.delenv("REACHAGENT_PORTSWIGGER_SESSION_TOKEN", raising=False)

    assert (
        build_configured_runner(
            ReachabilityGraph(), oracle_runner=validator.run_oracle, write_finding=lambda f, v: ""
        )
        is None
    )
