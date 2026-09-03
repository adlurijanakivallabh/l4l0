"""Phase 6 focused checks for deterministic evidence and oracle boundaries."""

from __future__ import annotations

import ast
import math
from pathlib import Path

import pytest

from reachagent.detection.oracle_gateway import registry_runner
from reachagent.execution.audit import AuditLog
from reachagent.graph.nodes import Finding, FindingStatus
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.business_rule import (
    BusinessRule,
    BusinessRuleEvidence,
    ReplayObservation,
)
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
)
from reachagent.oracles.evidence import EvidenceMetadata, EvidenceValidationError
from reachagent.oracles.execution_confirmation import ExecutionConfirmationEvidence
from reachagent.oracles.oob_callback import OOBCallbackEvidence
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence
from reachagent.oracles.timing_statistical import PairedTrialEvidence
from reachagent.tools import validator
from reachagent.tools.validator_support import UnconfirmedFindingError
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient


def _inconclusive_evidence(mechanism: OracleMechanism) -> object:
    if mechanism is OracleMechanism.DIFFERENTIAL:
        return DifferentialEvidence(
            axis=DiffAxis.CROSS_CONDITION,
            expectation=DiffExpectation.RESPONSES_INVARIANT,
            baseline=Observation("baseline", 500, ""),
            probe=Observation("probe", 200, "different"),
            evidence_ref="phase6/differential",
        )
    if mechanism is OracleMechanism.BUSINESS_RULE_INVARIANT:
        return BusinessRuleEvidence(
            rule=BusinessRule.PRICE_TAMPER,
            baseline=ReplayObservation("baseline", 500),
            violating=ReplayObservation("violating", 200),
            evidence_ref="phase6/business",
        )
    if mechanism is OracleMechanism.TIMING_STATISTICAL:
        samples = tuple(100.0 for _ in range(10))
        return PairedTrialEvidence(
            probe_latencies_ms=samples,
            baseline_latencies_ms=samples,
            evidence_ref="phase6/timing",
        )
    if mechanism is OracleMechanism.OOB_CALLBACK:
        return OOBCallbackEvidence(
            probe_nonce="phase6-nonce",
            observed_nonces=frozenset(),
            evidence_ref="phase6/oob",
        )
    if mechanism is OracleMechanism.EXECUTION_CONFIRMATION:
        return ExecutionConfirmationEvidence(evidence_ref="phase6/execution")
    return StructuralEvidence(
        check_type=StructuralCheckType.PATH_TRAVERSAL,
        probe_status=200,
        sentinel="root:x:0:0",
        response_body="safe response",
        evidence_ref="phase6/structural",
    )


def test_registry_is_exactly_six_families() -> None:
    from reachagent.oracles.registry import _REGISTRY

    expected = {
        "differential",
        "execution_confirmation",
        "oob_callback",
        "timing_statistical",
        "structural",
        "business_rule_invariant",
    }
    assert len(OracleMechanism) == 6
    assert {member.value for member in OracleMechanism} == expected
    assert len(_REGISTRY) == 6
    assert set(_REGISTRY) == set(OracleMechanism)


@pytest.mark.parametrize("mechanism", tuple(OracleMechanism))
def test_every_family_has_a_stable_inconclusive_reason(mechanism: OracleMechanism) -> None:
    evidence = _inconclusive_evidence(mechanism)
    first = registry_runner(mechanism, evidence)
    second = registry_runner(mechanism, evidence)

    assert first.status == FindingStatus.INCONCLUSIVE.value
    assert first.reason.startswith(f"{mechanism.value}:inconclusive:")
    assert first.reason == second.reason
    assert first.evidence_metadata == second.evidence_metadata
    if mechanism is OracleMechanism.TIMING_STATISTICAL:
        samples = first.evidence_metadata["timing_samples_ms"]
        assert isinstance(samples, list)
        assert len(samples) == 20
    else:
        assert isinstance(first.evidence_metadata, dict)


def test_typed_metadata_round_trips_without_raw_secrets() -> None:
    metadata = EvidenceMetadata(
        request_ref="fire-1",
        response_ref="response-1",
        baseline_body_projection="json:admin",
        probe_body_projection="json:admin",
        headers=(("Content-Type", "application/json"), ("X-Frame-Options", "DENY")),
        timing_samples_ms=(100.0, 101.5),
        oob_channels=(("phase6-nonce", "dns"),),
    )
    evidence = DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.RESPONSES_INVARIANT,
        baseline=Observation("baseline", 200, "same"),
        probe=Observation("probe", 200, "same"),
        evidence_ref="phase6/metadata",
        metadata=metadata,
    )
    verdict = validator.run_oracle(OracleMechanism.DIFFERENTIAL, evidence)

    assert verdict.evidence_metadata.as_dict() == {
        "baseline_body_projection": "json:admin",
        "probe_body_projection": "json:admin",
        "request_ref": "fire-1",
        "response_ref": "response-1",
        "headers": [("content-type", "application/json"), ("x-frame-options", "DENY")],
        "timing_samples_ms": [100.0, 101.5],
        "oob_channels": [("phase6-nonce", "dns")],
    }

    with pytest.raises(EvidenceValidationError, match="secret"):
        EvidenceMetadata(headers=(("Authorization", "Bearer super-secret"),)).validated()
    with pytest.raises(EvidenceValidationError, match="raw secret"):
        EvidenceMetadata(body_projection="token=super-secret").validated()


def test_invalid_status_and_timing_values_fail_closed() -> None:
    """v3 (CLAUDE.md): the old per-mechanism ``_validate_evidence`` upfront field
    checks (raising ``EvidenceValidationError``/``ValidationError`` on a
    malformed field like an impossible HTTP status or a non-finite multiplier)
    were part of the now-removed ``decide()`` path — llm_judgment.judge() does
    not run them, it hands the evidence to an LLM. Malformed evidence no longer
    raises; it fails closed to INCONCLUSIVE instead, the same as any other
    evidence the judgment can't make sense of. Never a fabricated violation
    either way — this is a narrower, still-safe fail-closed guarantee, not a
    weaker one."""
    invalid_diff = DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.RESPONSES_INVARIANT,
        baseline=Observation("baseline", 99, ""),
        probe=Observation("probe", 200, ""),
    )
    verdict = validator.run_oracle(OracleMechanism.DIFFERENTIAL, invalid_diff)
    assert verdict.status is FindingStatus.INCONCLUSIVE
    assert not verdict.is_violation

    invalid_timing = PairedTrialEvidence(
        probe_latencies_ms=tuple(100.0 for _ in range(10)),
        baseline_latencies_ms=tuple(100.0 for _ in range(10)),
        threshold_multiplier=math.nan,
    )
    timing_verdict = validator.run_oracle(OracleMechanism.TIMING_STATISTICAL, invalid_timing)
    assert timing_verdict.status is FindingStatus.INCONCLUSIVE
    assert not timing_verdict.is_violation


def test_negative_result_is_graph_and_audit_record() -> None:
    graph = ReachabilityGraph()
    audit = AuditLog()

    validator.mark_inconclusive(
        graph,
        "identity:guest",
        "endpoint:GET /health",
        evidence="phase6/negative",
        reason="baseline_missing",
        audit=audit,
    )

    assert (
        graph.can_call_status("identity:guest", "endpoint:GET /health")
        is FindingStatus.INCONCLUSIVE
    )
    assert len(audit.entries) == 1
    entry = audit.entries[0]
    assert entry.method == "ORACLE"
    assert "inconclusive:baseline_missing" in entry.outcome
    assert "phase6/negative" in entry.outcome

    with pytest.raises(EvidenceValidationError):
        validator.mark_inconclusive(
            graph,
            "identity:guest",
            "endpoint:GET /health",
            evidence="token=must-not-be-recorded",
            audit=audit,
        )


def test_run_oracle_can_emit_a_negative_audit_record_without_exposing_body() -> None:
    audit = AuditLog()
    evidence = _inconclusive_evidence(OracleMechanism.EXECUTION_CONFIRMATION)
    verdict = validator.run_oracle(
        OracleMechanism.EXECUTION_CONFIRMATION,
        evidence,
        audit=audit,
        identity="identity:guest",
        target="endpoint:GET /search",
    )
    assert verdict.status is FindingStatus.INCONCLUSIVE
    assert len(audit.entries) == 1
    assert audit.entries[0].target == "endpoint:GET /search"
    assert "oracle:execution_confirmation:inconclusive:" in audit.entries[0].outcome


def test_only_confirmed_violation_can_persist_and_metadata_is_safe() -> None:
    graph = ReachabilityGraph()
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.PATH_TRAVERSAL,
        probe_status=200,
        sentinel="root:x:0:0",
        response_body="root:x:0:0",
        evidence_ref="phase6/path",
    )
    verdict = validator.run_oracle(
        OracleMechanism.STRUCTURAL, evidence, client=FixedJudgmentClient(CONFIRMS.value)
    )
    assert verdict.is_violation
    node = validator.write_finding(
        graph,
        Finding("path_traversal", "high", "", ""),
        verdict,
        metadata={"probe_ref": "fire-1"},
    )
    assert graph.has_node(node)
    stored = graph.findings()[0][1]
    assert stored.status is FindingStatus.CONFIRMED_VIOLATION
    assert stored.metadata["oracle_reason"].startswith("structural:confirmed_violation:")

    inconclusive = validator.run_oracle(
        OracleMechanism.STRUCTURAL,
        StructuralEvidence(
            check_type=StructuralCheckType.PATH_TRAVERSAL,
            probe_status=200,
            sentinel="root:x:0:0",
            response_body="clean",
            evidence_ref="phase6/path-clean",
        ),
    )
    with pytest.raises(UnconfirmedFindingError, match="confirmed_violation"):
        validator.write_finding(graph, Finding("path_traversal", "high", "", ""), inconclusive)
    assert len(graph.findings()) == 1

    with pytest.raises(EvidenceValidationError, match="secret"):
        graph.add_finding(
            Finding(
                "path_traversal",
                "high",
                "structural",
                "phase6/direct",
                status=FindingStatus.CONFIRMED_VIOLATION,
                metadata={"password": "super-secret"},
            )
        )


def test_detector_modules_never_construct_verdict_or_finding() -> None:
    root = Path(__file__).parents[2] / "src" / "reachagent"
    detector_packages = (
        "bola",
        "business_logic",
        "clickjacking",
        "cors",
        "csrf",
        "fileupload",
        "graphql",
        "ldap",
        "nosql",
        "race",
        "sqli",
        "xss",
    )
    violations: list[str] = []
    for package in detector_packages:
        for path in (root / package).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for call in ast.walk(tree):
                if not isinstance(call, ast.Call):
                    continue
                name = ast.unparse(call.func)
                if name.endswith("OracleVerdict") or name.endswith("Finding"):
                    violations.append(f"{path}:{call.lineno}:{name}")
    assert violations == []


def test_verdict_constructors_are_confined_to_the_known_oracle_modules() -> None:
    """v3 (CLAUDE.md): the six legacy per-family modules' ``run()`` methods now
    raise ``NotImplementedError`` instead of returning a verdict (decide() is
    gone), so none of them constructs an ``OracleVerdict`` any more — the live
    judgment path, ``oracles/llm_judgment.py``, is the only remaining site. The
    discipline itself — verdict construction confined to a small, known,
    reviewed set of files — is unchanged, just narrower now."""
    root = Path(__file__).parents[2] / "src" / "reachagent"
    allowed = {root / "oracles" / "llm_judgment.py"}
    violations: list[str] = []
    count = 0
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not ast.unparse(call.func).endswith(
                "OracleVerdict"
            ):
                continue
            count += 1
            if path not in allowed:
                violations.append(f"{path}:{call.lineno}")
    assert count == 2  # success + fail-closed inconclusive, both in llm_judgment.py
    assert violations == []


# v3: the three tests below were removed by the decide()-removal pass (they
# called StructuralOracle().run(evidence) with no injected LLM client and
# asserted on its now-removed decide()-derived verdict) and are restored here
# targeting the relocation destination the removal task's report named:
# llm_judgment.py::_enrich_metadata now does this auto-fill, applied inside
# judge() regardless of what the LLM decides.


def test_structural_evidence_auto_fills_a_real_snippet_around_the_sentinel() -> None:
    """v2 Phase 6 Stage E1, relocated: the GUI/report must show real proof, not
    just an opaque evidence_ref handle — auto-fill a bounded snippet centered
    on the match, independent of what the judgment itself decides."""
    body = ("x" * 300) + "root:x:0:0:root:/root:/bin/bash" + ("y" * 300)
    verdict = validator.run_oracle(
        OracleMechanism.STRUCTURAL,
        StructuralEvidence(
            check_type=StructuralCheckType.PATH_TRAVERSAL,
            probe_status=200,
            sentinel="root:x:0:0",
            response_body=body,
            evidence_ref="path_traversal/test",
        ),
        client=FixedJudgmentClient(CONFIRMS.value),
    )
    assert verdict.status is FindingStatus.CONFIRMED_VIOLATION
    projection = verdict.evidence_metadata.body_projection
    assert projection  # real content, not empty
    assert "root:x:0:0:root:/root:/bin/bash" in projection
    assert len(projection) < len(body)  # bounded — not the whole 600+ char body
    assert projection.startswith("…")  # there was more body before the window
    assert projection.endswith("…")  # and after


def test_structural_evidence_does_not_overwrite_a_caller_supplied_projection() -> None:
    verdict = validator.run_oracle(
        OracleMechanism.STRUCTURAL,
        StructuralEvidence(
            check_type=StructuralCheckType.PATH_TRAVERSAL,
            probe_status=200,
            sentinel="root:x:0:0",
            response_body="root:x:0:0" + ("z" * 500),
            evidence_ref="path_traversal/test2",
            metadata=EvidenceMetadata(body_projection="caller already supplied this"),
        ),
        client=FixedJudgmentClient(CONFIRMS.value),
    )
    assert verdict.evidence_metadata.body_projection == "caller already supplied this"


def test_structural_evidence_projection_never_raises_on_a_body_that_looks_secret_like() -> None:
    """A real target's response could coincidentally contain something matching the
    generic secret-value pattern (e.g. a long random-looking token in an error page)
    — the ALREADY-DECIDED verdict must still come back; only the evidence snippet is
    dropped, never the judgment itself."""
    verdict = validator.run_oracle(
        OracleMechanism.STRUCTURAL,
        StructuralEvidence(
            check_type=StructuralCheckType.PATH_TRAVERSAL,
            probe_status=200,
            sentinel="root:x:0:0",
            response_body='root:x:0:0 {"password": "super-secret-value-12345"}',
            evidence_ref="path_traversal/test3",
        ),
        client=FixedJudgmentClient(CONFIRMS.value),
    )
    assert verdict.status is FindingStatus.CONFIRMED_VIOLATION  # never blocked


def test_oversized_response_body_is_truncated_not_rejected() -> None:
    """Caught live: crAPI's cache_poisoning driver constructed StructuralEvidence
    in-process (never through the MCP boundary) with a response body over the
    1,000,000-char validation cap, raising ValueError out of _validate_evidence
    and aborting the entire remaining scan. StructuralEvidence now caps
    response_body/reread_response_body at construction (__post_init__), the one
    choke point every caller — MCP and every in-process orchestrator driver alike
    — routes through, so an oversized live body degrades to a truncated, still-
    decidable value instead of crashing."""
    oversized = "z" * 1_000_050
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.WEB_CACHE_POISONING,
        probe_status=200,
        response_body=oversized,
        reread_response_body=oversized,
        evidence_ref="phase6/oversized",
    )
    assert len(evidence.response_body) == 1_000_000
    assert len(evidence.reread_response_body) == 1_000_000
