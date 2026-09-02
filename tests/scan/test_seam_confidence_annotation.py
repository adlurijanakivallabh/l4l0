"""LLM-confidence annotation wired into _ValidatorSeam.write() (Build Order 5).

Confirms the "additional signal, never a substitute" contract: confidence
is computed strictly after a real oracle verdict already confirmed a
violation, is stored on dedicated Finding fields (never merged into the
deterministic-provenance `metadata` dict), and a disabled/failing annotator
never blocks or alters whether the finding gets written.
"""

from __future__ import annotations

from unittest.mock import Mock

from reachagent.confirmation import confidence as _confidence_module
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence
from reachagent.scan.orchestrator import _ValidatorSeam
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient


def _confirmed_seam(graph: ReachabilityGraph, monkeypatch) -> _ValidatorSeam:  # noqa: ANN001
    # v3: run_oracle judges via LLM reasoning (oracles/llm_judgment.py) instead of
    # a fixed decide(). _ValidatorSeam.run() calls validator.run_oracle() with no
    # client= passthrough, so the injection seam is build_openai_compatible_client
    # itself — same pattern as tests/phase1/test_confirm_error_based_e2e.py.
    monkeypatch.setattr(
        "reachagent.oracles.llm_judgment.build_openai_compatible_client",
        lambda **_kw: FixedJudgmentClient(CONFIRMS.value),
    )
    seam = _ValidatorSeam(graph)
    seam.run(
        OracleMechanism.STRUCTURAL,
        StructuralEvidence(
            check_type=StructuralCheckType.PATH_TRAVERSAL,
            probe_status=200,
            sentinel="root:x:0:0",
            response_body="root:x:0:0:root:/root",
        ),
    )
    return seam


def test_flag_off_writes_a_finding_with_no_confidence_fields(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.delenv("REACHAGENT_CONFIDENCE_ANNOTATION", raising=False)
    graph = ReachabilityGraph()
    seam = _confirmed_seam(graph, monkeypatch)
    node_id = seam.write("path_traversal", seam.last)
    assert node_id is not None
    finding = dict(graph.findings())[node_id]
    assert finding.llm_confidence == ""
    assert finding.llm_confidence_rationale == ""


def test_flag_on_valid_annotation_lands_on_dedicated_fields_not_metadata(
    monkeypatch,  # noqa: ANN001
) -> None:
    monkeypatch.setenv("REACHAGENT_CONFIDENCE_ANNOTATION", "1")
    client = Mock()
    client.propose.return_value = {"confidence": "high", "rationale": "direct sentinel match"}
    monkeypatch.setattr(_confidence_module, "OpenAIConfidenceClient", lambda **_kw: client)

    graph = ReachabilityGraph()
    seam = _confirmed_seam(graph, monkeypatch)
    node_id = seam.write("path_traversal", seam.last, metadata={"some_ref": "abc"})
    assert node_id is not None
    finding = dict(graph.findings())[node_id]
    assert finding.llm_confidence == "high"
    assert finding.llm_confidence_rationale == "direct sentinel match"
    # The deterministic-provenance metadata dict is untouched by the LLM
    # annotation — no llm_confidence key leaks into it.
    assert "llm_confidence" not in finding.metadata
    assert finding.metadata.get("some_ref") == "abc"


def test_annotator_failure_never_blocks_the_write(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setenv("REACHAGENT_CONFIDENCE_ANNOTATION", "1")
    boom = Mock()
    boom.propose.side_effect = RuntimeError("provider unavailable")
    monkeypatch.setattr(_confidence_module, "OpenAIConfidenceClient", lambda **_kw: boom)

    graph = ReachabilityGraph()
    seam = _confirmed_seam(graph, monkeypatch)
    node_id = seam.write("path_traversal", seam.last)
    assert node_id is not None
    finding = dict(graph.findings())[node_id]
    assert finding.llm_confidence == ""


def test_no_verdict_still_writes_nothing_regardless_of_confidence_flag(
    monkeypatch,  # noqa: ANN001
) -> None:
    monkeypatch.setenv("REACHAGENT_CONFIDENCE_ANNOTATION", "1")
    graph = ReachabilityGraph()
    seam = _ValidatorSeam(graph)
    assert seam.write("path_traversal", None) is None
    assert graph.findings() == []
