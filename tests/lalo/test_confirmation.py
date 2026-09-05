"""Tests for semantic diffing and non-blocking confidence scoring."""

from __future__ import annotations

from lalo.confirmation import score_finding, semantic_diff
from lalo.confirmation.scoring import ConfidenceScorer
from lalo.models import Evidence, EvidenceKind, Finding, Severity


def _finding(**meta: object) -> Finding:
    f = Finding.create("t", "sqli", Severity.HIGH, "https://app.example.com/x")
    f.metadata.update(meta)
    return f


def test_semantic_diff_detects_change() -> None:
    d = semantic_diff("hello world", "hello world", baseline_status=200, candidate_status=200)
    assert d.similarity == 1.0
    assert d.magnitude == 0.0

    d2 = semantic_diff(
        "welcome user", "SQL syntax error near", baseline_status=200, candidate_status=500
    )
    assert d2.status_changed
    assert d2.magnitude > 0.5
    assert "SQL" in d2.added_markers or "syntax" in d2.added_markers


def test_more_corroboration_scores_higher() -> None:
    weak = _finding()
    weak.evidence.append(Evidence(EvidenceKind.STRUCTURAL, "one signal"))
    strong = _finding()
    strong.evidence.extend(
        [
            Evidence(EvidenceKind.DIFFERENTIAL, "diff", metadata={"diff_magnitude": 0.9}),
            Evidence(EvidenceKind.TIMING, "timing"),
            Evidence(EvidenceKind.OOB_CALLBACK, "callback hit"),
        ]
    )
    assert score_finding(strong).total > score_finding(weak).total


def test_chained_impact_and_reproducibility_boost() -> None:
    base = _finding()
    base.evidence.append(Evidence(EvidenceKind.STRUCTURAL, "s"))
    boosted = _finding(chained_impact=True, repeats_agreed=3, cross_context_reproduced=True)
    boosted.evidence.append(Evidence(EvidenceKind.STRUCTURAL, "s"))
    assert score_finding(boosted).total > score_finding(base).total


def test_nothing_is_withheld_only_annotated() -> None:
    # Even a bare finding gets a score and remains a finding (never dropped).
    f = _finding()
    bd = score_finding(f)
    assert 0.0 <= bd.total <= 100.0
    assert f.confidence == bd.total
    assert f.confidence_breakdown  # populated


def test_unverifiable_evidence_lowers_score_and_flags_but_ships() -> None:
    marker = "<script>xss</script>"
    verifiable = _finding()
    verifiable.evidence.append(
        Evidence(EvidenceKind.STRUCTURAL, "reflected", fire_ref="r1", observed=marker)
    )
    unverifiable = _finding()
    unverifiable.evidence.append(
        Evidence(EvidenceKind.STRUCTURAL, "reflected", fire_ref="r1", observed=marker)
    )
    captures = {"r1": f"... page body containing {marker} ..."}

    good = ConfidenceScorer().score(verifiable, captures=captures)
    bad = ConfidenceScorer().score(unverifiable, captures={"r1": "totally different body"})

    assert "evidence_unverified" not in good.flags
    assert "evidence_unverified" in bad.flags
    assert bad.components["provenance"] < good.components["provenance"]
    # The unverifiable finding still produced a score (was not dropped).
    assert bad.total >= 0.0
