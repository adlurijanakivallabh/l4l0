"""Hermetic tests for child-graph -> parent-graph merge (Build Order 2c)."""

from __future__ import annotations

from reachagent.graph.merge import merge_new_findings
from reachagent.graph.nodes import Finding, FindingStatus, Session
from reachagent.graph.store import ReachabilityGraph


def _finding(vuln_class: str, evidence_ref: str, **kwargs: object) -> Finding:
    defaults: dict[str, object] = {
        "vuln_class": vuln_class,
        "severity": "high",
        "oracle_used": "differential",
        "evidence_ref": evidence_ref,
        "status": FindingStatus.CONFIRMED_VIOLATION,
    }
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_merges_a_new_finding_into_the_target() -> None:
    source = ReachabilityGraph()
    target = ReachabilityGraph()
    source.add_finding(_finding("sqli", "ref-1"))

    new_ids = merge_new_findings(source, target)

    assert len(new_ids) == 1
    classes = {f.vuln_class for _fid, f in target.findings()}
    assert classes == {"sqli"}


def test_already_present_finding_is_not_re_merged() -> None:
    source = ReachabilityGraph()
    target = ReachabilityGraph()
    fid = source.add_finding(_finding("sqli", "ref-1"))
    target.add_finding(_finding("sqli", "ref-1"))

    new_ids = merge_new_findings(source, target)

    assert new_ids == []
    assert len(target.findings()) == 1
    assert fid in {f for f, _ in target.findings()}


def test_same_content_reencountered_never_warns(caplog) -> None:  # noqa: ANN001
    """The common, harmless case (a repeated merge of unchanged content)
    must stay quiet -- only a genuinely DIFFERING second confirmation
    (disclosed limit, adversarial review) should ever warn."""
    import logging

    source = ReachabilityGraph()
    target = ReachabilityGraph()
    source.add_finding(_finding("sqli", "ref-1"))
    target.add_finding(_finding("sqli", "ref-1"))

    with caplog.at_level(logging.WARNING, logger="reachagent.graph.merge"):
        merge_new_findings(source, target)

    assert caplog.records == []


def test_differing_content_for_the_same_finding_id_logs_a_warning(caplog) -> None:  # noqa: ANN001
    """Disclosed precondition: two separate merge calls supplying different
    content for the same deterministic finding id keep whichever landed
    first -- silently, except for this warning."""
    import logging

    source = ReachabilityGraph()
    target = ReachabilityGraph()
    source.add_finding(_finding("sqli", "ref-1", metadata={"note": "second"}))
    target.add_finding(_finding("sqli", "ref-1", metadata={"note": "first"}))

    with caplog.at_level(logging.WARNING, logger="reachagent.graph.merge"):
        new_ids = merge_new_findings(source, target)

    assert new_ids == []
    assert len(caplog.records) == 1
    assert "different content" in caplog.records[0].getMessage()
    _fid, kept = target.findings()[0]
    assert kept.metadata["note"] == "first"  # whichever landed first wins


def test_repeated_merge_of_the_same_source_is_idempotent() -> None:
    source = ReachabilityGraph()
    target = ReachabilityGraph()
    source.add_finding(_finding("sqli", "ref-1"))

    first = merge_new_findings(source, target)
    second = merge_new_findings(source, target)

    assert len(first) == 1
    assert second == []  # already merged, nothing new
    assert len(target.findings()) == 1


def test_enables_edge_between_two_newly_merged_findings_is_replayed() -> None:
    source = ReachabilityGraph()
    target = ReachabilityGraph()
    f1 = source.add_finding(_finding("sqli", "ref-1"))
    f2 = source.add_finding(_finding("xss_reflected", "ref-2"))
    source.add_enables(f1, f2)

    merge_new_findings(source, target)

    assert (f1, f2) in target.enables_edges()


def test_derived_credential_edge_replayed_when_spawned_node_already_in_target() -> None:
    source = ReachabilityGraph()
    target = ReachabilityGraph()
    # A session that pre-exists in BOTH graphs (established before the
    # specialist child was forked -- the common, in-scope case).
    session = Session(token_ref="tok-ref", identity_ref="user_a")
    session_node = target.add_session(session)
    source.add_session(session)  # same deterministic id in both graphs
    fid = source.add_finding(_finding("jwt_forgery", "ref-1"))
    source.add_derived_credential(fid, session_node)

    merge_new_findings(source, target)

    assert (fid, session_node) in target.derived_credential_edges()


def test_derived_credential_edge_to_a_node_missing_from_target_is_skipped_not_fatal() -> None:
    source = ReachabilityGraph()
    target = ReachabilityGraph()
    # A session created ONLY in the child (out of this module's disclosed
    # findings-only scope) -- must not crash the merge.
    session_node = source.add_session(Session(token_ref="tok-ref", identity_ref="user_a"))
    fid = source.add_finding(_finding("jwt_forgery", "ref-1"))
    source.add_derived_credential(fid, session_node)

    new_ids = merge_new_findings(source, target)  # must not raise

    assert new_ids == [fid]
    assert target.derived_credential_edges() == []


def test_no_new_findings_means_no_edge_replay_work_at_all() -> None:
    source = ReachabilityGraph()
    target = ReachabilityGraph()
    fid = source.add_finding(_finding("sqli", "ref-1"))
    target.add_finding(_finding("sqli", "ref-1"))
    other = source.add_finding(_finding("xss_reflected", "ref-2"))
    target.add_finding(_finding("xss_reflected", "ref-2"))
    source.add_enables(fid, other)

    new_ids = merge_new_findings(source, target)

    assert new_ids == []
    # The enables edge existed only between two already-present findings --
    # nothing new to trigger a replay for, and no crash either way.
    assert target.enables_edges() == []


def test_merged_finding_metadata_does_not_share_the_source_dict_instance() -> None:
    source = ReachabilityGraph()
    target = ReachabilityGraph()
    source.add_finding(_finding("sqli", "ref-1", metadata={"note": "original"}))

    merge_new_findings(source, target)

    _fid, source_finding = source.findings()[0]
    _fid2, target_finding = target.findings()[0]
    target_finding.metadata["note"] = "mutated in target"
    assert source_finding.metadata["note"] == "original"


def test_empty_source_graph_merges_nothing() -> None:
    source = ReachabilityGraph()
    target = ReachabilityGraph()
    target.add_finding(_finding("sqli", "ref-1"))

    new_ids = merge_new_findings(source, target)

    assert new_ids == []
    assert len(target.findings()) == 1
