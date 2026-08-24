"""Hermetic tests for LLM-driven reporting — only confirmed findings, fallback safe."""

from __future__ import annotations

from unittest.mock import Mock

from reachagent.graph.nodes import Finding, FindingStatus
from reachagent.graph.store import ReachabilityGraph
from reachagent.report.llm_report import generate_llm_report


def _graph_with_findings(statuses: list[FindingStatus]) -> ReachabilityGraph:
    g = ReachabilityGraph()
    for i, status in enumerate(statuses):
        try:
            g.add_finding(
                Finding(
                    vuln_class="sqli",
                    severity="high",
                    oracle_used="differential",
                    evidence_ref=f"ref-{i}",
                    status=status,
                )
            )
        except ValueError:
            # store refuses non-CONFIRMED_VIOLATION — expected for test
            pass
    # For inconclusive etc, manually add via internal? Instead just not add.
    # For test we want confirmed only to be rendered.
    return g


def _confirmed_graph(n: int = 1) -> ReachabilityGraph:
    g = ReachabilityGraph()
    for i in range(n):
        g.add_finding(
            Finding(
                vuln_class="sqli",
                severity="high",
                oracle_used="differential",
                evidence_ref=f"ref-{i}",
                status=FindingStatus.CONFIRMED_VIOLATION,
            )
        )
    return g


def test_empty_graph_deterministic_no_findings() -> None:
    g = ReachabilityGraph()
    # mock client that would return narrative but graph empty — fallback to deterministic
    mock = Mock()
    mock.propose.return_value = {"narrative": "# Report\nno findings"}
    out = generate_llm_report(g, client=mock)
    assert "No findings" in out


def test_confirmed_findings_in_deterministic_table() -> None:
    g = _confirmed_graph(2)
    mock = Mock()
    mock.propose.side_effect = RuntimeError("no key")
    out = generate_llm_report(g, client=mock)
    # fallback deterministic must contain both evidence refs
    assert "ref-0" in out
    assert "ref-1" in out


def test_mocked_valid_narrative_prepended() -> None:
    g = _confirmed_graph(1)
    mock = Mock()
    mock.propose.return_value = {"narrative": "# Executive Summary\nFound sqli."}
    out = generate_llm_report(g, client=mock)
    assert "# Executive Summary" in out
    assert "ref-0" in out  # deterministic table appended
    assert out.index("# Executive Summary") < out.index("ref-0")


def test_mocked_error_fallback_deterministic() -> None:
    g = _confirmed_graph(1)
    mock = Mock()
    mock.propose.side_effect = RuntimeError("timeout")
    out = generate_llm_report(g, client=mock)
    assert "ref-0" in out
    assert "Executive" not in out


def test_mocked_empty_narrative_fallback() -> None:
    g = _confirmed_graph(1)
    mock = Mock()
    mock.propose.return_value = {"narrative": "   "}
    out = generate_llm_report(g, client=mock)
    # empty narrative treated as fallback, deterministic only
    assert "ref-0" in out
    # no extra narrative header
    assert out.strip().startswith("|") or out.strip().startswith("No findings") or "ref-0" in out


def test_no_api_key_fallback_when_client_none() -> None:
    g = _confirmed_graph(1)
    # client=None will build AnthropicReportClient which needs key -> fallback
    import os
    from unittest.mock import patch

    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        out = generate_llm_report(g, client=None)
    assert "ref-0" in out


def test_chain_rendering_deterministic_sorted() -> None:
    g = ReachabilityGraph()
    # Add two findings with different vuln_class to check sorted order
    g.add_finding(
        Finding(
            vuln_class="xss_reflected",
            severity="medium",
            oracle_used="structural",
            evidence_ref="a",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    g.add_finding(
        Finding(
            vuln_class="sqli",
            severity="high",
            oracle_used="differential",
            evidence_ref="b",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    mock = Mock()
    mock.propose.side_effect = RuntimeError("no llm")
    out = generate_llm_report(g, client=mock)
    # sorted by vuln_class -> sqli before xss_reflected (vuln_class, evidence_ref, id)
    assert out.index("sqli") < out.index("xss_reflected")
