"""LLM-authored full report (v2 W13) — the LLM writes the ENTIRE report.

The one hard boundary: it cannot invent a CONFIRMED finding. The confirmed-findings
list is ground truth built from run_oracle results before the LLM ever sees the data;
a defense-in-depth check discards the LLM's report (falls back to the deterministic
template) if even one confirmed finding_id is missing from its output.
"""

from __future__ import annotations

from reachagent.graph.nodes import Finding, FindingStatus, SuspectedFinding
from reachagent.graph.store import ReachabilityGraph
from reachagent.report.llm_full_report import generate_llm_authored_report


class _FakeClient:
    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.seen_prompt = ""

    def complete(self, prompt: str, *, max_tokens: int = 512) -> str:
        self.seen_prompt = prompt
        return self.reply


def _graph_with_confirmed(
    *, vuln_class: str = "sqli", evidence_ref: str = "ev1"
) -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_finding(
        Finding(
            vuln_class=vuln_class,
            severity="high",
            oracle_used="differential",
            evidence_ref=evidence_ref,
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    return graph


def test_returns_the_llm_report_when_every_confirmed_finding_is_present() -> None:
    graph = _graph_with_confirmed()
    fake = _FakeClient("# Report\n\nfinding:sqli:ev1 was confirmed.\n")
    result = generate_llm_authored_report(graph, client=fake, target="https://t.test")
    assert result is not None
    assert "finding:sqli:ev1" in result
    assert "sqli" in fake.seen_prompt  # the ground-truth data was actually sent


def test_methodology_section_is_appended_and_never_left_to_the_llm() -> None:
    """The LLM is instructed not to write its own Methodology section, and a real
    one (built from actual scan facts, not model prose) is appended regardless."""
    graph = _graph_with_confirmed()
    fake = _FakeClient("# Report\n\nfinding:sqli:ev1 was confirmed.\n")
    result = generate_llm_authored_report(graph, client=fake, target="https://t.test")
    assert result is not None
    assert "## Methodology" in result
    assert "Proof standard" in result
    assert "do NOT write your own" in fake.seen_prompt


def test_falls_back_to_none_when_a_confirmed_finding_is_omitted() -> None:
    graph = _graph_with_confirmed()
    fake = _FakeClient("A report that never names the actual finding id.")
    result = generate_llm_authored_report(graph, client=fake)
    assert result is None


def test_falls_back_to_none_on_an_empty_reply() -> None:
    graph = _graph_with_confirmed()
    result = generate_llm_authored_report(graph, client=_FakeClient("   "))
    assert result is None


def test_falls_back_to_none_when_the_client_errors() -> None:
    class _BoomClient:
        def complete(self, prompt: str, *, max_tokens: int = 512) -> str:
            raise RuntimeError("provider down")

    graph = _graph_with_confirmed()
    result = generate_llm_authored_report(graph, client=_BoomClient())
    assert result is None


def test_multiple_confirmed_findings_must_all_be_present() -> None:
    graph = _graph_with_confirmed(vuln_class="sqli", evidence_ref="ev1")
    graph.add_finding(
        Finding(
            vuln_class="xss_reflected",
            severity="high",
            oracle_used="execution_confirmation",
            evidence_ref="ev2",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    only_one = _FakeClient("Report mentions finding:sqli:ev1 only.")
    assert generate_llm_authored_report(graph, client=only_one) is None

    both = _FakeClient("Report mentions finding:sqli:ev1 and finding:xss_reflected:ev2.")
    assert generate_llm_authored_report(graph, client=both) is not None


def test_suspected_leads_are_included_in_the_prompt_but_not_required_in_output() -> None:
    graph = _graph_with_confirmed()
    graph.add_suspected_finding(
        SuspectedFinding(
            vuln_class="nosqli",
            endpoint="/api/x",
            location="filter",
            source="oracle:nosqli",
            reason="oracle_tested_no_confirmation",
        )
    )
    fake = _FakeClient("finding:sqli:ev1 confirmed. No suspected leads worth noting.")
    assert "nosqli" in _prompt_after_call(graph, fake)


def test_never_writes_a_finding_or_touches_the_graph() -> None:
    graph = _graph_with_confirmed()
    before = list(graph.findings())
    fake = _FakeClient("finding:sqli:ev1 confirmed.")
    generate_llm_authored_report(graph, client=fake)
    assert list(graph.findings()) == before  # unchanged — this module never mutates the graph


def _prompt_after_call(graph: ReachabilityGraph, fake: _FakeClient) -> str:
    generate_llm_authored_report(graph, client=fake)
    return fake.seen_prompt


def test_prompt_forbids_generic_templated_restatement_of_evidence() -> None:
    """A real LLM-authored report once read like a raw field dump ('A path-traversal
    violation was confirmed... The associated probe response is referenced as
    fire-87') — this locks in the concrete anti-genericness rules added after that,
    so a future prompt refactor can't silently drop them."""
    graph = _graph_with_confirmed()
    fake = _FakeClient("finding:sqli:ev1 confirmed.")
    prompt = _prompt_after_call(graph, fake)
    assert "root cause" in prompt.lower()
    assert "never invent a request/" in prompt.lower()
    assert "generic" in prompt.lower()
