"""LLM-driven vulnerability review (v4 R1).

A broad surface-shape survey proposes leads; each proposed lead is then
independently confirmed through the real `run_oracle`/`judge()` seam before
anything is written — no separate lower-confidence tier. The fake client
below answers differently depending on which of the two calls it's serving
(the survey call names "Discovered surface:"; the per-lead confirmation call
is `judge()`'s own prompt, which names "Mechanism family:") so both stages
are genuinely exercised, not just the first one.
"""

from __future__ import annotations

from dataclasses import replace

from reachagent.graph.nodes import Endpoint, Finding, FindingStatus, Host, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.llm_vuln_review import run_llm_vulnerability_review


class _FakeClient:
    def __init__(self, leads_reply: dict, *, confirm_status: str = "confirmed_violation") -> None:
        self.leads_reply = leads_reply
        self.confirm_status = confirm_status
        self.seen_prompt = ""
        self.confirm_prompts: list[str] = []

    def propose_json(self, prompt: str, *, max_tokens: int = 1500) -> dict:
        if "Mechanism family:" in prompt:  # judge()'s own confirmation call
            self.confirm_prompts.append(prompt)
            return {"status": self.confirm_status, "reason": "matches the surface context given"}
        self.seen_prompt = prompt
        return self.leads_reply


def _graph_with_surface() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(Host(address="demo.example", source="t", technology="PHP"))
    ep = g.add_endpoint(Endpoint(method="GET", path="/api/users/1/invoices"))
    g.add_parameter(ep, Parameter(name="id", location="path", inferred_sink_type=SinkType.SQL))
    return g


def test_review_writes_a_real_finding_once_confirmed() -> None:
    g = _graph_with_surface()
    fake = _FakeClient(
        {
            "leads": [
                {
                    "vuln_class": "bola",
                    "endpoint": "/api/users/1/invoices",
                    "location": "id",
                    "reason": "sequential numeric id, no ownership check observed",
                    "severity": "high",
                }
            ]
        }
    )
    written = run_llm_vulnerability_review(graph=g, client=fake)
    assert written == 1
    findings = g.findings()
    assert len(findings) == 1
    _fid, finding = findings[0]
    assert finding.vuln_class == "bola"
    assert finding.status is FindingStatus.CONFIRMED_VIOLATION
    assert finding.oracle_used == "structural"
    assert "invoices" in fake.seen_prompt  # the real surface was actually sent
    assert len(fake.confirm_prompts) == 1  # the lead really was independently confirmed


def test_review_drops_a_lead_whose_confirmation_does_not_hold_up() -> None:
    """The survey proposing something is not enough on its own — confirmation can
    still say no, and that lead must not become a Finding."""
    g = _graph_with_surface()
    fake = _FakeClient(
        {"leads": [{"vuln_class": "bola", "endpoint": "/a", "reason": "r", "severity": "high"}]},
        confirm_status="inconclusive",
    )
    written = run_llm_vulnerability_review(graph=g, client=fake)
    assert written == 0
    assert g.findings() == []
    assert len(fake.confirm_prompts) == 1  # confirmation was genuinely attempted


def test_review_emits_one_event_per_confirmed_finding_not_a_silent_batch() -> None:
    """Operator feedback: leads only ever became visible via the next full-graph
    poll, reading as everything showing up at once. Each written finding must now
    carry its own live event, the same as every other driver's finding events."""
    from reachagent.scan.orchestrator import ScanEvent

    g = _graph_with_surface()
    fake = _FakeClient(
        {
            "leads": [
                {"vuln_class": "bola", "endpoint": "/a", "reason": "r1", "severity": "high"},
                {"vuln_class": "ssrf", "endpoint": "/b", "reason": "r2", "severity": "medium"},
            ]
        }
    )
    events: list[ScanEvent] = []
    written = run_llm_vulnerability_review(graph=g, client=fake, events=events)
    assert written == 2
    finding_events = [e for e in events if e.kind == "finding"]
    assert len(finding_events) == 2
    assert any("bola" in e.message and "/a" in e.message for e in finding_events)
    assert any("ssrf" in e.message and "/b" in e.message for e in finding_events)


def test_review_without_events_param_still_works() -> None:
    g = _graph_with_surface()
    fake = _FakeClient({"leads": [{"vuln_class": "bola", "endpoint": "/a", "reason": "r"}]})
    assert run_llm_vulnerability_review(graph=g, client=fake) == 1


def test_review_fails_open_on_provider_error() -> None:
    class Boom:
        def propose_json(self, prompt: str, *, max_tokens: int = 1500) -> dict:
            raise RuntimeError("no provider")

    g = _graph_with_surface()
    assert run_llm_vulnerability_review(graph=g, client=Boom()) == 0
    assert g.findings() == []


def test_review_one_lead_confirmation_failure_does_not_abort_the_rest() -> None:
    """One lead's own confirmation call raising must not lose every other lead."""

    class _FlakyConfirm:
        def __init__(self) -> None:
            self.calls = 0

        def propose_json(self, prompt: str, *, max_tokens: int = 1500) -> dict:
            if "Mechanism family:" not in prompt:
                return {
                    "leads": [
                        {"vuln_class": "bola", "endpoint": "/a", "reason": "r1"},
                        {"vuln_class": "ssrf", "endpoint": "/b", "reason": "r2"},
                    ]
                }
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("transient provider error")
            return {"status": "confirmed_violation", "reason": "ok"}

    g = _graph_with_surface()
    written = run_llm_vulnerability_review(graph=g, client=_FlakyConfirm())
    assert written == 1  # the second lead still confirmed despite the first's failure


def test_review_empty_graph_is_a_no_op() -> None:
    fake = _FakeClient({"leads": [{"vuln_class": "sqli", "endpoint": "/x"}]})
    assert run_llm_vulnerability_review(graph=ReachabilityGraph(), client=fake) == 0


def test_review_ignores_a_malformed_reply() -> None:
    g = _graph_with_surface()
    for bad_reply in ({"leads": "not-a-list"}, {"nope": []}, {}):
        assert run_llm_vulnerability_review(graph=g, client=_FakeClient(bad_reply)) == 0
    assert g.findings() == []


def test_review_drops_a_lead_with_no_vuln_class() -> None:
    g = _graph_with_surface()
    leads = [{"vuln_class": "", "endpoint": "/x"}, {"vuln_class": "ssrf", "endpoint": "/y"}]
    written = run_llm_vulnerability_review(graph=g, client=_FakeClient({"leads": leads}))
    assert written == 1


def test_review_caps_at_max_items() -> None:
    g = _graph_with_surface()
    leads = [{"vuln_class": f"class-{i}", "endpoint": f"/e{i}"} for i in range(20)]
    written = run_llm_vulnerability_review(graph=g, client=_FakeClient({"leads": leads}))
    assert written == 12  # _MAX_ITEMS cap, not 20


def test_review_invalid_severity_defaults_to_info() -> None:
    g = _graph_with_surface()
    fake = _FakeClient(
        {"leads": [{"vuln_class": "xss_reflected", "endpoint": "/e", "severity": "apocalyptic"}]}
    )
    run_llm_vulnerability_review(graph=g, client=fake)
    _fid, finding = g.findings()[0]
    assert finding.severity == "info"


def test_review_prompt_excludes_already_confirmed_from_repetition() -> None:
    g = _graph_with_surface()
    g.add_finding(
        Finding(
            vuln_class="sqli",
            severity="high",
            oracle_used="differential",
            evidence_ref="orchestrator/sqli /api/users/1/invoices id",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    fake = _FakeClient({"leads": []})
    run_llm_vulnerability_review(graph=g, client=fake)
    assert "CONFIRMED (do not repeat)" in fake.seen_prompt
    assert "orchestrator/sqli" in fake.seen_prompt


def test_review_includes_app_domain_when_classified() -> None:
    g = _graph_with_surface()
    for _n, h in g.hosts():
        g.add_host(replace(h, app_domain="ecommerce store"))
    fake = _FakeClient({"leads": []})
    run_llm_vulnerability_review(graph=g, client=fake)
    assert "ecommerce store" in fake.seen_prompt
