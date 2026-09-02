"""LLM-driven vulnerability review (v2, operator-requested).

Shannon/Strix-style LLM judgment over the discovered surface — but the ONLY place its
output can land is the structurally-separate Suspected/Unconfirmed tier, never a
`Finding`. This is the hard boundary under test throughout: no matter what the LLM
returns, `run_llm_vulnerability_review` must never touch `graph.add_finding`/
`write_finding`/`run_oracle`, and must fail open to zero leads on any error.
"""

from __future__ import annotations

from dataclasses import replace

from reachagent.graph.nodes import Endpoint, Finding, FindingStatus, Host, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.llm_vuln_review import run_llm_vulnerability_review


class _FakeClient:
    def __init__(self, reply: dict) -> None:
        self.reply = reply
        self.seen_prompt = ""

    def propose_json(self, prompt: str, *, max_tokens: int = 1500) -> dict:
        self.seen_prompt = prompt
        return self.reply


def _graph_with_surface() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(Host(address="demo.example", source="t", technology="PHP"))
    ep = g.add_endpoint(Endpoint(method="GET", path="/api/users/1/invoices"))
    g.add_parameter(ep, Parameter(name="id", location="path", inferred_sink_type=SinkType.SQL))
    return g


def test_review_writes_a_suspected_finding_never_a_finding() -> None:
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
    assert g.findings() == []  # never a Finding
    suspected = g.suspected_findings()
    assert len(suspected) == 1
    _sid, lead = suspected[0]
    assert lead.vuln_class == "bola"
    assert lead.source == "llm_judgment"
    assert lead.severity == "high"
    assert "invoices" in fake.seen_prompt  # the real surface was actually sent


def test_review_emits_one_event_per_lead_not_a_silent_batch() -> None:
    """Operator feedback: leads only ever became visible via the next full-graph
    poll, reading as everything showing up at once. Each written lead must now
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
    lead_events = [e for e in events if "suspected lead" in e.message]
    assert len(lead_events) == 2
    assert any("bola" in e.message and "/a" in e.message for e in lead_events)
    assert any("ssrf" in e.message and "/b" in e.message for e in lead_events)


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
    assert g.suspected_findings() == []


def test_review_empty_graph_is_a_no_op() -> None:
    fake = _FakeClient({"leads": [{"vuln_class": "sqli", "endpoint": "/x"}]})
    assert run_llm_vulnerability_review(graph=ReachabilityGraph(), client=fake) == 0


def test_review_ignores_a_malformed_reply() -> None:
    g = _graph_with_surface()
    for bad_reply in ({"leads": "not-a-list"}, {"nope": []}, {}):
        assert run_llm_vulnerability_review(graph=g, client=_FakeClient(bad_reply)) == 0
    assert g.suspected_findings() == []


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
    _sid, lead = g.suspected_findings()[0]
    assert lead.severity == "info"


def test_review_prompt_excludes_already_confirmed_and_suspected_from_repetition() -> None:
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
