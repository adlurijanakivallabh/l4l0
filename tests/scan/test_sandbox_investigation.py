"""LLM-driven sandbox investigation (v4 R3 slice 2).

A vuln class proposes a sandbox command for deeper investigation; the
resulting output is then independently confirmed through the real
`run_oracle`/`judge()` seam before anything is written — the same two-stage
shape as `scan/llm_vuln_review.py`. The fake client below answers
differently depending on which of the two calls it's serving (the propose
call's own prompt vs. `judge()`'s own prompt, which names "Mechanism
family:") so both stages are genuinely exercised.
"""

from __future__ import annotations

from dataclasses import dataclass

from reachagent.graph.nodes import Endpoint, Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.sandbox.agent_shell import SandboxResult
from reachagent.scan.sandbox_investigation import (
    propose_sandbox_command,
    run_sandbox_investigation,
)


class _FakeClient:
    def __init__(self, propose_reply: dict, *, confirm_status: str = "confirmed_violation") -> None:
        self.propose_reply = propose_reply
        self.confirm_status = confirm_status
        self.confirm_prompts: list[str] = []
        self.propose_prompts: list[str] = []

    def propose_json(self, prompt: str, *, max_tokens: int = 800) -> dict:
        if "Mechanism family:" in prompt:  # judge()'s own confirmation call
            self.confirm_prompts.append(prompt)
            return {"status": self.confirm_status, "reason": "matches the sandbox output given"}
        self.propose_prompts.append(prompt)
        return self.propose_reply


class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.commands: list[str] = []

    def run_command(self, command: str, *, timeout: float = 60.0) -> SandboxResult:
        self.commands.append(command)
        return self.result


def _graph() -> ReachabilityGraph:
    g = ReachabilityGraph()
    g.add_host(Host(address="target.test", source="t", technology="nginx"))
    g.add_endpoint(Endpoint(method="GET", path="/api/users"))
    return g


def test_propose_declines_returns_none_propose() -> None:
    fake = _FakeClient({"propose": False, "command": "", "rationale": "nothing to add"})
    result = propose_sandbox_command("clickjacking", _graph(), "http://target.test", client=fake)
    assert result is not None
    assert result.propose is False


def test_propose_with_no_client_returns_none() -> None:
    assert propose_sandbox_command("sqli", _graph(), "http://target.test", client=None) is None


def test_propose_empty_command_treated_as_decline() -> None:
    fake = _FakeClient({"propose": True, "command": "", "rationale": "changed my mind"})
    result = propose_sandbox_command("sqli", _graph(), "http://target.test", client=fake)
    assert result is not None
    assert result.propose is False


def test_propose_invalid_severity_falls_back_to_default() -> None:
    fake = _FakeClient(
        {
            "propose": True,
            "command": "nmap target.test",
            "rationale": "probe",
            "severity": "catastrophic",
        }
    )
    result = propose_sandbox_command("sqli", _graph(), "http://target.test", client=fake)
    assert result is not None
    assert result.severity == "medium"


def test_propose_valid_severity_is_kept() -> None:
    fake = _FakeClient(
        {"propose": True, "command": "nmap target.test", "rationale": "probe", "severity": "LOW"}
    )
    result = propose_sandbox_command("sqli", _graph(), "http://target.test", client=fake)
    assert result is not None
    assert result.severity == "low"


def test_investigation_writes_a_real_finding_once_confirmed() -> None:
    g = _graph()
    fake = _FakeClient(
        {
            "propose": True,
            "command": "sqlmap -u http://target.test/api/users?id=1 --batch",
            "rationale": "test the id parameter for blind sqli",
        }
    )
    sandbox = _FakeSandbox(
        SandboxResult(
            command="sqlmap ...",
            exit_code=0,
            output="[CRITICAL] the back-end DBMS is MySQL, parameter 'id' is vulnerable",
        )
    )
    written = run_sandbox_investigation(
        vuln_class="sqli", graph=g, sandbox=sandbox, target="http://target.test", client=fake
    )
    assert written == 1
    assert len(list(g.findings())) == 1
    _fid, finding = next(iter(g.findings()))
    assert finding.vuln_class == "sqli"
    assert finding.severity == "medium"  # this test's proposal reply omits severity -> default
    assert sandbox.commands == ["sqlmap -u http://target.test/api/users?id=1 --batch"]
    # both stages genuinely exercised
    assert len(fake.propose_prompts) == 1
    assert len(fake.confirm_prompts) == 1
    assert "sqlmap" in fake.confirm_prompts[0]  # sandbox output reached the judge


def test_investigation_writes_the_proposed_severity() -> None:
    g = _graph()
    fake = _FakeClient(
        {
            "propose": True,
            "command": "nmap -sV target.test",
            "rationale": "fingerprint",
            "severity": "critical",
        }
    )
    sandbox = _FakeSandbox(SandboxResult(command="nmap ...", exit_code=0, output="open port 443"))
    run_sandbox_investigation(
        vuln_class="ssrf", graph=g, sandbox=sandbox, target="http://target.test", client=fake
    )
    _fid, finding = next(iter(g.findings()))
    assert finding.severity == "critical"


def test_investigation_translates_info_severity_to_informational() -> None:
    g = _graph()
    fake = _FakeClient(
        {
            "propose": True,
            "command": "curl -s target.test/version",
            "rationale": "version disclosure",
            "severity": "info",
        }
    )
    sandbox = _FakeSandbox(SandboxResult(command="curl ...", exit_code=0, output="v1.2.3"))
    run_sandbox_investigation(
        vuln_class="business_logic",
        graph=g,
        sandbox=sandbox,
        target="http://target.test",
        client=fake,
    )
    _fid, finding = next(iter(g.findings()))
    assert finding.severity == "informational"


def test_investigation_drops_a_lead_that_does_not_confirm() -> None:
    g = _graph()
    fake = _FakeClient(
        {"propose": True, "command": "nmap -sV target.test", "rationale": "fingerprint services"},
        confirm_status="inconclusive",
    )
    sandbox = _FakeSandbox(SandboxResult(command="nmap ...", exit_code=0, output="22/tcp open ssh"))
    written = run_sandbox_investigation(
        vuln_class="ssrf", graph=g, sandbox=sandbox, target="http://target.test", client=fake
    )
    assert written == 0
    assert len(list(g.findings())) == 0


def test_investigation_emits_a_raw_command_output_event_even_when_not_confirmed() -> None:
    """v4 R3c: the Sandbox tab needs the raw command/output regardless of
    verdict -- not just the "confirmed" event, which only fires on a hit."""
    g = _graph()
    fake = _FakeClient(
        {"propose": True, "command": "nmap -sV target.test", "rationale": "fingerprint services"},
        confirm_status="inconclusive",
    )
    sandbox = _FakeSandbox(SandboxResult(command="nmap ...", exit_code=0, output="22/tcp open ssh"))
    events: list = []
    run_sandbox_investigation(
        vuln_class="ssrf",
        graph=g,
        sandbox=sandbox,
        target="http://target.test",
        client=fake,
        events=events,
        label="auth",
    )
    assert len(events) == 1
    event = events[0]
    assert event.message.startswith("[auth] sandbox: $ ")
    assert event.details["command"] == "nmap -sV target.test"
    assert event.details["output"] == "22/tcp open ssh"
    assert event.details["label"] == "auth"


def test_investigation_confirmed_event_also_carries_the_label() -> None:
    g = _graph()
    fake = _FakeClient(
        {
            "propose": True,
            "command": "sqlmap -u http://target.test/api/users?id=1 --batch",
            "rationale": "test the id parameter for blind sqli",
        }
    )
    sandbox = _FakeSandbox(
        SandboxResult(
            command="sqlmap ...",
            exit_code=0,
            output="[CRITICAL] the back-end DBMS is MySQL, parameter 'id' is vulnerable",
        )
    )
    events: list = []
    run_sandbox_investigation(
        vuln_class="sqli",
        graph=g,
        sandbox=sandbox,
        target="http://target.test",
        client=fake,
        events=events,
        label="injection",
    )
    # one raw command/output event, one confirmed-finding event
    assert len(events) == 2
    confirmed = events[1]
    assert confirmed.message.startswith("[injection] sandbox investigation confirmed:")
    assert confirmed.details["label"] == "injection"


def test_investigation_declined_never_runs_a_command() -> None:
    g = _graph()
    fake = _FakeClient({"propose": False, "command": "", "rationale": "nothing to add"})
    sandbox = _FakeSandbox(SandboxResult(command="", exit_code=0, output=""))
    written = run_sandbox_investigation(
        vuln_class="clickjacking",
        graph=g,
        sandbox=sandbox,
        target="http://target.test",
        client=fake,
    )
    assert written == 0
    assert sandbox.commands == []


def test_investigation_empty_output_never_reaches_the_judge() -> None:
    g = _graph()
    fake = _FakeClient(
        {
            "propose": True,
            "command": "curl -s http://target.test/robots.txt",
            "rationale": "check robots",
        }
    )
    sandbox = _FakeSandbox(SandboxResult(command="curl ...", exit_code=0, output="   "))
    written = run_sandbox_investigation(
        vuln_class="path_traversal",
        graph=g,
        sandbox=sandbox,
        target="http://target.test",
        client=fake,
    )
    assert written == 0
    assert fake.confirm_prompts == []


def test_investigation_sandbox_error_never_crashes() -> None:
    g = _graph()
    fake = _FakeClient(
        {
            "propose": True,
            "command": "ffuf -u http://target.test/FUZZ",
            "rationale": "content discovery",
        }
    )

    class _BrokenSandbox:
        def run_command(self, command: str, *, timeout: float = 60.0) -> SandboxResult:
            raise RuntimeError("docker exec failed")

    written = run_sandbox_investigation(
        vuln_class="idor",
        graph=g,
        sandbox=_BrokenSandbox(),
        target="http://target.test",
        client=fake,
    )
    assert written == 0


def test_investigation_confirm_client_error_never_crashes() -> None:
    g = _graph()

    @dataclass
    class _Boom:
        def propose_json(self, prompt: str, *, max_tokens: int = 800) -> dict:
            if "Mechanism family:" in prompt:
                raise RuntimeError("provider timeout")
            return {"propose": True, "command": "nmap target.test", "rationale": "probe"}

    sandbox = _FakeSandbox(SandboxResult(command="nmap ...", exit_code=0, output="some output"))
    written = run_sandbox_investigation(
        vuln_class="ssti", graph=g, sandbox=sandbox, target="http://target.test", client=_Boom()
    )
    assert written == 0
