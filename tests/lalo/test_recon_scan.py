"""Tests for the nmap ReconRunner: scope-gated before any packet, real XML parsing."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement
from lalo.recon.facts import FactKind
from lalo.recon.scan import (
    NmapExecutionError,
    NmapServiceScanRunner,
    UnsafeNmapArgumentError,
    _parse_nmap_xml,
)

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@dataclass
class _FakeResult:
    ok: bool
    stdout: str = ""


@dataclass
class _FakeContainer:
    which_ok: bool = True
    exec_ok: bool = True
    stdout: str = _NMAP_XML
    commands: list[str] | None = None

    def exec(self, command: str, *, timeout: float = 120.0) -> _FakeResult:
        if self.commands is None:
            self.commands = []
        self.commands.append(command)
        if command.startswith("command -v"):
            return _FakeResult(ok=self.which_ok)
        return _FakeResult(ok=self.exec_ok, stdout=self.stdout)


def _scope(*, egress_lock: bool = False) -> ScopeGuard:
    engagement = Engagement.from_specs(["127.0.0.1"])
    return ScopeGuard(engagement, egress_lock=egress_lock)


def test_is_available_false_for_an_out_of_engagement_host_before_touching_the_container() -> None:
    container = _FakeContainer()
    runner = NmapServiceScanRunner(container, _scope(), host="10.0.0.9")
    assert runner.is_available() is False
    assert container.commands is None  # never even checked for the nmap binary


def test_is_available_false_when_nmap_binary_is_missing() -> None:
    container = _FakeContainer(which_ok=False)
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1")
    assert runner.is_available() is False


def test_is_available_true_for_an_in_engagement_host_with_nmap_present() -> None:
    container = _FakeContainer()
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1")
    assert runner.is_available() is True


def test_run_parses_open_tcp_ports_only() -> None:
    container = _FakeContainer()
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1")
    facts = runner.run()
    urls = {f.url for f in facts}
    assert urls == {"tcp://127.0.0.1:80", "tcp://127.0.0.1:443"}
    assert all(f.kind is FactKind.HOST for f in facts)
    assert all(f.source == "nmap" for f in facts)


def test_run_captures_service_product_version_in_extra() -> None:
    container = _FakeContainer()
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1")
    facts = {f.url: f for f in runner.run()}
    http_fact = facts["tcp://127.0.0.1:80"]
    assert http_fact.extra == {"name": "http", "product": "nginx", "version": "1.18.0"}


def test_run_raises_when_the_container_exec_fails_never_returns_empty() -> None:
    """Regression: a failed nmap command used to return [] - indistinguishable
    from a genuine "scanned, zero open ports" result to both the agent and
    the operator, violating CLAUDE.md's own "honest coverage" principle.
    Raising lets run_recon_chain's own per-runner failure isolation record
    this distinctly in ChainReport.failed instead."""
    container = _FakeContainer(exec_ok=False)
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1")
    with pytest.raises(NmapExecutionError, match="127.0.0.1"):
        runner.run()


def test_run_raises_on_malformed_xml_never_returns_empty() -> None:
    container = _FakeContainer(stdout="not xml at all <<<")
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1")
    with pytest.raises(NmapExecutionError, match="did not parse"):
        runner.run()


def test_parse_nmap_xml_labels_each_host_with_its_own_resolved_address() -> None:
    """A real bug: a CIDR scan's XML has one <host> element per live address,
    but every result used to be labeled with the single literal host string
    passed to the scan (e.g. "10.0.0.0/24") instead of that host block's own
    resolved address - indistinguishable from every other host's ports."""
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
  </host>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
  </host>
</nmaprun>
"""
    facts = _parse_nmap_xml(xml, "10.0.0.0/24")
    urls = {f.url for f in facts}
    assert urls == {"tcp://10.0.0.5:22", "tcp://10.0.0.9:80"}


def test_parse_nmap_xml_falls_back_to_the_passed_in_host_with_no_address_element() -> None:
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
  </host>
</nmaprun>
"""
    facts = _parse_nmap_xml(xml, "127.0.0.1")
    assert {f.url for f in facts} == {"tcp://127.0.0.1:80"}


def test_run_shell_quotes_the_host_and_port_range() -> None:
    container = _FakeContainer()
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1", ports="1-100")
    runner.run()
    assert container.commands is not None
    assert "127.0.0.1" in container.commands[0]
    assert "1-100" in container.commands[0]


# --- argument injection: shlex.quote alone does not stop nmap flag smuggling -


def test_is_available_rejects_a_host_that_looks_like_an_nmap_flag() -> None:
    """shlex.quote leaves a value with no shell-special characters completely
    unchanged - "--script=vulners" passes through as a single, valid-looking
    argv token that nmap's OWN parser would read as a flag, not a target."""
    container = _FakeContainer()
    runner = NmapServiceScanRunner(container, _scope(), host="--script=vulners")
    with pytest.raises(UnsafeNmapArgumentError):
        runner.is_available()
    assert container.commands is None  # never even reached the container


def test_run_also_rejects_a_flag_shaped_host_even_called_directly() -> None:
    container = _FakeContainer()
    runner = NmapServiceScanRunner(container, _scope(), host="-oN/etc/cron.d/evil")
    with pytest.raises(UnsafeNmapArgumentError):
        runner.run()
    assert container.commands is None


def test_is_available_rejects_a_flag_shaped_ports_value() -> None:
    container = _FakeContainer()
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1", ports="--script=vulners")
    with pytest.raises(UnsafeNmapArgumentError):
        runner.is_available()


def test_is_available_accepts_a_legitimate_hyphenated_hostname() -> None:
    container = _FakeContainer()
    engagement = Engagement.from_specs(["staging-api.example.com"])
    scope = ScopeGuard(engagement)
    runner = NmapServiceScanRunner(container, scope, host="staging-api.example.com")
    assert runner.is_available() is True
