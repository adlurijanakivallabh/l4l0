"""Tests for the nmap ReconRunner: scope-gated before any packet, real XML parsing."""

from __future__ import annotations

from dataclasses import dataclass

from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement
from lalo.recon.facts import FactKind
from lalo.recon.scan import NmapServiceScanRunner

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


def test_run_returns_empty_when_the_container_exec_fails() -> None:
    container = _FakeContainer(exec_ok=False)
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1")
    assert runner.run() == []


def test_run_returns_empty_on_malformed_xml_never_crashes() -> None:
    container = _FakeContainer(stdout="not xml at all <<<")
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1")
    assert runner.run() == []


def test_run_shell_quotes_the_host_and_port_range() -> None:
    container = _FakeContainer()
    runner = NmapServiceScanRunner(container, _scope(), host="127.0.0.1", ports="1-100")
    runner.run()
    assert container.commands is not None
    assert "127.0.0.1" in container.commands[0]
    assert "1-100" in container.commands[0]
