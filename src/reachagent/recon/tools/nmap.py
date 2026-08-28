"""nmap recon wrapper — network/service facts from ``-oX`` XML (§9 recon tier).

Parses nmap's ``-oX`` XML into transport-tier facts: one ``Host`` per ``<host>``
(address + optional OS/product as ``technology``) and one ``Service`` per open
``<port>`` (port, protocol, service name, product/version banner), attached by a
``runs_service`` edge. Facts only — nmap never emits a candidate or a ``Finding``;
its version/CVE claims are *not* ingested here (those would be a signal-gated
concern, Big Task 2), only the network/service facts.

XML, not greppable stdout, is parsed because ``-oX`` is nmap's stable
machine-readable contract. Parsing uses the stdlib ``defusedxml`` guard — an
nmap XML file is attacker-influenceable output (hostnames, banners), so entity
expansion / external-entity attacks are refused rather than trusted.
"""

from __future__ import annotations

from xml.etree.ElementTree import Element  # noqa: S405 — parsed via defusedxml below

from defusedxml.ElementTree import fromstring

from reachagent.graph.nodes import Host, Service
from reachagent.recon.tools.base import ReconToolRunner


class NmapRunner(ReconToolRunner):
    """Emit ``Host``/``Service`` transport-tier facts from nmap ``-oX`` XML (§9)."""

    name = "nmap"
    binary = "nmap"

    def command(self, target: str) -> list[str]:
        """``nmap -oX - -sV <target>`` [+ ``-T``/``--top-ports``]."""
        import os

        argv: list[str] = ["nmap", "-n", "-Pn", "--open", "-oX", "-", "-sV"]
        timing = os.environ.get("REACHAGENT_NMAP_TIMING")
        if timing in ("0", "1", "2", "3", "4", "5"):
            argv += ["-T", timing]
        top = os.environ.get("REACHAGENT_NMAP_TOP_PORTS")
        if top and top.isdigit():
            argv += ["--top-ports", top]
        retries = os.environ.get("REACHAGENT_NMAP_MAX_RETRIES")
        if retries and retries.isdigit():
            argv += ["--max-retries", retries]
        host_timeout = os.environ.get("REACHAGENT_NMAP_HOST_TIMEOUT")
        if host_timeout and host_timeout.isdigit():
            argv += ["--host-timeout", f"{host_timeout}s"]
        argv.append(target)
        return argv

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse ``-oX`` XML into ``Host`` + ``Service`` nodes and ``runs_service`` edges."""
        written: list[str] = []
        root = fromstring(raw_output)
        for host_el in root.findall("host"):
            address = _host_address(host_el)
            if address is None:
                continue  # a host with no address is not a fact we can key on
            hostname = _first_hostname(host_el)
            technology, version = _os_fingerprint(host_el)
            host_node = self.graph.add_host(
                Host(
                    address=address,
                    hostname=hostname,
                    source=self.name,
                    technology=technology,
                    detected_version=version,
                )
            )
            written.append(host_node)
            for port_el in host_el.findall("./ports/port"):
                if not _port_is_open(port_el):
                    continue
                service_node = self.graph.add_service(host_node, _service_from_port(port_el))
                written.append(service_node)
        return tuple(written)


def _host_address(host_el: Element) -> str | None:
    """The host's addr — prefer IPv4/IPv6 ``address``, else the first PTR hostname."""
    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") in ("ipv4", "ipv6"):
            addr = addr_el.get("addr")
            if addr:
                return addr
    return _first_hostname(host_el)


def _first_hostname(host_el: Element) -> str | None:
    """The first ``<hostname name=...>`` for the host, or ``None``."""
    for hn in host_el.findall("./hostnames/hostname"):
        name = hn.get("name")
        if name:
            return name
    return None


def _os_fingerprint(host_el: Element) -> tuple[str | None, str | None]:
    """Best-effort OS name / version from an ``<osmatch>``, as Host attributes.

    A detected OS/stack is an *attribute* on the host (§6/§9), never a Technology
    node. Absent osmatch → ``(None, None)`` — a legitimate "not fingerprinted".
    """
    osmatch = host_el.find("./os/osmatch")
    if osmatch is None:
        return None, None
    return osmatch.get("name"), osmatch.get("accuracy")


def _port_is_open(port_el: Element) -> bool:
    """Only *open* ports are facts worth a Service node (closed/filtered are not)."""
    state = port_el.find("state")
    return state is not None and state.get("state") == "open"


def _service_from_port(port_el: Element) -> Service:
    """Build a ``Service`` from an nmap ``<port>`` — port/proto + service/version banner."""
    service_el = port_el.find("service")
    service_name = service_el.get("name") if service_el is not None else None
    product = service_el.get("product") if service_el is not None else None
    version = service_el.get("version") if service_el is not None else None
    banner = " ".join(p for p in (product, version) if p) or None
    return Service(
        port=int(port_el.get("portid", "0")),
        protocol=port_el.get("protocol", "tcp"),
        service_name=service_name,
        banner=banner,
        detected_version=version,
        source="nmap",
    )
