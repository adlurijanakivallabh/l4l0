"""masscan recon wrapper — open ports as Host/Service facts (§9 recon tier).

masscan emits either greppable lines "Discovered open port 80/tcp on 1.2.3.4" or
-oX XML similar to nmap. Both shapes are handled. Per §6/§9 each open port is a
Service + runs_service edge on a Host. Facts only.
"""

from __future__ import annotations

import re

from defusedxml.ElementTree import fromstring

from reachagent.graph.nodes import Host, Service
from reachagent.recon.tools.base import ReconToolRunner

_DISCOVERED_RE = re.compile(
    r"Discovered\s+open\s+port\s+(?P<port>\d+)/(?P<proto>\w+)\s+on\s+(?P<host>\S+)",
    re.IGNORECASE,
)


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


class MasscanRunner(ReconToolRunner):
    """Emit Host/Service + runs_service from masscan output (§9). Facts only."""

    name = "masscan"
    binary = "masscan"

    def command(self, target: str) -> list[str]:
        """masscan <target> -p1-65535 --rate N -oX - — XML to stdout."""
        import os

        rate_raw = os.environ.get("REACHAGENT_MASSCAN_RATE", "1000")
        try:
            rate = max(100, min(10000, int(rate_raw)))
        except ValueError:
            rate = 1000
        return ["masscan", target, "-p1-65535", "--rate", str(rate), "-oX", "-"]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse masscan greppable or XML output into Host/Service facts."""
        text = raw_output.strip()
        if not text:
            return ()
        # Prefer XML path when output looks like XML (mirrors nmap.py)
        if text.lstrip().startswith("<?xml") or "<nmaprun" in text or "<masscan" in text:
            return self._parse_xml(target, raw_output)
        return self._parse_grep(target, raw_output)

    def _parse_grep(self, target: str, raw_output: str) -> tuple[str, ...]:
        written: list[str] = []
        seen: set[tuple[str, int, str]] = set()
        host_nodes: dict[str, str] = {}
        for line in raw_output.splitlines():
            match = _DISCOVERED_RE.search(line)
            if match is None:
                continue
            host_addr = match.group("host")
            port = int(match.group("port"))
            proto = match.group("proto").lower()
            key = (host_addr, port, proto)
            if key in seen:
                continue
            seen.add(key)
            host_node = host_nodes.get(host_addr)
            if host_node is None:
                host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
                host_nodes[host_addr] = host_node
                written.append(host_node)
            service_node = self.graph.add_service(
                host_node,
                Service(port=port, protocol=proto, source=self.name),
            )
            written.append(service_node)
        return tuple(written)

    def _parse_xml(self, target: str, raw_output: str) -> tuple[str, ...]:
        written: list[str] = []
        host_nodes: dict[str, str] = {}
        seen: set[tuple[str, int, str]] = set()
        try:
            root = fromstring(raw_output)
        except Exception:  # noqa: BLE001
            return self._parse_grep(target, raw_output)
        for host_el in root.findall("host"):
            address = None
            for addr_el in host_el.findall("address"):
                addr = addr_el.get("addr")
                if addr:
                    address = addr
                    break
            if address is None:
                # masscan XML may use <address addr="...">
                address = _host_of(target)
            for port_el in host_el.findall("./ports/port"):
                state = port_el.find("state")
                if state is not None and state.get("state") not in (None, "open"):
                    continue
                port_str = port_el.get("portid")
                if port_str is None:
                    continue
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                proto = (port_el.get("protocol") or "tcp").lower()
                key = (address, port, proto)
                if key in seen:
                    continue
                seen.add(key)
                host_node = host_nodes.get(address)
                if host_node is None:
                    host_node = self.graph.add_host(Host(address=address, source=self.name))
                    host_nodes[address] = host_node
                    written.append(host_node)
                service_el = port_el.find("service")
                service_name = service_el.get("name") if service_el is not None else None
                service_node = self.graph.add_service(
                    host_node,
                    Service(port=port, protocol=proto, service_name=service_name, source=self.name),
                )
                written.append(service_node)
        return tuple(written)
