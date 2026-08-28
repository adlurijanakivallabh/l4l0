"""BBOT event-stream wrapper — scoped DNS, port, and URL facts only."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from reachagent.graph.nodes import Endpoint, Host, Service
from reachagent.recon.tools._net import host_of, path_of
from reachagent.recon.tools.base import ReconToolRunner, _scope_url

_PORT = re.compile(r"^(?P<host>[^:]+):(?P<port>[0-9]{1,5})$")


class BbotRunner(ReconToolRunner):
    """Parse BBOT JSON events into existing transport-tier graph nodes."""

    name = "bbot"
    binary = "bbot"

    def command(self, target: str) -> list[str]:
        modules = os.environ.get("REACHAGENT_BBOT_MODULES", "subdomain-enum,sslcert,http")
        allowed = {"subdomain-enum", "sslcert", "http", "portscan"}
        selected = [part.strip() for part in modules.split(",") if part.strip() in allowed]
        argv = ["bbot", "-t", host_of(target), "-om", "json"]
        if selected:
            argv.extend(["-m", *selected])
        rate = os.environ.get("REACHAGENT_BBOT_RATE")
        if rate and rate.isdigit():
            argv.extend(["--rate-limit", rate])
        return argv

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        written: list[str] = []
        host_nodes: dict[str, str] = {}
        service_seen: set[tuple[str, int]] = set()
        endpoint_seen: set[tuple[str, str]] = set()
        for line in raw_output.splitlines():
            raw = line.strip()
            if not raw:
                continue
            try:
                event: Any = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            event_type = str(event.get("type") or "").upper()
            data = (
                event.get("data_json")
                if isinstance(event.get("data_json"), dict)
                else event.get("data")
            )
            value = str(data or "").strip()
            if event_type in {"URL", "HTTP_RESPONSE"} or value.startswith(("http://", "https://")):
                url = value
                if event_type in {"URL", "HTTP_RESPONSE"} and isinstance(data, dict):
                    url = str(data.get("url") or data.get("host") or "")
                if not url.startswith(("http://", "https://")):
                    continue
                if not self.scope.is_in_scope(_scope_url(url)):
                    self.audit.record(self.name, "RECON", url, "refused_out_of_scope")
                    continue
                host = host_of(url)
                path = path_of(url)
                key = (host, path)
                if key in endpoint_seen:
                    continue
                endpoint_seen.add(key)
                host_node = host_nodes.get(host)
                if host_node is None:
                    host_node = self.graph.add_host(
                        Host(address=host, hostname=host, source=self.name)
                    )
                    host_nodes[host] = host_node
                    written.append(host_node)
                endpoint_node = self.graph.add_endpoint(Endpoint(method="GET", path=path))
                self.graph.add_resolves_to(host_node, endpoint_node)
                written.append(endpoint_node)
                continue
            if event_type in {"DNS_NAME", "HOSTNAME", "DOMAIN", "IP_ADDRESS", "OPEN_TCP_PORT"}:
                candidate = value
                port = None
                if isinstance(data, dict):
                    candidate = str(
                        data.get("host")
                        or data.get("hostname")
                        or data.get("address")
                        or data.get("ip")
                        or data.get("data")
                        or ""
                    ).strip()
                    raw_port = data.get("port")
                    if isinstance(raw_port, int) and 1 <= raw_port <= 65535:
                        port = raw_port
                match = _PORT.match(candidate)
                if match:
                    candidate = match.group("host")
                    port = int(match.group("port"))
                if not candidate or not self.scope.is_in_scope(_scope_url(candidate)):
                    if candidate:
                        self.audit.record(self.name, "RECON", candidate, "refused_out_of_scope")
                    continue
                host_node = host_nodes.get(candidate)
                if host_node is None:
                    host_node = self.graph.add_host(
                        Host(address=candidate, hostname=candidate, source=self.name)
                    )
                    host_nodes[candidate] = host_node
                    written.append(host_node)
                if port is not None and (candidate, port) not in service_seen:
                    service_seen.add((candidate, port))
                    written.append(
                        self.graph.add_service(
                            host_node,
                            Service(port=port, protocol="tcp", source=self.name),
                        )
                    )
        return tuple(written)


__all__ = ["BbotRunner"]
