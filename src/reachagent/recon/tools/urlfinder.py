"""Passive URLFinder wrapper — source-attributed URLs become graph facts."""

from __future__ import annotations

import json
import os

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools._net import host_of, path_of
from reachagent.recon.tools.base import ReconToolRunner, _scope_url


class UrlfinderRunner(ReconToolRunner):
    """Parse URLFinder JSONL (or plain URL fallback) into Host/Endpoint facts."""

    name = "urlfinder"
    binary = "urlfinder"

    def command(self, target: str) -> list[str]:
        argv = ["urlfinder", "-d", host_of(target), "-j", "-silent"]
        if os.environ.get("REACHAGENT_URLFINDER_ALL", "").lower() in {"1", "true", "yes"}:
            argv.append("-all")
        for env_name, flag in (
            ("REACHAGENT_URLFINDER_RATE", "-rl"),
            ("REACHAGENT_URLFINDER_TIMEOUT", "-timeout"),
            ("REACHAGENT_URLFINDER_MAX_TIME", "-max-time"),
        ):
            value = os.environ.get(env_name)
            if value and value.isdigit():
                argv.extend([flag, value])
        return argv

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        written: list[str] = []
        seen: set[tuple[str, str]] = set()
        hosts: dict[str, str] = {}
        for line in raw_output.splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            url = ""
            source = ""
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                item = None
            if isinstance(item, dict):
                url = str(item.get("url") or item.get("endpoint") or "").strip()
                source = str(item.get("source") or "").strip()
            elif raw.startswith(("http://", "https://")):
                url = raw.split()[0]
            if not url.startswith(("http://", "https://")):
                continue
            if not self.scope.is_in_scope(_scope_url(url)):
                self.audit.record(self.name, "RECON", url, "refused_out_of_scope")
                continue
            host = host_of(url)
            path = path_of(url)
            key = (host, path)
            if key in seen:
                continue
            seen.add(key)
            host_node = hosts.get(host)
            if host_node is None:
                host_node = self.graph.add_host(
                    Host(
                        address=host,
                        hostname=host,
                        source=self.name,
                        technology=f"url-source:{source}" if source else None,
                    )
                )
                hosts[host] = host_node
                written.append(host_node)
            endpoint_node = self.graph.add_endpoint(Endpoint(method="GET", path=path))
            self.graph.add_resolves_to(host_node, endpoint_node)
            written.append(endpoint_node)
        return tuple(written)


__all__ = ["UrlfinderRunner"]
