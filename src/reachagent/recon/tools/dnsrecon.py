"""Structured DNSRecon wrapper — DNS records become scoped Host facts."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from reachagent.graph.nodes import Host
from reachagent.recon.tools.base import ReconToolRunner, _scope_url


class DnsreconRunner(ReconToolRunner):
    """Parse DNSRecon JSON records without treating DNS output as a finding."""

    name = "dnsrecon"
    binary = "dnsrecon"

    def command(self, target: str) -> list[str]:
        fd, path = tempfile.mkstemp(suffix=".json", prefix="dnsrecon-")  # noqa: S108
        os.close(fd)
        return ["dnsrecon", "-d", target, "-t", "std", "-j", path]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        try:
            parsed: Any = json.loads(raw_output)
        except json.JSONDecodeError:
            return ()
        if isinstance(parsed, dict):
            records = parsed.get("records") or parsed.get("data") or parsed.get("results") or []
        else:
            records = parsed
        if not isinstance(records, list):
            return ()

        written: list[str] = []
        seen: set[tuple[str, str, str]] = set()
        for record in records:
            if not isinstance(record, dict):
                continue
            name = (
                str(
                    record.get("name")
                    or record.get("host")
                    or record.get("hostname")
                    or record.get("domain")
                    or ""
                )
                .strip()
                .rstrip(".")
            )
            if not name or not self.scope.is_in_scope(_scope_url(name)):
                if name:
                    self.audit.record(self.name, "RECON", name, "refused_out_of_scope")
                continue
            record_type = str(record.get("type") or record.get("rrtype") or "dns").lower()
            value = (
                str(
                    record.get("address")
                    or record.get("target")
                    or record.get("exchange")
                    or record.get("value")
                    or name
                )
                .strip()
                .rstrip(".")
            )
            key = (name, record_type, value)
            if key in seen:
                continue
            seen.add(key)
            address = value if record_type in {"a", "aaaa"} else name
            host_node = self.graph.add_host(
                Host(
                    address=address,
                    hostname=name,
                    source=self.name,
                    technology=f"dns:{record_type}",
                )
            )
            if host_node not in written:
                written.append(host_node)
        return tuple(written)


__all__ = ["DnsreconRunner"]
