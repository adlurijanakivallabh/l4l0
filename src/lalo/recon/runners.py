"""Recon tool runners.

Each runner builds a tool command and parses its (JSON-lines) output into typed
:class:`ReconFact` objects. Parsers are pure and unit-tested against canned tool
output; ``run`` is a no-op when the tool's binary is absent.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field

from .executor import Executor


@dataclass
class ReconFact:
    kind: str  # endpoint | host | subdomain | service | fingerprint
    value: str
    metadata: dict[str, object] = field(default_factory=dict)


def _jsonl(stdout: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


@dataclass
class ReconRunner:
    name: str
    binary: str
    build: Callable[[str], list[str]]
    parse: Callable[[str], list[ReconFact]]

    def run(self, target: str, executor: Executor) -> list[ReconFact]:
        if not executor.has_binary(self.binary):
            return []
        output = executor.run(self.build(target))
        return self.parse(output.stdout)


# --- parsers (pure) --------------------------------------------------------
def _parse_httpx(stdout: str) -> list[ReconFact]:
    facts: list[ReconFact] = []
    for row in _jsonl(stdout):
        url = row.get("url") or row.get("input")
        if isinstance(url, str):
            facts.append(ReconFact("endpoint", url, {"status": row.get("status_code")}))
        tech = row.get("tech")
        if isinstance(tech, list):
            for item in tech:
                facts.append(ReconFact("fingerprint", str(item), {"source": "httpx"}))
    return facts


def _parse_subfinder(stdout: str) -> list[ReconFact]:
    facts: list[ReconFact] = []
    for row in _jsonl(stdout):
        host = row.get("host")
        if isinstance(host, str):
            facts.append(ReconFact("subdomain", host, {"source": row.get("source")}))
    return facts


def _parse_naabu(stdout: str) -> list[ReconFact]:
    facts: list[ReconFact] = []
    for row in _jsonl(stdout):
        host = row.get("host") or row.get("ip")
        port = row.get("port")
        if isinstance(host, str) and isinstance(port, int):
            facts.append(ReconFact("service", f"{host}:{port}", {"host": host, "port": port}))
    return facts


def _parse_katana(stdout: str) -> list[ReconFact]:
    facts: list[ReconFact] = []
    for row in _jsonl(stdout):
        request = row.get("request")
        endpoint = None
        if isinstance(request, dict):
            endpoint = request.get("endpoint") or request.get("url")
        endpoint = endpoint or row.get("endpoint")
        if isinstance(endpoint, str):
            facts.append(ReconFact("endpoint", endpoint, {"source": "katana"}))
    return facts


def _parse_nuclei(stdout: str) -> list[ReconFact]:
    facts: list[ReconFact] = []
    for row in _jsonl(stdout):
        template = row.get("template-id") or row.get("templateID")
        matched = row.get("matched-at") or row.get("host")
        if isinstance(template, str) and isinstance(matched, str):
            info = row.get("info") if isinstance(row.get("info"), dict) else {}
            severity = info.get("severity") if isinstance(info, dict) else None
            facts.append(ReconFact("fingerprint", f"{template}@{matched}", {"severity": severity}))
    return facts


DEFAULT_RUNNERS: list[ReconRunner] = [
    ReconRunner("httpx", "httpx", lambda t: ["httpx", "-json", "-silent", "-u", t], _parse_httpx),
    ReconRunner(
        "subfinder",
        "subfinder",
        lambda t: ["subfinder", "-silent", "-json", "-d", t],
        _parse_subfinder,
    ),
    ReconRunner(
        "naabu", "naabu", lambda t: ["naabu", "-json", "-silent", "-host", t], _parse_naabu
    ),
    ReconRunner(
        "katana", "katana", lambda t: ["katana", "-jsonl", "-silent", "-u", t], _parse_katana
    ),
    ReconRunner(
        "nuclei", "nuclei", lambda t: ["nuclei", "-jsonl", "-silent", "-u", t], _parse_nuclei
    ),
]
