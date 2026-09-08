"""A concrete :class:`~lalo.recon.runner.ReconRunner`: nmap service/version scan.

Phase 9's plan named a tool-runner framework wrapping best-in-class external
tools, and :mod:`lalo.recon.runner` built the availability-gated chain
orchestrator for it — but no phase ever actually implemented one, leaving
:func:`~lalo.recon.runner.run_recon_chain` with nothing to run. This is the
first one, informed by one studied reference agent's own sandboxed recon
roster (nmap as the curated port/service-discovery tool) and another's
raw-engine-vs-orchestrator split already adopted in ``runner.py`` — the
runner here is the "raw engine" half, a thin adapter around one external
command, never a policy decision
point itself.

Runs inside the disposable runtime container (via the same
:class:`~lalo.runtime.tool.CommandExecutor` seam ``run_command`` uses), never
on the host — network scanning is exactly the kind of workload the container
boundary exists for. Scope is checked at the HOST level before a single
packet is sent (:meth:`is_available` refuses an out-of-engagement host
outright, mirroring the ``http`` tool's "check before any I/O" principle);
each individual open port :func:`~lalo.recon.facts.merge_facts` later
receives is still independently scope-checked before landing on the graph,
exactly like every other recon fact — a host authorized only on one port
does not get that specific port's *fact* accepted just because the host
itself was in scope broadly enough to authorize the scan. Documented,
deliberate residual gap: the scan itself (packets, not facts) is authorized
per-host, not per-port, since nmap has no notion of "which ports you're
allowed to even ask about" — a real, narrower per-port pre-authorization
would need new ``Engagement``/``TargetRule`` introspection API this module
does not add, rather than being silently assumed away.

nmap's own XML output (``-oX -``) is parsed with ``defusedxml`` — declared as
a project dependency specifically for XXE-safe XML parsing but, until this
module, never actually used anywhere.

``host``/``ports`` are validated against a strict allowlist, not just
``shlex.quote``-escaped, before ever reaching a command line.
``shlex.quote`` only defeats shell-metacharacter injection (breaking out of
the argument into a second shell command); it does nothing to stop a value
like ``"--script=vulners"`` — which contains no shell-special characters at
all, so ``shlex.quote`` returns it completely unchanged — from being parsed
by nmap ITSELF as a flag rather than a hostname, once it lands as a single
argv token. ``host``/``ports`` here trace back to the agent's own tool-call
arguments (:func:`~lalo.recon.tool.build_recon_tool`'s ``scan_ports``
action), so treating them as adversarial input at this boundary is the same
discipline :func:`~lalo.findings.model.validate_finding_fields` already
applies to every other agent-supplied field reaching a structured tool.

Fixed a real correctness bug an audit surfaced: ``_SAFE_HOST`` permits a
CIDR suffix, latent support for scanning a whole range in one call, but
:func:`_parse_nmap_xml` used to label every result across every ``<host>``
element nmap's XML returns with the single literal ``host`` string that was
passed in, never that specific ``<host>`` block's own resolved
``<address addr=...>`` — scanning a ``/24`` would have attributed every live
host's open ports to the same literal CIDR string, indistinguishable from
each other. Now reads the address per ``<host>`` block.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from defusedxml import ElementTree

from ..execution.scope import ScopeGuard
from ..runtime.tool import CommandExecutor
from .facts import FactKind, ReconFact

_DEFAULT_PORT_RANGE = "1-1000"
_SCAN_TIMEOUT_S = 180.0

# A hostname, IPv4/IPv6 literal, or CIDR block - never leading with "-" (which
# is what would let a value be parsed as an nmap flag rather than a target).
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]*(?:/[0-9]{1,3})?$")
# A port, comma list, or range ("80", "80,443", "1-1000") - same leading-"-"
# constraint.
_SAFE_PORTS = re.compile(r"^[0-9]+(?:[,-][0-9]+)*$")


class UnsafeNmapArgumentError(ValueError):
    """``host`` or ``ports`` doesn't match the safe positional-argument allowlist."""


def _parse_nmap_xml(xml_text: str, host: str) -> list[ReconFact]:
    """One :class:`ReconFact` per open TCP port, labeled with the address
    each ``<host>`` block actually resolved to - never the literal ``host``
    argument that was passed in. That distinction only matters once ``host``
    covers more than one live address (a CIDR block: ``_SAFE_HOST`` permits
    the ``/N`` suffix), where nmap's XML returns one ``<host>`` element per
    live address; using the invocation argument for every result would
    attribute every host's ports to the same literal string, indistinguishable
    from each other and not a real resolvable host for downstream scope-
    checking or reporting. Falls back to ``host`` only if a ``<host>`` block
    is missing its own ``<address>`` element, which real nmap output never
    does.
    """
    facts: list[ReconFact] = []
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return facts
    for host_el in root.findall(".//host"):
        address_el = host_el.find("address")
        resolved_host = address_el.get("addr") if address_el is not None else None
        target_host = resolved_host or host
        for port_el in host_el.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            port_id = port_el.get("portid")
            protocol = port_el.get("protocol", "tcp")
            if port_id is None or protocol != "tcp":
                continue
            service_el = port_el.find("service")
            extra: dict[str, object] = {}
            if service_el is not None:
                for attr in ("name", "product", "version"):
                    value = service_el.get(attr)
                    if value:
                        extra[attr] = value
            facts.append(
                ReconFact(
                    kind=FactKind.HOST,
                    url=f"tcp://{target_host}:{port_id}",
                    source="nmap",
                    extra=extra,
                )
            )
    return facts


@dataclass
class NmapServiceScanRunner:
    """One nmap service/version scan of ``host``'s ``ports`` range."""

    container: CommandExecutor
    scope: ScopeGuard
    host: str
    ports: str = _DEFAULT_PORT_RANGE
    name: str = "nmap"

    def _validate_arguments(self) -> None:
        if not _SAFE_HOST.match(self.host):
            raise UnsafeNmapArgumentError(f"host {self.host!r} is not a safe scan target")
        if not _SAFE_PORTS.match(self.ports):
            raise UnsafeNmapArgumentError(f"ports {self.ports!r} is not a safe port spec")

    def is_available(self) -> bool:
        # Argument-shape validation before anything else: a malformed value
        # is refused outright, never merely quoted-and-passed-through.
        self._validate_arguments()
        # Host-level scope check next: an out-of-engagement host never even
        # reaches the point of asking whether nmap is installed - refusing to
        # fire is a scope decision, not an availability one, but this is the
        # gate run_recon_chain actually calls before run(), so it belongs here.
        if not self.scope.check(f"tcp://{self.host}").allowed:
            return False
        result = self.container.exec("command -v nmap")
        return bool(getattr(result, "ok", False))

    def run(self) -> list[ReconFact]:
        # Re-validated here too (cheap, defense in depth): run() must never
        # trust that is_available() was actually called first.
        self._validate_arguments()
        command = f"nmap -sV -T4 -p {shlex.quote(self.ports)} -oX - {shlex.quote(self.host)}"
        result = self.container.exec(command, timeout=_SCAN_TIMEOUT_S)
        if not getattr(result, "ok", False):
            return []
        stdout = getattr(result, "stdout", "")
        return _parse_nmap_xml(stdout, self.host)
