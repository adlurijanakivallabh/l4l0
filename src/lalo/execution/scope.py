"""ScopeGuard — the firer's engagement + safety check, enforced before any I/O.

Read a reference recon tool's actual SSRF-guard source in full before building
this (not just its comparison notes): its guard resolves a host's DNS exactly
once and *pins* the resulting IP so the caller dials that literal address —
this is what actually defeats DNS rebinding (a naive "check the hostname, then
let the HTTP client resolve it again to fire" design has a real TOCTOU gap
between the check and the connect, which this module closes via
:meth:`pin_for_connect`, used by the firer to build the literal request).

Deliberately diverges from that reference on policy, not mechanism: it default-
denies private/loopback/link-local ranges (a general "fetch any public URL"
tool's correct default) with an opt-in override for authorized internal use.
L4L0's `http` tool exists specifically to test the operator's declared
engagement, which is routinely local/internal by nature (a lab container, an
internal corporate host) — blanket-denying private ranges would break the
tool's actual purpose. The engagement allowlist is the sole scope authority;
only cloud metadata and non-http(s) schemes stay denied unconditionally,
mirroring that reference's own "blocked regardless of the internal-allow
override" treatment of metadata specifically.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlsplit

from ..core.errors import TargetOutOfScopeError
from .target import Engagement, Resolver, default_resolver

# Link-local / cloud-metadata ranges denied unconditionally (never a legitimate
# direct target in any web/API engagement — a target's own SSRF reaching these
# is a finding to prove, not something L4L0's own firer should dial directly).
_METADATA_NETS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),  # AWS/GCP/Azure IMDS + link-local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IMDSv2 IPv6
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata
)

# Well-known metadata hostnames, denied by name regardless of what they resolve
# to (a name can point anywhere; block the well-known ones outright).
_METADATA_HOSTS: frozenset[str] = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "metadata.azure.com",
        "metadata.oraclecloud.com",
        "instance-data",
        "instance-data.ec2.internal",
    }
)

# The `http` tool only ever needs to speak these — a non-http(s) scheme (file://,
# gopher://, ...) is never a legitimate target regardless of engagement.
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# Non-HTTP tools that still route through this same check() reuse a scheme
# tag purely to name what kind of probe this is for check()'s own logging
# and for TargetRule.matches()'s scheme-restriction comparison (an operator
# scoping "https://app.example.com" only, not "app.example.com" bare, means
# these should also be excluded) — never scheme-restricted the way the HTTP
# firer is.
_SCHEME_NEUTRAL_CHECKS: frozenset[str] = frozenset({"tcp", "dns"})

# A URL with no explicit port relies on the scheme's well-known default; a
# port-restricted engagement rule has to be checked against THAT port, not
# against None (which TargetRule.matches() treats as "this rule doesn't
# restrict by port at all" — the same sentinel, silently conflated).
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


class Decision(StrEnum):
    ALLOWED = "allowed"
    SKIPPED = "skipped_out_of_engagement"
    DENIED = "denied"


@dataclass(frozen=True)
class ScopeDecision:
    decision: Decision
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOWED


def _in_metadata_range(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _METADATA_NETS)


@dataclass
class ScopeGuard:
    engagement: Engagement
    egress_lock: bool = False
    deny_metadata: bool = True
    resolver: Resolver = default_resolver
    _resolved: dict[str, frozenset[str]] = field(default_factory=dict, repr=False, compare=False)
    # Guards the check-then-set below - one ScopeGuard instance is shared for
    # the whole scan, and fire_concurrent/spawn_agents can have several
    # threads resolving the SAME host at once. An audit found this
    # unsynchronized: two concurrent misses for one host each call
    # self.resolver(host) and the LAST writer wins, so a rebinding DNS
    # answer could let one thread's check() validate a benign IP while a
    # racing thread's resolution (now the cached value) is what
    # pin_for_connect() actually dials - reopening exactly the TOCTOU this
    # cache exists to close.
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def resolve_and_pin(self, host: str) -> frozenset[str]:
        """Resolve ``host`` once and cache; reused for both the check and the
        actual connection (see :meth:`pin_for_connect`) — this identity is what
        defeats DNS rebinding, not the resolution itself."""
        with self._lock:
            if host not in self._resolved:
                self._resolved[host] = self.resolver(host)
            return self._resolved[host]

    def pin_for_connect(self, host: str) -> str | None:
        """Return the literal IP the firer must dial for ``host``.

        A literal IP host is returned as-is. An FQDN is resolved via the SAME
        cached lookup :meth:`resolve_and_pin` uses for the scope check — the
        firer dialing this exact value (not re-resolving the hostname itself)
        is the actual DNS-rebinding defense.
        """
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        ips = self.resolve_and_pin(host)
        return next(iter(ips), None)

    def _hits_metadata(self, host: str | None) -> bool:
        if not host:
            return False
        if host.lower() in _METADATA_HOSTS:
            return True
        if _in_metadata_range(host):  # literal IP
            return True
        return any(_in_metadata_range(ip) for ip in self.resolve_and_pin(host))

    def check(self, url: str) -> ScopeDecision:
        parts = urlsplit(url)
        host = parts.hostname
        scheme = (parts.scheme or "").lower()
        if scheme and scheme not in _ALLOWED_SCHEMES and parts.scheme:
            if scheme not in _SCHEME_NEUTRAL_CHECKS:
                return ScopeDecision(Decision.DENIED, "scheme_not_allowed")
        try:
            explicit_port = parts.port  # lazily parsed; raises ValueError if non-numeric
        except ValueError:
            return ScopeDecision(Decision.DENIED, "malformed_port")
        # A request with no explicit port dials the scheme's default (httpx's
        # own behavior), so the scope check must use that, not None, or a
        # port-restricted rule is silently bypassed by simply omitting the port.
        effective_port = explicit_port if explicit_port is not None else _DEFAULT_PORTS.get(scheme)
        if self.deny_metadata and self._hits_metadata(host):
            return ScopeDecision(Decision.DENIED, "cloud_metadata_denied")
        if self.engagement.in_engagement(host, effective_port, parts.scheme, parts.path):
            return ScopeDecision(Decision.ALLOWED, "in_engagement")
        if self.egress_lock:
            return ScopeDecision(Decision.DENIED, "egress_lock_out_of_engagement")
        return ScopeDecision(Decision.SKIPPED, "out_of_engagement")

    def enforce(self, url: str) -> ScopeDecision:
        decision = self.check(url)
        if decision.decision is Decision.DENIED:
            raise TargetOutOfScopeError(decision.reason, code="scope_violation")
        return decision
