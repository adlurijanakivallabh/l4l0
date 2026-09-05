"""ScopeGuard — the structured firers' engagement check.

Decisions:
- **ALLOWED**: host is in the declared engagement (and not a metadata endpoint).
- **SKIPPED**: out of engagement, egress lock off — the firer does not fire (so
  L4L0 stays on the operator's engagement) but the run continues.
- **DENIED**: a cloud-metadata endpoint, or out of engagement with the optional
  egress lock on. ``enforce`` raises for DENIED.

DNS is resolved once and pinned per host so the metadata check and the eventual
connection agree.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

from ..core.errors import TargetOutOfScopeError
from .target import Engagement, Resolver, _default_resolver

# Link-local / cloud-metadata ranges denied by default.
_METADATA_NETS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),  # AWS/GCP/Azure IMDS + link-local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IMDSv2 IPv6
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata
)

# Cloud-metadata *hostnames* denied by default (a rebinding-safe complement to the
# IP ranges — a name can point anywhere, so block the well-known ones outright).
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


class Decision(Enum):
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
    resolver: Resolver = _default_resolver
    _resolved: dict[str, frozenset[str]] = field(default_factory=dict, repr=False)

    def resolve_and_pin(self, host: str) -> frozenset[str]:
        """Resolve ``host`` once and cache; reuse for both the check and the connection."""
        if host not in self._resolved:
            self._resolved[host] = self.resolver(host)
        return self._resolved[host]

    def _hits_metadata(self, host: str | None) -> bool:
        if not host:
            return False
        if host.lower() in _METADATA_HOSTS:  # well-known metadata hostname
            return True
        if _in_metadata_range(host):  # literal IP
            return True
        return any(_in_metadata_range(ip) for ip in self.resolve_and_pin(host))

    def check(self, url: str) -> ScopeDecision:
        parts = urlsplit(url)
        host = parts.hostname
        if self.deny_metadata and self._hits_metadata(host):
            return ScopeDecision(Decision.DENIED, "cloud_metadata_denied")
        if self.engagement.in_engagement(host, parts.port, parts.scheme):
            return ScopeDecision(Decision.ALLOWED, "in_engagement")
        if self.egress_lock:
            return ScopeDecision(Decision.DENIED, "egress_lock_out_of_engagement")
        return ScopeDecision(Decision.SKIPPED, "out_of_engagement")

    def enforce(self, url: str) -> ScopeDecision:
        decision = self.check(url)
        if decision.decision is Decision.DENIED:
            raise TargetOutOfScopeError(decision.reason, code="scope_violation")
        return decision
