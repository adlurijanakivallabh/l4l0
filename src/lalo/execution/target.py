"""The declared-engagement target model.

An :class:`Engagement` is the set of hosts/ports/schemes the operator authorized.
This IS the scope authority for L4L0's firer — deliberately unlike a general-
purpose "fetch any URL" tool that default-denies private/loopback ranges and
requires an opt-in override for internal targets: L4L0's `http` tool exists
specifically to test the operator's OWN declared engagement, which is routinely
a local lab or an internal corporate host. Blanket-blocking private/loopback
ranges here would break the tool's actual purpose, so the engagement allowlist
alone decides what's in scope — see scope.py for the small set of things that
stay denied regardless (cloud metadata, non-http(s) schemes).
"""

from __future__ import annotations

import fnmatch
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

Resolver = Callable[[str], frozenset[str]]


def default_resolver(host: str) -> frozenset[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return frozenset()
    return frozenset(str(info[4][0]) for info in infos)


def _host_matches(pattern: str, host: str | None) -> bool:
    if not host:
        return False
    return fnmatch.fnmatch(host.lower(), pattern.lower())


@dataclass(frozen=True)
class TargetRule:
    """One authorized entry: a host (exact or glob like ``*.example.com``) with
    optional port/scheme restrictions (``None`` means "any")."""

    host: str
    ports: frozenset[int] | None = None
    schemes: frozenset[str] | None = None

    def matches(self, host: str | None, port: int | None, scheme: str | None) -> bool:
        if not _host_matches(self.host, host):
            return False
        if self.ports is not None and port is not None and port not in self.ports:
            return False
        return not (
            self.schemes is not None and scheme is not None and scheme.lower() not in self.schemes
        )


@dataclass(frozen=True)
class Engagement:
    """The full set of authorized target rules."""

    rules: tuple[TargetRule, ...]

    def in_engagement(
        self, host: str | None, port: int | None = None, scheme: str | None = None
    ) -> bool:
        return any(rule.matches(host, port, scheme) for rule in self.rules)

    @classmethod
    def from_specs(cls, specs: list[str]) -> Engagement:
        """Build an engagement from operator specs.

        Accepts ``example.com``, ``*.example.com``, ``example.com:8080``,
        ``https://example.com``, ``https://*.example.com:8443``, ``127.0.0.1``.
        """
        rules: list[TargetRule] = []
        for raw in specs:
            spec = raw.strip()
            if not spec:
                continue
            scheme: str | None = None
            port: int | None = None
            if "://" in spec:
                parts = urlsplit(spec)
                scheme = parts.scheme or None
                host = parts.hostname or ""
                port = parts.port
            elif spec.count(":") == 1 and not spec.startswith("["):
                host, _, port_str = spec.partition(":")
                port = int(port_str) if port_str.isdigit() else None
            else:
                host = spec
            if not host:
                continue
            rules.append(
                TargetRule(
                    host=host,
                    ports=frozenset({port}) if port else None,
                    schemes=frozenset({scheme}) if scheme else None,
                )
            )
        return cls(rules=tuple(rules))
