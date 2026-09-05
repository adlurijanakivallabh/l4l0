"""The declared-engagement target model.

An :class:`Engagement` is the set of hosts/ports/schemes the operator authorized.
It is target *definition*, not a network cage — the structured firers consult it
to stay on the engagement. DNS is resolved once and pinned so a later check and
the actual connection agree (defeats rebinding).
"""

from __future__ import annotations

import fnmatch
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

Resolver = Callable[[str], frozenset[str]]


def _default_resolver(host: str) -> frozenset[str]:
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
        if self.schemes is not None and scheme is not None and scheme.lower() not in self.schemes:
            return False
        return True


@dataclass(frozen=True)
class Engagement:
    """The full set of authorized target rules."""

    rules: tuple[TargetRule, ...]

    def in_engagement(
        self, host: str | None, port: int | None = None, scheme: str | None = None
    ) -> bool:
        return any(rule.matches(host, port, scheme) for rule in self.rules)

    @classmethod
    def from_specs(cls, specs: Iterable[str]) -> Engagement:
        """Build an engagement from operator specs.

        Accepts ``example.com``, ``*.example.com``, ``example.com:8080``,
        ``https://example.com``, ``https://*.example.com:8443``.
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
