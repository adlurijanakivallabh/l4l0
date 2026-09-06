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

Phase 3, PentestGPT pass: read `pentestgpt_agent/src/pentestgpt_agent/plan.py`
in full. Its ``_target_is_allowed``/``_canonical_url_target`` is a real, careful
deny-by-default target-scope check — the closest thing in that codebase to this
module — extended to PATH-prefix granularity, not just host/port/scheme, with
genuine anti-bypass rigor: percent-decoding iterated up to 4 rounds with a
residue check (catching multi-layer encoding like ``%252e%252e%252f``, while
still rejecting anything STILL further-decodable after 4 rounds), a rejected
backslash/control-character set, and ``.``/``..`` segment rejection AFTER full
decoding (checked on decoded segments, not the raw string, so a traversal
attempt can't hide behind encoding). L4L0 had no path-scoping concept at all
before this — a real, common engagement shape ("test only /api/v2/* on this
shared host, not /admin or other paths") had no way to be expressed or
enforced, and worse, an operator who DID include a path in a target spec (e.g.
``https://example.com/api/v2``) had it silently discarded, granting the whole
host rather than what was actually declared. Adapted, not ported: PentestGPT's
own check runs once against a proposed task's target *string*, before any
traffic fires (this comparison's own real finding is that this doesn't cover
the Executor's actual tool calls at all); this module's path check runs
inside :meth:`TargetRule.matches`, called from every real `fire()` via
ScopeGuard.check — enforced per-request, not per-task-description.
"""

from __future__ import annotations

import fnmatch
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

Resolver = Callable[[str], frozenset[str]]

_MAX_DECODE_ROUNDS = 4


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


def _canonical_path_segments(path: str) -> tuple[str, ...] | None:
    """Fully percent-decode ``path`` and split it into segments, or ``None`` if
    it's suspicious in any way a path-scope check must never quietly ignore.

    Returns ``None`` (never a permissive guess) for: an unparseable/misencoded
    string, control characters, a backslash, a still-further-decodable residue
    after :data:`_MAX_DECODE_ROUNDS` rounds (blocks multi-layer percent-encoding
    bypass tricks), or any ``.``/``..`` segment once fully decoded (blocks path
    traversal, including traversal hidden behind encoding). Callers must treat
    ``None`` as "does not match", not as "no restriction".
    """
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
        return None
    try:
        decoded = path
        for _ in range(_MAX_DECODE_ROUNDS):
            next_round = unquote(decoded, errors="strict")
            if next_round == decoded:
                break
            decoded = next_round
        if unquote(decoded, errors="strict") != decoded:
            return None  # still decodable after the round cap -- reject, don't guess
    except (UnicodeDecodeError, ValueError):
        return None
    if (
        "%" in decoded
        or "\\" in decoded
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in decoded)
    ):
        return None
    segments = tuple(segment for segment in decoded.split("/") if segment)
    if any(segment.split(";", 1)[0] in {".", ".."} for segment in segments):
        return None
    return segments


@dataclass(frozen=True)
class TargetRule:
    """One authorized entry: a host (exact or glob like ``*.example.com``) with
    optional port/scheme/path-prefix restrictions (``None`` means "any").

    ``path_prefix`` holds pre-canonicalized segments (see
    :func:`_canonical_path_segments`) so a stored ``/api/v2`` restriction is
    compared against the REQUEST's own canonicalized segments, never against
    a raw, possibly-encoded string.
    """

    host: str
    ports: frozenset[int] | None = None
    schemes: frozenset[str] | None = None
    path_prefix: tuple[str, ...] | None = None

    def matches(
        self,
        host: str | None,
        port: int | None,
        scheme: str | None,
        path: str | None = None,
    ) -> bool:
        if not _host_matches(self.host, host):
            return False
        if self.ports is not None and port is not None and port not in self.ports:
            return False
        if self.schemes is not None and scheme is not None and scheme.lower() not in self.schemes:
            return False
        if self.path_prefix is not None:
            candidate = _canonical_path_segments(path or "/")
            if candidate is None:
                return False  # suspicious path shape -- fail closed, never guess a match
            if candidate[: len(self.path_prefix)] != self.path_prefix:
                return False
        return True


@dataclass(frozen=True)
class Engagement:
    """The full set of authorized target rules, plus an optional exclude list.

    ``exclude_rules`` is a narrower, deliberately partial adaptation of a
    reference platform's own filesystem-path exclusion for a bind-mounted
    source repo — that mechanism patches a threat (host-repo access) L4L0's
    own no-bind-mount container model never creates, so it isn't ported as
    designed. What genuinely transfers is the shape: an operator scoping
    ``*.example.com`` broadly may still want ``admin.example.com`` or
    ``/internal/*`` on an otherwise-in-scope host carved OUT, not tested at
    all — L4L0 had no way to express that before (only "add a narrower
    include rule" existed, which can't subtract from an existing broad one).
    An exclude match always wins over an include match, checked first.
    """

    rules: tuple[TargetRule, ...]
    exclude_rules: tuple[TargetRule, ...] = ()

    def in_engagement(
        self,
        host: str | None,
        port: int | None = None,
        scheme: str | None = None,
        path: str | None = None,
    ) -> bool:
        if any(rule.matches(host, port, scheme, path) for rule in self.exclude_rules):
            return False
        return any(rule.matches(host, port, scheme, path) for rule in self.rules)

    @classmethod
    def from_specs(cls, specs: list[str], *, exclude_specs: list[str] | None = None) -> Engagement:
        """Build an engagement from operator specs.

        Accepts ``example.com``, ``*.example.com``, ``example.com:8080``,
        ``https://example.com``, ``https://*.example.com:8443``, ``127.0.0.1``.
        ``exclude_specs`` accepts the identical forms and always overrides an
        otherwise-matching include rule.
        """
        return cls(
            rules=_parse_target_specs(specs),
            exclude_rules=_parse_target_specs(exclude_specs or []),
        )

    def describe(self) -> str:
        """A human-readable rendering of every authorized (and excluded) rule."""
        if not self.rules:
            return "(no targets declared)"
        lines = [f"- {_describe_rule(rule)}" for rule in self.rules]
        if self.exclude_rules:
            lines.append("Excluded (always overrides an otherwise-matching rule above):")
            lines += [f"- {_describe_rule(rule)}" for rule in self.exclude_rules]
        return "\n".join(lines)


def _parse_target_specs(specs: list[str]) -> tuple[TargetRule, ...]:
    rules: list[TargetRule] = []
    for raw in specs:
        spec = raw.strip()
        if not spec:
            continue
        scheme: str | None = None
        port: int | None = None
        path_prefix: tuple[str, ...] | None = None
        if "://" in spec:
            parts = urlsplit(spec)
            scheme = parts.scheme or None
            host = parts.hostname or ""
            # .port is lazily parsed and raises ValueError on a malformed
            # or out-of-range port string (e.g. "https://x.com:abc") — one
            # bad entry among possibly many operator-supplied specs must
            # not crash the whole engagement, so treat it as "no port
            # restriction" the same way the plain host:port branch below
            # already does for a non-digit port.
            try:
                port = parts.port
            except ValueError:
                port = None
            if parts.path and parts.path != "/":
                canonical = _canonical_path_segments(parts.path)
                if canonical is None:
                    # An operator's OWN scope declaration is suspicious/
                    # unparseable -- unlike a bad port (which degrades to
                    # "no restriction", a widening a port mistake can't
                    # really weaponize), silently widening a path
                    # restriction to "the whole host" would be a real
                    # scope escalation the operator never asked for. Drop
                    # the whole spec rather than guess.
                    continue
                path_prefix = canonical
        elif spec.startswith("["):
            # A bracketed IPv6 literal ("[::1]" or "[::1]:8080") with no
            # scheme prefix — urlsplit needs a "//" authority marker to
            # parse the brackets/port correctly rather than treating the
            # whole spec as an opaque path, which is what silently
            # produced a TargetRule that could never match anything here.
            parts = urlsplit(f"//{spec}")
            host = parts.hostname or ""
            try:
                port = parts.port
            except ValueError:
                port = None
        elif spec.count(":") == 1:
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
                path_prefix=path_prefix,
            )
        )
    return tuple(rules)


def _describe_rule(rule: TargetRule) -> str:
    parts = [rule.host]
    if rule.schemes:
        parts.append(f"scheme(s): {', '.join(sorted(rule.schemes))}")
    if rule.ports:
        parts.append(f"port(s): {', '.join(str(p) for p in sorted(rule.ports))}")
    if rule.path_prefix:
        parts.append(f"path prefix: /{'/'.join(rule.path_prefix)}")
    return " - ".join(parts)
