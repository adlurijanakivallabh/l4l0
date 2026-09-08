"""The named lab-target benchmark cases from the governing plan.

Ground-truth classes are each target's own well-documented, publicly known
vulnerability set (VAmPI/crAPI's own READMEs, Juice Shop's own scoreboard
categories, DVWA's own vulnerability list) — not derived from any of the
five studied reference agents, so no reference-reading applies to this
file's actual content beyond the harness mechanism itself (:mod:`.cases`,
:mod:`.scoring`).

These containers are brought up only for a live eval run and torn down
immediately after — never left running between sessions (see this
project's own standing convention). Bringing a target container up/down is
deliberately left to the operator's own ``docker compose``/``docker run``
invocation rather than wrapped in a Python lifecycle helper here: the
Docker command itself is one line, and a live case run
(``@pytest.mark.live``) simply expects the target already reachable at a
given URL, matching this project's existing ``live`` pytest marker
convention (``pyproject.toml``) rather than introducing a second one.
"""

from __future__ import annotations

from .cases import BenchmarkCase

VAMPI = BenchmarkCase(
    name="vampi",
    description="VAmPI - a deliberately vulnerable API for API-security tool evaluation.",
    # Corrected after a live scan's own results prompted re-verifying this
    # set against real sources rather than assuming it was right: the
    # author's own README/blog (erev0s.com) and an independent researcher's
    # full exploitation writeup (csbygb.gitbook.io/pentips) both confirm
    # VAmPI plants exactly 8 vulnerabilities, mapped to OWASP API Security
    # Top 10:2019 - SQL injection, unauthorized password change (BOLA),
    # BOLA on books, mass assignment on registration, excessive data
    # exposure via /users/v1/_debug, user/password enumeration, a RegexDoS
    # on the email-update endpoint, and no rate limiting anywhere.
    # "insecure-deserialization" was NEVER a real VAmPI vulnerability - no
    # source anywhere connects it to pickle/deserialization; it was wrong
    # in this set from the start. "jwt" is dropped too: VAmPI uses real
    # JWTs for auth (an agent CAN legitimately find a real weakness there,
    # as one live run did - alg=none acceptance - and that finding is
    # genuine and valuable), but no source documents JWT weakness as one
    # of the target's own INTENDED planted vulnerabilities, so it doesn't
    # belong in a ground-truth set used to score recall against known
    # answers. The RegexDoS and rate-limiting items are deliberately
    # excluded from ground_truth_classes even though real: both need
    # DoS-adjacent request patterns (a resource-exhaustion payload, or
    # genuinely bulk sequential requests) that this project's own
    # mission-prompt discipline treats as opt-in/exceptional, not default
    # black-box testing (CLAUDE.md: "Non-destructive testing and no-DoS
    # are prompt-guided... not mechanically blocked") - scoring recall
    # against a class a default-configured, non-destructive agent isn't
    # even expected to attempt would be misleading, not honest.
    ground_truth_classes=frozenset(
        {
            "access-control",  # unauthorized password change, BOLA on books, debug-endpoint leak
            "sql-injection",
            "mass-assignment",  # undocumented fields (e.g. an admin flag) accepted at registration
            "weak-credentials",  # trivially weak password policy + username enumeration
        }
    ),
)

CRAPI = BenchmarkCase(
    name="crapi",
    description="crAPI (Completely Ridiculous API) - OWASP's vulnerable microservices target.",
    ground_truth_classes=frozenset(
        {
            "access-control",
            "ssrf",
            "command-injection",
        }
    ),
)

JUICE_SHOP = BenchmarkCase(
    name="juice-shop",
    description="OWASP Juice Shop - a deliberately insecure web application.",
    ground_truth_classes=frozenset(
        {
            "access-control",
            "sql-injection",
            "xss",
            "insecure-deserialization",
            "path-traversal",
        }
    ),
)

DVWA = BenchmarkCase(
    name="dvwa",
    description="DVWA (Damn Vulnerable Web Application) - a PHP/MySQL training target.",
    ground_truth_classes=frozenset(
        {
            "sql-injection",
            "xss",
            "command-injection",
            "path-traversal",
        }
    ),
)

LAB_TARGETS: tuple[BenchmarkCase, ...] = (VAMPI, CRAPI, JUICE_SHOP, DVWA)
