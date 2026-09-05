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
    ground_truth_classes=frozenset(
        {
            "access-control",
            "sql-injection",
            "jwt",
            "insecure-deserialization",
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
