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
    # Corrected the same way VAmPI's set above was, once the same real-
    # sources discipline was applied here too: crAPI's own docs/challenges.md
    # (github.com/OWASP/crAPI) documents 18 numbered challenges across BOLA,
    # broken auth, excessive data exposure, rate limiting, BFLA, mass
    # assignment, SSRF, NoSQL injection, SQL injection, unauthenticated
    # access, JWT forgery, and LLM prompt injection. "command-injection" was
    # WRONG here: it's not an officially documented crAPI challenge - the
    # real chain (mass-assignment+SSRF into a shell via conversion_params)
    # is only reported in third-party writeups, exactly the same real-but-
    # undocumented situation this file already excludes JWT-in-VAmPI for by
    # its own established precedent, so dropped rather than kept as ground
    # truth. Rate limiting (challenge 6, DoS) excluded for the same non-
    # destructive/no-DoS reason VAmPI's own RegexDoS/rate-limiting items are.
    ground_truth_classes=frozenset(
        {
            "access-control",  # BOLA (vehicle/mechanic reports) + BFLA (delete others' video)
            "ssrf",  # official challenge 11: HTTP call to an attacker-controlled URL
            "mass-assignment",  # challenges 8-10: free item/balance/video-props via extra fields
            "sql-injection",  # challenge 13: redeem an already-claimed coupon via a DB write
            "nosql-injection",  # challenge 12: free coupons
            "jwt",  # challenge 15: forge valid JWTs
            "information-disclosure",  # challenges 4-5: excessive data exposure of other users
            "llm-prompt-injection",  # challenges 16-18: chatbot prompt injection/credential leak
        }
    ),
)

JUICE_SHOP = BenchmarkCase(
    name="juice-shop",
    description="OWASP Juice Shop - a deliberately insecure web application.",
    # The original 5 classes here were already real and accurate (unlike
    # VAmPI/crAPI above, nothing here was WRONG) - checked against Juice
    # Shop's own official companion guide's 16 documented challenge
    # categories (pwning.owasp-juice.shop/companion-guide), this set was
    # just incomplete. Added 4 more real, documented categories this
    # project already has a skill file for; NOT added (no matching skill
    # file yet): Cryptographic Issues, Vulnerable Components, Security
    # Misconfiguration, Broken Anti-Automation, Observability Failures.
    ground_truth_classes=frozenset(
        {
            "access-control",
            "sql-injection",
            "xss",
            "insecure-deserialization",  # genuinely one of Juice Shop's own documented categories
            "path-traversal",
            "xxe",  # official "XML External Entities (XXE)" category
            "open-redirect",  # official "Unvalidated Redirects" category
            "weak-credentials",  # official "Broken Authentication" category
            "information-disclosure",  # official "Sensitive Data Exposure" category
        }
    ),
)

DVWA = BenchmarkCase(
    name="dvwa",
    description="DVWA (Damn Vulnerable Web Application) - a PHP/MySQL training target.",
    # Same story as Juice Shop above: the original 4 were already real and
    # correctly mapped, just incomplete. DVWA's own README has no
    # consolidated vuln list, so the authoritative primary source is its own
    # lab-module directory names under vulnerabilities/ in
    # github.com/digininja/DVWA. Added 5 more of DVWA's own real lab modules
    # this project already has a skill file for; NOT added (no matching
    # skill file yet): DVWA's own "cryptography" (weak crypto/session),
    # "csp" (CSP bypass), "javascript" (client-side bypass), and "weak_id"
    # (weak session IDs) labs.
    ground_truth_classes=frozenset(
        {
            "sql-injection",  # DVWA's own "sqli"/"sqli_blind" labs
            "xss",  # DVWA's own "xss_r"/"xss_s"/"xss_d" labs
            "command-injection",  # DVWA's own "exec" lab
            "path-traversal",  # DVWA's own "fi" (file inclusion) lab
            "csrf",  # DVWA's own "csrf" lab
            "open-redirect",  # DVWA's own "open_redirect" lab
            "insecure-file-uploads",  # DVWA's own "upload" lab
            "access-control",  # DVWA's own "bac" + "authbypass" labs
            "weak-credentials",  # DVWA's own "brute" + "captcha" labs
        }
    ),
)

LAB_TARGETS: tuple[BenchmarkCase, ...] = (VAMPI, CRAPI, JUICE_SHOP, DVWA)
