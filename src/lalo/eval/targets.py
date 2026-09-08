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

from dataclasses import replace

from .cases import BenchmarkCase

VAMPI = BenchmarkCase(
    name="vampi",
    description="VAmPI - a deliberately vulnerable API for API-security tool evaluation.",
    # Corrected TWICE now, each time after real evidence surfaced a gap in
    # the prior pass rather than assuming either version was right:
    #
    # Pass 1 (a live scan's own results prompted re-verifying this set
    # against real sources at all): the author's own README/blog
    # (erev0s.com) and an independent researcher's writeup
    # (csbygb.gitbook.io/pentips) were read and summarized as showing 8
    # vulnerabilities with NO documented JWT weakness and NO
    # insecure-deserialization at all. "insecure-deserialization" being
    # wrong held up (see below) - "jwt" being dropped did NOT.
    #
    # Pass 2 (four independent, detailed, hands-on exploitation writeups
    # supplied directly by the operator - not blog summaries, actual
    # commands/payloads/results, spanning Apr 2025 to Mar 2026) ALL FOUR
    # independently forge a valid JWT against the real, default
    # `erev0s/vampi` image using a guessed weak secret (most commonly the
    # literal string "secret") and use the forged token to access
    # protected/admin endpoints - one of them explicitly names "JWT
    # authentication bypass via weak signing key" as one of erev0s.com's
    # OWN documented vulnerabilities, directly contradicting pass 1's own
    # summary of that same source. Four independent reproductions across
    # nearly a year is strong, corroborated evidence pass 1's web research
    # simply missed or misread this - "jwt" belongs back in ground truth.
    # None of the four writeups mention insecure-deserialization at all,
    # reaffirming pass 1 was right to remove that one.
    #
    # Real, sourced, and remaining classes: SQL injection, unauthorized
    # password change (BOLA), BOLA on books, mass assignment on
    # registration, excessive data exposure via /users/v1/_debug,
    # user/password enumeration, JWT forgery via a weak/guessable signing
    # secret, a RegexDoS on the email-update endpoint, and no rate
    # limiting anywhere. The RegexDoS and rate-limiting items stay
    # deliberately excluded from ground_truth_classes even though real
    # (confirmed reproducible in 2 of the 4 writeups, not vulnerable in a
    # 3rd - environment-dependent, but genuinely real): both need
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
            "jwt",  # forge a valid token via a guessed weak/default signing secret
        }
    ),
)

# A separate case, not part of LAB_TARGETS' default rotation, for the one
# scenario where scoring the two excluded classes IS honest: an operator
# explicitly authorizing destructive/DoS-adjacent testing for this specific,
# disposable run (see regex-dos.md's own opt-in-only gate). Kept distinct
# from VAMPI itself rather than folding these into its default set, because
# baking them in would misscore every ordinary, non-destructive-by-default
# run against two classes it was never asked to attempt - exactly the
# "misleading, not honest" scoring VAMPI's own comment above warns against.
VAMPI_DESTRUCTIVE = replace(
    VAMPI,
    name="vampi-destructive",
    description=VAMPI.description + " (destructive/DoS-adjacent testing authorized)",
    ground_truth_classes=VAMPI.ground_truth_classes | {"regex-dos", "rate-limiting"},
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
    # is only reported in third-party writeups, not crAPI's own
    # docs/challenges.md, so dropped rather than kept as ground truth
    # (unlike VAmPI's own "jwt" - see that entry's own comment for why
    # four independent hands-on writeups made that one a keep, not a
    # drop: undocumented-by-the-primary-source is a reason to look
    # harder for corroboration, not an automatic exclusion). Rate
    # limiting (challenge 6, DoS) excluded for the same non-destructive/
    # no-DoS reason VAmPI's own RegexDoS/rate-limiting items are.
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
