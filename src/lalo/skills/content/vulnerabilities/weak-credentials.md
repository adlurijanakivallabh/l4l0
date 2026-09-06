---
name: weak-credentials
category: vulnerability
description: Weak, default, and reused credentials — username enumeration, targeted brute-force, credential stuffing, and rate-limit/lockout bypass, with a per-class proof ladder
keywords: [weak password, default credentials, brute force, credential stuffing, password spraying, account lockout bypass]
---

# Weak and Default Credentials

Weak or default credentials remain one of the most prevalent, highest-yield
findings across every target type L4L0 assesses — web login forms, admin
panels, and raw network services (SSH/FTP/RDP/database ports) alike.
Prioritize enumeration and targeted spraying over brute force: knowing
which usernames are real, and which password policy is actually enforced,
usually matters more than the size of the wordlist.

## Attack Surface

- Web/API login endpoints, admin panels and management consoles, and
  self-registration flows with a weak or unenforced password policy.
- Raw network services with their own authentication: SSH, FTP, Telnet,
  RDP, SMB, and database ports (MySQL/PostgreSQL/Redis/MongoDB) commonly
  left on default or vendor-shipped credentials.
- Password-reset flows that hand out a predictable temporary password or a
  reset token generated from a weak or time-based source.
- API keys and service-to-service secrets provisioned with a
  weak/predictable value rather than genuine random generation.

## Recon

- Determine the authentication mechanism precisely before testing: form
  POST, HTTP Basic, a bearer-token/JWT password grant, an API key in a
  header/query/body, or a multi-step (username-then-password) flow — each
  needs a different test harness.
- Enumerate valid usernames first — brute-forcing passwords against
  unconfirmed usernames wastes effort. Check for an error-message
  difference between "invalid username" and "invalid password," a
  registration-page availability check, and response-timing differences
  on the password-reset flow.
- Fingerprint rate-limiting and lockout behavior on a handful of probe
  requests before committing to a full run: is there a 429, a growing
  delay, a CAPTCHA that only appears after N attempts, or nothing at all?
  This determines whether password spraying (few passwords, many users) or
  targeted brute force (many passwords, one user) is the viable approach.
- Build a target-specific wordlist rather than reaching for a generic one
  first: company/product name variants, season+year patterns, and any
  vendor-default list matching the identified service/framework.

## Techniques (start quiet, escalate only as needed)

1. **Default-credential check first.** Try the vendor/framework's own
   documented default credentials for the identified service before any
   broader attempt — this is the single highest-yield, lowest-noise test
   in this class and costs almost nothing.
2. **Password spraying.** Test one or a small number of common/likely
   passwords against every enumerated username, spaced to stay under any
   observed lockout threshold — this avoids locking out individual
   accounts while still covering the population.
3. **Targeted brute force.** Only once spraying is exhausted, and only
   against a specific high-value account, escalate to a larger
   password list built from the target-specific wordlist above.
4. **Credential stuffing.** Where email-format usernames matching the
   target's domain are known, test previously-breached email:password
   pairs — a match proves password reuse rather than a weak policy per
   se, but the account-compromise impact is identical.
5. **Rate-limit and lockout bypass probes.** If a limit exists, test
   whether it's keyed on IP alone (bypassable via distinct source
   addresses/proxies), on a header value the client controls, or on the
   username with no cross-username correlation (allowing an unthrottled
   spray across many accounts even with per-account lockout in place).
6. **Multi-step flow bypass.** For a username-then-password flow, test
   whether the password step can be reached directly (skipping the
   username step's own separate throttling), and whether a session/step
   identifier can be reused across different candidate usernames.

## Proof Ladder

- **L1 — policy gap identified.** A weak password policy, an unthrottled
  login endpoint, or a username-enumeration oracle is confirmed
  structurally, but no actual credential pair has been shown to
  authenticate yet.
- **L2 — valid username enumerated.** A specific username is confirmed to
  exist via a genuine oracle (timing, message, or side-channel
  difference) — real signal, but not yet an authenticated session.
- **L3 — successful authentication achieved.** A weak, default, or
  credential-stuffed pair is shown producing a real, valid session (a
  captured token, cookie, or authenticated response) against the live
  target. This is the threshold for a reportable finding.
- **L4 — privileged access or systemic exposure.** The compromised account
  carries administrative or otherwise elevated privileges, the same
  credentials are shown working across multiple accounts/services
  (systemic default-credential exposure, not one account), or the
  authenticated session is chained into a further compromise.

Calibrate severity separately per [[severity-calibration]] — an
internet-facing admin panel with a vendor default credential still active
is critical; the same default credential on an already-internal-only
service is high but not automatically critical.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- A honeypot or decoy account designed to bait credential attacks looks
  identical to a genuine compromise from the response alone — confirm the
  account's role and data are real before treating access as meaningful.
- A temporary lockout that clears quickly is not the same as no
  protection at all — distinguish "rate-limited, still eventually
  crackable within the engagement window" from "genuinely unthrottled,"
  and report the actual observed throttling behavior rather than assuming
  none exists.
- A 429 response is not the same as a 401 — confirm which one a given
  attempt actually returned before concluding a credential pair failed,
  since a naive script can misread rate-limiting as invalid credentials.
- Successful authentication must be confirmed via a genuine session
  artifact (a token that subsequently authorizes a real request), not
  merely a 200 status on the login endpoint itself, which some
  implementations return regardless of credential validity.

## Impact

Full account takeover for the affected identity, administrative or
system-wide compromise where the credential belongs to a privileged or
service account, lateral reach into other systems sharing the same reused
credential, and — for a default credential found on one instance of a
widely-deployed service — a systemic finding likely to recur across every
similarly-deployed instance in the engagement.

## Summary

Weak-credential findings are won by enumeration and targeting, not brute
force volume: confirm real usernames, fingerprint the actual throttling in
place, and prioritize default/vendor credentials and targeted spraying
before any large wordlist run.
