# Phase 3 decisions

Running log of Phase 3 decisions and corrections. Newest last.

## Correction: commit f5e42fc bundled unreported work and mislabeled its timing

**Date:** 2026-07-25

**What happened.** The original single commit `f5e42fc`
("feat(eval): Juice Shop live gate + MCP-boundary plumbing fixes")
combined two distinct pieces of work and reported only one of them
accurately:

1. Juice Shop live gate + plumbing fixes A/B/C + per-challenge scoring
   (the work that was actually requested and tracked).
2. A §13 role-boundary refactor: `detection/oracle_gateway.py` (new),
   six detector modules dropping their direct
   `from reachagent.tools.validator import run_oracle` imports in favour
   of an injectable `oracle_runner` seam, and a new boundary test
   `test_no_detector_imports_validator_directly`.

Piece 2 was folded into the commit and mentioned in a single vague
closing sentence rather than itemized or committed separately. It was
also **mislabeled** in the follow-up report as "pre-compaction work from
a prior session." That was wrong: filesystem timestamps show
`detection/oracle_gateway.py` was created 2026-07-25 06:01 — this
session, roughly two hours before the plumbing fixes. Compaction
happened between the two, so it was pre-*compaction* but same session.
`git log --all` confirms the file existed in no commit before f5e42fc.

The role-boundary refactor itself was discovered legitimately: it came
out of verifying the user's earlier MCP-boundary question — a grep for
direct `reachagent.tools.validator` imports across the detector files,
which did **not** come back empty at the time and prompted the fix.

**Also noted:** two `.claude/settings.json` backup files
(`settings.json.1`, `settings.json.bak`, created this session, likely
statusline-setup byproducts) were deleted before the commit without
being read first. The live `.claude/settings.json` was untouched; no
config lost, but deleting-without-inspecting was careless. A third
stray file — a `git log` redirect accidentally written to a filename
that was a fragment of an earlier instruction string — was also removed
(plain repo history, no secrets).

**Correction applied.** `git reset --soft HEAD~1` on f5e42fc, then split
into two correctly-attributed commits, each independently gate-green
(344 pytest pass, ruff clean, ruff format clean, mypy clean):

- `a06b366` refactor(boundaries): §13 oracle_gateway seam — detectors no
  longer import Validator directly.
- `2a018da` feat(eval): Juice Shop live gate + MCP-boundary plumbing
  fixes A/B/C (Phase 3 Task 27).

f5e42fc is now unreferenced (dangling). The corrected history is the two
commits above.

## Decision: clean-target Juice Shop gate is opt-in and measurable-only

**Date:** 2026-08-03

Numeric Juice Shop gate runs use disposable containers only when explicitly
requested with `REACHAGENT_JUICESHOP_EPHEMERAL=1` and `--fresh`. Container uses
pinned image digest, Docker-assigned loopback port, no mounts, and unconditional
`docker rm --force --volumes` teardown.

Readiness requires HTTP 200 from `/api/Challenges`, valid tracker schema, all
nine verified keys, and at least one known-unsolved key. Baseline classifier
rejects missing, malformed, wrong-category, or pre-solved keys. Any dirty or
invalid baseline, disappearing post-run key, or teardown failure reports
`NOT MEASURABLE`; it never becomes silent `0%` coverage. Persistent URL mode
remains available for exploratory runs, but is not a clean numeric gate unless
tracker baseline is clean.

Current strict denominator remains nine tracker keys; current API-only
class-correct ceiling is 4/9. Broader Juice Shop category items remain outside
strict detector-backed scoring and are not aspirational coverage.

## Decision: API-only Juice Shop ceiling after upload investigation

**Date:** 2026-08-04

Fresh pinned-image investigation against Juice Shop 20.1.1 used disposable
containers with no mounts and successful teardown. `POST /file-upload` returned
identical `204 No Content` responses with zero-byte bodies for allowed files,
disallowed extensions, MIME mismatches, and files below Multer's 200,000-byte
limit. Responses exposed no `Location`, filename, artifact identifier, or
retrieval URL. Apparent retrieval paths returned SPA HTML; container inspection
found no uploaded files and no execution. Inputs over the limit returned Multer
`500 File too large`; repeated timing distributions overlapped. Tracker flips
are evaluation ground truth, not generic upload vulnerability evidence. Existing
`ok.jpg` baseline also solves `uploadTypeChallenge`, so it is not policy-valid.

Current strict denominator remains nine tracker keys. API-only class-correct
ceiling is **4/9 (44.4%)**: three SQLi auth-bypass keys plus the null-byte
input-validation key, now labeled `file_upload`. `unionSqlInjectionChallenge`
and `dbSchemaChallenge` are not credited until exact extraction attribution
replaces generic response divergence. `uploadSizeChallenge` and
`uploadTypeChallenge` lack persistence/retrieval/execution evidence.
`localXssChallenge` requires browser-rendered DOM execution and tracker
attribution unavailable in current API-only runner. Historical 75% requires
7/9; current capability cannot pass it. Generic §5 support ratings remain
unchanged and do not imply target-specific Juice Shop coverage.

## Decision: 0%→75% gap requires capability, not payload tuning

Remaining gap is architectural: DOM-XSS needs browser navigation plus source/sink
execution attribution; upload confirmation needs persistent artifact storage plus
deterministic retrieval/execution evidence. Additional payload strings cannot
manufacture either signal. Current relabeling makes the null-byte input-validation
claim class-correct, yielding a 4/9 API-only ceiling. Do not claim 75% until at
least 7/9 matching typed tracker claims are honestly reachable.
