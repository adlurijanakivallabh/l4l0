# Vendored payload corpora (`third_party/`)

Plan §9/§12 (v1.6+): the payload library is seeded from the **full
PayloadsAllTheThings and SecLists repositories, vendored under `third_party/`**,
ingested via a folder→(vuln_class, inferred_sink_type) map + a regex oracle-tagging
rule table (`src/reachagent/payloads/corpus.py`).

## What is vendored

A **curated minimal snapshot** — only the machine-readable, one-per-line payload
files under the folders the corpus loader maps, at a **pinned commit SHA** per
source. The full multi-GB repos are *not* cloned: SecLists is mostly unmapped
wordlists, PayloadsAllTheThings is mostly prose `.md`. Each snapshot root carries
a `SOURCE.txt` recording the upstream repo URL, the pinned SHA, the license (both
MIT), and the exact vendored relpaths.

  - `third_party/seclists-snapshot/`            — SecLists, pinned `5aa4cb18…`
  - `third_party/payloadsallthethings-snapshot/` — PayloadsAllTheThings, pinned `434cc897…`

Upstream relpaths are preserved under each snapshot root, so a `payload_ref` of
`source/relpath#Ln` maps directly back to the vendored file and line.

## Network-free at detection time (§9, non-negotiable)

Fetching the snapshot is **dev setup only**. A detection run never reaches the
network for payloads: the loader reads the vendored files off disk, and the
resolver reads a payload string from a vendored line on demand. Re-fetching /
re-pinning is a manual maintainer step (see each `SOURCE.txt` for the command);
CI and tests run entirely against the checked-in snapshot.

## Refreshing the snapshot (maintainer, dev only)

1. Pick the new upstream commit; note its SHA.
2. Re-fetch each relpath listed in that source's `SOURCE.txt` from
   `raw.githubusercontent.com/<repo>/<sha>/<relpath>`.
3. Update the `Commit:` line in `SOURCE.txt`.
4. Run `uv run pytest tests/phase3/test_corpus_ingest.py` — the ingest census,
   sink-isolation, and semantic-validity guards will flag any drift.
