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

## Hand-tagged base-slice payloads (not vendored — in-tree, `data/library.yaml` + `payload_resolver._TEMPLATES`)

Alongside the vendored corpus snapshots, a small hand-authored base slice is
checked into `src/reachagent/payloads/data/library.yaml` with its parameterized
templates in `payload_resolver._TEMPLATES`. These are the oracle-proven, curated
payloads that sort *before* bulk corpus line-locators (template-first ordering,
§9 v1.11) — the definitive probe for a class fires first. Added over v1.11:

- **JWT forgery** (STRUCTURAL, sink null) — three precomputed tokens:
  `jwt_forgery/none-alg`, `jwt_forgery/hs256-key-confusion` (HS256 signed with a
  placeholder public key), `jwt_forgery/weak-secret` (HS256 signed with `secret`).
  Precomputed (not slot-filled) because JWT segments are base64url — a `{slot}`
  inside an encoded segment would corrupt the token.
- **Blind OOB shapes** (OOB_CALLBACK, `{nonce}.{collab}`) —
  `sqli_blind/oob-xxe-exfil` (external-entity `SYSTEM` fetch) and
  `command_injection/log4shell-oob` (`${jndi:ldap://…}`).
- **SSRF** (three families, `inferred_sink_type: url`) — 9 blind callback URLs
  (http/https/file/gopher/redirect-chain/internal-proxy + oob creds exfil,
  OOB_CALLBACK, `reaches`/`derived_credential`); 15 non-blind cloud-metadata /
  internal URLs (AWS IMDS / GCP / Azure / Alibaba / DigitalOcean / OpenStack /
  K8s / docker socket / internal admin, STRUCTURAL `SSRF_RESPONSE` sentinel-in-body,
  `reaches`); 4 cloud-metadata *token* entries (`derived_credential` edge). See the
  library.yaml rows for the per-entry oracle + edge tagging.

These are stimulus only — every one still routes through `run_oracle`; none is a
confirmation on its own, and the hand-tagged sets never change a §5 rating level.

**v1.13:** `payloads/encoding.py` bounded encoding variants (url/double-url, 2/variant) tag-preserving via `_VARIANT_CACHE`; `corpus _dedup_canonical` dedups url-decoded families.
