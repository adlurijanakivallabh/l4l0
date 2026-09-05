---
name: path-traversal
category: vulnerability
description: Path traversal and local/remote file inclusion — normalization bypass, wrapper abuse, and a per-class proof ladder
keywords: [path traversal, directory traversal, lfi, rfi, file inclusion, zip slip, file read]
---

# Path Traversal and File Inclusion

File-path handling breaks when a value that should select among a fixed set
of files instead becomes a path the application resolves and trusts.
Treat every user-influenced filename, path segment, or archive entry as
untrusted until it is either eliminated entirely or bound to a real
allowlist after normalization.

## Attack Surface

- Parameters that plausibly name a file, template, or resource: things
  like a filename, template selector, page/view identifier, download
  target, export/report name, or theme/locale selector.
- Upload and conversion pipelines, thumbnailers, and document/report
  converters, which frequently resolve a path internally that never
  appears in the request itself.
- Archive extraction (zip/tar/gzip) — an entry name containing traversal
  sequences can write outside the intended extraction directory even when
  the *request* that triggered extraction looks completely unrelated to a
  file path.
- Server/proxy layers in front of the application (reverse proxies, CDNs)
  frequently decode or normalize paths differently than the application
  itself — a value that looks safe to one layer can still reach the other
  unnormalized.

## Recon

- Map every place a value joins onto a base directory or reaches an
  include/require/render-template call, not just obviously
  "file"-or-"path"-named parameters — a template or locale selector is
  just as much a path join as an explicit `file=` parameter.
- Note the platform and any framework-specific static-file serving in
  front of the application; traversal and normalization behavior differs
  meaningfully between them and is worth confirming rather than assuming.
- For anything that inflates an archive, check whether entries are
  extracted with their names trusted as-is or sanitized first — this is
  usually not observable from outside without actually testing it.

## Techniques (start quiet, escalate only as needed)

1. **Baseline traversal read.** Request a well-known, harmless file well
   outside the intended root (an OS hosts file or equivalent) using the
   simplest relative-traversal sequence for the platform. A same-endpoint
   request for a legitimate in-root file is your control — the presence or
   absence of the traversal effect should be the only difference between
   the two responses.
2. **Normalization and encoding variants, only if the baseline is
   blocked.** URL-encoding (including double-encoding), mixed path
   separators, redundant path segments, and proxy/application decoding
   mismatches exist specifically to survive a naive filter — use the
   minimum variant that gets through, not an exhaustive sweep, once one
   works.
3. **Wrapper and scheme abuse, where the language/framework exposes one.**
   Some runtimes expose stream wrappers that read a file through a filter
   (useful for reading source code as encoded text rather than executing
   it) — this is a read-only technique, strictly lower-risk than inclusion
   and worth preferring when the goal is disclosure rather than execution.
4. **Inclusion, only once a read primitive is confirmed.** If the target
   dynamically includes or renders a file by path, escalate from "I can
   read this file" to "I can make the application execute or render
   content I influenced" — this is a materially higher-impact claim and
   needs its own distinct proof, not just an inference from the read
   primitive.
5. **Archive-entry traversal (Zip Slip), tested with a synthetic archive
   you control.** Craft an archive whose entry names contain traversal
   sequences and confirm extraction writes outside the target directory —
   verify with a harmless marker file, not a payload with side effects.
6. **File-write-to-execution characterization, only after a write
   primitive is confirmed.** Before choosing a payload, establish exactly
   what you control: create vs. overwrite, the directory and filename, the
   byte content, and what would actually cause the application to load or
   execute the written file (an immediate route, a cache/reload cycle, a
   scheduled task) — writing a file that nothing ever reads again proves
   nothing.

## Proof Ladder

- **L1 — normalization gap suspected.** A response difference (error
  text, status, timing) suggests a traversal or inclusion attempt reached
  the filesystem layer, but no file content was retrieved.
- **L2 — out-of-root read confirmed.** You retrieved the actual content of
  a file outside the intended root, but it was a low-sensitivity file used
  only to prove the primitive (not application secrets or source).
- **L3 — sensitive content read or a write primitive proven.** You read
  genuinely sensitive content (configuration, credentials, source code) or
  proved a file-write primitive lands where you predicted, confirmed by
  reading it back. This is the threshold for a reportable finding.
- **L4 — execution via inclusion or write.** You demonstrated that the
  application actually loads or executes content you wrote or included,
  not merely that the file exists on disk afterward.

Calibrate severity separately per [[severity-calibration]] — reading a
low-sensitivity file outside the root is a different severity story than
reading credentials or achieving execution, even though both can occur
within the same class.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps:

- Content that looks like a real file but is actually served from a
  database or object store behind a virtual path is not a filesystem
  traversal — confirm the content is genuinely coming from the
  filesystem, not a look-alike virtual path space.
- A path that canonicalizes to inside the intended root after
  normalization, even though the raw input contained traversal sequences,
  is not a finding — confirm the *resolved* path, not the literal
  characters you sent.
- An archive extractor that already sanitizes entry names or enforces the
  destination directory is a real control — confirm this by actually
  testing extraction with a crafted archive, not by assuming a specific
  library version is safe.
- A file write with no way for the application to ever load or execute it
  again (no matching route, no cache/reload path, no scheduled consumer)
  is a proof gap for execution impact specifically, even though the write
  itself may still be a valid, lower-severity finding on its own.

## Impact

Sensitive configuration, credential, or source-code disclosure; code
execution when a write or inclusion primitive reaches a location the
application later loads or renders; persistence via a dropped file in a
served or executed location; and lateral movement enabled by secrets
recovered from disclosed files.

## Summary

Eliminate user-controlled paths where possible; otherwise resolve to a
canonical path and check it against a real allowlist, not against the raw
input string. Prove read, write, and execution as three separate claims —
each needs its own evidence, not an inference from the others.
