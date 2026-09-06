---
name: insecure-file-uploads
category: vulnerability
description: File upload security — extension/MIME/magic-byte bypass, archive and toolchain exploits, cloud-storage vectors, with a per-class proof ladder
keywords: [file upload, insecure file upload, web shell, zip slip, polyglot, magic bytes, imagemagick, presigned url]
---

# Insecure File Uploads

Upload surfaces are high-impact because acceptance is only the first step of
a pipeline — client, ingress validation, storage, one or more processors
(image/document conversion, thumbnailing, virus scanning), and a serving
path each make their own trust decision, and a mismatch between any two of
them is what actually produces impact. Explicitly named as an in-scope RCE
vector alongside command injection, SSTI, deserialization, and SSRF-to-
internal — treat it with the same proof discipline as any of those.

## Attack Surface

- Direct web/API/mobile uploads, and direct-to-cloud presigned flows
  (S3/GCS/Azure) where the client talks straight to object storage — the
  application's own validation may never see the object at all.
- Resumable/multipart upload protocols (tus-style, S3 multipart): metadata
  set at *init* is not necessarily what's still true at *complete* —
  validation that only runs once, at the wrong step, is a recurring gap.
- Media/document processing pipelines (image conversion, PDF/Office
  rendering, EXIF/metadata extraction, thumbnailing, malware scanning) —
  each processor is a distinct consumer of the same uploaded bytes and can
  disagree with the original validator about what the file actually is.
- Non-obvious upload fields: avatars, rich-text-editor attachments, bulk/CSV
  importers, report and archive uploads, email-attachment ingestion.

## Recon

- Map the full pipeline before touching bypasses: client → ingress
  validation → storage → processor(s) → serving path (app-served, object
  storage, CDN, email). Note exactly where validation and authorization
  happen, and whether every later consumer trusts that same decision.
- Capture a legitimate upload's full response: resulting URL, `Content-
  Type`, `Content-Disposition`, and presence/absence of `X-Content-Type-
  Options: nosniff` on retrieval — this is the baseline every bypass attempt
  gets compared against.
- Identify which validator actually runs (extension allowlist? MIME sniffing
  from client-supplied header? magic-byte inspection? content-aware parsing?)
  and, separately, every later parser/converter/renderer that will touch the
  same bytes — a detector and a consumer disagreeing about type or structure
  is the core mechanism behind most upload bypasses.
- For direct-to-cloud flows, check which fields the client controls in the
  presigned request (`key`, `acl`, `Content-Type`, `Content-Disposition`,
  `x-amz-meta-*`) — anything client-settable here is untrusted input, even
  though the actual bytes never transit the application server.

## Techniques (start quiet, escalate only as needed)

1. **Extension/MIME mismatch probe.** Upload a small file whose extension,
   declared MIME type, and actual magic bytes each claim something
   different (e.g. a `.jpg`-named file with a PHP payload and no real JPEG
   header) — the response and later retrieval headers reveal whether
   validation trusts the extension, the client-supplied `Content-Type`, or
   the actual bytes.
2. **Magic-byte polyglot.** Once you know which signal is checked, craft a
   file valid enough to pass that ONE check while still carrying an
   executable/renderable payload for the actual consumer (a GIF89a header
   followed by embedded PHP; a valid JPEG header with an appended script) —
   this exploits exactly a detector/consumer disagreement, not a missing
   check.
3. **Content-type / rendering probe.** Upload an SVG or HTML file and
   retrieve it: does it come back `image/svg+xml`/`text/html` and render
   inline (stored XSS risk), or download as `attachment` with `nosniff` set
   (safe)? This needs no server-side execution at all to produce a real
   finding.
4. **Archive-structure probe.** Upload a small zip/tar containing a `../`
   path-traversal entry or a symlink pointing outside the extraction
   directory — a target that extracts without validating entry paths is a
   Zip Slip write-primitive, not just a content-type issue.
5. **Toolchain-specific probes.** Where the pipeline shells out to
   ImageMagick/GraphicsMagick, Ghostscript, or ExifTool, a crafted
   SVG/PS/EPS or oversized EXIF/XMP block can reach a known parser
   vulnerability class in that specific toolchain — confirm the actual
   version/config in use before assuming a legacy vector still applies
   (many are mitigated by a locked-down `policy.xml` or a sandboxed
   converter).
6. **Resumable/multipart late-swap.** For a create→upload→finalize flow,
   upload a benign file but change the declared `Content-Type`/
   `Content-Disposition` (or the final chunk's content) only at the
   finalize step — many implementations validate only at initiation.
7. **Processing-window race.** Request the freshly uploaded object
   immediately, before an asynchronous AV/CDR (content-disarm-and-
   reconstruct) scan can complete — a background scanner is not a real
   control if the object is servable during its own scan window.

## Proof Ladder

- **L1 — validation gap identified.** A mismatch is confirmed structurally
  (extension/MIME/magic-byte disagreement accepted, or an archive path-
  traversal entry not rejected), but nothing has yet been retrieved or
  executed.
- **L2 — bypass accepted and retrievable.** The crafted object was accepted
  by validation and is retrievable from the server/storage/CDN, with
  response headers captured — but rendering or execution has not yet been
  observed.
- **L3 — execution or high-impact rendering proven.** A web shell actually
  executes server-side, or an SVG/HTML upload renders inline as script in a
  real browser context (stored XSS), or an archive extraction actually wrote
  outside its intended directory. This is the threshold for a reportable
  finding.
- **L4 — full compromise or systemic pipeline failure.** Remote code
  execution on the application or toolchain host, a write primitive that
  overwrites or corrupts unrelated data at scale, or proof that the gap
  applies across the entire upload pipeline (every content type, every
  serving path) rather than one narrow probe file.

Calibrate severity separately per [[severity-calibration]] — a stored-XSS-
via-upload finding on a low-traffic internal tool differs sharply from
unauthenticated RCE on an internet-facing upload endpoint, even though both
can start from the same magic-byte bypass technique.

## Validation and False-Positive Discipline

Apply [[closure-discipline]] before recording anything. Class-specific
traps to check before calling something confirmed:

- An object that is stored but genuinely never served back (no retrieval
  path exists, or it is always forced `attachment` with `nosniff` set) is
  not a rendering/execution finding, regardless of what content it contains
  — prove the actual retrieval, headers included, not just successful
  storage.
- A converter or processor that runs in a locked-down sandbox with no
  external I/O and no scripting engine available genuinely closes the
  toolchain-exploit path — confirm the actual deployed configuration rather
  than assuming a known CVE applies to "ImageMagick" generically.
- If AV/CDR scanning genuinely blocks retrieval until the scan completes
  (checked directly, not assumed), a race-window claim needs a real,
  reproduced timing win, not a theoretical one.
- A password-protected or otherwise-opaque archive that a scanner cannot
  inspect is a real finding only if the SAME opacity that defeats the
  scanner does not ALSO prevent the extraction step from processing it —
  confirm both ends of that gap independently.

## Impact

Remote code execution on the application server or a toolchain host,
persistent cross-site scripting via served/rendered uploads, storage
takeover or malware distribution through public object storage or a CDN,
and data loss or service degradation through archive-extraction overwrites
(Zip Slip) or decompression exhaustion (zip bombs).

## Summary

Secure uploads are a pipeline property, not a single check: strict type/size/
header validation at ingress, active-content stripping or transformation
before serving, and private storage with controlled, signed access all have
to hold together — a bypass anywhere one validator and one later consumer
disagree about what the file actually is.
