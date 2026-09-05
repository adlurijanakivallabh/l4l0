# Third-Party Notices

## Source-code provenance policy

L4L0's source is **original (clean-room)**. Prior agentic-pentest projects were
read for understanding of proven patterns, but their source code is **not copied**
into this repository. This policy exists for concrete legal reasons and is not
optional:

- One studied project is licensed **AGPL-3.0** — copying its code would place
  L4L0 itself under AGPL-3.0 (including a network-use source-disclosure
  obligation). It is treated as **idea-level reference only**, with care to avoid
  line-by-line derivation.
- One studied project mixes **MIT** with **proprietary, research-only** additions
  — its proprietary portions are **idea-level reference only**.
- The remaining studied projects are **MIT / Apache-2.0** (permissive). Even so,
  to keep L4L0's source free of external attribution obligations and of any
  external project's name (a project requirement), their code is also **not
  copied** — patterns are reimplemented originally.

Consequence: there are no external agent-project names anywhere in L4L0's code or
docs, and no external-project copyright/attribution obligation attaches to L4L0's
own source.

## Bundled third-party components

L4L0 depends on third-party Python packages (declared in `pyproject.toml`), each
under its own license as published on PyPI. It may also bundle public wordlist /
payload corpora at build time; those retain their upstream licenses and are
recorded here as they are added:

| Component | Type | License | Notes |
|-----------|------|---------|-------|
| (Python runtime deps) | pip packages | per-package (see PyPI) | httpx, networkx, fastapi, uvicorn, pyyaml, mcp, playwright, defusedxml, weasyprint, html2docx |
| (payload/wordlist corpora) | data | per-corpus | recorded here when vendored (e.g. SecLists — MIT) |

This file is updated whenever a component with attribution requirements is
actually bundled into the distribution.
