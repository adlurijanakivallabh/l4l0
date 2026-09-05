# L4L0

**L4L0** (package `lalo`) is an autonomous web/API + network + cloud offensive-security
agent. You point it at an authorized engagement and give it an objective; it runs an
autonomous think→act→observe loop — freely running or installing any tool it needs
inside a disposable, host-isolated container — and reports everything it finds with
honest, non-blocking confidence scores.

- **Execution model:** mission prompt → free-shell agentic loop → the agent finds,
  exploits, and confirms vulnerabilities using real tools + skill playbooks +
  reasoning (not fixed detectors).
- **Confirmation:** an independent, LLM-driven adversarial review ("assume false,
  disprove from real captured evidence") + a proof ladder. Nothing is withheld —
  the verdict adjusts a transparent confidence score.
- **Safety floor:** scope is code-enforced (authorized targets only); the runtime
  container has no host mounts, no Docker socket, and dropped capabilities, so the
  free shell never reaches your machine.

Architecture: see `docs/CODEBASE_MAP.md` and `CLAUDE.md`.

## Quick start

```bash
uv sync
uv run pytest tests/lalo -q          # test suite
uv run lalo-gui --host 127.0.0.1 --port 8000   # web GUI
```

Provide an LLM via a provider key (e.g. `ANTHROPIC_API_KEY`, or a local
`OPENCODEX_API_KEY` gateway) — the multi-provider router fails over between them.

## Development

- Python 3.13, `uv`, Ruff (lint+format, `S` security rules), `mypy --strict`, pytest.
- Package at `src/lalo/`, tests at `tests/lalo/`.

Third-party components and the clean-room source-provenance policy: see
`THIRD_PARTY_NOTICES.md`.
