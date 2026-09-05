# L4L0

**L4L0** (package `lalo`) is an autonomous web/API + network + cloud offensive-security
agent. You point it at an authorized engagement and give it an objective; it runs an
autonomous think→act→observe loop — freely running or installing any tool it needs
inside a disposable, host-isolated container — and reports everything it finds with
honest, non-blocking confidence scores.

- **Execution model:** mission prompt → free-shell agentic loop → the agent finds,
  exploits, and confirms vulnerabilities using real tools + skill playbooks +
  reasoning (not fixed detectors). It can spawn focused sub-agents for parallel
  lines of investigation.
- **Confirmation:** an independent, LLM-driven adversarial review ("assume false,
  disprove from real captured evidence") + a proof ladder. Nothing is withheld —
  the verdict adjusts a transparent confidence score.
- **Safety floor:** scope is code-enforced (authorized targets only, for both the
  `http` and `browser` tools); the runtime container has no host mounts, no Docker
  socket, and dropped capabilities, so the free shell never reaches your machine.
- **Reporting:** Markdown, JSON, SARIF, PDF, and DOCX, generated deterministically
  from the same graph of what the agent actually observed — never an LLM call.

Architecture: see `docs/CODEBASE_MAP.md` and `CLAUDE.md`.

## Quick start

```bash
uv sync
uv run pytest tests/lalo -q -m "not integration"   # test suite (fast; needs no browser/Docker)

# Build the disposable per-scan runtime image once (large — installs a broad
# recon/exploitation toolkit; only needed before your first live scan):
docker build -t lalo-runtime:latest -f docker/lalo-runtime.Dockerfile .

uv run lalo-gui   # web GUI — prints a tokened URL, e.g. http://127.0.0.1:8765/?token=...
```

Open the printed URL, fill in a mission and one or more targets in the launch
form, and start a scan. Provide an LLM via a provider key (e.g.
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, or a local
`OPENCODEX_API_KEY`/`LALO_CUSTOM_*` gateway) — the multi-provider router fails
over between whichever of these are actually configured. A working `docker`
daemon is required: the agent's free shell only ever runs inside the disposable
container built above, never on your host.

## Development

- Python 3.13, `uv`, Ruff (lint+format, `S` security rules), `mypy --strict`, pytest.
- Package at `src/lalo/`, tests at `tests/lalo/`.
- `pytest -m "not integration"` skips the handful of tests that spin up a real
  headless browser; `pytest -m integration` runs just those. `pytest -m live`
  is a separate marker for tests needing a live target container (self-skip if
  one isn't running).

## License

MIT — see `LICENSE`. Third-party components and the clean-room source-provenance
policy: see `THIRD_PARTY_NOTICES.md`.

## Responsible use

L4L0 tests only the engagement you declare — it does not autonomously attack
hosts you never named, and it will not run without a working provider
credential and a real Docker daemon for host isolation. You are responsible for
having explicit authorization for every target you point it at. See `CLAUDE.md`
for the full safety posture.
