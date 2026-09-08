"""A real, end-to-end live eval: an actual autonomous AgentLoop run, driven
through ScanRunner exactly as an operator would run it, against a live
VAmPI container - scored by the eval harness and appended to a durable,
git-tracked eval-history file.

Closes a real, previously uncomfortable gap an audit found: eval/cases.py's
own scoring code (recall/precision/calibration) and eval/targets.py's own
ground-truth LAB_TARGETS have genuine, well-built mechanics, but had NEVER
actually been exercised against a real LLM-driven agent run -
test_eval_live_vampi.py's own "live" test deliberately bypasses AgentLoop
(its own docstring explains why: wiring a full autonomous run end to end
was out of scope for that phase) - it fires one hand-picked HTTP request
and calls record_finding directly. Until this test ran for real, L4L0 had
produced zero real evidence of how well its actual autonomous
think-act-observe loop performs against a genuine target, independent of
how well any individual component (scoring, confidence, redaction, ...) is
tested in isolation.

Same bring-up convention as test_eval_live_vampi.py: this test does NOT
manage the target container's lifecycle itself - bring VAmPI up manually
before running it (docker run -d --rm -p 5000:5000 erev0s/vampi) and tear
it down immediately after, per this project's own "eval targets on-demand
only" discipline (CLAUDE.md). It also needs a real, working LLM provider
credential in the environment - this is a genuine live run, not a scripted
one - and the disposable lalo-runtime image already built (the free-shell
tool needs it, exactly like a real operator-launched scan). Skipped if any
of the three isn't available, exactly like every other real-infra live
test in this suite.

_HISTORY_PATH is intentionally a real, committed file, not a tmp_path
fixture: the whole point (per scoring.py's own append_composite_history
docstring, "the project's own eval trend across its development") is a
durable record that survives across runs and across commits. Each real
run appends one dated entry; nothing already there is ever overwritten.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest

from lalo.core.config import load_settings
from lalo.eval.cases import run_case
from lalo.eval.scoring import append_composite_history, score_composite
from lalo.eval.targets import VAMPI
from lalo.graph.model import ReachabilityGraph
from lalo.runtime.container import docker_available
from lalo.scan import ScanConfig, ScanRunner

VAMPI_HOST = "127.0.0.1"
VAMPI_PORT = 5000

_HISTORY_PATH = Path(__file__).resolve().parents[2] / "docs" / "eval_history.json"


def _vampi_reachable() -> bool:
    try:
        with socket.create_connection((VAMPI_HOST, VAMPI_PORT), timeout=0.5):
            return True
    except OSError:
        return False


def _a_real_provider_is_configured() -> bool:
    return bool(load_settings().resolved)


@pytest.mark.live
@pytest.mark.skipif(not _vampi_reachable(), reason="VAmPI is not running on 127.0.0.1:5000")
@pytest.mark.skipif(not docker_available(), reason="docker is not reachable")
@pytest.mark.skipif(
    not _a_real_provider_is_configured(),
    reason="no real LLM provider credentials are configured in the environment",
)
def test_live_autonomous_agent_run_against_vampi_is_scored_and_recorded(tmp_path: Path) -> None:
    config = ScanConfig(
        mission=(
            "Assess the VAmPI REST API at http://127.0.0.1:5000 for OWASP API "
            "Top 10 vulnerabilities. Focus on broken access control (one user "
            "reading or modifying another user's data), SQL injection, mass "
            "assignment (undocumented fields accepted on registration/update), "
            "weak credentials (password policy, username enumeration), and JWT "
            "weaknesses (a weak or guessable signing secret). Use the http tool "
            "directly against http://127.0.0.1:5000 - this is a REST API, no "
            "browser needed. Register findings as you confirm them."
        ),
        target_specs=[f"{VAMPI_HOST}:{VAMPI_PORT}"],
        run_dir=tmp_path / "run",
        max_steps=20,
        max_duration_s=900.0,  # a hard 15-real-minute ceiling on one live eval run
    )
    outcome = ScanRunner(config, env=None).run()

    graph = ReachabilityGraph.load(config.run_dir / "graph.json")
    case_result = run_case(VAMPI, graph)
    composite = score_composite([case_result])

    append_composite_history(
        composite,
        _HISTORY_PATH,
        label="vampi-live-agent",
        recorded_at=datetime.now(UTC).isoformat(),
    )

    # A real assertion, not just "it ran": the autonomous loop must have
    # produced at least one real, scored finding for this to mean anything.
    assert case_result.found_classes, (
        f"live agent run against VAmPI found nothing at all "
        f"(stop_reason={outcome.result.stop_reason!r}) - see {config.run_dir} for the transcript"
    )
