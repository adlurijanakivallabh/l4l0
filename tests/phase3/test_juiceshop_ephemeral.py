"""Hermetic tests for disposable Juice Shop lifecycle and clean baseline gate."""

from __future__ import annotations

import os
import subprocess

import httpx
import pytest

from reachagent.eval.juiceshop_ephemeral import (
    IMAGE_DIGEST,
    EphemeralConfig,
    EphemeralJuiceshopError,
    _ready,
    fresh_juiceshop,
    run_ephemeral_gate,
    validate_clean_baseline,
)
from reachagent.eval.juiceshop_harness import (
    VERIFIED_CHALLENGE_SCOPE,
    BaselineState,
    JuiceshopRun,
    Phase3GateResult,
    classify_baseline,
)
from reachagent.eval.juiceshop_live import JuiceshopTarget


def _tracker(*, solved: str | None = None) -> dict[str, dict[str, object]]:
    return {
        key: {
            "category": {
                "injection": "Injection",
                "file_upload": "Improper Input Validation",
                "xss": "XSS",
            }[scope],
            "solved": key == solved,
        }
        for key, scope in VERIFIED_CHALLENGE_SCOPE.items()
    }


def _response(tracker: dict[str, dict[str, object]], status_code: int = 200) -> httpx.Response:
    rows = [{"key": key, **value} for key, value in tracker.items()]
    return httpx.Response(status_code, json={"data": rows})


def test_clean_baseline_requires_all_verified_keys() -> None:
    assessment = classify_baseline(_tracker())
    assert assessment.state is BaselineState.CLEAN
    assert validate_clean_baseline(_tracker()).keys == frozenset(VERIFIED_CHALLENGE_SCOPE)


def test_dirty_baseline_is_not_measurable() -> None:
    assessment = classify_baseline(_tracker(solved="uploadTypeChallenge"))
    assert assessment.state is BaselineState.DIRTY
    with pytest.raises(EphemeralJuiceshopError, match="not measurable"):
        validate_clean_baseline(_tracker(solved="uploadTypeChallenge"))


def test_missing_baseline_key_is_invalid() -> None:
    tracker = _tracker()
    tracker.pop("uploadTypeChallenge")
    assert classify_baseline(tracker).state is BaselineState.INVALID


def test_wrong_category_and_non_boolean_solved_are_invalid() -> None:
    tracker = _tracker()
    tracker["loginAdminChallenge"] = {"category": "XSS", "solved": "false"}
    assert classify_baseline(tracker).state is BaselineState.INVALID


def test_not_measurable_report_has_no_numeric_percentages() -> None:
    run = JuiceshopRun.not_measurable(baseline=None, detail="baseline dirty: uploadTypeChallenge")
    report = Phase3GateResult(juiceshop=run).report()
    assert "NOT MEASURABLE" in report
    assert "Coverage and false-positive metrics were not scored." in report
    assert "0.0%" not in report


def test_readiness_retries_transient_failures() -> None:
    responses: list[httpx.Response | Exception] = [
        httpx.Response(503),
        httpx.ConnectError("starting", request=httpx.Request("GET", "http://target")),
        _response(_tracker()),
    ]
    calls = 0

    def getter(url: str, **kwargs: object) -> httpx.Response:
        nonlocal calls
        current = responses[calls]
        calls += 1
        if isinstance(current, Exception):
            raise current
        return current

    now = iter([0.0, 0.1, 0.2, 0.3, 0.4])
    target = JuiceshopTarget("http://127.0.0.1:32123")
    tracker = _ready(
        target,
        timeout=1.0,
        poll_interval=0.0,
        clock=lambda: next(now),
        sleep=lambda _: None,
        getter=getter,
    )
    assert calls == 3
    assert tracker == _tracker()


def test_readiness_rejects_timeout() -> None:
    target = JuiceshopTarget("http://127.0.0.1:32123")
    with pytest.raises(EphemeralJuiceshopError, match="readiness timeout"):
        _ready(
            target,
            timeout=0.0,
            poll_interval=0.0,
            clock=lambda: 1.0,
            sleep=lambda _: None,
            getter=lambda *_args, **_kwargs: httpx.Response(503),
        )


def test_fresh_lifecycle_uses_digest_no_volumes_and_tears_down() -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        if args[1] == "inspect":
            return subprocess.CompletedProcess(args, 0, "45678\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    with fresh_juiceshop(
        EphemeralConfig(readiness_timeout=1.0),
        runner=runner,
        clock=lambda: 0.0,
        sleep=lambda _: None,
        getter=lambda *_args, **_kwargs: _response(_tracker()),
        name_factory=lambda prefix: f"{prefix}test",
    ) as (target, baseline):
        assert target.base_url == "http://127.0.0.1:45678"
        assert baseline.tracker == _tracker()

    run_args = calls[0][0]
    cleanup_args = calls[-1][0]
    assert IMAGE_DIGEST in run_args
    assert "--publish" in run_args
    assert "--volume" not in run_args
    assert "-v" not in run_args
    assert cleanup_args[1:] == ["rm", "--force", "--volumes", "reachagent-juiceshop-test"]
    assert all(call[1]["shell"] is False for call in calls)


def test_fresh_lifecycle_tears_down_when_readiness_fails() -> None:
    calls: list[list[str]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[1] == "inspect":
            return subprocess.CompletedProcess(args, 0, "45678\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    with pytest.raises(EphemeralJuiceshopError):
        with fresh_juiceshop(
            EphemeralConfig(readiness_timeout=0.0),
            runner=runner,
            clock=lambda: 1.0,
            sleep=lambda _: None,
            getter=lambda *_args, **_kwargs: httpx.Response(503),
            name_factory=lambda prefix: f"{prefix}test",
        ):
            raise AssertionError("context should not yield")
    assert calls[-1][1:] == ["rm", "--force", "--volumes", "reachagent-juiceshop-test"]


def test_cleanup_failure_is_not_silent() -> None:
    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[1] == "inspect":
            return subprocess.CompletedProcess(args, 0, "45678\n", "")
        if args[1] == "rm":
            return subprocess.CompletedProcess(args, 1, "", "cleanup failed")
        return subprocess.CompletedProcess(args, 0, "", "")

    with pytest.raises(EphemeralJuiceshopError, match="cleanup failed"):
        with fresh_juiceshop(
            EphemeralConfig(readiness_timeout=1.0),
            runner=runner,
            clock=lambda: 0.0,
            sleep=lambda _: None,
            getter=lambda *_args, **_kwargs: _response(_tracker()),
            name_factory=lambda prefix: f"{prefix}cleanup",
        ):
            pass

    with pytest.raises(ValueError, match="pinned digest"):
        EphemeralConfig(image="bkimminich/juice-shop:latest")


def test_ephemeral_gate_requires_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_JUICESHOP_EPHEMERAL", raising=False)
    with pytest.raises(EphemeralJuiceshopError, match="disabled"):
        run_ephemeral_gate()


def test_fresh_context_config_reports_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_JUICESHOP_EPHEMERAL", raising=False)
    # Lifecycle stays injectable; public gate entrypoint enforces opt-in.
    assert EphemeralConfig().enabled is False


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("REACHAGENT_JUICESHOP_EPHEMERAL") != "1",
    reason="set REACHAGENT_JUICESHOP_EPHEMERAL=1 for Docker lifecycle integration",
)
def test_real_ephemeral_container_is_fresh() -> None:
    pytest.importorskip("docker")

    result = run_ephemeral_gate()
    assert result.environment_ok
