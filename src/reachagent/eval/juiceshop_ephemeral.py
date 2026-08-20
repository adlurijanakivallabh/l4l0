"""Opt-in disposable Juice Shop lifecycle for measurable Phase 3 runs."""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol, cast

import httpx

from reachagent.eval.juiceshop_harness import (
    VERIFIED_CHALLENGE_SCOPE,
    BaselineState,
    JuiceshopRun,
    Phase3GateResult,
    classify_baseline,
    validate_tracker_snapshot,
)
from reachagent.eval.juiceshop_live import JuiceshopTarget, run_juiceshop

IMAGE_DIGEST = (
    "bkimminich/juice-shop@sha256:e68144772ebaaca0ec117b38d44903af92416793230288ef7c5437fc4f26850a"
)
DEFAULT_CONTAINER_PREFIX = "reachagent-juiceshop-"
DEFAULT_READINESS_TIMEOUT = 120.0
DEFAULT_POLL_INTERVAL = 1.0


class EphemeralJuiceshopError(RuntimeError):
    """Fresh-target lifecycle or baseline validation failed."""


class RunProcess(Protocol):
    def __call__(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]: ...


_DEFAULT_RUNNER: RunProcess = cast("RunProcess", subprocess.run)


@dataclass(frozen=True)
class CleanBaseline:
    """Validated clean tracker baseline for one measurable run."""

    tracker: dict[str, dict[str, object]]

    @property
    def keys(self) -> frozenset[str]:
        return frozenset(VERIFIED_CHALLENGE_SCOPE)


@dataclass(frozen=True)
class EphemeralConfig:
    """Pinned disposable-container configuration."""

    image: str = IMAGE_DIGEST
    name_prefix: str = DEFAULT_CONTAINER_PREFIX
    readiness_timeout: float = DEFAULT_READINESS_TIMEOUT
    poll_interval: float = DEFAULT_POLL_INTERVAL

    def __post_init__(self) -> None:
        if self.image != IMAGE_DIGEST:
            raise ValueError("ephemeral Juice Shop image must use pinned digest")

    @property
    def enabled(self) -> bool:
        return os.environ.get("REACHAGENT_JUICESHOP_EPHEMERAL") == "1"


def _container_name(prefix: str = DEFAULT_CONTAINER_PREFIX) -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


def _docker(
    args: list[str], *, runner: RunProcess = _DEFAULT_RUNNER, check: bool = True
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            ["docker", *args],
            capture_output=True,
            text=True,
            check=check,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise EphemeralJuiceshopError("not measurable: Docker CLI unavailable") from exc
    except subprocess.CalledProcessError as exc:
        raise EphemeralJuiceshopError(
            f"not measurable: Docker command failed ({exc.returncode})"
        ) from exc
    if check and result.returncode != 0:
        raise EphemeralJuiceshopError(
            f"not measurable: Docker command failed ({result.returncode})"
        )
    return result


def _host_port(name: str, *, runner: RunProcess = _DEFAULT_RUNNER) -> int:
    result = _docker(
        [
            "inspect",
            '--format={{(index (index .NetworkSettings.Ports "3000/tcp") 0).HostPort}}',
            name,
        ],
        runner=runner,
    )
    try:
        return int(result.stdout.strip())
    except ValueError as exc:
        raise EphemeralJuiceshopError("not measurable: Docker returned no host port") from exc


def _tracker_from_response(response: httpx.Response) -> dict[str, dict[str, object]]:
    if response.status_code != 200:
        raise EphemeralJuiceshopError(f"tracker HTTP {response.status_code}")
    body = response.json()
    if not isinstance(body, dict) or not isinstance(body.get("data"), list):
        raise EphemeralJuiceshopError("tracker response has no data list")
    tracker: dict[str, dict[str, object]] = {}
    for row in body["data"]:
        if not isinstance(row, dict):
            raise EphemeralJuiceshopError("tracker response contains malformed row")
        key = row.get("key")
        if not isinstance(key, str) or key in tracker:
            raise EphemeralJuiceshopError("tracker response contains invalid or duplicate key")
        tracker[key] = {
            "category": row.get("category"),
            "solved": row.get("solved"),
        }
    return tracker


def _ready(
    target: JuiceshopTarget,
    *,
    timeout: float,
    poll_interval: float,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    getter: Callable[..., httpx.Response] = httpx.get,
) -> dict[str, dict[str, object]]:
    """Wait for valid tracker schema plus at least one known-unsolved key."""
    deadline = clock() + timeout
    last_error = "target did not become ready"
    while clock() < deadline:
        try:
            tracker = _tracker_from_response(getter(f"{target.api}/api/Challenges", timeout=3.0))
            assessment = validate_tracker_snapshot(tracker)
            if assessment.state is BaselineState.CLEAN:
                if any(not bool(tracker[key]["solved"]) for key in VERIFIED_CHALLENGE_SCOPE):
                    return tracker
                last_error = "tracker ready but all verified challenges are solved"
            elif assessment.state is BaselineState.INVALID:
                last_error = assessment.detail
            else:
                # Dirty but complete target is measurable as a readiness response;
                # clean-baseline validation below converts it to NOT_MEASURABLE.
                return tracker
        except (httpx.HTTPError, ValueError, TypeError, KeyError, EphemeralJuiceshopError) as exc:
            last_error = str(exc)
        sleep(poll_interval)
    raise EphemeralJuiceshopError(f"not measurable: Juice Shop readiness timeout: {last_error}")


def validate_clean_baseline(
    tracker: dict[str, dict[str, object]],
) -> CleanBaseline:
    """Reject dirty or invalid baselines before any detector request runs."""
    assessment = classify_baseline(tracker)
    if assessment.state is not BaselineState.CLEAN:
        raise EphemeralJuiceshopError(f"not measurable: {assessment.detail}")
    return CleanBaseline(tracker)


def _not_measurable(detail: str) -> Phase3GateResult:
    run = JuiceshopRun.not_measurable(baseline=None, detail=detail)
    return Phase3GateResult(
        juiceshop=run,
        setup_failures=1,
        setup_failure_details=[detail],
    )


@contextmanager
def fresh_juiceshop(
    config: EphemeralConfig | None = None,
    *,
    runner: RunProcess = _DEFAULT_RUNNER,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    getter: Callable[..., httpx.Response] = httpx.get,
    name_factory: Callable[[str], str] = _container_name,
) -> Iterator[tuple[JuiceshopTarget, CleanBaseline]]:
    """Start disposable pinned container, validate clean tracker, always remove it."""
    config = config or EphemeralConfig()
    name = name_factory(config.name_prefix)
    started = False
    primary_error: BaseException | None = None
    try:
        _docker(
            [
                "run",
                "--detach",
                "--name",
                name,
                "--publish",
                "127.0.0.1::3000",
                "--restart=no",
                config.image,
            ],
            runner=runner,
        )
        started = True
        port = _host_port(name, runner=runner)
        target = JuiceshopTarget(f"http://127.0.0.1:{port}")
        tracker = _ready(
            target,
            timeout=config.readiness_timeout,
            poll_interval=config.poll_interval,
            clock=clock,
            sleep=sleep,
            getter=getter,
        )
        yield target, validate_clean_baseline(tracker)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if started:
            try:
                cleanup = _docker(["rm", "--force", "--volumes", name], runner=runner, check=False)
                if cleanup.returncode != 0:
                    raise EphemeralJuiceshopError(
                        f"not measurable: Docker cleanup failed ({cleanup.returncode})"
                    )
            except BaseException as exc:
                if primary_error is not None:
                    primary_error.add_note(str(exc))
                else:
                    raise


def run_ephemeral_gate(
    config: EphemeralConfig | None = None,
    *,
    runner: RunProcess = _DEFAULT_RUNNER,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    getter: Callable[..., httpx.Response] = httpx.get,
    name_factory: Callable[[str], str] = _container_name,
) -> Phase3GateResult:
    """Run clean-target Juice Shop gate only with explicit environment opt-in."""
    config = config or EphemeralConfig()
    if not config.enabled:
        raise EphemeralJuiceshopError(
            "ephemeral gate disabled; set REACHAGENT_JUICESHOP_EPHEMERAL=1"
        )
    try:
        with fresh_juiceshop(
            config,
            runner=runner,
            clock=clock,
            sleep=sleep,
            getter=getter,
            name_factory=name_factory,
        ) as (target, baseline):
            run = run_juiceshop(target, before=baseline.tracker)
            return Phase3GateResult(juiceshop=run)
    except EphemeralJuiceshopError as exc:
        return _not_measurable(str(exc))
    except subprocess.CalledProcessError as exc:
        return _not_measurable(f"not measurable: Docker command failed ({exc.returncode})")
    except FileNotFoundError:
        return _not_measurable("not measurable: Docker CLI unavailable")
