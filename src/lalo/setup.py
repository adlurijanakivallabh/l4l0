"""``lalo-setup``: a tiny, interactive provider-credential wizard.

A real gap a Shannon-comparison audit found and this closes: the reference
agent's own ``setup`` command is a real interactive wizard - pick a
provider from a curated list, enter the credential via a masked prompt,
verified end to end before it's ever trusted. L4L0's own credential setup
was pure README prose naming four env vars with no picker, no masked
input, no verification - a missing or bad key was discovered only by
starting a real scan through the GUI and reading the resulting
``AllProvidersFailedError`` event, after the (potentially slow)
container/OAST startup already happened for nothing.

This is a narrow, deliberate exception to ``pyproject.toml``'s own stated
"no CLI, no TUI" design center for the *product* (``lalo-gui`` stays the
only way to actually run a scan) - a one-shot, stdlib-only setup helper is
not a competing interface to the GUI, it just gets a working credential
into a ``.env`` file before the GUI's first real launch. Reuses
``core.providers.verify_router`` directly rather than reimplementing any
verification logic of its own - the same real, cheap completion call
``scan.py`` already runs as its own provider preflight.
"""

from __future__ import annotations

import getpass
from pathlib import Path

from .core.config import CURATED_PROVIDERS, ProviderSpec, load_settings
from .core.env_file import merge_env_file
from .core.providers import build_router, verify_router

_ENV_PATH = Path(".env")


def _prompt_provider() -> ProviderSpec:
    print("L4L0 provider setup\n")
    for i, spec in enumerate(CURATED_PROVIDERS, start=1):
        needs = " + ".join((*spec.candidate_key_envs[:1], *spec.extra_required_envs))
        print(f"  {i}. {spec.id}  (needs: {needs})")
    choice = input(f"\nPick a provider [1-{len(CURATED_PROVIDERS)}]: ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(CURATED_PROVIDERS)):
        raise ValueError(f"not a valid choice: {choice!r}")
    return CURATED_PROVIDERS[int(choice) - 1]


def _collect_env(spec: ProviderSpec) -> dict[str, str]:
    key_env = spec.candidate_key_envs[0]
    api_key = getpass.getpass(f"API key for {spec.id} ({key_env}): ").strip()
    if not api_key:
        raise ValueError("an empty API key is not usable")
    env = {key_env: api_key}
    for extra_env in spec.extra_required_envs:
        value = input(f"{extra_env}: ").strip()
        if not value:
            raise ValueError(f"{extra_env} is required for {spec.id!r} and cannot be empty")
        env[extra_env] = value
    return env


def main() -> None:
    try:
        spec = _prompt_provider()
        env = _collect_env(spec)
    except (ValueError, EOFError, KeyboardInterrupt) as exc:
        print(f"\nsetup cancelled: {exc}")
        raise SystemExit(1) from None

    # _collect_env already guarantees every env var this spec needs
    # (candidate_key_envs[0] plus every extra_required_envs entry) is set
    # and non-empty, so settings.resolved is guaranteed to include spec.id
    # here - no separate "did it resolve" check needed.
    settings = load_settings(env)
    print("\nVerifying (a real, minimal completion call)...")
    router = build_router(settings)
    ok, reason = verify_router(router)[spec.id]
    if not ok:
        print(f"✗ {spec.id} failed verification: {reason} - nothing written")
        raise SystemExit(1)

    merge_env_file(_ENV_PATH, env)
    print(f"✓ {spec.id} verified working. Wrote {_ENV_PATH.resolve()}")
    print(f"Run the GUI with:  uv run --env-file {_ENV_PATH} lalo-gui")


if __name__ == "__main__":
    main()
