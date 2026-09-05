"""Provider/model configuration — curated table + generic fallback + explicit spec.

Design, informed by a reference CLI's config resolver (env-first, a declarative
table mapping each credential to its candidate env vars, a human-readable
credential hint per provider, and a `<provider>:<model>` single spec string for
picking the active model): every curated entry beyond the native Anthropic one
is an instance of one generic OpenAI-compatible adapter kind (works for OpenAI
itself, a local gateway, OpenRouter, Ollama, vLLM — anything speaking the
OpenAI chat/completions schema), not a bespoke one-off class per name. A second
reference agent's own multi-provider layer achieves the same "no bespoke class
per provider name" property, just via a third-party routing library instead of
a hand-rolled HTTP adapter — this module's contribution is the curated table +
multi-env-var + explicit-spec-override shape, not the generic-adapter idea in
isolation. A curated provider can also require MORE than one env var (mirrors
the first reference's region+token style multi-var providers) via
``extra_required_envs`` — used here to make a provider's model id mandatory,
not optional, for exactly the reason described on the ``custom`` spec below.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

ProviderKind = Literal["anthropic", "openai_compatible"]

# Explicit single-spec override: LALO_MODEL="<provider>:<model>" forces that
# provider (if configured) to the front of the failover chain with that model.
_MODEL_SPEC_ENV = "LALO_MODEL"


@dataclass(frozen=True)
class ProviderSpec:
    """A curated provider's static shape — not its resolved credentials."""

    id: str
    kind: ProviderKind
    candidate_key_envs: tuple[str, ...]  # first one SET wins
    credential_hint: str
    default_model: str
    extra_required_envs: tuple[str, ...] = ()
    default_base_url: str | None = None  # openai_compatible only
    base_url_env: str | None = None  # optional override env for the base URL
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    model_env: str | None = None  # optional override env for the model id


# Curated providers, in default failover preference order. A local/self-hosted
# gateway is tried first (fast, free, under the operator's control), then
# hosted providers.
CURATED_PROVIDERS: tuple[ProviderSpec, ...] = (
    ProviderSpec(
        id="opencodex",
        kind="openai_compatible",
        candidate_key_envs=("OPENCODEX_API_KEY",),
        credential_hint="OPENCODEX_API_KEY",
        default_model="gpt-5.6-luna",
        default_base_url="http://localhost:10100",
        base_url_env="OPENCODEX_BASE_URL",
        auth_header="x-opencodex-api-key",
        auth_prefix="",
        model_env="OPENCODEX_MODEL",
    ),
    ProviderSpec(
        id="anthropic",
        kind="anthropic",
        candidate_key_envs=("ANTHROPIC_API_KEY",),
        credential_hint="ANTHROPIC_API_KEY",
        default_model="claude-sonnet-5",
        model_env="ANTHROPIC_MODEL",
    ),
    ProviderSpec(
        id="openai",
        kind="openai_compatible",
        candidate_key_envs=("OPENAI_API_KEY",),
        credential_hint="OPENAI_API_KEY",
        default_model="gpt-5.4",
        default_base_url="https://api.openai.com",
        model_env="OPENAI_MODEL",
    ),
    ProviderSpec(
        id="gemini",
        kind="openai_compatible",
        candidate_key_envs=("GEMINI_API_KEY",),
        credential_hint="GEMINI_API_KEY",
        default_model="gemini-2.5-pro",
        default_base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        model_env="GEMINI_MODEL",
    ),
    # Generic slot for anything not curated above (mirrors a "bring your own
    # provider" generic-credential path) — any OpenAI-compatible endpoint.
    # LALO_CUSTOM_MODEL is required, not just an optional override: a reference
    # CLI's own <provider>:<model> resolver treats the model id as a mandatory
    # part of the credential contract for exactly this reason — an optional
    # model with an empty-string default resolves "successfully" with model=""
    # and fails every real request instead of failing the config check.
    ProviderSpec(
        id="custom",
        kind="openai_compatible",
        candidate_key_envs=("LALO_CUSTOM_API_KEY",),
        credential_hint="LALO_CUSTOM_API_KEY + LALO_CUSTOM_BASE_URL + LALO_CUSTOM_MODEL",
        default_model="",
        extra_required_envs=("LALO_CUSTOM_BASE_URL", "LALO_CUSTOM_MODEL"),
        base_url_env="LALO_CUSTOM_BASE_URL",
        model_env="LALO_CUSTOM_MODEL",
    ),
)


@dataclass(frozen=True)
class ResolvedProvider:
    """A curated provider WITH its credentials actually resolved from the environment."""

    id: str
    kind: ProviderKind
    api_key: str
    model: str
    base_url: str | None = None
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "


@dataclass(frozen=True)
class ModelSpec:
    provider_id: str
    model: str


def parse_model_spec(spec: str) -> ModelSpec | str:
    """Parse ``<provider>:<model-id>``. Splits on the FIRST colon only, so a
    colon inside the model id survives. Returns an error string, never raises."""
    trimmed = spec.strip()
    sep = trimmed.find(":")
    malformed = f'{_MODEL_SPEC_ENV} must be "<provider>:<model-id>", got {trimmed!r}'
    if sep == -1:
        return malformed
    provider_id, model_id = trimmed[:sep].strip(), trimmed[sep + 1 :].strip()
    if not provider_id or not model_id:
        return malformed
    return ModelSpec(provider_id, model_id)


def _resolve_one(spec: ProviderSpec, env: Mapping[str, str]) -> ResolvedProvider | None:
    api_key = next((env[e] for e in spec.candidate_key_envs if env.get(e)), None)
    if api_key is None:
        return None
    if any(not env.get(e) for e in spec.extra_required_envs):
        return None
    model = (env.get(spec.model_env) if spec.model_env else None) or spec.default_model
    base_url = (env.get(spec.base_url_env) if spec.base_url_env else None) or spec.default_base_url
    return ResolvedProvider(
        id=spec.id,
        kind=spec.kind,
        api_key=api_key,
        model=model,
        base_url=base_url,
        auth_header=spec.auth_header,
        auth_prefix=spec.auth_prefix,
    )


@dataclass(frozen=True)
class Settings:
    resolved: tuple[ResolvedProvider, ...]  # only providers with credentials present
    failover_order: tuple[str, ...]  # provider ids, in the order to try

    def get(self, provider_id: str) -> ResolvedProvider | None:
        return next((p for p in self.resolved if p.id == provider_id), None)

    def missing_credential_hints(self) -> dict[str, str]:
        """Human-readable hint for every curated provider that ISN'T configured."""
        configured = {p.id for p in self.resolved}
        return {s.id: s.credential_hint for s in CURATED_PROVIDERS if s.id not in configured}


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Resolve every curated provider against the environment (env-first, no
    file layer needed for a single-operator tool) and build the failover order.

    An explicit ``LALO_MODEL=<provider>:<model>`` pins that provider (if it has
    credentials) to the FRONT of the chain with that model, overriding its
    curated default model.
    """
    environ: Mapping[str, str] = env if env is not None else os.environ
    resolved = [r for spec in CURATED_PROVIDERS if (r := _resolve_one(spec, environ)) is not None]

    order = [p.id for p in resolved]
    spec_raw = environ.get(_MODEL_SPEC_ENV)
    if spec_raw:
        parsed = parse_model_spec(spec_raw)
        if isinstance(parsed, ModelSpec):
            forced = next((p for p in resolved if p.id == parsed.provider_id), None)
            if forced is not None:
                resolved = [
                    ResolvedProvider(
                        id=forced.id,
                        kind=forced.kind,
                        api_key=forced.api_key,
                        model=parsed.model,
                        base_url=forced.base_url,
                        auth_header=forced.auth_header,
                        auth_prefix=forced.auth_prefix,
                    ),
                    *[p for p in resolved if p.id != parsed.provider_id],
                ]
                order = [parsed.provider_id, *[i for i in order if i != parsed.provider_id]]

    return Settings(resolved=tuple(resolved), failover_order=tuple(order))
