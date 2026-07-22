"""Business-logic invariant templates (plan §5, §7, §9).

The four-template library — single-use reuse, quantity/limit, price/parameter
tamper, and step-order — that instantiates concrete checks from recon-discovered
resources and fires them as sequential replays, feeding the deterministic
``business_rule_invariant`` oracle. No template decides a verdict and no LLM is
in the loop; a confirmed business-logic violation is reachable only via
``run_oracle`` → ``write_finding`` (§13), exactly like the differential oracle.
"""

from __future__ import annotations

from reachagent.business_logic.runner import ReplayOutcome, SequentialReplayRunner
from reachagent.business_logic.templates import (
    TEMPLATES,
    InstantiationResult,
    PriceTamperTemplate,
    QuantityLimitTemplate,
    ReplayStep,
    SingleUseReuseTemplate,
    StepOrderTemplate,
    StepRole,
    Template,
    TemplateCheck,
    instantiate_all,
)

__all__ = [
    "TEMPLATES",
    "InstantiationResult",
    "PriceTamperTemplate",
    "QuantityLimitTemplate",
    "ReplayOutcome",
    "ReplayStep",
    "SequentialReplayRunner",
    "SingleUseReuseTemplate",
    "StepOrderTemplate",
    "StepRole",
    "Template",
    "TemplateCheck",
    "instantiate_all",
]
