"""Oracle registry — maps an :class:`OracleMechanism` to its oracle (plan §7).

The Validator's ``run_oracle`` dispatches through here rather than importing a
concrete oracle directly, so the six-family set (§7) has one authoritative
lookup and adding a family is a single registration, not a scattered edit.

Phase 1 registered only the differential oracle (§15); Phase 2 adds the
``business_rule_invariant`` family (§5, §7). The still-unimplemented families
raise :class:`UnknownOracleError` until their phase builds them — an explicit
"not built yet", never a silent inconclusive.
"""

from __future__ import annotations

from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle
from reachagent.oracles.business_rule import BusinessRuleOracle
from reachagent.oracles.differential import DifferentialOracle
from reachagent.oracles.oob_callback import OOBCallbackOracle
from reachagent.oracles.timing_statistical import TimingStatisticalOracle


class UnknownOracleError(KeyError):
    """Raised when a mechanism has no registered oracle (unknown, or not yet built)."""


# One instance per family — oracles are stateless, pure over their evidence.
_REGISTRY: dict[OracleMechanism, Oracle] = {
    OracleMechanism.DIFFERENTIAL: DifferentialOracle(),
    OracleMechanism.BUSINESS_RULE_INVARIANT: BusinessRuleOracle(),
    OracleMechanism.TIMING_STATISTICAL: TimingStatisticalOracle(),
    OracleMechanism.OOB_CALLBACK: OOBCallbackOracle(),
}


def get_oracle(mechanism: OracleMechanism) -> Oracle:
    """Return the oracle for ``mechanism`` or raise :class:`UnknownOracleError`.

    Refusing an unregistered mechanism loudly is deliberate: a mistyped or
    not-yet-implemented family must never fall through to a default that could
    manufacture (or suppress) a confirmation.
    """
    try:
        return _REGISTRY[mechanism]
    except KeyError as exc:
        raise UnknownOracleError(f"no oracle registered for mechanism {mechanism!r}") from exc
