"""Oracle registry — maps an :class:`OracleMechanism` to its oracle (plan §7).

The Validator's ``run_oracle`` dispatches through here rather than importing a
concrete oracle directly, so the six-family set (§7) has one authoritative
lookup and adding a family is a single registration, not a scattered edit.

Phase 1 registers only the differential oracle (§15); the other five families
raise :class:`UnknownOracleError` until their phase implements them — an explicit
"not built yet", never a silent inconclusive.
"""

from __future__ import annotations

from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle
from reachagent.oracles.differential import DifferentialOracle


class UnknownOracleError(KeyError):
    """Raised when a mechanism has no registered oracle (unknown, or not yet built)."""


# One instance per family — oracles are stateless, pure over their evidence.
_REGISTRY: dict[OracleMechanism, Oracle] = {
    OracleMechanism.DIFFERENTIAL: DifferentialOracle(),
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
