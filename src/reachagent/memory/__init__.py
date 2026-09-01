"""Cross-engagement advisory memory ("My additions") — see pattern_db."""

from reachagent.memory.pattern_db import (
    Pattern,
    load_patterns,
    patterns_for_technology,
    record_confirmed_pattern,
)

__all__ = [
    "Pattern",
    "load_patterns",
    "patterns_for_technology",
    "record_confirmed_pattern",
]
