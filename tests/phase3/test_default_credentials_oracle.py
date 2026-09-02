"""Default credentials — STRUCTURAL DEFAULT_CREDENTIALS oracle tests (§7).

v3: the fixed decide() decision logic this file tested was removed (live
judgment now goes through reachagent.oracles.llm_judgment.judge), so every
test here tested removed functionality and was deleted. The detector/driver
tests live in tests/scan/test_default_credentials_driver.py.
"""

from __future__ import annotations
