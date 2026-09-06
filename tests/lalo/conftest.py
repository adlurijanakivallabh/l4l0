"""Suite-wide fixtures - global-state resets that no single test file owns.

``core.redaction``'s ``set_redaction_enabled`` toggles a process-wide
module global (see its own docstring for why): unlike the pre-existing
``shared_redactor()`` exact-match secret set (unique marker strings across
tests rarely collide, so that leakage has never caused an observable
failure), a left-disabled toggle is all-or-nothing - it would silently
make every OTHER test file's redaction assertions fail depending purely on
what ran earlier in the same pytest process. Reset after every test in the
whole suite, not just within one file, since ``ScanConfig.redact_findings``
defaults to ``False`` and any real ``ScanRunner.run()`` call anywhere sets
it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from lalo.core.redaction import set_redaction_enabled


@pytest.fixture(autouse=True)
def _restore_redaction_enabled() -> Iterator[None]:
    yield
    set_redaction_enabled(True)
