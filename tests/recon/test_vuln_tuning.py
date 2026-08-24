"""Hermetic tests for live-reasoning vuln-class targeting — proposal-only, allowlist-gated."""

from __future__ import annotations

from unittest.mock import Mock

from reachagent.recon.vuln_tuning import (
    _SAFE_DEFAULT_CLASSES,
    VULN_CLASS_ALLOWLIST,
    VulnTargetChoice,
    propose_vuln_targets,
)


def _fake_client(returning: dict[str, object]) -> Mock:
    m = Mock()
    m.propose.return_value = returning
    return m  # type: ignore[no-any-return]


def test_mocked_valid_allowlisted_returns_subset() -> None:
    raw = {"vuln_classes": ["file_upload", "path_traversal"]}
    choice = propose_vuln_targets({"param_name": "file"}, client=_fake_client(raw))
    assert choice.vuln_classes == ("file_upload", "path_traversal")
    assert all(c in VULN_CLASS_ALLOWLIST for c in choice.vuln_classes)


def test_mocked_outside_allowlist_fallback_safe_default() -> None:
    raw: dict[str, object] = {"vuln_classes": ["rce", "file_upload"]}  # rce not in allowlist
    choice = propose_vuln_targets({"param_name": "file"}, client=_fake_client(raw))
    # invented string → fallback, not use invalid
    assert "rce" not in choice.vuln_classes
    assert choice.vuln_classes == _SAFE_DEFAULT_CLASSES


def test_mocked_non_list_fallback() -> None:
    raw: dict[str, object] = {"vuln_classes": "file_upload"}  # type: ignore[dict-item]
    choice = propose_vuln_targets({"param_name": "file"}, client=_fake_client(raw))
    assert choice.vuln_classes == _SAFE_DEFAULT_CLASSES


def test_mocked_invented_string_logs_and_fallback() -> None:
    raw: dict[str, object] = {"vuln_classes": ["evil-class"]}  # type: ignore[dict-item]
    choice = propose_vuln_targets({"param_name": "file"}, client=_fake_client(raw))
    assert "evil-class" not in choice.vuln_classes
    assert choice.vuln_classes == _SAFE_DEFAULT_CLASSES


def test_mocked_error_fallback_cleanly() -> None:
    m = Mock()
    m.propose.side_effect = RuntimeError("timeout")
    choice = propose_vuln_targets({"param_name": "file"}, client=m)
    assert choice.vuln_classes == _SAFE_DEFAULT_CLASSES
    assert isinstance(choice, VulnTargetChoice)


def test_mocked_empty_after_strip_fallback() -> None:
    raw: dict[str, object] = {"vuln_classes": []}
    choice = propose_vuln_targets({"param_name": "file"}, client=_fake_client(raw))
    assert choice.vuln_classes == _SAFE_DEFAULT_CLASSES


def test_dedup_preserves_order() -> None:
    raw: dict[str, object] = {"vuln_classes": ["sqli", "sqli", "xss_reflected"]}
    choice = propose_vuln_targets({"param_name": "id"}, client=_fake_client(raw))
    assert choice.vuln_classes == ("sqli", "xss_reflected")
