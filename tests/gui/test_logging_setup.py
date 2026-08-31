"""Durable file logging — attaches once, actually writes, never double-attaches."""

from __future__ import annotations

import logging

from reachagent.logging_setup import configure_file_logging


def test_configure_file_logging_creates_the_directory_and_file(tmp_path) -> None:
    log_dir = tmp_path / "logs"
    log_path = configure_file_logging(log_dir)
    try:
        assert log_path == log_dir / "reachagent.log"
        assert log_dir.is_dir()
        logging.getLogger("reachagent.somewhere").info("hello")
        assert log_path.exists()
        assert "hello" in log_path.read_text(encoding="utf-8")
    finally:
        _detach(log_path)


def test_configure_file_logging_is_idempotent(tmp_path) -> None:
    log_dir = tmp_path / "logs"
    log_path = configure_file_logging(log_dir)
    try:
        before = len(logging.getLogger("reachagent").handlers)
        configure_file_logging(log_dir)
        after = len(logging.getLogger("reachagent").handlers)
        assert after == before
    finally:
        _detach(log_path)


def _detach(log_path) -> None:
    logger = logging.getLogger("reachagent")
    for handler in list(logger.handlers):
        if getattr(handler, "baseFilename", None) == str(log_path):
            logger.removeHandler(handler)
            handler.close()
