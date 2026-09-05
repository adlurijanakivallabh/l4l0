"""Structured, secret-redacting logging.

Every log line passes through :func:`lalo.core.redaction.redact` at format time,
so a stray token in a message/argument can't reach stderr or a log file. Use
:func:`get_logger` everywhere instead of ``logging.getLogger`` directly.
"""

from __future__ import annotations

import logging
import sys

from .redaction import redact

_DEFAULT_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


class RedactingFormatter(logging.Formatter):
    """A ``logging.Formatter`` that redacts secret-shaped text from the final line."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def get_logger(name: str = "lalo", *, level: int = logging.INFO) -> logging.Logger:
    """Return a configured logger with the redacting formatter attached once."""
    logger = logging.getLogger(name)
    if not any(isinstance(h.formatter, RedactingFormatter) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(RedactingFormatter(_DEFAULT_FORMAT))
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
