"""Durable file logging for the ``reachagent`` logger namespace.

``execution/audit.py`` already mirrors every fired/refused/errored action to
``logging.getLogger("reachagent.execution.audit").info(...)``, and several
other modules log via their own ``logging.getLogger(__name__)`` — all of it a
child of the ``"reachagent"`` namespace, none of it currently wired to a sink.
Attaching one handler here at the namespace root turns that into a durable,
on-disk audit/debug trail for every entry point, without touching any of the
existing call sites.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

_MAX_BYTES = 5 * 1024 * 1024
_BACKUP_COUNT = 3
_LOGGER_NAME = "reachagent"


def configure_file_logging(log_dir: Path | None = None) -> Path:
    """Attach a rotating file handler to the ``reachagent`` logger; return its path.

    Idempotent — calling this more than once (e.g. on a module reload) never
    attaches a second handler.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    directory = log_dir or Path(__file__).resolve().parents[2] / "logs"
    directory.mkdir(parents=True, exist_ok=True)
    log_path = directory / "reachagent.log"

    for handler in logger.handlers:
        if (
            isinstance(handler, logging.handlers.RotatingFileHandler)
            and Path(handler.baseFilename) == log_path
        ):
            return log_path

    handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return log_path
