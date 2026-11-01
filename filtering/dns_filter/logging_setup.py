"""Logging configuration.

The original module configured logging as an import side effect.  Logging is
now an explicit startup step, owned by the CLI, so importing library modules is
free of global side effects.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from .config import LoggingConfig

_LOG_FORMAT = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"


def configure_logging(settings: LoggingConfig) -> None:
    """Apply *settings* to the root logger."""

    if not settings.enabled:
        logging.disable(logging.CRITICAL)
        return

    logging.disable(logging.NOTSET)
    level = getattr(logging, settings.level.upper(), logging.INFO)
    formatter = logging.Formatter(_LOG_FORMAT)

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if settings.file is not None:
        settings.file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            RotatingFileHandler(
                settings.file,
                maxBytes=settings.max_bytes,
                backupCount=settings.backup_count,
                encoding="utf-8",
            )
        )

    logging.basicConfig(level=level, handlers=handlers, format=_LOG_FORMAT, force=True)
    for handler in logging.getLogger().handlers:
        handler.setFormatter(formatter)
