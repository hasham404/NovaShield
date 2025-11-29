from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def get_logger(name: str = "anonymizer") -> logging.Logger:
    """
    Return a module-level logger configured with a rotating file handler.

    The first call configures a 'logs/anonymizer.log' file in the project
    root. Subsequent calls reuse the same configuration.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    base_dir = Path(__file__).resolve().parents[1]
    logs_dir = base_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    logfile = logs_dir / "anonymizer.log"

    handler = RotatingFileHandler(logfile, maxBytes=5 * 1024 * 1024, backupCount=5)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Optional console handler for local debugging.
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    return logger


