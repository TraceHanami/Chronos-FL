"""
Structured Logging Infrastructure for CHRONOS-FL.
"""

import logging
import sys
from chronos.config.settings import get_settings


def get_logger(name: str = "chronos") -> logging.Logger:
    """Configures and returns a structured logger instance."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        settings = get_settings()
        logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    return logger
