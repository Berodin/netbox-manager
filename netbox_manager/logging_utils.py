# SPDX-License-Identifier: Apache-2.0
"""Logging helpers for consistent application output."""

from loguru import logger
import sys


def init_logger(debug: bool = False) -> None:
    """Initialize logger with consistent format and level."""
    log_fmt = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
        "<level>{message}</level>"
    )

    log_level = "DEBUG" if debug else "INFO"

    logger.remove()
    logger.add(sys.stderr, format=log_fmt, level=log_level, colorize=True)

