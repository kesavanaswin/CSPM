"""
utils/logger.py
----------------
Centralized logging configuration for the CSPM framework.

Provides a single get_logger() factory so every module (ingestion,
analysis, risk, mitigation) emits consistently formatted logs to both
the console and a rotating log file under /logs.

Log levels used across the project:
    INFO     - normal operational events (scan started, container ingested)
    WARNING  - misconfigurations / medium-risk findings
    CRITICAL - high/critical risk findings, admission-controller blocks
"""

import logging
import os
from logging.handlers import RotatingFileHandler

_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(_LOG_DIR, exist_ok=True)

_LOG_FILE = os.path.join(_LOG_DIR, "cspm.log")

_FORMATTER = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)-22s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_configured_loggers = {}


def get_logger(name: str) -> logging.Logger:
    """
    Return a configured logger instance for the given module name.
    Loggers are cached so repeated calls don't duplicate handlers.
    """
    if name in _configured_loggers:
        return _configured_loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(_FORMATTER)
        console_handler.setLevel(logging.INFO)

        file_handler = RotatingFileHandler(
            _LOG_FILE, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(_FORMATTER)
        file_handler.setLevel(logging.INFO)

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    _configured_loggers[name] = logger
    return logger
