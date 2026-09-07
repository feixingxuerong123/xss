"""Centralized logging configuration (Phase 23-4).

Provides ``get_logger(name)`` for every module to obtain a logger that
inherits from the ``xssentinel`` root, and ``configure_logging(level)``
for the CLI to set the verbosity in one place.

This replaces the ad-hoc ``print(f"[!] ...")`` diagnostics with proper
leveled logging so that:
  * CI / production runs can control verbosity (DEBUG/INFO/WARNING/ERROR).
  * Exceptions that were previously silently swallowed can now surface
    their traceback via ``logger.debug(..., exc_info=True)``.
  * Structured log handlers can be attached without touching call sites.
"""
from __future__ import annotations

import logging
import sys
import threading

_ROOT_NAME = "xssentinel"
_configured = False
_config_lock = threading.Lock()


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger under the ``xssentinel`` namespace.

    If ``configure_logging`` has not been called yet, a NullHandler is
    attached so library users see no stray output.  The CLI calls
    ``configure_logging`` at startup to install a real handler.
    """
    if name and not name.startswith(_ROOT_NAME):
        name = f"{_ROOT_NAME}.{name}"
    elif not name:
        name = _ROOT_NAME
    logger = logging.getLogger(name)
    # Phase 29-3: guard the _configured check + addHandler with a lock so
    # concurrent threads calling get_logger() simultaneously don't attach
    # duplicate NullHandlers.
    global _configured
    with _config_lock:
        if not _configured:
            logger.addHandler(logging.NullHandler())
    return logger


def configure_logging(level: str | int = "WARNING",
                      stream=None) -> None:
    """Configure the ``xssentinel`` root logger with a stream handler.

    Args:
        level: ``"DEBUG"`` / ``"INFO"`` / ``"WARNING"`` / ``"ERROR"`` or
            the numeric equivalent.
        stream: output stream (default: ``sys.stderr``).
    """
    global _configured
    if isinstance(level, str):
        level = level.upper()
    root = logging.getLogger(_ROOT_NAME)
    with _config_lock:
        # Remove previously attached handlers so repeated calls (e.g. in
        # tests) don't duplicate output.
        for h in list(root.handlers):
            if not isinstance(h, logging.NullHandler):
                root.removeHandler(h)
        handler = logging.StreamHandler(stream or sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        root.addHandler(handler)
        root.setLevel(level)
        _configured = True


def is_configured() -> bool:
    """Return True if ``configure_logging`` has been called."""
    return _configured
