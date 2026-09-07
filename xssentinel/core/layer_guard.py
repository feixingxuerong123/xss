# -*- coding: utf-8 -*-
"""Per-layer fault isolation with wiring-error escalation.

Every detection layer runs behind a broad ``except Exception`` -- that is
deliberate, a broken layer must not abort a scan.  But the audit found the
same failure shape over and over: the *dispatch* level swallowed the
error at DEBUG, so a missing import or a typo silently turned an entire
layer (and, before the per-layer guards, every layer after it) off with
no trace at the default log level.

  * Phase 63: one AttributeError in the async shim aborted all 17 page
    layers -- async reported NONE of them.
  * Phase 84: ``scanner_crawl`` never imported ``param_miner``; the
    resulting NameError was eaten and L9 mining "worked" while doing
    nothing.

Two rules this module enforces:

1. **Wiring-class exceptions escalate to WARNING.**  ``ImportError``,
   ``NameError`` and friends can never be a legitimate runtime condition
   of a target -- they are always a code defect, so they must be visible
   by default.  ``AttributeError``/``TypeError``/``KeyError`` stay at
   DEBUG: duck-typing and dict-shape probing are normal in this codebase
   (``getattr`` feature probes, optional headers), and warning on them
   would cry wolf.
2. **One layer failing never stops the others.**  ``run_layer`` is the
   only sanctioned way to invoke a layer from a dispatch loop.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from .budget import BudgetExhausted, CircuitOpen

_log = logging.getLogger(__name__)

# A target can never legitimately cause these -- they mean the scanner's
# own code is broken, so they must be visible at WARNING.
WIRING_EXCEPTIONS = (
    ImportError,          # includes ModuleNotFoundError
    NameError,
    UnboundLocalError,
    SyntaxError,
)


def is_wiring_error(exc: BaseException) -> bool:
    return isinstance(exc, WIRING_EXCEPTIONS)


def run_layer(scanner: Any, name: str, fn: Callable, *args,
              **kwargs) -> None:
    """Run one detection layer; isolate it from the dispatch loop.

    * ``BudgetExhausted`` / ``CircuitOpen`` propagate untouched -- a
      budget stop is a deliberate scan end, not a layer bug.
    * Wiring-class errors log at WARNING (with the layer name) and the
      dispatch loop continues.
    * Everything else logs at DEBUG and the loop continues.
    """
    try:
        fn(*args, **kwargs)
    except (BudgetExhausted, CircuitOpen):
        # A budget/circuit stop is a deliberate scan end, not a layer bug
        # -- it must reach the scan loop (Phase 86 semantics).
        raise
    except Exception as e:                                  # noqa: BLE001
        if is_wiring_error(e):
            _log.warning(
                "[layer:%s] %s: %s -- this layer is OFF until the defect "
                "is fixed; the remaining layers still run",
                name, type(e).__name__, e)
            if getattr(scanner, "verbose", False):
                _log.debug("[layer:%s] traceback", name, exc_info=True)
            return
        if getattr(scanner, "verbose", False):
            _log.debug("[layer:%s] error: %s", name, e,
                       exc_info=True)
