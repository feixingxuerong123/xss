"""Shared helpers for the advanced detection layers (Phase 39 split)."""
from __future__ import annotations

from typing import Any

from ..findings import EVIDENCE_BROWSER_EXECUTED, EVIDENCE_NO_BROWSER

def _make_finding(**kwargs) -> Any:
    """Build a Finding object with standard fields filled in."""
    from ..scanner import Finding
    # Layer callers pass ``ftype=`` as the specific finding type
    # (e.g. "postmessage_xss").  Map it to the Finding's ``type`` field
    # so reports and the self-test can distinguish advanced sub-types
    # instead of collapsing them all into "advanced_xss".
    if "ftype" in kwargs:
        kwargs.setdefault("type", kwargs.pop("ftype"))
    # Ensure required fields have defaults.
    kwargs.setdefault("url", "")
    kwargs.setdefault("method", "GET")
    kwargs.setdefault("param", None)
    kwargs.setdefault("payload", "")
    kwargs.setdefault("context", "")
    kwargs.setdefault("severity", "medium")
    kwargs.setdefault("type", "advanced_xss")
    kwargs.setdefault("confidence", "high")
    kwargs.setdefault("detail", kwargs.pop("evidence", ""))
    kwargs.setdefault("headless", None)
    kwargs.setdefault("proof", None)
    # Every advanced-layer finding routes through here, so this is where the
    # evidence class can be stated WITHOUT guessing: the caller already declared
    # whether a browser confirmed anything, by whether it passed `headless`.
    # Callers that know better (e.g. an OOB or model-only verdict) pass
    # `evidence_class=` themselves and `setdefault` leaves it alone.
    _h = kwargs.get("headless") or {}
    kwargs.setdefault(
        "evidence_class",
        EVIDENCE_BROWSER_EXECUTED
        if (_h.get("outcome") == "fired" or _h.get("confirmed"))
        else EVIDENCE_NO_BROWSER)
    return Finding(**kwargs)

