"""Shared helpers for the advanced detection layers (Phase 39 split)."""
from __future__ import annotations

from typing import Any

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
    return Finding(**kwargs)

