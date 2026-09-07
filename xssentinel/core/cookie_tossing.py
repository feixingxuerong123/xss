"""Cookie-tossing XSS detection.

Cookie tossing is a technique where an attacker sets a cookie on a
*parent* domain (e.g. ``example.com``) from a vulnerable *subdomain*
(e.g. ``sub.example.com``).  Because cookies with a broad ``Domain=``
attribute are sent to every subdomain under that parent, the attacker's
cookie value will be delivered to sibling subdomains (e.g.
``www.example.com``) that may reflect cookie values into HTML without
sanitization -- yielding XSS on an origin the attacker does not
control directly.

A typical attack chain::

    1. Attacker finds that sub.example.com sets cookies with
       ``Domain=.example.com`` (a parent-domain cookie).
    2. Attacker sets a malicious cookie on sub.example.com:
       ``document.cookie = "theme=<svg onload=alert(1)>; domain=.example.com"``
    3. Victim's browser stores the cookie scoped to .example.com.
    4. Victim visits www.example.com, which reads the ``theme`` cookie
       and reflects it into HTML: ``<div class="<svg onload=alert(1)>">``
    5. XSS fires on www.example.com -- an origin that has nothing to do
       with the vulnerable sub.example.com.

Detection strategy (static + header analysis):

  1. **Set-Cookie Domain attribute on parent**: any response whose
     ``Set-Cookie`` header includes ``Domain=<parent>`` where ``<parent>``
     is broader than the response's own host (i.e. the cookie will be
     sent to sibling subdomains).
  2. **Client-side ``document.cookie`` with Domain attribute**: JS code
     that sets a cookie with an explicit ``domain=`` attribute -- a
     common pattern in cookie-tossing payloads.
  3. **Cookie read -> sink pattern**: JS that reads ``document.cookie``
     and passes a parsed value into a dangerous DOM sink (innerHTML,
     eval, etc.) -- this is the *receiving* side of cookie tossing.
  4. **Cookie read into server-rendered HTML**: pages that render a
     cookie value server-side (already covered by ``cookie_xss.py`` for
     the *reflection* part; here we add the *tossing* side).

This module is pure-Python and uses regex heuristics.
"""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Set-Cookie header analysis
# ---------------------------------------------------------------------------

# Matches a Set-Cookie header value, capturing the cookie name and the
# Domain attribute (if present).  We do not rely on the stdlib
# http.cookies module because it does not parse Domain correctly for
# some edge cases and we want to preserve the raw value.
_SET_COOKIE_NAME_RE = re.compile(r"^([^=;]+)=([^;]*)", re.IGNORECASE)
_SET_COOKIE_DOMAIN_RE = re.compile(r"\bDomain\s*=\s*([^;]+)", re.IGNORECASE)
_SET_COOKIE_PATH_RE = re.compile(r"\bPath\s*=\s*([^;]+)", re.IGNORECASE)
_SET_COOKIE_HTTPONLY_RE = re.compile(r"\bHttpOnly\b", re.IGNORECASE)
_SET_COOKIE_SECURE_RE = re.compile(r"\bSecure\b", re.IGNORECASE)
_SET_COOKIE_SAMESITE_RE = re.compile(
    r"\bSameSite\s*=\s*(Lax|Strict|None)", re.IGNORECASE,
)


def parse_set_cookie(header_value: str) -> Optional[dict]:
    """Parse a ``Set-Cookie`` header value into a dict.

    Returns ``None`` if the header is empty / malformed.  The returned
    dict has the keys:

      * ``name``            -- cookie name
      * ``value``           -- cookie value (raw, may contain URL-encoded chars)
      * ``domain``          -- Domain attribute value (or ``None``)
      * ``path``            -- Path attribute value (or ``None``)
      * ``httponly``        -- bool
      * ``secure``          -- bool
      * ``samesite``        -- ``"Lax"`` / ``"Strict"`` / ``"None"`` / ``None``
    """
    if not header_value:
        return None
    name_match = _SET_COOKIE_NAME_RE.match(header_value.strip())
    if not name_match:
        return None
    name = name_match.group(1).strip()
    value = name_match.group(2).strip()
    domain_m = _SET_COOKIE_DOMAIN_RE.search(header_value)
    path_m = _SET_COOKIE_PATH_RE.search(header_value)
    samesite_m = _SET_COOKIE_SAMESITE_RE.search(header_value)
    return {
        "name": name,
        "value": value,
        "domain": domain_m.group(1).strip() if domain_m else None,
        "path": path_m.group(1).strip() if path_m else None,
        "httponly": bool(_SET_COOKIE_HTTPONLY_RE.search(header_value)),
        "secure": bool(_SET_COOKIE_SECURE_RE.search(header_value)),
        "samesite": (samesite_m.group(1).capitalize()
                     if samesite_m else None),
    }


def is_parent_domain_cookie(set_cookie: dict, response_host: str) -> bool:
    """Return True if the cookie's Domain attribute is a *parent* of the
    response host (i.e. the cookie will be delivered to sibling
    subdomains, enabling cookie tossing).

    Examples::

        # response from sub.example.com sets Domain=.example.com
        is_parent_domain_cookie({"domain": "example.com"}, "sub.example.com")
        # -> True

        # response from example.com sets Domain=example.com (self-scope)
        is_parent_domain_cookie({"domain": "example.com"}, "example.com")
        # -> False (cookie is scoped to the response's own host)
    """
    if not set_cookie or not set_cookie.get("domain") or not response_host:
        return False
    domain = set_cookie["domain"].lstrip(".")
    host = response_host.lower()
    domain = domain.lower()
    # If the domain equals the host, it's a self-scope (no toss risk).
    if domain == host:
        return False
    # If the host is a subdomain of the cookie domain, the cookie will
    # be delivered to ALL subdomains of `domain` -> toss risk.
    if host.endswith("." + domain) or host == domain:
        # The "host == domain" case is handled above; this catches
        # sub.example.com vs example.com.
        return host.endswith("." + domain)
    # If the cookie domain is a subdomain of the host, the cookie is
    # scoped narrower than the host -> no toss risk.
    return False


def analyze_set_cookie_headers(
    set_cookie_headers: list[str] | str,
    response_host: str,
) -> dict:
    """Analyze a list of Set-Cookie headers for cookie-tossing risk.

    ``set_cookie_headers`` may be a list of header values or a single
    newline-joined string (as the requester may collapse headers).

    Returns a dict::

        {
            "cookies":         list[dict],  # parsed cookies
            "tossing_cookies": list[dict],  # subset with parent-domain scope
            "has_tossing_risk": bool,
        }
    """
    if isinstance(set_cookie_headers, str):
        # Split on newlines (some servers join multiple Set-Cookie
        # headers with newlines) -- but also handle comma-joined values
        # cautiously (we cannot reliably split on commas because cookie
        # values may contain commas; use a simple newline split).
        headers = [h.strip() for h in set_cookie_headers.split("\n") if h.strip()]
    else:
        headers = list(set_cookie_headers or [])
    cookies: list[dict] = []
    tossing: list[dict] = []
    for h in headers:
        parsed = parse_set_cookie(h)
        if not parsed:
            continue
        cookies.append(parsed)
        if is_parent_domain_cookie(parsed, response_host):
            parsed["tossing_risk"] = True
            tossing.append(parsed)
    return {
        "cookies": cookies,
        "tossing_cookies": tossing,
        "has_tossing_risk": bool(tossing),
    }


# ---------------------------------------------------------------------------
# Client-side document.cookie analysis
# ---------------------------------------------------------------------------

# Matches `document.cookie = "...; domain=..."` patterns.  We look for
# the explicit `domain=` attribute because that's the marker of a
# cookie being set with a broader scope than the current origin.
_DOC_COOKIE_SET_RE = re.compile(
    r"document\.cookie\s*=\s*(['\"])((?:[^\\]|\\.)*?)\1",
    re.IGNORECASE | re.DOTALL,
)
# Also matches document.cookie = name + "=value; domain=..." (concat form)
_DOC_COOKIE_CONCAT_RE = re.compile(
    r"document\.cookie\s*=\s*([^;,]{1,200}?)\s*\+\s*"
    r"['\"]([^'\"]*domain=[^'\"]*)['\"]",
    re.IGNORECASE,
)
# Extracts the domain= attribute from a cookie string.
_COOKIE_DOMAIN_ATTR_RE = re.compile(
    r"domain\s*=\s*([^;'\"]+)", re.IGNORECASE,
)


def find_client_side_tossing(html: str) -> list[dict]:
    """Find client-side ``document.cookie`` assignments that set a
    ``domain=`` attribute (a strong cookie-tossing signal).

    Returns a list of dicts with ``snippet``, ``domain``, ``cookie_name``
    (if extractable).
    """
    if not html:
        return []
    findings: list[dict] = []
    # Dedup on the matched cookie string + domain (not the surrounding
    # snippet, which differs when the same assignment appears in
    # different <script> blocks).
    seen_keys: set[str] = set()

    # Pattern 1: quoted full cookie string.
    for m in _DOC_COOKIE_SET_RE.finditer(html):
        cookie_str = m.group(2)
        dom_m = _COOKIE_DOMAIN_ATTR_RE.search(cookie_str)
        if not dom_m:
            continue
        domain_val = dom_m.group(1).strip()
        dedup_key = cookie_str + "|" + domain_val
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)
        snippet = _extract_snippet(html, m.start(), m.end())
        # Try to extract the cookie name from the start of the string.
        name = cookie_str.split("=", 1)[0].strip()
        findings.append({
            "snippet": snippet,
            "domain": domain_val,
            "cookie_name": name,
            "pattern": "quoted_string",
        })

    # Pattern 2: concatenated form (name + "; domain=...").
    for m in _DOC_COOKIE_CONCAT_RE.finditer(html):
        snippet = _extract_snippet(html, m.start(), m.end())
        dom_str = m.group(2)
        dom_m = _COOKIE_DOMAIN_ATTR_RE.search(dom_str)
        domain_val = dom_m.group(1).strip() if dom_m else ""
        dedup_key = m.group(1) + "|" + domain_val
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)
        findings.append({
            "snippet": snippet,
            "domain": domain_val,
            "cookie_name": m.group(1).strip(),
            "pattern": "concat",
        })

    return findings


# ---------------------------------------------------------------------------
# Cookie read -> sink pattern (the receiving side of cookie tossing)
# ---------------------------------------------------------------------------

# DOM sources that read cookies.  Each entry is (regex, source_name).
_COOKIE_READ_RES = [
    # document.cookie
    (re.compile(r"\bdocument\.cookie\b", re.IGNORECASE), "document.cookie"),
    # getCookie("name") helper
    (re.compile(r"\bgetCookie\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE), "getCookie"),
    # cookie.get("name") (js-cookie / similar libs)
    (re.compile(r"\bcookies?\.get\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE), "cookies.get"),
]

# Dangerous DOM sinks (subset of trusted_types.py sinks -- the most
# commonly-exploited ones for cookie-tossing XSS).
_DANGER_SINKS = [
    (re.compile(r"\.innerHTML\s*[\+\-\*\/]?=", re.IGNORECASE), "innerHTML"),
    (re.compile(r"\.outerHTML\s*[\+\-\*\/]?=", re.IGNORECASE), "outerHTML"),
    (re.compile(r"insertAdjacentHTML\s*\(", re.IGNORECASE), "insertAdjacentHTML"),
    (re.compile(r"document\.write\s*\(", re.IGNORECASE), "document.write"),
    (re.compile(r"document\.writeln\s*\(", re.IGNORECASE), "document.writeln"),
    (re.compile(r"\beval\s*\(", re.IGNORECASE), "eval"),
    (re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE), "dangerouslySetInnerHTML"),
    (re.compile(r"\bv-html\s*=", re.IGNORECASE), "v-html"),
    (re.compile(r"\[innerHTML\]\s*=", re.IGNORECASE), "[innerHTML]"),
    (re.compile(r"\{@html\b", re.IGNORECASE), "{@html}"),
]


def find_cookie_to_sink_flows(html: str) -> list[dict]:
    """Detect flows where a cookie value reaches a dangerous DOM sink.

    This is a heuristic: we look for a cookie-read source and a sink
    within ~500 chars of each other (or in the same <script> block).
    """
    if not html:
        return []
    flows: list[dict] = []
    # Extract <script> blocks to scope the search (cookie -> sink flows
    # almost always live in the same script block).
    script_blocks = re.findall(
        r"<script[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL,
    )
    for block in script_blocks:
        cookie_reads: list[tuple[int, str]] = []
        for r, src_name in _COOKIE_READ_RES:
            for m in r.finditer(block):
                cookie_reads.append((m.start(), src_name))
        if not cookie_reads:
            continue
        sinks: list[tuple[int, str]] = []
        for sink_re, sink_name in _DANGER_SINKS:
            for m in sink_re.finditer(block):
                sinks.append((m.start(), sink_name))
        if not sinks:
            continue
        # For each cookie read, look for a sink within 500 chars.
        for read_pos, src_name in cookie_reads:
            for sink_pos, sink_name in sinks:
                if abs(sink_pos - read_pos) <= 500:
                    snippet_start = min(read_pos, sink_pos)
                    snippet_end = max(read_pos, sink_pos) + 80
                    snippet = block[snippet_start:snippet_end].strip()
                    flows.append({
                        "source": src_name,
                        "sink": sink_name,
                        "snippet": _clean_snippet(snippet),
                        "mitigated": False,  # no policy check here
                        "severity": "high",
                    })
                    break  # one sink per read is enough
    return flows


# ---------------------------------------------------------------------------
# Aggregate page analysis
# ---------------------------------------------------------------------------

def analyze_page(
    html: str | None,
    set_cookie_headers: list[str] | str | None = None,
    response_host: str = "",
) -> dict:
    """Analyze a page + its Set-Cookie headers for cookie-tossing XSS.

    Returns a dict with:

      * ``has_tossing_header`` -- bool (Set-Cookie with parent Domain)
      * ``has_client_tossing`` -- bool (document.cookie with domain=)
      * ``has_cookie_sink_flow`` -- bool (cookie -> DOM sink)
      * ``tossing_cookies`` -- list of header-parsed cookies at risk
      * ``client_tossing`` -- list of client-side tossing assignments
      * ``cookie_sink_flows`` -- list of cookie -> sink flows
      * ``violations`` -- aggregated list of violation dicts
    """
    html = html or ""
    set_cookie_headers = set_cookie_headers or []
    response_host = response_host or ""

    header_result = analyze_set_cookie_headers(set_cookie_headers, response_host)
    client_tossing = find_client_side_tossing(html)
    sink_flows = find_cookie_to_sink_flows(html)

    violations: list[dict] = []

    # Violation 1: server-side Set-Cookie with parent Domain.
    if header_result["has_tossing_risk"]:
        for c in header_result["tossing_cookies"][:3]:
            violations.append({
                "type": "cookie_tossing_set_cookie",
                "severity": "high",
                "title": (
                    f"Set-Cookie for '{c['name']}' sets Domain={c['domain']} "
                    f"which is a parent of the response host {response_host}; "
                    f"the cookie will be delivered to ALL subdomains of "
                    f"{c['domain']}, enabling cookie-tossing XSS on sibling "
                    f"origins that reflect cookie values"
                ),
                "evidence": _format_cookie_header(c),
                "cookie_name": c["name"],
                "cookie_domain": c["domain"],
                "response_host": response_host,
            })
            break  # one header finding per page is enough

    # Violation 2: client-side document.cookie with domain=.
    if client_tossing:
        for ct in client_tossing[:2]:
            violations.append({
                "type": "cookie_tossing_client",
                "severity": "medium",
                "title": (
                    f"Client-side document.cookie sets Domain={ct['domain']} "
                    f"-- a parent-domain cookie that enables cookie-tossing "
                    f"XSS on sibling origins"
                ),
                "evidence": ct["snippet"],
                "cookie_name": ct.get("cookie_name", ""),
                "cookie_domain": ct.get("domain", ""),
            })

    # Violation 3: cookie read -> DOM sink (the receiving side).
    if sink_flows:
        for flow in sink_flows[:2]:
            violations.append({
                "type": "cookie_sink_flow",
                "severity": "high",
                "title": (
                    f"Cookie value flows into {flow['sink']} sink without "
                    f"sanitization -- if an attacker can toss a cookie "
                    f"(set it on a parent domain), this sink will execute "
                    f"the injected payload"
                ),
                "evidence": flow["snippet"],
                "sink": flow["sink"],
                "source": flow["source"],
            })

    return {
        "has_tossing_header": header_result["has_tossing_risk"],
        "has_client_tossing": bool(client_tossing),
        "has_cookie_sink_flow": bool(sink_flows),
        "tossing_cookies": header_result["tossing_cookies"],
        "client_tossing": client_tossing,
        "cookie_sink_flows": sink_flows,
        "violations": violations,
    }


# ---------------------------------------------------------------------------
# PoC generation
# ---------------------------------------------------------------------------

def build_poc_html(
    url: str,
    cookie_name: str = "theme",
    payload: str = "<svg/onload=alert(document.domain)>",
    tossing_domain: str = "",
) -> str:
    """Build an HTML PoC for cookie-tossing XSS.

    The PoC sets a cookie with ``Domain=<tossing_domain>`` (or the
    target's parent domain if not specified) and then navigates to the
    target URL where the cookie value is reflected into HTML.
    """
    if not url:
        return ""
    # Derive a parent domain from the URL if none was given.
    if not tossing_domain:
        host = urlparse(url).hostname or ""
        parts = host.split(".")
        # Take the last two parts (e.g. example.com from sub.example.com).
        tossing_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    payload = payload or "<svg/onload=alert(document.domain)>"
    # Escape payload for embedding in a JS string.
    js_payload = payload.replace("\\", "\\\\").replace("'", "\\'")
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
        "  <title>XSSentinel cookie-tossing PoC</title>\n"
        "  <style>\n"
        "    body{font:14px/1.4 monospace;background:#111;color:#eee;"
        "padding:24px}\n"
        "    pre{background:#000;color:#0f0;padding:12px;"
        "border:1px solid #333;white-space:pre-wrap}\n"
        "    a{color:#6cf}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>XSSentinel &mdash; Cookie Tossing XSS PoC</h1>\n"
        f"  <p>This PoC must be hosted on a subdomain of "
        f"  <code>{tossing_domain}</code> (e.g. <code>attacker.{tossing_domain}</code>)\n"
        f"   so that the <code>Domain={tossing_domain}</code> cookie\n"
        f"   attribute is accepted by the browser.</p>\n"
        f"  <p>Cookie being tossed: <code>{cookie_name}</code> on\n"
        f"   <code>.{tossing_domain}</code></p>\n"
        f'  <p><a href="{safe_url}" target="_blank">open target: {url}</a></p>\n'
        "  <pre id=\"dbg\">[setup...]</pre>\n"
        "  <script>\n"
        "    (function () {\n"
        "      var dbg = document.getElementById('dbg');\n"
        f"      var cookieName = '{cookie_name}';\n"
        f"      var payload = '{js_payload}';\n"
        f"      var tossingDomain = '{tossing_domain}';\n"
        "      try {\n"
        "        document.cookie = cookieName + '=' + payload +\n"
        "          '; domain=.' + tossingDomain + '; path=/';\n"
        "        dbg.textContent = '[cookie tossed] ' + cookieName + '=' +\n"
        "          payload + '; domain=.' + tossingDomain + '\\n' +\n"
        "          '[document.cookie] ' + document.cookie;\n"
        "      } catch (e) {\n"
        "        dbg.textContent = '[toss failed] ' + e;\n"
        "        return;\n"
        "      }\n"
        "      // Navigate to the target -- the tossed cookie will be\n"
        "      // sent along because its domain matches.\n"
        "      setTimeout(function () {\n"
        f"        window.open('{safe_url}', '_blank');\n"
        "      }, 200);\n"
        "    })();\n"
        "  </script>\n"
        "</body>\n"
        "</html>\n"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_snippet(html: str, start: int, end: int, padding: int = 40) -> str:
    """Extract a code snippet around [start, end) with padding."""
    s = max(0, start - padding)
    e = min(len(html), end + padding)
    return _clean_snippet(html[s:e])


def _clean_snippet(text: str) -> str:
    """Collapse whitespace and trim a snippet for display."""
    if not text:
        return ""
    # Replace runs of whitespace with a single space.
    text = re.sub(r"\s+", " ", text).strip()
    return text[:300]


def _format_cookie_header(cookie: dict) -> str:
    """Format a parsed cookie back into a Set-Cookie header string."""
    if not cookie:
        return ""
    parts = [f"{cookie.get('name', '')}={cookie.get('value', '')}"]
    if cookie.get("domain"):
        parts.append(f"Domain={cookie['domain']}")
    if cookie.get("path"):
        parts.append(f"Path={cookie['path']}")
    if cookie.get("httponly"):
        parts.append("HttpOnly")
    if cookie.get("secure"):
        parts.append("Secure")
    if cookie.get("samesite"):
        parts.append(f"SameSite={cookie['samesite']}")
    return "; ".join(parts)
