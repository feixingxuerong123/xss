"""Subresource Integrity (SRI) bypass detection.

Subresource Integrity (SRI) is a browser security mechanism that lets
a page verify the integrity of externally-loaded scripts and stylesheets
by embedding a cryptographic hash in the ``integrity`` attribute:

    <script src="https://cdn.example.com/lib.js"
            integrity="sha384-Base64Hash..."
            crossorigin="anonymous"></script>

When the browser fetches the external resource, it computes the hash
and compares it against the declared one.  If they differ (e.g. the CDN
was compromised or a MITM modified the file), the browser refuses to
execute the script.

SRI is a critical defense against CDN compromise and CDN-based supply-
chain attacks.  Without SRI, any compromise of the CDN (or a MITM
attack on the CDN connection) yields immediate XSS on every page that
loads scripts from that CDN.

This module performs STATIC analysis of a page's HTML to detect:

  1. **Missing SRI on cross-origin scripts**: ``<script src=>`` tags
     loading from a different origin than the page, with no
     ``integrity=`` attribute.  This is the canonical SRI bypass --
     if the CDN is compromised, the attacker can inject arbitrary JS.
  2. **Missing SRI on cross-origin stylesheets**: ``<link rel="stylesheet"
     href=>`` tags loading from a different origin, with no
     ``integrity=`` attribute.  Stylesheet injection can be leveraged
     into CSS-based data exfiltration and, in some browsers, script
     execution via ``-moz-binding`` (legacy) or ``behavior`` (IE).
  3. **Missing ``crossorigin`` on SRI-protected resources**: a
     ``<script>`` with ``integrity=`` but no ``crossorigin`` attribute
     will fail the SRI check in most browsers because the browser
     cannot read the response body of a cross-origin resource without
     CORS.  This is a misconfiguration that silently disables SRI.
  4. **Empty / malformed ``integrity=`` values**: ``integrity=""``
     or ``integrity="sha256-"`` (no hash) are treated as no SRI by
     the browser.
  5. **Missing SRI on ``<link rel="preload" as="script">``**: preload
     directives that fetch scripts without integrity also expose the
     page to CDN compromise.
  6. **Insecure ``http://`` origins for scripts/stylesheets**: loading
     scripts from a plaintext origin (even with SRI) is vulnerable to
     MITM, because an active network attacker can substitute the
     response AND the integrity hash is computed over the attacker's
     content (SRI does not protect against MITM on http:// origins
     when the page itself is http://).

This module is pure-Python and uses regex + BeautifulSoup (if
available) to parse the page HTML.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Tag extraction
# ---------------------------------------------------------------------------

# We try BeautifulSoup first for robust HTML parsing; fall back to regex
# if bs4 is not installed.  Regex parsing is brittle but sufficient for
# the well-formed HTML we expect in real pages.
try:
    from bs4 import BeautifulSoup  # type: ignore
    _HAS_BS4 = True
except ImportError:  # pragma: no cover -- bs4 is in requirements.txt
    _HAS_BS4 = False


# Regex fallbacks for tag extraction.  These match opening tags only
# (we don't need the closing tag for SRI analysis).
_SCRIPT_TAG_RE = re.compile(
    r"<script\b([^>]*)>", re.IGNORECASE | re.DOTALL,
)
_LINK_TAG_RE = re.compile(
    r"<link\b([^>]*)>", re.IGNORECASE | re.DOTALL,
)

# Attribute extractors.
_ATTR_RE = re.compile(
    r"(\w[\w-]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
    re.IGNORECASE,
)
_INTEGRITY_ATTR_RE = re.compile(
    r"\bintegrity\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
    re.IGNORECASE,
)
_CROSSORIGIN_ATTR_RE = re.compile(
    r"\bcrossorigin\b", re.IGNORECASE,
)


def _parse_attrs(attr_str: str) -> dict:
    """Parse an HTML attribute string into a dict.

    Values are lowercased keys; the value is the raw string (or True
    for boolean attributes with no value).
    """
    attrs: dict = {}
    for m in _ATTR_RE.finditer(attr_str):
        name = m.group(1).lower()
        value = m.group(2) or m.group(3) or m.group(4) or ""
        attrs[name] = value
    # Also detect boolean attributes (e.g. ``crossorigin`` with no =).
    for m in re.finditer(r"\b([a-z][\w-]*)\b(?!\s*=)", attr_str, re.IGNORECASE):
        name = m.group(1).lower()
        if name not in attrs:
            attrs[name] = ""
    return attrs


def _extract_script_tags(html: str) -> list[dict]:
    """Extract all ``<script>`` tags from the HTML.

    Returns a list of dicts with ``src``, ``integrity``, ``crossorigin``,
    ``snippet``, and ``attrs``.
    """
    if not html:
        return []
    scripts: list[dict] = []
    if _HAS_BS4:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("script"):
                src = tag.get("src", "")
                if not src:
                    continue  # inline scripts have no SRI surface
                integrity = tag.get("integrity", "")
                crossorigin = tag.has_attr("crossorigin")
                attrs = {k.lower(): (v[0] if isinstance(v, list) else v)
                         for k, v in tag.attrs.items()}
                snippet = _extract_snippet_around(html, str(tag)[:200])
                scripts.append({
                    "src": src,
                    "integrity": integrity,
                    "crossorigin": crossorigin,
                    "attrs": attrs,
                    "snippet": snippet,
                })
            return scripts
        except Exception:
            pass  # fall back to regex
    # Regex fallback.
    for m in _SCRIPT_TAG_RE.finditer(html):
        attr_str = m.group(1)
        attrs = _parse_attrs(attr_str)
        src = attrs.get("src", "")
        if not src:
            continue
        snippet = _extract_snippet_around(html, m.group(0))
        scripts.append({
            "src": src,
            "integrity": attrs.get("integrity", ""),
            "crossorigin": "crossorigin" in attrs,
            "attrs": attrs,
            "snippet": snippet,
        })
    return scripts


def _extract_link_tags(html: str) -> list[dict]:
    """Extract all ``<link>`` tags from the HTML.

    Returns a list of dicts with ``rel``, ``href``, ``integrity``,
    ``crossorigin``, ``as``, ``snippet``, and ``attrs``.
    """
    if not html:
        return []
    links: list[dict] = []
    if _HAS_BS4:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("link"):
                href = tag.get("href", "")
                rel = tag.get("rel", "")
                if isinstance(rel, list):
                    rel = " ".join(rel)
                if not href:
                    continue
                integrity = tag.get("integrity", "")
                crossorigin = tag.has_attr("crossorigin")
                as_attr = tag.get("as", "")
                attrs = {k.lower(): (v[0] if isinstance(v, list) else v)
                         for k, v in tag.attrs.items()}
                snippet = _extract_snippet_around(html, str(tag)[:200])
                links.append({
                    "rel": rel,
                    "href": href,
                    "integrity": integrity,
                    "crossorigin": crossorigin,
                    "as": as_attr,
                    "attrs": attrs,
                    "snippet": snippet,
                })
            return links
        except Exception:
            pass
    for m in _LINK_TAG_RE.finditer(html):
        attr_str = m.group(1)
        attrs = _parse_attrs(attr_str)
        href = attrs.get("href", "")
        if not href:
            continue
        snippet = _extract_snippet_around(html, m.group(0))
        links.append({
            "rel": attrs.get("rel", ""),
            "href": href,
            "integrity": attrs.get("integrity", ""),
            "crossorigin": "crossorigin" in attrs,
            "as": attrs.get("as", ""),
            "attrs": attrs,
            "snippet": snippet,
        })
    return links


# ---------------------------------------------------------------------------
# Origin comparison
# ---------------------------------------------------------------------------

def _is_same_origin(url_a: str, url_b: str) -> bool:
    """Return True if two URLs share the same scheme + host + port."""
    if not url_a or not url_b:
        return False
    try:
        a = urlparse(url_a)
        b = urlparse(url_b)
    except Exception:
        return False
    # If the resource URL is protocol-relative (//host/path), inherit
    # the page's scheme.
    scheme_a = a.scheme or "http"
    scheme_b = b.scheme or scheme_a
    return (scheme_a.lower() == scheme_b.lower()
            and (a.hostname or "").lower() == (b.hostname or "").lower()
            and (a.port or _default_port(scheme_a)) == (b.port or _default_port(scheme_b)))


def _default_port(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def _is_insecure_origin(url: str) -> bool:
    """Return True if the URL uses ``http://`` (not https://)."""
    if not url:
        return False
    try:
        scheme = urlparse(url).scheme.lower()
    except Exception:
        return False
    # Protocol-relative URLs (//host/path) are NOT inherently insecure;
    # they inherit the page's scheme.  We only flag explicit http://.
    return scheme == "http"


def _is_cross_origin(page_url: str, resource_url: str) -> bool:
    """Return True if the resource URL is cross-origin to the page.

    Protocol-relative URLs (``//cdn.example.com/lib.js``) are resolved
    against the page's scheme before comparison.  Relative URLs
    (``/local.js`` or ``sub/page.js``) are same-origin.
    """
    if not resource_url:
        return False
    # Data: and blob: URIs are same-origin (they don't load external
    # content -- they're inline).
    if resource_url.startswith(("data:", "blob:")):
        return False
    # Relative URLs (no scheme) are same-origin.
    try:
        parsed = urlparse(resource_url)
        if not parsed.scheme and not parsed.netloc:
            return False  # relative URL -> same origin
    except Exception:
        pass
    # Resolve protocol-relative URLs.
    if resource_url.startswith("//"):
        try:
            page_scheme = urlparse(page_url).scheme or "https"
        except Exception:
            page_scheme = "https"
        resource_url = page_scheme + ":" + resource_url
    return not _is_same_origin(page_url, resource_url)


# ---------------------------------------------------------------------------
# Integrity attribute validation
# ---------------------------------------------------------------------------

# Valid SRI hash format: <hash-algo>-<base64>
# Supported algos: sha256, sha384, sha512 (sha1 is deprecated and
# rejected by browsers).
_VALID_SRI_RE = re.compile(
    r"^(sha256|sha384|sha512)-[A-Za-z0-9+/]{40,}={0,2}$",
)


def is_valid_integrity(integrity_attr: str) -> bool:
    """Return True if the ``integrity=`` attribute is well-formed and
    contains at least one valid hash.

    Browser behavior:
      * Empty string -> no SRI check.
      * ``sha256-`` (no hash) -> no SRI check.
      * ``sha1-...`` -> rejected (sha1 is not in the allowed list).
      * Multiple hashes separated by spaces -> all are checked; the
        resource passes if ANY matches.
    """
    if not integrity_attr or not integrity_attr.strip():
        return False
    # Multiple hashes may be space-separated.
    for token in integrity_attr.split():
        if _VALID_SRI_RE.match(token):
            return True
    return False


# ---------------------------------------------------------------------------
# Aggregate analysis
# ---------------------------------------------------------------------------

def analyze_page(html: str | None, page_url: str = "") -> dict:
    """Analyze a page for SRI bypass vulnerabilities.

    Returns a dict with:

      * ``scripts``            -- list of parsed <script> tags
      * ``links``              -- list of parsed <link> tags
      * ``cross_origin_scripts`` -- subset missing SRI
      * ``cross_origin_styles``  -- subset missing SRI
      * ``broken_sri``         -- tags with integrity= but no crossorigin
      * ``malformed_integrity`` -- tags with empty/malformed integrity=
      * ``insecure_origins``   -- scripts/styles loaded over http://
      * ``violations``         -- aggregated list of violation dicts
    """
    html = html or ""
    page_url = page_url or ""

    scripts = _extract_script_tags(html)
    links = _extract_link_tags(html)

    cross_origin_scripts: list[dict] = []
    cross_origin_styles: list[dict] = []
    broken_sri: list[dict] = []
    malformed_integrity: list[dict] = []
    insecure_origins: list[dict] = []

    for s in scripts:
        src = s["src"]
        if _is_cross_origin(page_url, src):
            if not is_valid_integrity(s.get("integrity", "")):
                cross_origin_scripts.append(s)
            else:
                # Has valid SRI -- check for missing crossorigin.
                if not s.get("crossorigin"):
                    broken_sri.append(s)
        # Malformed integrity attribute (present but invalid).
        # Note: we check "integrity" in attrs (key presence) rather than
        # truthiness, because integrity="" is falsy but still a malformed
        # attribute that browsers treat as no SRI.
        if "integrity" in s.get("attrs", {}) and not is_valid_integrity(s.get("integrity", "")):
            malformed_integrity.append(s)
        # Insecure origin.
        if _is_insecure_origin(src):
            insecure_origins.append(s)

    for l in links:
        rel = (l.get("rel") or "").lower()
        href = l["href"]
        # Only analyze stylesheets and script preloads.
        is_stylesheet = "stylesheet" in rel
        is_script_preload = "preload" in rel and (l.get("as", "") or "").lower() == "script"
        if not (is_stylesheet or is_script_preload):
            continue
        if _is_cross_origin(page_url, href):
            if not is_valid_integrity(l.get("integrity", "")):
                cross_origin_styles.append(l)
            else:
                if not l.get("crossorigin"):
                    broken_sri.append(l)
        if "integrity" in l.get("attrs", {}) and not is_valid_integrity(l.get("integrity", "")):
            malformed_integrity.append(l)
        if _is_insecure_origin(href):
            insecure_origins.append(l)

    violations: list[dict] = []

    # Violation 1: cross-origin script without SRI (high severity).
    if cross_origin_scripts:
        # Report the first 3; one finding per tag is too noisy.
        for s in cross_origin_scripts[:3]:
            violations.append({
                "type": "sri_missing_script",
                "severity": "high",
                "title": (
                    f"Cross-origin <script src=\"{s['src']}\"> loaded without "
                    f"an integrity= attribute -- if the CDN is compromised "
                    f"or a MITM modifies the response, arbitrary JS will "
                    f"execute on this origin"
                ),
                "evidence": s["snippet"],
                "resource_url": s["src"],
                "resource_type": "script",
            })
        if len(cross_origin_scripts) > 3:
            violations.append({
                "type": "sri_missing_script_summary",
                "severity": "medium",
                "title": (
                    f"{len(cross_origin_scripts)} cross-origin scripts lack "
                    f"SRI (showing first 3); each is a CDN-compromise XSS "
                    f"vector"
                ),
                "evidence": "",
                "resource_count": len(cross_origin_scripts),
            })

    # Violation 2: cross-origin stylesheet without SRI.
    if cross_origin_styles:
        for l in cross_origin_styles[:3]:
            rtype = "script preload" if "preload" in (l.get("rel", "")) else "stylesheet"
            violations.append({
                "type": "sri_missing_style",
                "severity": "medium",
                "title": (
                    f"Cross-origin <link> {rtype} href=\"{l['href']}\" loaded "
                    f"without integrity= -- CDN compromise or MITM can inject "
                    f"arbitrary CSS (data exfiltration via CSS selectors, "
                    f"script execution via -moz-binding/behavior on legacy "
                    f"browsers)"
                ),
                "evidence": l["snippet"],
                "resource_url": l["href"],
                "resource_type": rtype,
            })

    # Violation 3: integrity= present but crossorigin missing (broken SRI).
    if broken_sri:
        for s in broken_sri[:2]:
            violations.append({
                "type": "sri_broken_no_crossorigin",
                "severity": "medium",
                "title": (
                    f"<script src=\"{s.get('src', s.get('href', ''))}\"> has "
                    f"integrity= but no crossorigin attribute -- the browser "
                    f"cannot read the cross-origin response body to verify "
                    f"the hash, so SRI is silently disabled"
                ),
                "evidence": s["snippet"],
                "resource_url": s.get("src", s.get("href", "")),
            })

    # Violation 4: malformed integrity attribute.
    if malformed_integrity:
        for s in malformed_integrity[:2]:
            violations.append({
                "type": "sri_malformed",
                "severity": "medium",
                "title": (
                    f"<script src=\"{s.get('src', s.get('href', ''))}\"> has "
                    f"a malformed integrity attribute "
                    f"({s.get('integrity', '')!r}) -- browsers treat this as "
                    f"no SRI protection"
                ),
                "evidence": s["snippet"],
                "resource_url": s.get("src", s.get("href", "")),
                "integrity_value": s.get("integrity", ""),
            })

    # Violation 5: insecure http:// origin for scripts.
    if insecure_origins:
        for s in insecure_origins[:2]:
            violations.append({
                "type": "sri_insecure_origin",
                "severity": "medium",
                "title": (
                    f"<script src=\"{s.get('src', s.get('href', ''))}\"> loaded "
                    f"over http:// -- an active MITM can substitute the "
                    f"response (SRI over http:// protects against CDN "
                    f"compromise but NOT against network MITM because the "
                    f"attacker controls both the response and the page)"
                ),
                "evidence": s["snippet"],
                "resource_url": s.get("src", s.get("href", "")),
            })

    return {
        "scripts": scripts,
        "links": links,
        "cross_origin_scripts": cross_origin_scripts,
        "cross_origin_styles": cross_origin_styles,
        "broken_sri": broken_sri,
        "malformed_integrity": malformed_integrity,
        "insecure_origins": insecure_origins,
        "violations": violations,
    }


# ---------------------------------------------------------------------------
# PoC generation
# ---------------------------------------------------------------------------

def build_poc_html(url: str, resource_url: str = "", resource_type: str = "script") -> str:
    """Build an HTML PoC illustrating the SRI bypass impact.

    The PoC simulates a CDN compromise: the attacker substitutes the
    external resource with one that runs ``alert(document.domain)``.
    """
    if not url:
        return ""
    resource_url = resource_url or "https://cdn.example.com/lib.js"
    safe_url = (
        url.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    safe_resource = (
        resource_url.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '  <meta charset="utf-8">\n'
        "  <title>XSSentinel SRI bypass PoC</title>\n"
        "  <style>\n"
        "    body{font:14px/1.4 monospace;background:#111;color:#eee;"
        "padding:24px}\n"
        "    pre{background:#000;color:#0f0;padding:12px;"
        "border:1px solid #333;white-space:pre-wrap}\n"
        "    a{color:#6cf}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>XSSentinel &mdash; SRI Bypass PoC</h1>\n"
        f"  <p>Target page: <code>{safe_url}</code></p>\n"
        f"  <p>Vulnerable resource: <code>{safe_resource}</code></p>\n"
        "  <p>This PoC simulates a CDN compromise: the external resource\n"
        "   is replaced with a malicious one that executes arbitrary JS\n"
        "   on the page's origin.  Because the page does not enforce SRI,\n"
        "   the browser has no way to detect the substitution.</p>\n"
        "  <pre>\n"
        f"# Attacker's CDN compromise payload (substituted for {safe_resource}):\n"
        "    alert('XSS via CDN compromise: ' + document.domain)\n"
        "\n"
        "# Real-world impact:\n"
        "    - Cookie theft (document.cookie)\n"
        "    - Credential theft (read localStorage / sessionStorage)\n"
        "    - Keylogging (addEventListener on keypress)\n"
        "    - CSRF on same-origin actions\n"
        "    - Persistent backdoor (register a Service Worker)\n"
        "  </pre>\n"
        "  <p><strong>Mitigation:</strong> add an integrity= attribute\n"
        "   with the resource's SHA-384 hash, and crossorigin=\"anonymous\".</p>\n"
        "</body>\n"
        "</html>\n"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_snippet_around(html: str, tag_str: str, padding: int = 60) -> str:
    """Find ``tag_str`` in ``html`` and return a snippet around it."""
    if not html or not tag_str:
        return ""
    idx = html.find(tag_str[:80])  # search by the first 80 chars
    if idx < 0:
        return _clean_snippet(tag_str)
    start = max(0, idx - padding)
    end = min(len(html), idx + len(tag_str) + padding)
    return _clean_snippet(html[start:end])


def _clean_snippet(text: str) -> str:
    """Collapse whitespace and trim a snippet for display."""
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    return text[:300]
