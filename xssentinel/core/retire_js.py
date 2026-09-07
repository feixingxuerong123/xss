"""Outdated JavaScript library scan (Phase 44) -- learned from XSStrike's
retireJS plugin.

Outdated front-end libraries are a cheap, high-value finding: they carry
known CVEs (many of them XSS) and signal stale dependency hygiene.  This
module extracts static <script src> references from a page, resolves the
library name + version from the URL, and matches against a curated
fingerprint table of common libraries with known vulnerable version
ranges.

Design:
  * Version extraction is anchored to the library name: find the name in
    the URL, then look for a version right after it (jquery-1.12.4.min.js,
    /jquery/3.1.0/jquery.min.js, vue@2.6.14 ...).  Path prefixes that are
    *before* the library name (e.g. /static/v2/jquery.min.js) never leak
    into the version.
  * Fingerprint table: (name, url_regex, match, ranges, cve).  A library
    is flagged only when its version falls inside a known vulnerable range
    -- no guessing when the version cannot be resolved.
  * Severity: medium (library version alone is not an exploit).
"""
from __future__ import annotations

import re

# Fingerprint table.  Each entry:
#   name    -- display name
#   url_rx  -- regex matched against the <script src> URL (lowercased)
#   match   -- substring to locate in the URL; the version is parsed from
#              the text right after it
#   ranges  -- list of (min, max) vulnerable version ranges (inclusive lower
#              bound, exclusive upper bound; None = unbounded)
#   cve     -- short human hint
#
# Ranges are intentionally conservative (known-bad only) and are updated as
# new disclosures land.
_LIBS = [
    {
        "name": "jQuery",
        # Negative lookahead excludes the plugin family (jquery-ui,
        # jquery-migrate, jquery-mobile, ...) whose OWN versions must not be
        # reported as core-jQuery vulnerabilities -- CVE-2020-11022 etc.
        # belong to core jQuery, not to these files (silent-FP bug).
        "url_rx": re.compile(
            r"jquery(?!-(?:ui|migrate|mobile))[^/]*\.js$|/jquery/"),
        "match": "jquery",
        "ranges": [
            # CVE-2020-11022 / CVE-2020-11023 (XSS, < 3.5.0),
            # CVE-2019-11358 (prototype pollution, < 3.4.0),
            # CVE-2012-6708 / CVE-2015-9251 (XSS, < 3.0.0)
            ((0,), (3, 4, 0)),
            ((3, 4, 0), (3, 5, 0)),
        ],
        "cve": "CVE-2020-11022/11023 (XSS); CVE-2019-11358 (proto pollution)",
    },
    {
        "name": "AngularJS",
        "url_rx": re.compile(r"angular[^/]*\.js$|/angular(?:\.js)?/"),
        "match": "angular",
        "ranges": [
            # CVE-2016-10069 (XSS), CVE-2014-6396 (sandbox escape)
            ((0,), (1, 8, 0)),
        ],
        "cve": "CVE-2016-10069; CVE-2014-6396 (XSS / sandbox escape)",
    },
    {
        "name": "Bootstrap",
        "url_rx": re.compile(r"bootstrap[^/]*\.js$|/bootstrap/"),
        "match": "bootstrap",
        "ranges": [
            # CVE-2018-14040/14041/14042 (XSS, < 3.3.7 / 4.0.0)
            ((0,), (3, 3, 7)),
            ((3, 3, 7), (4, 0, 0)),
        ],
        "cve": "CVE-2018-14040/14041/14042 (XSS)",
    },
    {
        "name": "Vue.js",
        "url_rx": re.compile(r"vue[^/]*\.js$|/vue/"),
        "match": "vue",
        "ranges": [
            # CVE-2019-16361 (XSS via v-html w/ template compilation, < 2.6.10)
            ((0,), (2, 6, 10)),
        ],
        "cve": "CVE-2019-16361 (XSS)",
    },
    {
        "name": "Underscore.js",
        "url_rx": re.compile(r"underscore[^/]*\.js$|/underscore/"),
        "match": "underscore",
        "ranges": [
            # CVE-2021-26658 (prototype pollution, < 1.13.0-0)
            ((0,), (1, 13, 0)),
        ],
        "cve": "CVE-2021-26658 (proto pollution)",
    },
    {
        "name": "Lodash",
        "url_rx": re.compile(r"lodash[^/]*\.js$|/lodash/"),
        "match": "lodash",
        "ranges": [
            # CVE-2020-8203 (proto pollution, < 4.17.20), CVE-2018-3721/3722
            ((0,), (4, 17, 20)),
        ],
        "cve": "CVE-2020-8203; CVE-2018-3721/3722 (proto pollution)",
    },
    {
        "name": "Handlebars.js",
        "url_rx": re.compile(r"handlebars[^/]*\.js$|/handlebars/"),
        "match": "handlebars",
        "ranges": [
            # CVE-2021-23383 (prototype pollution, < 4.7.7),
            # CVE-2019-19919 (XSS, < 4.4.4)
            ((0,), (4, 4, 4)),
            ((4, 4, 4), (4, 7, 7)),
        ],
        "cve": "CVE-2021-23383; CVE-2019-19919 (XSS / proto pollution)",
    },
]


def _parse_version(text: str | None) -> tuple | None:
    """Parse '1.2.3' -> (1, 2, 3); '4.0' -> (4, 0); None on garbage."""
    if not text:
        return None
    parts = re.findall(r"\d+", text)
    if not parts:
        return None
    return tuple(int(x) for x in parts[:4])


def _version_in_ranges(ver: tuple, ranges: list) -> bool:
    for lo, hi in ranges:
        if ver >= lo and (hi is None or ver < hi):
            return True
    return False


def _extract_version_from_url(url: str, entry: dict) -> tuple | None:
    """Parse the version anchored to the library name in the URL.

    Examples that work:
      jquery-1.12.4.min.js            -> (1, 12, 4)
      /jquery/3.1.0/jquery.min.js     -> (3, 1, 0)
      vue@2.6.14/dist/vue.min.js      -> (2, 6, 14)
    Examples that do NOT leak:
      /static/v2/jquery.min.js        -> None (v2 precedes the name)
      vue-router.js                   -> None (no digit after "vue")
    """
    url_l = url.lower()
    idx = url_l.find(entry["match"])
    if idx == -1:
        return None
    tail = url_l[idx + len(entry["match"]):]
    m = re.search(r"(?:[-./@])(\d+(?:\.\d+){1,3})", tail)
    if not m:
        return None
    return _parse_version(m.group(1))


def extract_script_srcs(html: str | None) -> list[str]:
    """Return the raw ``src`` values of every <script> tag in ``html``."""
    if not html:
        return []
    out = []
    for m in re.finditer(
            r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']",
            html, re.I):
        out.append(m.group(1))
    return out


def scan_html(html: str | None, base_url: str = "") -> list[dict]:
    """Scan a page's HTML for outdated JS libraries.

    Returns a list of finding dicts::

        {
          "url": base_url, "library": name, "version": "1.2.3",
          "script_src": "...", "cve": "...", "severity": "medium",
          "type": "outdated_js_lib", "confidence": "high",
        }

    A script whose version cannot be resolved is NOT reported (no guessing).
    """
    if not html:
        return []
    findings: list[dict] = []
    seen: set[tuple] = set()
    for src in extract_script_srcs(html):
        src_l = src.lower()
        for entry in _LIBS:
            if not entry["url_rx"].search(src_l):
                continue
            ver = _extract_version_from_url(src, entry)
            if ver is None:
                continue
            key = (entry["name"], ver)
            if key in seen:
                continue
            seen.add(key)
            if _version_in_ranges(ver, entry["ranges"]):
                findings.append({
                    "url": base_url,
                    "library": entry["name"],
                    "version": ".".join(str(x) for x in ver),
                    "script_src": src,
                    "cve": entry["cve"],
                    "severity": "medium",
                    "type": "outdated_js_lib",
                    "confidence": "high",
                })
    return findings
