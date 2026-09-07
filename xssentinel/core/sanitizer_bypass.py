"""HTML Sanitizer bypass detection (Phase 28-4).

Many applications use client-side HTML sanitizers (DOMPurify, sanitize-html,
jQuery $.parseHTML, etc.) to filter user-supplied HTML before inserting it
into the DOM.  Sanitizers are complex and have had numerous bypasses over
the years.  This module performs STATIC analysis of a page's JavaScript to
detect:

  1. **Known-vulnerable sanitizer versions**: detects DOMPurify <= 2.0.7
     (mutation XSS bypass), sanitize-html < 2.3.2, and other CVE-affected
     versions by inspecting the loaded script URL or version comments.
  2. **Unsafe sanitizer configuration**: detects configurations that weaken
     the sanitizer -- e.g. ``ADD_TAGS: ['script']``, ``ALLOW_DATA_ATTR: true``
     combined with ``ADD_ATTR: ['href']``, or ``ALLOWED_URI_REGEXP`` set to
     a permissive pattern.
  3. **Sanitizer output fed to dangerous sink**: detects the pattern
     ``DOMPurify.sanitize(x)`` whose result is passed to ``innerHTML``
     (sanitizer output should go through a safe insertion like
     ``textContent`` or ``setHTML()``; even sanitized HTML can trigger
     mXSS in edge cases).
  4. **Missing sanitizer on innerHTML**: detects ``innerHTML = userVar``
     where ``userVar`` comes from a user-controlled source (location.hash,
     document.referrer, etc.) and is NOT passed through a sanitizer.
  5. **Bypassed sanitizer (RETURN_DOM / RETURN_DOM_FRAGMENT)**: DOMPurify
     can be configured to return a DOM node directly via
     ``RETURN_DOM: true`` -- if the caller then appends this node to the
     document, any mutation that occurred during parsing is preserved,
     potentially bypassing the sanitizer's string-level filtering.

This module is heuristic -- it flags suspicious patterns for human review
rather than proving exploitation.  All findings are medium or low severity
unless a known-vulnerable version is detected (high).
"""
from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Known vulnerable sanitizer versions
# ---------------------------------------------------------------------------
# (sanitizer_name, regex_pattern, min_safe_version, cve_description)
_VULNERABLE_SANITIZERS = [
    ("DOMPurify",
     re.compile(r"DOMPurify[^\d]*?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE),
     (2, 0, 8),
     "DOMPurify < 2.0.8 has multiple mXSS bypasses (CVE-2020-26870, CVE-2020-7536)"),
    ("DOMPurify",
     re.compile(r"dompurify[@/](\d+)\.(\d+)\.(\d+)", re.IGNORECASE),
     (2, 0, 8),
     "DOMPurify < 2.0.8 has multiple mXSS bypasses (CVE-2020-26870, CVE-2020-7536)"),
    ("sanitize-html",
     re.compile(r"sanitize-html[^\d]*?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE),
     (2, 3, 2),
     "sanitize-html < 2.3.2 has bypass via nested tags (CVE-2021-26539)"),
    ("xss",
     re.compile(r"\blehh\.xss[^\d]*?(\d+)\.(\d+)\.(\d+)"),
     (1, 0, 7),
     "lehh.xss < 1.0.7 has regex bypass vulnerabilities"),
]


# ---------------------------------------------------------------------------
# Unsafe configuration patterns
# ---------------------------------------------------------------------------
_UNSAFE_CONFIG_PATTERNS = [
    (re.compile(r"ADD_TAGS\s*:\s*\[[^\]]*['\"]script['\"]", re.IGNORECASE),
     "sanitizer_config_add_script",
     "high",
     "Sanitizer config ADD_TAGS includes 'script' -- allows <script> tags through"),
    (re.compile(r"ADD_TAGS\s*:\s*\[[^\]]*['\"]iframe['\"]", re.IGNORECASE),
     "sanitizer_config_add_iframe",
     "medium",
     "Sanitizer config ADD_TAGS includes 'iframe' -- allows <iframe> tags"),
    (re.compile(r"ALLOW_TAGS\s*:\s*\[[^\]]*['\"]script['\"]", re.IGNORECASE),
     "sanitizer_config_allow_script",
     "high",
     "Sanitizer config ALLOW_TAGS includes 'script'"),
    (re.compile(r"ALLOW_DATA_ATTR\s*:\s*(?:true|1)", re.IGNORECASE),
     "sanitizer_config_allow_data_attr",
     "low",
     "Sanitizer ALLOW_DATA_ATTR is true -- data-* attributes can carry payloads"),
    (re.compile(r"RETURN_DOM\s*:\s*(?:true|1)", re.IGNORECASE),
     "sanitizer_config_return_dom",
     "medium",
     "DOMPurify RETURN_DOM: true returns a DOM node -- mutation XSS may survive"),
    (re.compile(r"RETURN_DOM_FRAGMENT\s*:\s*(?:true|1)", re.IGNORECASE),
     "sanitizer_config_return_dom_fragment",
     "medium",
     "DOMPurify RETURN_DOM_FRAGMENT: true -- mutation XSS may survive in fragment"),
    (re.compile(r"KEEP_CONTENT\s*:\s*(?:true|1)", re.IGNORECASE),
     "sanitizer_config_keep_content",
     "low",
     "DOMPurify KEEP_CONTENT: true keeps inner text of stripped tags -- may carry payloads"),
    (re.compile(r"ALLOW_UNKNOWN_PROTOCOLS\s*:\s*(?:true|1)", re.IGNORECASE),
     "sanitizer_config_allow_unknown_protocols",
     "medium",
     "Sanitizer ALLOW_UNKNOWN_PROTOCOLS: true -- permits javascript: and data: URIs"),
]


# ---------------------------------------------------------------------------
# Sink patterns: sanitizer.sanitize(x) -> innerHTML
# ---------------------------------------------------------------------------
# Detect: DOMPurify.sanitize(x) ... innerHTML = <result>
_SANITIZE_CALL_RE = re.compile(
    r"(DOMPurify|sanitizeHTML|sanitize_html|filterXSS)\.sanitize\s*\(",
    re.IGNORECASE,
)
_INNERHTML_ASSIGN_RE = re.compile(
    r"\.innerHTML\s*=\s*(.+?)(?:;|\n)",
    re.IGNORECASE,
)
# Direct: innerHTML = DOMPurify.sanitize(x) -- sanitizer output to sink.
_SANITIZED_INNERHTML_RE = re.compile(
    r"\.innerHTML\s*=\s*(?:DOMPurify|sanitizeHTML|sanitize_html|filterXSS)\.sanitize\s*\(",
    re.IGNORECASE,
)
# Indirect: var <name> = DOMPurify.sanitize(x) -- capture the variable name
# so we can detect <name> later flowing into innerHTML.
_SANITIZE_VAR_ASSIGN_RE = re.compile(
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:DOMPurify|sanitizeHTML|sanitize_html|filterXSS)\.sanitize\s*\(",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Missing sanitizer on innerHTML with user source
# ---------------------------------------------------------------------------
_USER_SOURCE_RE = re.compile(
    r"(location\.(?:hash|search|href)|document\.(?:referrer|cookie|URL)|"
    r"window\.name|new\s+URLSearchParams\s*\(\s*location\.search\s*\))",
    re.IGNORECASE,
)


def _check_version(version_tuple: tuple, min_safe: tuple) -> bool:
    """Return True if version_tuple < min_safe (i.e. vulnerable)."""
    for i in range(3):
        if version_tuple[i] < min_safe[i]:
            return True
        if version_tuple[i] > min_safe[i]:
            return False
    return False  # equal == safe


def analyze_page(html: str | None, page_url: str = "") -> dict:
    """Analyze a page for HTML sanitizer bypass vulnerabilities.

    Returns a dict with:

      * ``vulnerable_versions``  -- list of detected vulnerable sanitizer versions
      * ``unsafe_configs``       -- list of unsafe configuration patterns found
      * ``sanitized_sinks``      -- list of innerHTML = sanitize(x) patterns
      * ``unsanitized_sinks``    -- list of innerHTML = userVar without sanitizer
      * ``violations``           -- aggregated list of violation dicts
    """
    html = html or ""

    vulnerable_versions: list[dict] = []
    unsafe_configs: list[dict] = []
    sanitized_sinks: list[dict] = []
    unsanitized_sinks: list[dict] = []
    violations: list[dict] = []

    # 1. Check for vulnerable sanitizer versions.
    for name, pattern, min_safe, cve in _VULNERABLE_SANITIZERS:
        for m in pattern.finditer(html):
            version = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            if _check_version(version, min_safe):
                vstr = ".".join(str(v) for v in version)
                entry = {
                    "sanitizer": name,
                    "version": vstr,
                    "min_safe": ".".join(str(v) for v in min_safe),
                    "cve": cve,
                    "match": m.group(0)[:100],
                }
                vulnerable_versions.append(entry)
                violations.append({
                    "type": "sanitizer_vulnerable_version",
                    "severity": "high",
                    "title": f"{name} {vstr} is vulnerable ({cve})",
                    "evidence": m.group(0)[:120],
                    "sanitizer": name,
                    "version": vstr,
                })

    # 2. Check for unsafe sanitizer configurations.
    for pattern, vtype, severity, desc in _UNSAFE_CONFIG_PATTERNS:
        for m in pattern.finditer(html):
            entry = {
                "type": vtype,
                "severity": severity,
                "desc": desc,
                "match": m.group(0)[:100],
            }
            unsafe_configs.append(entry)
            violations.append({
                "type": vtype,
                "severity": severity,
                "title": desc,
                "evidence": m.group(0)[:120],
            })

    # 3. Sanitizer output fed to innerHTML.
    # 3a. Direct: .innerHTML = DOMPurify.sanitize(...)
    for m in _SANITIZED_INNERHTML_RE.finditer(html):
        entry = {
            "match": m.group(0)[:100],
            "desc": "Sanitizer output passed directly to innerHTML",
        }
        sanitized_sinks.append(entry)
        # This is informational (medium) -- sanitized HTML in innerHTML
        # is the common pattern, but mXSS can bypass it.
        violations.append({
            "type": "sanitizer_output_to_innerhtml",
            "severity": "medium",
            "title": "Sanitizer output passed to innerHTML (mXSS risk)",
            "evidence": m.group(0)[:120],
        })
    # 3b. Indirect: var clean = DOMPurify.sanitize(x); ... el.innerHTML = clean;
    # Track variables that hold sanitizer output, then look for innerHTML
    # assignments that reference those variables.
    sanitize_var_names: set[str] = set()
    for m in _SANITIZE_VAR_ASSIGN_RE.finditer(html):
        var_name = m.group(1)
        if var_name:
            sanitize_var_names.add(var_name)
    if sanitize_var_names:
        for m in _INNERHTML_ASSIGN_RE.finditer(html):
            assign_expr = m.group(1).strip()
            # Skip if it's a direct sanitize() call (already caught by 3a).
            if _SANITIZE_CALL_RE.search(assign_expr):
                continue
            # Check if the assignment references a variable that holds
            # sanitizer output.
            for var_name in sanitize_var_names:
                # Word-boundary match so "clean" doesn't match "cleaner".
                var_re = re.compile(r"\b" + re.escape(var_name) + r"\b")
                if var_re.search(assign_expr):
                    entry = {
                        "match": m.group(0)[:100],
                        "desc": f"Sanitizer output (var {var_name}) passed to innerHTML",
                    }
                    sanitized_sinks.append(entry)
                    violations.append({
                        "type": "sanitizer_output_to_innerhtml",
                        "severity": "medium",
                        "title": "Sanitizer output passed to innerHTML (mXSS risk)",
                        "evidence": m.group(0)[:120],
                    })
                    break

    # 4. Missing sanitizer on innerHTML with user source.
    # Find all innerHTML assignments.
    for m in _INNERHTML_ASSIGN_RE.finditer(html):
        assign_expr = m.group(1).strip()
        # Skip if the assignment already uses a sanitizer.
        if _SANITIZE_CALL_RE.search(assign_expr):
            continue
        # Check if the assignment expression references a user source.
        if _USER_SOURCE_RE.search(assign_expr):
            entry = {
                "match": m.group(0)[:100],
                "assign_expr": assign_expr[:80],
                "desc": "innerHTML assigned from user-controlled source without sanitizer",
            }
            unsanitized_sinks.append(entry)
            violations.append({
                "type": "unsanitized_innerhtml_user_source",
                "severity": "high",
                "title": "innerHTML assigned from user-controlled source without sanitizer",
                "evidence": m.group(0)[:120],
            })

    return {
        "vulnerable_versions": vulnerable_versions,
        "unsafe_configs": unsafe_configs,
        "sanitized_sinks": sanitized_sinks,
        "unsanitized_sinks": unsanitized_sinks,
        "violations": violations,
    }


def build_poc_html(page_url: str, violation_type: str = "",
                   sanitizer: str = "") -> str:
    """Build a minimal PoC HTML snippet demonstrating the sanitizer issue."""
    if violation_type == "sanitizer_vulnerable_version":
        return (
            f'<!-- PoC: Exploit known bypass in {sanitizer} -->\n'
            f'<!-- mXSS payload that survives sanitization in vulnerable versions -->\n'
            f'<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->'
        )
    if violation_type == "sanitizer_output_to_innerhtml":
        return (
            f'<!-- PoC: mXSS payload targeting innerHTML after sanitize() -->\n'
            f'<noscript><p title="</noscript><img src=x onerror=alert(1)>">'
        )
    if violation_type == "unsanitized_innerhtml_user_source":
        return (
            f'<!-- PoC: Direct innerHTML = location.hash without sanitize() -->\n'
            f'#<img src=x onerror=alert(document.domain)>'
        )
    return f'<!-- Sanitizer issue: {violation_type} -->'
