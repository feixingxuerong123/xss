"""Framework-specific DOM XSS detection (React/Vue/AngularJS/Svelte/Lit).

The detection-rule corpus now lives in ``data/framework_xss.json`` -- edit
THAT file to add or adjust rules -- and this module re-compiles the regexes
at import.  Public API unchanged (contract guarded by tests):

    detect_framework(html) -> list[str]
    find_dangerous_patterns(html, framework=None) -> list[dict]
    analyze_page(html) -> dict
    build_poc_html(target_url, framework, payload) -> str
"""
from __future__ import annotations

import json
import os
import re

_DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "data", "framework_xss.json")

with open(_DATA_FILE, encoding="utf-8") as _f:
    _RULES = json.load(_f)

PatternDef = tuple[re.Pattern, str, str]

# (compiled_regex, description, severity) per framework.
FRAMEWORK_PATTERNS: dict[str, list[PatternDef]] = {
    framework: [
        (re.compile(src, re.IGNORECASE | re.DOTALL), desc, sev)
        for src, desc, sev in patterns
    ]
    for framework, patterns in _RULES["framework_raw_patterns"].items()
}

# Framework-detection regexes (compiled).  Used by ``detect_framework``.
_FRAMEWORK_DETECTORS: list[tuple[re.Pattern, str]] = [
    (re.compile(src, re.IGNORECASE), name)
    for src, name in _RULES["framework_detectors"]
]

# Backwards-compatible raw view (string regexes).
_FRAMEWORK_RAW_PATTERNS: dict[str, list[tuple[str, str, str]]] = {
    k: [tuple(t) for t in v]
    for k, v in _RULES["framework_raw_patterns"].items()
}

# Severity ranking -- higher = more dangerous.
_SEVERITY_RANK: dict[str, int] = _RULES["severity_rank"]


def detect_framework(html: str | None) -> list[str]:
    """Return a list of framework names detected in ``html``.

    Detection is based on framework-specific attributes, runtime
    globals, and CDN script URLs.  The list is de-duplicated and
    returned in order of first match.  Returns an empty list for
    ``None`` / empty input.
    """
    if not html:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for pattern, name in _FRAMEWORK_DETECTORS:
        if name not in seen and pattern.search(html):
            seen.add(name)
            out.append(name)
    return out


def find_dangerous_patterns(
    html: str | None,
    framework: str,
) -> list[dict]:
    """Find dangerous patterns for ``framework`` in ``html``.

    Returns a list of findings, each::

        {
            "pattern":     str,   # regex source
            "description": str,   # human-readable explanation
            "severity":    str,   # "high" | "medium" | "low"
            "snippet":     str,   # ~80-char window around the match
        }

    Returns an empty list if ``html`` is empty, ``framework`` is not
    recognized, or no patterns match.
    """
    if not html or not framework:
        return []
    patterns = FRAMEWORK_PATTERNS.get(framework.lower())
    if not patterns:
        return []
    # Phase 30-3: sort patterns by severity descending (high first) so
    # that high-severity findings are recorded before medium/low ones.
    # This prevents a generic medium-severity pattern (e.g. bare
    # [innerHTML]) from suppressing a more specific high-severity pattern
    # (e.g. | bypassSecurityTrustHtml pipe) that overlaps the same span.
    # Within the same severity, preserve the original list order.
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    sorted_patterns = sorted(
        enumerate(patterns),
        key=lambda iv: (sev_rank.get(iv[1][2], 9), iv[0]),
    )
    findings: list[dict] = []
    seen_spans: set[tuple[int, int]] = set()
    for _, (regex, desc, sev) in sorted_patterns:
        for m in regex.finditer(html):
            start, end = m.span()
            # De-duplicate overlapping matches from multiple patterns
            # that target the same sink.  We treat two matches as
            # duplicates when their spans overlap by more than 50%.
            duplicate = False
            for s, e in seen_spans:
                overlap = max(0, min(end, e) - max(start, s))
                if overlap > 0 and overlap >= 0.5 * min(end - start, e - s):
                    duplicate = True
                    break
            if duplicate:
                continue
            seen_spans.add((start, end))
            # Build a ~80-char snippet centered on the match.
            ctx_start = max(0, start - 40)
            ctx_end = min(len(html), end + 40)
            snippet = html[ctx_start:ctx_end]
            # Collapse whitespace for readability.
            snippet = re.sub(r"\s+", " ", snippet).strip()
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            findings.append({
                "pattern": regex.pattern,
                "description": desc,
                "severity": sev,
                "snippet": snippet,
            })
    return findings


def analyze_page(html: str | None) -> dict:
    """Aggregate per-framework findings into a page-level summary.

    Returns::

        {
            "frameworks_detected": list[str],   # frameworks present
            "vulnerable_count":    int,         # total findings
            "findings":            list[dict],  # all findings, with
                                                # a "framework" field
                                                # added to each
            "exploitable":        bool,        # True if at least one
                                                # finding is "high"
                                                # severity (direct sink)
        }
    """
    if not html:
        return {
            "frameworks_detected": [],
            "vulnerable_count": 0,
            "findings": [],
            "exploitable": False,
        }
    frameworks = detect_framework(html)
    all_findings: list[dict] = []
    exploitable = False
    for fw in frameworks:
        for finding in find_dangerous_patterns(html, fw):
            entry = dict(finding)
            entry["framework"] = fw
            all_findings.append(entry)
            if finding["severity"] == "high":
                exploitable = True
    # Sort findings by severity (high first), then by framework.
    all_findings.sort(
        key=lambda f: (-_SEVERITY_RANK.get(f["severity"], 0), f["framework"]),
    )
    return {
        "frameworks_detected": frameworks,
        "vulnerable_count": len(all_findings),
        "findings": all_findings,
        "exploitable": exploitable,
    }


def build_poc_html(target_url: str, framework: str, payload: str) -> str:
    """Build a standalone HTML PoC demonstrating a framework XSS sink.

    The PoC loads the framework from its canonical CDN and renders a
    component that uses the framework's dangerous sink with the
    supplied ``payload``.  The auditor opens the PoC in a browser to
    confirm execution; the same payload can then be sent to
    ``target_url`` to exploit the live site.

    ``framework`` is one of ``react``, ``vue``, ``angular``,
    ``svelte`` (case-insensitive).  Unknown frameworks produce an
    empty string.
    """
    if not target_url or not framework or not payload:
        return ""
    fw = framework.lower()
    # JS-string-safe versions of the inputs for embedding in script.
    js_url = target_url.replace("\\", "\\\\").replace("'", "\\'").replace("</", "<\\/")
    js_payload = (
        payload.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("</", "<\\/")
    )
    # HTML-escape the payload for display in <pre> blocks.
    html_payload = (
        payload.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    header = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        '  <meta charset="utf-8">\n'
        "  <title>XSSentinel framework XSS PoC</title>\n"
        "  <style>\n"
        "    body{font:14px/1.4 monospace;background:#111;color:#eee;"
        "padding:24px}\n"
        "    pre{background:#000;color:#0f0;padding:12px;"
        "border:1px solid #333;white-space:pre-wrap}\n"
        "    a{color:#6cf}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>XSSentinel &mdash; Framework XSS PoC</h1>\n"
        f"  <p>Framework: <code>{fw}</code></p>\n"
        f"  <p>Target: <code>{target_url}</code></p>\n"
        f"  <p>Payload (source):</p>\n"
        f"  <pre>{html_payload}</pre>\n"
        "  <p>Live demo below.  If the payload executes (alert / "
        "console log), the framework sink is exploitable.</p>\n"
        "  <hr>\n"
        "  <div id=\"app\"></div>\n"
        "  <hr>\n"
    )
    footer = "</body>\n</html>\n"

    if fw == "react":
        return header + (
            "  <script src=\"https://unpkg.com/react@18/umd/react.development.js\" crossorigin></script>\n"
            "  <script src=\"https://unpkg.com/react-dom@18/umd/react-dom.development.js\" crossorigin></script>\n"
            "  <script>\n"
            "    var payload = '" + js_payload + "';\n"
            "    var targetUrl = '" + js_url + "';\n"
            "    // dangerouslySetInnerHTML is the canonical React XSS sink.\n"
            "    // The component below renders the payload as raw HTML.\n"
            "    function Vulnerable() {\n"
            "      return React.createElement('div', {\n"
            "        dangerouslySetInnerHTML: { __html: payload }\n"
            "      });\n"
            "    }\n"
            "    ReactDOM.createRoot(document.getElementById('app'))\n"
            "      .render(React.createElement(Vulnerable));\n"
            "  </script>\n"
        ) + footer
    if fw == "vue":
        return header + (
            "  <script src=\"https://unpkg.com/vue@3/dist/vue.global.js\"></script>\n"
            "  <script>\n"
            "    var payload = '" + js_payload + "';\n"
            "    var targetUrl = '" + js_url + "';\n"
            "    // v-html is the canonical Vue XSS sink.\n"
            "    var app = Vue.createApp({\n"
            "      template: '<div v-html=\"payload\"></div>',\n"
            "      data: function () { return { payload: payload }; }\n"
            "    });\n"
            "    app.mount('#app');\n"
            "  </script>\n"
        ) + footer
    if fw == "angular":
        return header + (
            "  <!-- Angular PoC requires a build step; this snippet shows\n"
            "       the vulnerable template + component pair. -->\n"
            "  <script>\n"
            "    var payload = '" + js_payload + "';\n"
            "    var targetUrl = '" + js_url + "';\n"
            "    /*\n"
            "       // vulnerable.component.ts\n"
            "       import { Component } from '@angular/core';\n"
            "       import { DomSanitizer } from '@angular/platform-browser';\n"
            "       @Component({\n"
            "         selector: 'app-vulnerable',\n"
            "         template: '<div [innerHTML]=\"trusted\"></div>'\n"
            "       })\n"
            "       export class VulnerableComponent {\n"
            "         trusted = this.sanitizer.bypassSecurityTrustHtml(payload);\n"
            "         constructor(private sanitizer: DomSanitizer) {}\n"
            "       }\n"
            "    */\n"
            "    document.getElementById('app').innerHTML =\n"
            "      '<pre>[Angular PoC requires a build step -- see source comment above]</pre>';\n"
            "  </script>\n"
        ) + footer
    if fw == "svelte":
        return header + (
            "  <!-- Svelte PoC requires a build step; this snippet shows\n"
            "       the vulnerable component source. -->\n"
            "  <script>\n"
            "    var payload = '" + js_payload + "';\n"
            "    var targetUrl = '" + js_url + "';\n"
            "    /*\n"
            "       <!-- Vulnerable.svelte -->\n"
            "       <script>\n"
            "         export let payload;\n"
            "       </script>\n"
            "       <div>{@html payload}</div>\n"
            "    */\n"
            "    document.getElementById('app').innerHTML =\n"
            "      '<pre>[Svelte PoC requires a build step -- see source comment above]</pre>';\n"
            "  </script>\n"
        ) + footer
    if fw == "lit":
        return header + (
            "  <script type=\"module\">\n"
            "    import { html, render } from 'https://cdn.jsdelivr.net/npm/lit@3/+esm';\n"
            "    import { unsafeHTML } from 'https://cdn.jsdelivr.net/npm/lit@3/+esm/directives/unsafe-html.js';\n"
            "    var payload = '" + js_payload + "';\n"
            "    var targetUrl = '" + js_url + "';\n"
            "    // unsafeHTML() is the canonical Lit XSS sink.\n"
            "    // The template below renders the payload as raw HTML.\n"
            "    var template = html`<div>${unsafeHTML(payload)}</div>`;\n"
            "    render(template, document.getElementById('app'));\n"
            "  </script>\n"
        ) + footer
    return ""
