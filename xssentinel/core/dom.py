"""DOM-based XSS taint analysis (static, source -> sink).

Walks inline <script> blocks and inline handlers for dangerous *sinks* that
write untrusted data into executable sinks, and checks whether a known
*source* (user-controllable input) flows into that sink. This catches
client-side XSS that never touches the server, which classic reflected scanners
miss. Heuristic and clearly labeled low/medium confidence.

Improvements over a naive scanner:
  * jQuery sinks ($().html/.attr/.append/...) and React/Vue/Angular sinks.
  * More sources incl. window.location variants, postMessage event.data,
    XHR/fetch response bodies.
  * Lightweight variable-propagation: a var assigned from a source and later
    passed to a sink is treated as tainted.
  * postMessage handler flow (addEventListener('message') -> e.data -> sink).
"""
from __future__ import annotations

import re

# Sources: attacker-influenced browser/URL/data.
SOURCES = [
    r"location", r"window\.location", r"document\.URL", r"document\.documentURI",
    r"document\.baseURI", r"document\.referrer", r"document\.cookie",
    r"window\.name", r"localStorage", r"sessionStorage", r"URLSearchParams",
    r"postMessage", r"document\.forms", r"history\.(pushState|replaceState)",
    r"navigator", r"getParameter", r"XMLHttpRequest", r"fetch\(", r"WebSocket",
    r"document\.domain",
]

# Sinks: writing data into an executable context.
SINKS = [
    r"\.innerHTML", r"\.outerHTML", r"\.insertAdjacentHTML",
    r"document\.write(?:ln)?", r"\.src\s*=", r"\.href\s*=",
    r"\.data\s*=", r"eval\s*\(", r"setTimeout\s*\(", r"setInterval\s*\(",
    r"new\s+Function\s*\(", r"\.appendChild\s*\(", r"\.html\s*\(",
    r"\.attr\s*\(", r"\.append\s*\(", r"\.prepend\s*\(",
    r"\.after\s*\(", r"\.before\s*\(", r"\.replaceWith\s*\(", r"\.load\s*\(",
    r"\.prop\s*\(", r"\.val\s*\(", r"document\.title\s*=",
    r"\.setAttribute", r"location\.(href|assign|replace)\s*=",
    r"\.srcdoc\s*=",
    r"window\.open", r"dangerouslySetInnerHTML", r"v-html", r"ng-bind-html",
    r"\$sce",
]

_VAR_RE = re.compile(r"(?:var|let|const|window\.|globalThis\.)\s*([A-Za-z_$][\w$]*)\s*=\s*([^;]+);")
_SOURCE_RE = re.compile("(" + "|".join(SOURCES) + ")", re.I)
_SINK_RE = re.compile("(" + "|".join(SINKS) + ")", re.I)
# \b is REQUIRED: without it, 'content="script-src ..."' in a CSP meta tag
# yields a phantom 'ontent=' handler match (observed as a real-world FP).
_HANDLER_RE = re.compile(r"\b(on\w+)\s*=\s*[\"']([^\"']*)[\"']", re.I)
_JAVASCRIPT_URI_RE = re.compile(r"href\s*=\s*[\"']javascript:([^\"']+)", re.I)
_POSTMSG_RE = re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.I)


def _line_of(code: str, pos: int) -> int:
    return code.count("\n", 0, pos) + 1


def _tainted_vars(code: str) -> set[str]:
    """Variables assigned from a source are treated as tainted."""
    tainted = set()
    for m in _VAR_RE.finditer(code):
        name, rhs = m.group(1), m.group(2)
        if _SOURCE_RE.search(rhs):
            tainted.add(name)
    return tainted


def analyze_script(code: str) -> list[dict]:
    findings = []
    seen = set()
    # Phase 43: AST channel first (DalFox-style data flow).  Real
    # source->sink chains through variables/assignments that regex windows
    # cannot follow; on parse failure we transparently fall back to regex.
    ast_findings = None
    try:
        from . import js_ast as ast_mod
        ast_findings = ast_mod.analyze_script(code)
    except Exception:
        ast_findings = None
    if ast_findings:
        for f in ast_findings:
            f.pop("_srcs", None)
            findings.append(f)
            seen.add((f["line"], f["sink"], f["source"]))
    tainted = _tainted_vars(code)
    for m in _SINK_RE.finditer(code):
        sink = m.group(0)
        line = _line_of(code, m.start())
        snippet = code[max(0, m.start() - 80): m.start() + 80].replace("\n", " ")
        window = code[max(0, m.start() - 200): min(len(code), m.end() + 60)]
        # Phase 114b: the sink match itself often CONTAINS a source
        # keyword as its left-hand side -- "location.href =" contains
        # "location", so every location assignment was its own taint
        # source and a fixed redirect read as attacker fed (found via the
        # benchmark's safe twin neg-redirect-01).  Blank the sink text out
        # of the window before searching for a source; the RIGHT-hand side
        # stays, because that is where a real source lives
        # ("location.href = location.hash.slice(1)").
        w_start = max(0, m.start() - 200)
        sink_at = m.start() - w_start
        masked = (window[:sink_at] + " " * (m.end() - m.start())
                  + window[sink_at + (m.end() - m.start()):])
        src_match = _SOURCE_RE.search(masked)
        source = src_match.group(0) if src_match else None
        # variable-propagation: a tainted var name near the sink counts.
        if not source:
            for v in tainted:
                if re.search(r"\b" + re.escape(v) + r"\b", masked):
                    source = f"var:{v}"
                    break
        key = (line, sink, source)
        if key in seen:
            continue
        seen.add(key)
        # Phase 43: AST findings already carry a real data-flow chain, so a
        # regex hit on the SAME sink without a source adds no information --
        # skip it to keep reports clean (AST subsumes the regex layer).
        if ast_findings and any(f["sink"] == sink.strip() and f["source"]
                                for f in findings):
            continue
        findings.append({
            "type": "dom_sink",
            "line": line,
            "sink": sink.strip(),
            "source": source,
            "snippet": snippet.strip(),
            "confidence": "medium" if source else "low",
            "detail": (f"sink '{sink.strip()}' fed by source '{source}'"
                       if source else
                       f"sink '{sink.strip()}' found (no obvious source in window)"),
        })
    # postMessage -> sink flow (strong DOM XSS signal)
    if _POSTMSG_RE.search(code):
        for m in _POSTMSG_RE.finditer(code):
            tail = code[m.end(): m.end() + 400]
            if re.search(r"\.data", tail) and _SINK_RE.search(tail):
                findings.append({
                    "type": "dom_postmessage",
                    "line": _line_of(code, m.start()),
                    "sink": "postMessage event.data -> sink",
                    "source": "postMessage",
                    "snippet": tail[:120].replace("\n", " "),
                    "confidence": "medium",
                    "detail": "postMessage event.data flows into a sink (unvalidated message handler)",
                })
    return findings


def analyze_handlers_and_uris(html: str) -> list[dict]:
    findings = []
    for m in _HANDLER_RE.finditer(html):
        handler, body = m.group(1), m.group(2)
        if any(x in body.lower() for x in ("alert", "document.", "location",
                                            "eval", "innerHTML", "fetch",
                                            "xmlhttp", "src", "href")):
            findings.append({
                "type": "inline_handler",
                "sink": handler,
                "source": None,
                "snippet": body[:120],
                "confidence": "low",
                "detail": f"inline handler '{handler}' with dynamic content",
            })
    for m in _JAVASCRIPT_URI_RE.finditer(html):
        findings.append({
            "type": "javascript_uri",
            "sink": "href=javascript:",
            "source": None,
            "snippet": m.group(1)[:120],
            "confidence": "low",
            "detail": "javascript: URI in href attribute",
        })
    # Framework template interpolation sinks (best-effort).
    if re.search(r"ng-app", html, re.I):
        for m in re.finditer(r"\{\{(.+?)\}\}", html):
            if "constructor" in m.group(1) or "alert" in m.group(1):
                findings.append({
                    "type": "angular_interpolation",
                    "sink": "{{ }} interpolation",
                    "source": "template",
                    "snippet": m.group(0)[:120],
                    "confidence": "medium",
                    "detail": "Angular expression interpolation with dangerous call",
                })
    return findings


def analyze(code_or_html: str, is_html: bool = False) -> list[dict]:
    if is_html:
        findings = analyze_handlers_and_uris(code_or_html)
        for sm in re.finditer(r"<script\b[^>]*>(.*?)</script>", code_or_html,
                              re.S | re.I):
            findings.extend(analyze_script(sm.group(1)))
        return findings
    return analyze_script(code_or_html)
