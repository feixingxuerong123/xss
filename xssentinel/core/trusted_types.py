"""Trusted Types violation detection.

Trusted Types (TT) is a browser-level DOM-XSS mitigation: when the page
sends a CSP header containing ``require-trusted-types-for 'script'``, the
browser refuses to pass a plain string to any DOM sink that consumes
HTML (``innerHTML``, ``outerHTML``, ``document.write``, ``Range.createContextualFragment``,
``insertAdjacentHTML``, etc.).  The only way to pass HTML to such a sink
is via a *Trusted Type* produced by a registered policy:

    const policy = trustedTypes.createPolicy('myPolicy', {
      createHTML: (input) => DOMPurify.sanitize(input),
    });
    el.innerHTML = policy.createHTML(userInput);   // OK

This module performs STATIC analysis of a page's HTML/JS to detect:

  1. **TT policy absence** -- the page uses dangerous DOM sinks but no
     ``trustedTypes.createPolicy(...)`` call is present.  If the page
     ALSO doesn't ship ``require-trusted-types-for 'script'`` in CSP,
     these sinks are live DOM-XSS primitives.  (If TT is enforced in
     CSP but no policy is registered, the page is *broken* -- every
     sink call throws at runtime.)

  2. **TT policy bypass** -- the page registers a policy whose
     ``createHTML`` (or ``createScript``) is a no-op identity function
     (``input => input``, ``s => s``, ``x => x``).  This is a common
     migration anti-pattern: developers add TT to satisfy a CSP
     requirement but the policy does nothing, so the DOM-XSS surface
     is unchanged.  An attacker who reaches the sink still wins.

  3. **Unsafe sink + user-tainted data** -- the page passes
     user-controlled data (``location.hash``, ``location.search``,
     ``document.referrer``, ``event.data``, ``localStorage`` reads,
     ``new URLSearchParams(...).get(...)``) into a dangerous sink
     without a TT policy wrapping it.  This is a concrete DOM-XSS
     finding, not just a defense-in-depth note.

This module is pure-Python and uses regex heuristics; it is *not* a
taint tracker.  False negatives are possible when the data flow is
indirect (e.g. ``var x = location.hash; el.innerHTML = x``); the
advanced_layers caller therefore also runs the dedicated DOM taint
engine (``dom.py``) for higher-fidelity detection.
"""
from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Dangerous DOM sinks governed by Trusted Types
# ---------------------------------------------------------------------------
# Each entry: (regex, severity, description, sink_name)
# The regex matches an assignment or call that writes HTML to the DOM.
# Severity is "high" when the sink can execute script directly, "medium"
# for indirect sinks (e.g. setAttribute for event-handler attributes).
_DANGER_SINKS: list[tuple[str, str, str, str]] = [
    (r'\.innerHTML\s*[\+\-\*\/]?=', "high",
     "innerHTML assignment", "innerHTML"),
    (r'\.outerHTML\s*[\+\-\*\/]?=', "high",
     "outerHTML assignment", "outerHTML"),
    (r'insertAdjacentHTML\s*\(', "high",
     "insertAdjacentHTML call", "insertAdjacentHTML"),
    (r'document\.write\s*\(', "high",
     "document.write call", "document.write"),
    (r'document\.writeln\s*\(', "high",
     "document.writeln call", "document.writeln"),
    (r'Range\.createContextualFragment\s*\(', "high",
     "Range.createContextualFragment call", "createContextualFragment"),
    (r'createContextualFragment\s*\(', "high",
     "createContextualFragment call", "createContextualFragment"),
    # Framework-specific sinks
    (r'dangerouslySetInnerHTML', "high",
     "React dangerouslySetInnerHTML", "dangerouslySetInnerHTML"),
    (r'\bv-html\s*=', "high",
     "Vue v-html directive", "v-html"),
    (r'\[innerHTML\]\s*=', "high",
     "Angular [innerHTML] binding", "[innerHTML]"),
    (r'\{@html\b', "high",
     "Svelte {@html} tag", "{@html}"),
    # jQuery HTML sinks
    (r'jQuery\s*(?:\.\s*html\s*\(|\$\([^)]*\)\.html\s*\()', "high",
     "jQuery .html() call", "jQuery.html"),
    (r'\$\s*\([^)]*\)\s*\.(?:append|prepend|after|before|replaceWith|wrap)\s*\(',
     "medium",
     "jQuery DOM insertion method", "jQuery.insertion"),
    # Script-execution sinks (TT also governs these under 'script' policy)
    (r'\beval\s*\(', "high",
     "eval() call", "eval"),
    (r'new\s+Function\s*\(', "high",
     "new Function() call", "new Function"),
    (r'setTimeout\s*\(\s*["\']', "high",
     "setTimeout(string) call", "setTimeout(string)"),
    (r'setInterval\s*\(\s*["\']', "high",
     "setInterval(string) call", "setInterval(string)"),
    #setAttribute for dangerous attributes (event handlers / script URLs)
    (r'\.setAttribute\s*\(\s*["\'](?:on\w+|href|src|action|formaction|style|data-[a-z]+)["\']',
     "medium",
     "setAttribute for dangerous attribute", "setAttribute"),
]

# Combined regex for sink detection.
SINK_RE = re.compile(
    "|".join("(?:%s)" % s[0] for s in _DANGER_SINKS),
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Trusted Types policy detection
# ---------------------------------------------------------------------------

# trustedTypes.createPolicy('name', { createHTML: ..., createScript: ... })
CREATE_POLICY_RE = re.compile(
    r'(?:trustedTypes|window\.trustedTypes)\s*\.\s*createPolicy\s*\(\s*'
    r'["\']([^"\']+)["\']\s*,?\s*'
    r'(\{[\s\S]*?\})\s*\)',
    re.IGNORECASE,
)

# A policy factory that returns input unchanged (identity bypass).
# Matches patterns like:  createHTML: input => input   /   createHTML: x => x
#                          createHTML: function(s){ return s; }
#                          createHTML: s => s
# Also catches ``return input;`` / ``return s;`` / ``return x;``.
# Phase 116b: the identifier must be followed by a DELIMITER, not by
# ``.replace(`` / ``.trim()`` / any other transform.  A plain ``\b``
# matched ``s`` in ``s.replace(...)`` too, which made sanitising policies
# indistinguishable from passthrough ones.
_END = r'(?=\s*[,;)}\]]|\s*$)'

_IDENTITY_ARROW_RE = re.compile(
    r'createHTML\s*:\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*=>\s*\1' + _END,
)
_IDENTITY_FUNCTION_RE = re.compile(
    r'createHTML\s*:\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{'
    r'[\s\S]*?return\s+\1[\s;]*\}',
)
_IDENTITY_SHORT_RE = re.compile(
    r'createHTML\s*:\s*([A-Za-z_$][\w$]*)\s*=>\s*\1' + _END,
)

# ``createScript`` no-op policy (also a bypass if the page uses eval sinks).
_CREATE_SCRIPT_IDENTITY_RE = re.compile(
    r'createScript\s*:\s*(?:\([^)]*\)|([A-Za-z_$][\w$]*))\s*=>\s*\1'
    + _END,
)

# Use of the policy: ``policy.createHTML(...)`` (proves the policy is
# actually wired into a sink).  We capture the policy variable name.
POLICY_USE_RE = re.compile(
    r'([A-Za-z_$][\w$]*)\s*\.\s*createHTML\s*\(',
)

# require-trusted-types-for directive in CSP (parsed by csp.py too, but
# we re-check here so the static analysis is self-contained).
REQUIRE_TT_RE = re.compile(
    r"require-trusted-types-for\s+['\"]?script['\"]?",
    re.IGNORECASE,
)

# ``trusted-types`` CSP directive value (list of allowed policy names).
TRUSTED_TYPES_DIRECTIVE_RE = re.compile(
    r"trusted-types\s+([^;]+)",
    re.IGNORECASE,
)

# Phase 160: a script we cannot see inside may hold the sink the no-op policy
# feeds.  Same rule as the Phase 159 DOM pre-screen -- prove-dead, never
# prove-alive: only skip when the page provably cannot consume the policy.
_EXT_SCRIPT_RE = re.compile(r"<script[^>]*\ssrc\s*=", re.IGNORECASE)


# ---------------------------------------------------------------------------
# User-controlled data sources (DOM taint sources)
# ---------------------------------------------------------------------------
# These are the classic DOM XSS sources.  When a script reads from one of
# them and the value flows into a danger sink WITHOUT passing through a
# TT policy, the page is exploitable.
_TAINT_SOURCES = [
    r'location\.hash',
    r'location\.search',
    r'location\.href',
    r'location\.pathname',
    r'location\.replace',
    r'document\.referrer',
    r'document\.URL',
    r'document\.documentURI',
    r'document\.baseURI',
    r'window\.name',
    r'event\.data',
    r'\be\.data\b',
    r'localStorage\.getItem',
    r'sessionStorage\.getItem',
    r'new\s+URLSearchParams\s*\(\s*location\.search\s*\)',
    r'new\s+URLSearchParams\s*\(\s*[a-zA-Z_$][\w$]*\.search\s*\)',
    r'document\.cookie',
]
_TAINT_SOURCE_RE = re.compile(
    "|".join("(?:%s)" % p for p in _TAINT_SOURCES),
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_unsafe_sinks(html_or_js: str) -> list[dict]:
    """Find dangerous DOM sinks in the page/script.

    Returns a list of dicts::

        {
            "sink":         str,    # matched sink text
            "sink_name":    str,    # short name (e.g. "innerHTML")
            "severity":     str,    # "high" or "medium"
            "description":  str,    # human-readable
            "snippet":      str,    # ~200 char context around the match
            "has_taint":    bool,   # a taint source appears nearby
            "taint_source": str,    # the matched taint source, if any
        }
    """
    if not html_or_js:
        return []

    out: list[dict] = []
    seen_spans: list[tuple[int, int]] = []
    for m in SINK_RE.finditer(html_or_js):
        # De-duplicate overlapping matches from different sink patterns.
        if any(s <= m.start() < e for s, e in seen_spans):
            continue
        seen_spans.append((m.start(), m.end()))

        snippet_start = max(0, m.start() - 120)
        snippet_end = min(len(html_or_js), m.end() + 120)
        snippet = html_or_js[snippet_start:snippet_end]

        # Find which sink pattern matched.
        sink_name = "unknown"
        severity = "medium"
        description = "dangerous DOM sink"
        for pat, sev, desc, name in _DANGER_SINKS:
            if re.search(pat, m.group(0), re.IGNORECASE):
                sink_name = name
                severity = sev
                description = desc
                break

        taint_match = _TAINT_SOURCE_RE.search(snippet)
        out.append({
            "sink": m.group(0),
            "sink_name": sink_name,
            "severity": severity,
            "description": description,
            "snippet": snippet.strip()[:300],
            "has_taint": bool(taint_match),
            "taint_source": taint_match.group(0) if taint_match else "",
        })
    return out


def find_policies(html_or_js: str) -> list[dict]:
    """Find Trusted Types policy registrations.

    Returns a list of dicts::

        {
            "policy_name":    str,  # name passed to createPolicy()
            "policy_body":    str,  # raw object body matched
            "is_identity":    bool, # createHTML returns input unchanged
            "is_bypass":      bool, # identity OR no createHTML at all
            "snippet":        str,
        }
    """
    if not html_or_js:
        return []

    out: list[dict] = []
    for m in CREATE_POLICY_RE.finditer(html_or_js):
        name = m.group(1)
        body = m.group(2)
        is_identity = bool(
            _IDENTITY_ARROW_RE.search(body)
            or _IDENTITY_FUNCTION_RE.search(body)
            or _IDENTITY_SHORT_RE.search(body)
            or _CREATE_SCRIPT_IDENTITY_RE.search(body)
        )
        # A policy without createHTML (or createScript) is also a bypass:
        # the developer registered an empty policy object just to satisfy
        # the CSP, but no sink can use it.
        has_create_html = "createHTML" in body
        has_create_script = "createScript" in body
        is_bypass = is_identity or (not has_create_html and not has_create_script)

        snippet_start = max(0, m.start() - 60)
        snippet_end = min(len(html_or_js), m.end() + 60)
        out.append({
            "policy_name": name,
            "policy_body": body.strip()[:400],
            "is_identity": is_identity,
            "is_bypass": is_bypass,
            "snippet": html_or_js[snippet_start:snippet_end].strip()[:400],
        })
    return out


def detect_policy_usage(html_or_js: str) -> list[str]:
    """Return the list of variable names used as ``<var>.createHTML(...)``.

    This is the proof that a registered policy is actually wired into a
    sink -- without this call, the policy is dead code.
    """
    if not html_or_js:
        return []
    return [m.group(1) for m in POLICY_USE_RE.finditer(html_or_js)]


def find_taint_flows(html_or_js: str) -> list[dict]:
    """Find taint-source-to-sink flows in the script.

    A flow is reported when a taint source and a danger sink appear in
    the same ~300-char window AND no TT policy call (``policy.createHTML``)
    appears between them.  Each flow is a candidate DOM-XSS finding.
    """
    if not html_or_js:
        return []

    flows: list[dict] = []
    # Extract <script> blocks so the window doesn't span unrelated blocks.
    blocks: list[str] = []
    for m in re.finditer(r'<script[^>]*>([\s\S]*?)</script>',
                         html_or_js, re.IGNORECASE):
        blocks.append(m.group(1))
    if not blocks:
        blocks = [html_or_js]

    for block in blocks:
        for sink_m in SINK_RE.finditer(block):
            window_start = max(0, sink_m.start() - 200)
            window_end = min(len(block), sink_m.end() + 200)
            window = block[window_start:window_end]
            taint_m = _TAINT_SOURCE_RE.search(window)
            if not taint_m:
                continue
            # Check whether a policy.createHTML call sits between the
            # taint source and the sink -- if so, the data is wrapped and
            # the flow is *mitigated* (not exploitable).
            taint_pos = window_start + taint_m.start()
            sink_pos = sink_m.start()
            lo, hi = sorted((taint_pos, sink_pos))
            between = block[lo:hi]
            if POLICY_USE_RE.search(between):
                continue  # mitigated by a policy call
            # Sink name lookup.
            sink_name = "unknown"
            severity = "medium"
            for pat, sev, desc, name in _DANGER_SINKS:
                if re.search(pat, sink_m.group(0), re.IGNORECASE):
                    sink_name = name
                    severity = sev
                    break
            flows.append({
                "sink": sink_m.group(0),
                "sink_name": sink_name,
                "severity": severity,
                "taint_source": taint_m.group(0),
                "snippet": window.strip()[:400],
                "mitigated": False,
            })
    return flows


def has_trusted_types_csp(csp_header: str | None) -> bool:
    """Return True if the CSP header enforces Trusted Types."""
    if not csp_header:
        return False
    return bool(REQUIRE_TT_RE.search(csp_header))


def get_trusted_types_policy_names(csp_header: str | None) -> list[str]:
    """Return the policy names whitelisted by the CSP ``trusted-types``
    directive.  Empty list means no whitelist (any policy name allowed)
    OR no directive present.
    """
    if not csp_header:
        return []
    m = TRUSTED_TYPES_DIRECTIVE_RE.search(csp_header)
    if not m:
        return []
    raw = m.group(1).strip()
    # Split on whitespace, strip quotes.
    names = []
    for tok in raw.split():
        tok = tok.strip("'\"")
        if tok and tok not in ("'none'", "'*'", "'allow-duplicates'"):
            names.append(tok)
    return names


def analyze_page(html: str | None, csp_header: str | None = None) -> dict:
    """Analyze a page for Trusted Types violations and policy bypasses.

    Returns a dict::

        {
            "has_unsafe_sinks":    bool,
            "sink_count":          int,
            "sinks":               list[dict],   # from find_unsafe_sinks
            "has_policy":          bool,
            "policies":            list[dict],   # from find_policies
            "policy_used":         list[str],    # var names used
            "tt_enforced_in_csp":  bool,
            "tt_policy_whitelist": list[str],
            "has_bypass_policy":   bool,         # any identity/empty policy
            "taint_flows":         list[dict],   # from find_taint_flows
            "exploitable_flows":   list[dict],   # subset of taint_flows
            "violations":          list[dict],   # structured findings
        }

    ``violations`` is the primary output -- each entry is a structured
    finding that the advanced_layers caller turns into a scanner Finding.
    """
    if not html:
        return {
            "has_unsafe_sinks": False,
            "sink_count": 0,
            "sinks": [],
            "has_policy": False,
            "policies": [],
            "policy_used": [],
            "tt_enforced_in_csp": False,
            "tt_policy_whitelist": [],
            "has_bypass_policy": False,
            "taint_flows": [],
            "exploitable_flows": [],
            "violations": [],
        }

    sinks = find_unsafe_sinks(html)
    policies = find_policies(html)
    policy_used = detect_policy_usage(html)
    tt_enforced = has_trusted_types_csp(csp_header)
    tt_whitelist = get_trusted_types_policy_names(csp_header)
    has_bypass = any(p["is_bypass"] for p in policies)
    taint_flows = find_taint_flows(html)
    # Exploitable flows are those NOT mitigated by a policy call.
    exploitable_flows = [f for f in taint_flows if not f["mitigated"]]

    violations: list[dict] = []

    # Violation 1: unsafe sink + user taint + no policy wrapping.
    # This is a concrete DOM-XSS finding.
    for flow in exploitable_flows[:3]:
        violations.append({
            "type": "tt_taint_flow",
            "severity": flow["severity"],
            "title": (
                f"User-controlled data ({flow['taint_source']}) flows into "
                f"{flow['sink_name']} without a Trusted Types policy"
            ),
            "evidence": flow["snippet"],
            "sink": flow["sink_name"],
            "taint_source": flow["taint_source"],
        })

    # Violation 2: identity/no-op policy registered (bypass).
    #
    # Phase 160: a no-op policy is only a BYPASS if the page can actually feed
    # it to an HTML sink.  Measured false positive: neg-dom-08, the safe twin
    # of pos-dom-08.  It registers the very same identity policy but writes
    # through ``textContent``, and this layer still reported a high-severity
    # XSS.  The benchmark never saw it: its scorer only counts finding types
    # the case declared.  Can't see inside an external bundle?  Keep the
    # finding -- prove-dead, not prove-alive.
    if has_bypass and (sinks or _EXT_SCRIPT_RE.search(html or "")):
        for p in policies:
            if not p["is_bypass"]:
                continue
            violations.append({
                "type": "tt_policy_bypass",
                "severity": "high",
                "title": (
                    f"Trusted Types policy '{p['policy_name']}' is a no-op "
                    f"(identity function or empty) -- TT enforcement is "
                    f"bypassable"
                ),
                "evidence": p["snippet"],
                "policy_name": p["policy_name"],
                "is_identity": p["is_identity"],
            })
            break  # one bypass finding per page is enough

    # Violation 3: unsafe sinks present but no policy registered at all.
    # If TT is enforced in CSP, the page is BROKEN (sinks throw).  If TT
    # is NOT enforced, the sinks are live DOM-XSS primitives (defense-
    # in-depth gap).
    if sinks and not policies:
        if tt_enforced:
            sev = "medium"
            note = ("CSP enforces Trusted Types but no policy is registered; "
                    "every sink call will throw at runtime (broken page)")
        else:
            sev = "medium"
            note = ("Page uses dangerous DOM sinks without Trusted Types; "
                    "if a sink receives user-controlled data, DOM XSS is "
                    "trivially exploitable (TT is the only reliable "
                    "DOM-XSS mitigation)")
        violations.append({
            "type": "tt_no_policy",
            "severity": sev,
            "title": note,
            "evidence": sinks[0]["snippet"],
            "sink": sinks[0]["sink_name"],
            "sink_count": len(sinks),
        })

    # Violation 4: policy registered but never used (dead code).  Lower
    # severity -- indicates the developer added TT for compliance but
    # didn't actually wire it into the sinks.
    if policies and not policy_used:
        violations.append({
            "type": "tt_policy_unused",
            "severity": "low",
            "title": (
                f"Trusted Types policy registered but never called via "
                f"policy.createHTML() -- sinks still receive raw strings"
            ),
            "evidence": policies[0]["snippet"],
            "policy_name": policies[0]["policy_name"],
        })

    return {
        "has_unsafe_sinks": bool(sinks),
        "sink_count": len(sinks),
        "sinks": sinks,
        "has_policy": bool(policies),
        "policies": policies,
        "policy_used": policy_used,
        "tt_enforced_in_csp": tt_enforced,
        "tt_policy_whitelist": tt_whitelist,
        "has_bypass_policy": has_bypass,
        "taint_flows": taint_flows,
        "exploitable_flows": exploitable_flows,
        "violations": violations,
    }


# ---------------------------------------------------------------------------
# PoC generation
# ---------------------------------------------------------------------------

def build_poc_html(url: str, sink_name: str, taint_source: str = "") -> str:
    """Build a PoC HTML page that demonstrates the TT violation.

    The PoC shows how an attacker would deliver a payload to the
    vulnerable sink.  For ``location.hash`` sources, the PoC is a link
    with the payload in the fragment; for ``event.data`` / postMessage
    sources, the PoC is an attacker-controlled page that sends a
    message; for other sources, a generic link PoC is emitted.
    """
    payload = "<img src=x onerror=alert(1)>"
    if taint_source == "location.hash":
        return (
            f"<!-- PoC: open this URL in a browser -->\n"
            f"{url}#{payload}\n\n"
            f"<!-- Or as an HTML link: -->\n"
            f'<a href="{url}#{payload}">click here</a>\n'
        )
    if taint_source in ("event.data", "e.data"):
        return (
            f"<!-- PoC: host this HTML on an attacker-controlled origin -->\n"
            f"<html><body><script>\n"
            f"var w = window.open('{url}');\n"
            f"setTimeout(function() {{\n"
            f"  w.postMessage('{payload}', '*');\n"
            f"}}, 1000);\n"
            f"</script></body></html>\n"
        )
    return (
        f"<!-- PoC: deliver a payload to the {sink_name} sink on {url} -->\n"
        f"<!-- The exact delivery vector depends on how the sink is fed. -->\n"
        f"<!-- If the sink reads from a URL parameter, visit: -->\n"
        f"{url}?q={payload}\n"
    )
