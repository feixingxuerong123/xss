"""Self-test: run XSSentinel against the local vulnerable server and assert
each detection layer fires. Self-test only (do NOT point at real sites).

Layers exercised:
  L1 reflected  - /echo /attr /script /href /evt
  L2 WAF-evade  - /waf (blocks <script>, transform families bypass)
  L3 DOM        - /dom (location.hash -> innerHTML)  [static heuristic]
  L6 DOM-dynamic- /dom also CONFIRMED in a real browser (Playwright) when
                   available: marker injected into location.hash executes in
                   the innerHTML sink -> high-confidence dom_dynamic finding.
  L4 stored     - /store (POST) -> /view (GET)
  L5 blind/OOB  - /blind with a SELF-HOSTED callback listener (auto-confirm)
  extra contexts- /cdata /meta /tpl (CDATA, meta-refresh, {{ }} template)
  L7 advanced   - /mxss (mXSS) /clobber (DOM clobber) /tpl-eval (SSTI)
                  /jsonp (JSONP callback) /csp-weak /csp-strong (CSP analysis)
                  /css /comment (additional reflection contexts)
  control       - /safe must yield ZERO findings (no false positives)
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner
from xssentinel.core.oob import SelfHostedListener
from xssentinel.core import dom_engine as dom_engine_mod

BASE = "http://127.0.0.1:8899"
ENDPOINTS = [
    ("/echo",   "GET", {"q": "test"}, {}),    # L1 html_element
    ("/attr",   "GET", {"q": "test"}, {}),    # L1 html_attribute_dq
    ("/script", "GET", {"q": "test"}, {}),    # L1 script_string_dq
    ("/href",   "GET", {"q": "test"}, {}),    # L1 url_href
    ("/evt",    "GET", {"q": "test"}, {}),    # L1 event_handler
    ("/dom",    "GET", {},            {}),    # L3 DOM taint
    ("/safe",   "GET", {"q": "test"}, {}),    # control: must find nothing
    ("/waf",    "GET", {"q": "test"}, {}),    # L2 WAF-evasion
    ("/blind",  "GET", {"q": "test"}, {}),    # L5 blind XSS (auto-confirm)
    ("/cdata",  "GET", {"q": "test"}, {}),    # context: CDATA
    ("/meta",   "GET", {"q": "test"}, {}),    # context: meta-refresh
    ("/tpl",    "GET", {"q": "test"}, {}),    # context: {{ }} template
    # L7 advanced detection layers:
    ("/mxss",      "GET", {"q": "test"}, {}),              # mXSS
    ("/clobber",   "GET", {"q": "test"}, {}),              # DOM clobber
    ("/tpl-eval",  "GET", {"q": "test"}, {}),              # Template SSTI
    ("/jsonp",     "GET", {"callback": "test"}, {}),       # JSONP callback
    ("/csp-weak",  "GET", {"q": "test"}, {}),              # CSP weak (bypassable)
    ("/csp-strong","GET", {"q": "test"}, {}),              # CSP strong (not bypassable)
    ("/css",       "GET", {"q": "test"}, {}),              # CSS context
    ("/comment",   "GET", {"q": "test"}, {}),              # HTML comment
    # L8 Modern XSS vectors (Phase 9-11):
    ("/postmsg",   "GET", {},            {}),              # postMessage XSS
    ("/proto",     "GET", {"q": "{}"},   {}),              # Prototype pollution
    ("/sw",        "GET", {"q": "x.js"}, {}),              # Service Worker XSS
    ("/worker",    "GET", {"q": "x.js"}, {}),              # Web Worker XSS
    ("/redirect",  "GET", {"url": "x"},  {}),              # Open redirect -> XSS
    ("/react",     "GET", {"q": "test"}, {}),              # Framework XSS
    ("/header-reflect", "GET", {},        {}),             # Header XSS
    ("/path-reflect",   "GET", {},        {}),             # Path XSS
    ("/cookie-reflect", "GET", {},        {}),             # Cookie XSS
    ("/markdown",  "GET", {"q": "![x](x)"}, {}),           # Markdown XSS
    # Phase 15: DOM-based SW/Worker/Prototype endpoints (client-side taint,
    # not server-side reflection).  These properly exercise the static DOM
    # analyzers in sw_xss / worker_xss / prototype that look for
    # location.hash/search -> register()/new Worker()/merge() patterns.
    ("/dom-sw",      "GET", {}, {}),                       # DOM Service Worker XSS
    ("/dom-worker",  "GET", {}, {}),                       # DOM Web Worker XSS
    ("/dom-proto",   "GET", {}, {}),                       # DOM Prototype Pollution -> XSS
    # Phase 26: GraphQL + WebSocket XSS fixtures.
    # /graphql-app is the page that triggers the GraphQL layer (it has
    # Apollo Client + dangerouslySetInnerHTML + a /graphql endpoint
    # reference).  The layer then probes /graphql for introspection +
    # alias + argument reflection.
    ("/graphql-app", "GET", {}, {}),                       # GraphQL client-sink XSS + endpoint probe
    ("/ws-app",      "GET", {}, {}),                       # WebSocket XSS (onmessage + innerHTML)
    ("/ws-insecure", "GET", {}, {}),                       # Insecure ws:// WebSocket (MITM risk)
    # Phase 27-2: Trusted Types + CSP nonce reuse fixtures.
    ("/tt-taint",         "GET", {}, {}),                  # TT taint flow (location.hash -> innerHTML)
    ("/tt-bypass",        "GET", {}, {}),                  # TT identity policy bypass
    ("/tt-no-policy",     "GET", {}, {}),                  # TT no policy registered
    ("/tt-unused",        "GET", {}, {}),                  # TT policy registered but unused
    ("/csp-nonce-short",  "GET", {}, {}),                  # CSP nonce too short (8 chars)
    ("/csp-nonce-seq",    "GET", {}, {}),                  # CSP nonce predictable (sequential)
    ("/csp-nonce-missing","GET", {}, {}),                  # CSP nonce declared but absent from HTML
    ("/csp-nonce-multi",  "GET", {}, {}),                  # CSP declares multiple nonces
    ("/csp-nonce-strong", "GET", {}, {}),                  # Control: strong nonce, no finding
    # Phase 27-3: Cookie tossing XSS + SRI bypass fixtures.
    ("/cookie-toss-client",  "GET", {}, {}),                # Client-side cookie tossing (document.cookie + domain=)
    ("/cookie-sink-flow",    "GET", {}, {}),                # Cookie read -> innerHTML sink flow
    ("/sri-missing-script",  "GET", {}, {}),                # Cross-origin script without SRI
    ("/sri-missing-style",   "GET", {}, {}),                # Cross-origin stylesheet without SRI
    ("/sri-broken",          "GET", {}, {}),                # SRI present but no crossorigin
    ("/sri-malformed",       "GET", {}, {}),                # Malformed integrity= attribute
    ("/sri-insecure",        "GET", {}, {}),                # http:// origin for script
    ("/sri-strong",          "GET", {}, {}),                # Control: valid SRI + crossorigin, no finding
    # Phase 28-4: Import Maps tampering + Sanitizer bypass fixtures.
    ("/import-map-vuln",       "GET", {"q": "test"}, {}),     # Import map with cross-origin + insecure entries
    ("/import-map-reflect",    "GET", {"q": "evilPayload"}, {}), # Import map reflects user input
    ("/import-map-late",       "GET", {}, {}),                # Import map after module script
    ("/import-map-strong",     "GET", {}, {}),                # Control: same-origin relative entries, no finding
    ("/sanitizer-vuln-version","GET", {}, {}),                # DOMPurify 1.0.7 (known CVE)
    ("/sanitizer-unsafe-config","GET", {}, {}),               # ADD_TAGS includes 'script'
    ("/sanitizer-to-innerhtml","GET", {}, {}),                # sanitize() -> innerHTML
    ("/sanitizer-missing",     "GET", {}, {}),                # innerHTML = userVar without sanitizer
    ("/sanitizer-strong",      "GET", {}, {}),                # Control: safe version + textContent, no finding
    # Phase 30-1: CSS Injection (CSSI) fixtures.
    ("/cssi-font-face",        "GET", {}, {}),                # @font-face unicode-range exfil gadget
    ("/cssi-keylogger",        "GET", {}, {}),                # CSS keylogger (input[value^=...] + url())
    ("/cssi-import",           "GET", {}, {}),                # @import external stylesheet
    ("/cssi-cssom",            "GET", {}, {}),                # CSSOM sinks (cssText/insertRule/background)
    ("/cssi-template",         "GET", {}, {}),                # Template placeholder inside <style>
    ("/cssi-legacy",           "GET", {}, {}),                # expression/behavior/moz-binding
    ("/cssi-dynamic-exfil",    "GET", {}, {}),                # Dynamic CSS keylogger built in JS
    ("/cssi-strong",           "GET", {}, {}),                # Control: safe inline style
    # Phase 30-2: Dangling Markup Injection fixtures.
    ("/dangling-risk",         "GET", {"q": "test"}, {}),     # href reflection + CSRF token downstream
    ("/dangling-hidden",       "GET", {"q": "test"}, {}),     # src reflection + hidden input value
    ("/dangling-potential",    "GET", {},            {}),     # Sensitive data + URL attrs, no reflection
    ("/dangling-safe",         "GET", {"q": "test"}, {}),     # Control: no sensitive data near reflection
    # Phase 30-3: Modern framework SSTI fixtures.
    ("/fw-vue3-vhtml",         "GET", {},            {}),     # Vue 3 v-html directive
    ("/fw-angular-pipe",       "GET", {},            {}),     # Angular bypassSecurityTrustHtml pipe
    ("/fw-svelte-store",       "GET", {},            {}),     # Svelte {@html $store}
    ("/fw-lit-unsafe",         "GET", {},            {}),     # Lit unsafeHTML() directive
    ("/fw-safe",               "GET", {},            {}),     # Control: auto-escaped framework usage
    # Phase 30-4: SVG XSS fixtures.
    ("/svg-script",            "GET", {},            {}),     # Inline <script> in SVG
    ("/svg-foreignobject",     "GET", {},            {}),     # <foreignObject> + <script>
    ("/svg-smil",              "GET", {},            {}),     # SMIL <set> attributeName=onload
    ("/svg-use-jsuri",         "GET", {},            {}),     # <use href="javascript:...">
    ("/svg-a-jsuri",           "GET", {},            {}),     # <a xlink:href="javascript:...">
    ("/svg-safe",              "GET", {},            {}),     # Control: benign SVG shapes
]

req = Requester(timeout=10)
# Self-hosted OOB listener: the /blind endpoint simulates the victim's browser
# firing the beacon back, so we can verify auto-confirmation offline.
oob = SelfHostedListener(host="127.0.0.1")
sc = Scanner(requester=req, verbose=False, oob=oob)

print("=== L1/L2/L3/L5 reflected + context scan ===")
for path, method, params, data in ENDPOINTS:
    print(f"\n--- {method} {BASE}{path} ---")
    sc.scan_endpoint(BASE + path, method, params, data)

print("\n=== L4 stored XSS (/store -> /view) ===")
sc.scan_stored(BASE + "/store", view_url=BASE + "/view", method="POST", param="q")

print("\n=== L4 second-order XSS (/so-inject -> crawl -> /dashboard) ===")
# Phase 21-4: inject at /so-inject, crawl to discover /dashboard, confirm
# the stored payload executes there.  Uses a dedicated scanner with crawl
# enabled so _crawl() can discover the viewer page from the inject page's
# link to /dashboard.
so_scanner = Scanner(requester=Requester(timeout=10), verbose=False,
                     crawl=True, crawl_depth=2, dom_engine="static")
so_found = so_scanner.scan_second_order(
    BASE + "/so-inject", param="q", method="POST",
    start_url=BASE + "/so-inject")
so_findings = [f for f in so_scanner.findings
               if f.data.get("type") == "second_order"]
print(f"    second-order findings: {len(so_findings)}")

print("\n=== L4 second-order XSS negative control (/so-inject-safe -> /dashboard-safe) ===")
# Negative control: the safe variant HTML-escapes on render, so the token
# will appear as escaped text -- verify_semantic must NOT confirm it.
so_safe_scanner = Scanner(requester=Requester(timeout=10), verbose=False,
                          crawl=True, crawl_depth=2, dom_engine="static")
so_safe_found = so_safe_scanner.scan_second_order(
    BASE + "/so-inject-safe", param="q", method="POST",
    start_url=BASE + "/so-inject-safe")
so_safe_findings = [f for f in so_safe_scanner.findings
                    if f.data.get("type") == "second_order"]
print(f"    second-order safe findings (must be 0): {len(so_safe_findings)}")

print("\n=== L5 blind XSS auto-confirm (poll callback listener) ===")
sc.collect_oob(timeout=12)

# === L7 crawler + dedup + reproducible PoC (separate scanner, crawl /links) ===
crawler = Scanner(requester=Requester(timeout=10), verbose=False,
                  crawl=True, crawl_depth=2, dom_engine="auto")
crawler.scan_target(BASE + "/links", method="GET", params={}, data={},
                    oob_collect=False)
crawler.dedup()
crawler.attach_pocs()

crawled_urls = {f.data.get("url") for f in crawler.findings}
dom_via_crawl = [f for f in crawler.findings
                 if "/dom" in f.data.get("url", "")
                 and f.data.get("type") in ("dom", "dom_dynamic")]
safe_via_crawl = [f for f in crawler.findings
                  if "/safe" in f.data.get("url", "")]
# reflected via crawl: proves the crawler's query-param endpoints are actually
# scanned for reflection (regression guard for the old ?q=hi&q=marker bug).
reflected_via_crawl = [f for f in crawler.findings
                       if f.data.get("type") == "reflected"
                       and ("/echo" in f.data.get("url", "")
                            or "/script" in f.data.get("url", ""))]
# duplicate check: same (type,url,param,context) must not appear twice
_seen = set()
_dups = 0
for f in crawler.findings:
    k = crawler._dedup_key(f.data)
    if k in _seen:
        _dups += 1
    _seen.add(k)
poc_ok = any(((f.data.get("poc") or {}).get("curl")
             or (f.data.get("poc") or {}).get("html"))
            for f in crawler.findings)
print(f"\n[+] L7 crawler: {len(crawler.findings)} finding(s) from crawling /links "
      f"(discovered URLs: {sorted(u for u in crawled_urls if u)})")
print(f"    dom_via_crawl={len(dom_via_crawl)} safe_via_crawl={len(safe_via_crawl)} "
      f"duplicates={_dups} poc_attached={poc_ok}")

# Summaries
hi = sum(1 for f in sc.findings if f.data.get("severity") == "high")
med = sum(1 for f in sc.findings if f.data.get("severity") == "medium")
low = sum(1 for f in sc.findings if f.data.get("severity") in ("low", "info"))

by_type = {}
for f in sc.findings:
    t = f.data.get("type")
    by_type[t] = by_type.get(t, 0) + 1

safe_findings = [f for f in sc.findings
                 if f.data.get("url", "").endswith("/safe")]

print(f"\n[+] Total requests made: {sc.requests_made}")
print(f"[+] WAF detected: {sc.waf_name}")
print(f"[+] Total findings: {len(sc.findings)}  "
      f"(high={hi} medium={med} low/info={low})")
print(f"[+] By type: {by_type}")
print("\n--- findings ---")
for f in sc.findings:
    d = f.data
    print(f"  - [{d.get('severity')}] {d.get('type'):8} "
          f"param={d.get('param')} ctx={d.get('context')} conf={d.get('confidence')}")
    print(f"      {(d.get('detail') or '')[:100]}")

# Assertions
ok = True
if safe_findings:
    ok = False
    print(f"\n[!] FAIL: /safe produced {len(safe_findings)} false-positive finding(s)!")
else:
    print("\n[+] PASS: /safe => 0 findings (no false positives)")
for need in ("reflected", "stored", "blind"):
    if by_type.get(need, 0) == 0:
        ok = False
        print(f"[!] FAIL: layer '{need}' produced no findings")
    else:
        print(f"[+] PASS: layer '{need}' fired ({by_type[need]})")

# DOM layer: either real-browser confirmed (dom_dynamic, high) or static hint.
dom_layer_ok = by_type.get("dom_dynamic", 0) > 0 or by_type.get("dom", 0) > 0
if dom_layer_ok:
    print(f"[+] PASS: DOM layer fired "
          f"(dom_dynamic={by_type.get('dom_dynamic', 0)}, "
          f"dom_static={by_type.get('dom', 0)})")
else:
    ok = False
    print("[!] FAIL: DOM layer produced no findings at all")

# If a real browser is available, the /dom sink MUST be confirmed (high),
# proving the engine executes the page rather than guessing.
dom_available = dom_engine_mod.DynamicDomAnalyzer.available()
if dom_available:
    dyn_confirmed = [f for f in sc.findings
                     if f.data.get("type") == "dom_dynamic"
                     and f.data.get("confidence") == "high"]
    if dyn_confirmed:
        print(f"[+] PASS: L6 real-browser DOM-XSS CONFIRMED "
              f"({len(dyn_confirmed)} high-confidence finding(s))")
    else:
        ok = False
        print("[!] FAIL: dynamic DOM engine available but /dom NOT confirmed")
else:
    print("[*] (Playwright not installed — skipping L6 dynamic-confirm assertion; "
          "static DOM heuristic still reported)")

# L5 must be CONFIRMED (callback received), not merely injected.
blind_confirmed = [f for f in sc.findings
                   if f.data.get("type") == "blind"
                   and f.data.get("confidence") == "high"]
if blind_confirmed:
    print(f"[+] PASS: L5 blind XSS auto-confirmed "
          f"({len(blind_confirmed)} callback-confirmed finding(s))")
else:
    ok = False
    print("[!] FAIL: L5 blind XSS was injected but NOT auto-confirmed "
          "(no OOB callback received)")

# --- L7: deep crawler + dedup + PoC (separate scanner, crawled /links) ---
if dom_via_crawl:
    print(f"[+] PASS: L7 crawler discovered /dom and produced a DOM finding "
          f"({len(dom_via_crawl)})")
else:
    ok = False
    print("[!] FAIL: L7 crawler did not discover /dom or produced no DOM finding")
if safe_via_crawl:
    ok = False
    print(f"[!] FAIL: L7 crawler reported a /safe false positive "
          f"({len(safe_via_crawl)})")
else:
    print("[+] PASS: L7 crawler => /safe clean (0 false positives)")
if reflected_via_crawl:
    print(f"[+] PASS: L7 crawler found reflected XSS on crawled query-param "
          f"endpoints ({len(reflected_via_crawl)})")
else:
    ok = False
    print("[!] FAIL: L7 crawler found no reflected XSS on /echo|/script "
          "(regression of query-string-in-URL bug)")
if _dups == 0:
    print("[+] PASS: L7 dedup => no duplicate (type,url,param,context) findings")
else:
    ok = False
    print(f"[!] FAIL: L7 dedup left {_dups} duplicate finding(s)")
if poc_ok:
    print("[+] PASS: L7 reproducible PoC attached to findings (curl / HTML)")
else:
    ok = False
    print("[!] FAIL: L7 no PoC generated for any finding")

# --- L7 advanced detection layer assertions ---
advanced_checks = {
    "mutation_xss":          "mXSS (mutation XSS)",
    "dom_clobber":           "DOM clobbering",
    "template_ssti_angularjs": "Template SSTI -> XSS",
    "jsonp_xss":             "JSONP callback XSS",
    "csp_bypass":            "CSP bypass analysis",
}
for ftype, label in advanced_checks.items():
    count = by_type.get(ftype, 0)
    if count > 0:
        print(f"[+] PASS: L7 {label} fired ({count})")
    else:
        ok = False
        print(f"[!] FAIL: L7 {label} produced no findings")

# CSP strong must NOT produce a bypass finding (negative control).
csp_strong_findings = [f for f in sc.findings
                       if f.data.get("url", "").endswith("/csp-strong")
                       and f.data.get("type") == "csp_bypass"]
if csp_strong_findings:
    ok = False
    print(f"\n[!] FAIL: /csp-strong produced a false-positive CSP bypass "
          f"({len(csp_strong_findings)})")
else:
    print("\n[+] PASS: /csp-strong => no false-positive CSP bypass")

# Phase 27-2: /csp-nonce-strong must NOT produce a CSP nonce finding
# (negative control -- the nonce is properly random and properly applied).
csp_nonce_strong_findings = [f for f in sc.findings
                             if f.data.get("url", "").endswith("/csp-nonce-strong")
                             and f.data.get("type", "").startswith("csp_nonce_")]
if csp_nonce_strong_findings:
    ok = False
    print(f"\n[!] FAIL: /csp-nonce-strong produced a false-positive CSP nonce "
          f"finding ({len(csp_nonce_strong_findings)})")
else:
    print("\n[+] PASS: /csp-nonce-strong => no false-positive CSP nonce finding")

# Phase 27-3: /sri-strong must NOT produce an SRI finding
# (negative control -- valid integrity= + crossorigin + https).
sri_strong_findings = [f for f in sc.findings
                       if f.data.get("url", "").endswith("/sri-strong")
                       and f.data.get("type", "").startswith("sri_")]
if sri_strong_findings:
    ok = False
    print(f"\n[!] FAIL: /sri-strong produced a false-positive SRI "
          f"finding ({len(sri_strong_findings)})")
else:
    print("\n[+] PASS: /sri-strong => no false-positive SRI finding")

# Phase 28-4: negative controls for Import Maps + Sanitizer bypass.
import_map_strong_findings = [f for f in sc.findings
    if f.data.get("url", "").endswith("/import-map-strong")
    and f.data.get("type", "").startswith("import_map_")]
if import_map_strong_findings:
    ok = False
    print(f"\n[!] FAIL: /import-map-strong produced a false-positive "
          f"import-map finding ({len(import_map_strong_findings)})")
else:
    print("[+] PASS: /import-map-strong => no false-positive import-map finding")

sanitizer_strong_findings = [f for f in sc.findings
    if f.data.get("url", "").endswith("/sanitizer-strong")
    and (f.data.get("type", "").startswith("sanitizer_")
         or f.data.get("type", "") == "unsanitized_innerhtml_user_source")]
if sanitizer_strong_findings:
    ok = False
    print(f"\n[!] FAIL: /sanitizer-strong produced a false-positive "
          f"sanitizer finding ({len(sanitizer_strong_findings)})")
else:
    print("[+] PASS: /sanitizer-strong => no false-positive sanitizer finding")

# Phase 30-1: CSS Injection (CSSI) negative control.
cssi_strong_findings = [f for f in sc.findings
    if f.data.get("url", "").endswith("/cssi-strong")
    and (f.data.get("type", "").startswith("css_")
         or f.data.get("type", "").startswith("cssom_")
         or f.data.get("type", "") == "css_dynamic_exfil_gadget")]
if cssi_strong_findings:
    ok = False
    print(f"\n[!] FAIL: /cssi-strong produced a false-positive "
          f"CSSI finding ({len(cssi_strong_findings)})")
else:
    print("[+] PASS: /cssi-strong => no false-positive CSSI finding")

# Phase 30-2: Dangling Markup Injection assertions.
# /dangling-risk and /dangling-hidden should produce dangling_markup
# findings (risk or potential).  /dangling-safe must produce NONE.
dangling_risk_findings = [f for f in sc.findings
    if f.data.get("url", "").endswith("/dangling-risk")
    and f.data.get("type", "") in ("dangling_markup_risk",
                                    "dangling_markup_potential")]
if dangling_risk_findings:
    print(f"[+] PASS: /dangling-risk => dangling_markup finding "
          f"({dangling_risk_findings[0].data.get('type')})")
else:
    ok = False
    print("[!] FAIL: /dangling-risk produced no dangling_markup finding")

dangling_hidden_findings = [f for f in sc.findings
    if f.data.get("url", "").endswith("/dangling-hidden")
    and f.data.get("type", "") in ("dangling_markup_risk",
                                    "dangling_markup_potential")]
if dangling_hidden_findings:
    print(f"[+] PASS: /dangling-hidden => dangling_markup finding "
          f"({dangling_hidden_findings[0].data.get('type')})")
else:
    ok = False
    print("[!] FAIL: /dangling-hidden produced no dangling_markup finding")

dangling_potential_findings = [f for f in sc.findings
    if f.data.get("url", "").endswith("/dangling-potential")
    and f.data.get("type", "") in ("dangling_markup_risk",
                                    "dangling_markup_potential")]
if dangling_potential_findings:
    print(f"[+] PASS: /dangling-potential => dangling_markup finding "
          f"({dangling_potential_findings[0].data.get('type')})")
else:
    ok = False
    print("[!] FAIL: /dangling-potential produced no dangling_markup finding")

# Negative control: /dangling-safe must NOT produce any dangling_markup finding.
dangling_safe_findings = [f for f in sc.findings
    if f.data.get("url", "").endswith("/dangling-safe")
    and f.data.get("type", "") in ("dangling_markup_risk",
                                    "dangling_markup_potential")]
if dangling_safe_findings:
    ok = False
    print(f"\n[!] FAIL: /dangling-safe produced a false-positive "
          f"dangling_markup finding ({len(dangling_safe_findings)})")
else:
    print("[+] PASS: /dangling-safe => no false-positive dangling_markup finding")

# Phase 30-3: Modern framework SSTI assertions.
# Each framework endpoint must produce a framework_*_xss finding of the
# expected type.  /fw-safe must produce NONE (negative control).
fw_endpoint_to_type = [
    ("/fw-vue3-vhtml",   "framework_vue_xss",     "Vue 3 v-html directive"),
    ("/fw-angular-pipe", "framework_angular_xss", "Angular bypassSecurityTrustHtml pipe"),
    ("/fw-svelte-store", "framework_svelte_xss",  "Svelte {@html $store}"),
    ("/fw-lit-unsafe",   "framework_lit_xss",     "Lit unsafeHTML() directive"),
]
for ep_path, expected_type, label in fw_endpoint_to_type:
    fw_findings = [f for f in sc.findings
                   if f.data.get("url", "").endswith(ep_path)
                   and f.data.get("type", "") == expected_type]
    if fw_findings:
        print(f"[+] PASS: {ep_path} => {expected_type} finding "
              f"({len(fw_findings)})")
    else:
        ok = False
        print(f"[!] FAIL: {ep_path} produced no {expected_type} finding "
              f"({label})")

# Negative control: /fw-safe must NOT produce any framework_*_xss finding.
fw_safe_findings = [f for f in sc.findings
    if f.data.get("url", "").endswith("/fw-safe")
    and f.data.get("type", "").startswith("framework_")]
if fw_safe_findings:
    ok = False
    print(f"\n[!] FAIL: /fw-safe produced a false-positive framework "
          f"finding ({len(fw_safe_findings)})")
else:
    print("[+] PASS: /fw-safe => no false-positive framework finding")

# Phase 30-4: SVG XSS assertions.
# Each SVG endpoint must produce an svg_xss_* finding of the expected type.
# /svg-safe must produce NONE (negative control).
svg_endpoint_to_type = [
    ("/svg-script",        "svg_xss_svg_script",                "Inline <script> in SVG"),
    ("/svg-foreignobject", "svg_xss_svg_foreignobject_script",  "<foreignObject> + <script>"),
    ("/svg-smil",          "svg_xss_svg_set_event",             "SMIL <set> attributeName=onload"),
    ("/svg-use-jsuri",     "svg_xss_svg_use_jsuri",             "<use href=\"javascript:...\">"),
    ("/svg-a-jsuri",       "svg_xss_svg_a_jsuri",               "<a xlink:href=\"javascript:...\">"),
]
for ep_path, expected_type, label in svg_endpoint_to_type:
    svg_findings = [f for f in sc.findings
                    if f.data.get("url", "").endswith(ep_path)
                    and f.data.get("type", "") == expected_type]
    if svg_findings:
        print(f"[+] PASS: {ep_path} => {expected_type} finding "
              f"({len(svg_findings)})")
    else:
        ok = False
        print(f"[!] FAIL: {ep_path} produced no {expected_type} finding "
              f"({label})")

# Negative control: /svg-safe must NOT produce any svg_xss_* finding.
svg_safe_findings = [f for f in sc.findings
    if f.data.get("url", "").endswith("/svg-safe")
    and f.data.get("type", "").startswith("svg_xss_")]
if svg_safe_findings:
    ok = False
    print(f"\n[!] FAIL: /svg-safe produced a false-positive svg_xss "
          f"finding ({len(svg_safe_findings)})")
else:
    print("[+] PASS: /svg-safe => no false-positive svg_xss finding")

# --- L8: Modern XSS vectors (Phase 9-11 + Phase 15) ---
# Phase 15: these are now HARD assertions (not warnings) because the
# vuln_server has proper DOM-based fixtures for each layer:
#   - /dom-sw: location.search -> navigator.serviceWorker.register()
#   - /dom-worker: location.hash -> new Worker()
#   - /dom-proto: recursive merge + innerHTML(data.html) sink
#   - /error-404 + root-level probe: 404 page reflects URL-decoded path
modern_checks = {
    "postmessage_xss":      "postMessage handler XSS",
    "prototype_pollution":  "Prototype pollution -> XSS",
    "service_worker_xss":   "Service Worker XSS",
    "web_worker_xss":       "Web Worker XSS",
    "open_redirect_xss":    "Open redirect -> XSS",
    "error_page_xss":       "Error page XSS",
    "markdown_xss":         "Markdown/BBCode XSS",
    # Phase 26: GraphQL + WebSocket XSS layers.
    "graphql_xss":          "GraphQL XSS (client sink or endpoint reflection)",
    "websocket_xss":        "WebSocket XSS (onmessage + sink)",
    # Phase 27-2: Trusted Types + CSP nonce reuse layers.
    "trusted_types_taint_flow":    "Trusted Types taint flow (DOM source -> sink)",
    "trusted_types_policy_bypass": "Trusted Types identity-policy bypass",
    "trusted_types_no_policy":     "Trusted Types no policy registered",
    "csp_nonce_too_short":         "CSP nonce too short",
    "csp_nonce_predictable":       "CSP nonce predictable",
    "csp_nonce_misconfigured":     "CSP nonce misconfigured (declared but absent)",
    # Phase 27-3: Cookie tossing + SRI bypass layers.
    "cookie_tossing_client":       "Cookie tossing (client-side document.cookie + domain=)",
    "cookie_sink_flow":            "Cookie read -> DOM sink flow",
    "sri_missing_script":          "SRI missing on cross-origin script",
    "sri_missing_style":           "SRI missing on cross-origin stylesheet",
    "sri_broken_no_crossorigin":   "SRI broken (integrity= but no crossorigin)",
    "sri_malformed":               "SRI malformed integrity= attribute",
    "sri_insecure_origin":         "SRI insecure http:// origin",
    # Phase 28-4: Import Maps + Sanitizer bypass layers.
    "import_map_cross_origin":         "Import map cross-origin entry (no integrity)",
    "import_map_insecure_origin":      "Import map insecure http:// origin",
    "import_map_after_module":         "Import map after module script (spec violation)",
    "import_map_user_controlled":      "Import map user-controlled reflection",
    "sanitizer_vulnerable_version":    "Sanitizer known-vulnerable version (CVE)",
    "sanitizer_config_add_script":     "Sanitizer unsafe config (ADD_TAGS: script)",
    "sanitizer_output_to_innerhtml":   "Sanitizer output to innerHTML (mXSS risk)",
    "unsanitized_innerhtml_user_source": "Unsanitized innerHTML from user source",
    # Phase 30-1: CSS Injection (CSSI) layers.
    "css_font_face_exfil":             "CSS @font-face unicode-range exfiltration",
    "css_selector_exfil":              "CSS keylogger (input[value^=...])",
    "css_import_injection":            "CSS @import external stylesheet",
    "css_template_reflection":         "Template placeholder in <style>",
    "cssom_cssText":                   "CSSOM sink: element.style.cssText",
    "cssom_insertrule":                "CSSOM sink: insertRule()",
    "css_dynamic_exfil_gadget":        "Dynamic CSS exfil gadget in JS",
    "css_javascript_uri":              "CSS url(javascript:) (legacy)",
    "css_expression":                  "CSS expression() (IE < 11)",
    "css_moz_binding":                 "CSS -moz-binding (legacy Firefox)",
    "css_behavior":                    "CSS behavior:url() (IE HTC)",
    # Phase 30-3: Modern framework SSTI layers.
    "framework_vue_xss":               "Vue 3 v-html / ref+innerHTML sink",
    "framework_angular_xss":           "Angular bypassSecurityTrust* / sanitizer pipe",
    "framework_svelte_xss":            "Svelte {@html $store} sink",
    "framework_lit_xss":               "Lit unsafeHTML() / Polymer innerHTML sink",
    # Phase 30-4: SVG XSS layers.
    "svg_xss_svg_script":              "SVG inline <script> vector",
    "svg_xss_svg_foreignobject_script":"SVG <foreignObject> + <script> vector",
    "svg_xss_svg_set_event":           "SVG SMIL <set> event-handler vector",
    "svg_xss_svg_use_jsuri":           "SVG <use href=\"javascript:\"> vector",
    "svg_xss_svg_a_jsuri":             "SVG <a xlink:href=\"javascript:\"> vector",
}
for ftype, label in modern_checks.items():
    count = by_type.get(ftype, 0)
    if count > 0:
        print(f"[+] PASS: L8 {label} fired ({count})")
    else:
        ok = False
        print(f"[!] FAIL: L8 {label} produced no findings")

# --- L4 second-order XSS (Phase 21-4) ---
if so_findings:
    viewer = so_findings[0].data.get("proof", {}).get("viewer_url", "")
    print(f"[+] PASS: L4 second-order XSS confirmed "
          f"(viewer={viewer}, context={so_findings[0].data.get('context')})")
else:
    ok = False
    print("[!] FAIL: L4 second-order XSS produced no findings "
          "(inject /so-inject -> /dashboard)")

# Negative control: the HTML-escaped variant MUST NOT fire.
if so_safe_findings:
    ok = False
    print(f"[!] FAIL: L4 second-order XSS false positive on escaped variant "
          f"({len(so_safe_findings)} finding(s) on /dashboard-safe)")
else:
    print("[+] PASS: L4 second-order negative control => 0 false positives "
          "(/dashboard-safe escaped)")

print("\n[RESULT]", "ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)
