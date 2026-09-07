#!/usr/bin/env python
"""XSSentinel Benchmark Server — manifest-driven reflection environment.

Serves HTTP endpoints that simulate vulnerable and safe reflection behaviors.
Each endpoint's rendering is determined by the "mode" field in manifest.json.
Used exclusively by the benchmark runner to evaluate scanner accuracy.

Usage:
    python benchmark/server.py [--port 8877]
"""
from __future__ import annotations

import base64
import html
import json
import os
import re
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote, quote

_HERE = os.path.dirname(os.path.abspath(__file__))
_MANIFEST_PATH = os.path.join(_HERE, "manifest.json")
DEFAULT_PORT = 8877


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

def load_routes() -> dict[str, dict]:
    """Load manifest and build path -> case routing table."""
    with open(_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    routes = {}
    for case in manifest["cases"]:
        routes[case["path"]] = case
    return routes


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class BenchmarkHandler(BaseHTTPRequestHandler):
    routes: dict[str, dict] = {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Health check
        if path == "/health":
            self._respond(200, {"Content-Type": "text/plain"}, "ok")
            return

        case = self.routes.get(path)
        if case is None:
            self._respond(404, {"Content-Type": "text/plain"}, f"not found: {path}")
            return

        mode = case["mode"]
        param = case.get("param", "q")
        handler = MODES.get(mode)
        if handler is None:
            self._respond(500, {"Content-Type": "text/plain"}, f"unknown mode: {mode}")
            return

        # Extract parameter value from query string
        qs = parse_qs(parsed.query, keep_blank_values=True)
        value = qs.get(param, ["test"])[0] if param else ""

        try:
            status, headers, body = handler(value)
        except Exception as e:
            self._respond(500, {"Content-Type": "text/plain"}, f"mode error: {e}")
            return

        self._respond(status, headers, body)

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

    server = HTTPServer(("127.0.0.1", port), BenchmarkHandler)
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
