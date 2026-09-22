"""Re-verification of historical findings (Phase 20-4).

Given a previous JSON report produced by XSSentinel, this module re-tests
every recorded finding to determine whether the vulnerability has been
*fixed* (no longer exploitable) or is *still present*.

Usage from the CLI::

    python -m xssentinel --verify-fix old_report.json -o verify_result.html

The verifier replays the original payload against the original (url, method,
param) and applies the same semantic confirmation used during the original
scan (``verifier.verify_semantic``).  Findings are classified as:

  * **fixed**      -- payload no longer reflects in an executable context.
  * **still_vuln** -- payload still reflects and executes (regression /
                      incomplete fix).
  * **error**      -- endpoint unreachable / request failed (inconclusive).
  * **skipped**    -- finding type cannot be replayed headlessly from a
                      JSON report alone (e.g. blind OOB, stored, DOM-
                      dynamic) -- requires the original scanner context.

The result is emitted as a stand-alone HTML or JSON report.
"""
from __future__ import annotations

import json
import re
import secrets
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Finding loading
# ---------------------------------------------------------------------------
def load_findings(path: str) -> list[dict]:
    """Load findings from a previously-generated JSON report.

    Accepts both the top-level ``{"findings": [...]}`` envelope produced by
    ``report.build_json`` and a bare ``[...]`` list of finding dicts.
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        # Top-level report envelope.
        fs = raw.get("findings")
        if isinstance(fs, list):
            return [f for f in fs if isinstance(f, dict)]
    return []


# ---------------------------------------------------------------------------
# Re-verification
# ---------------------------------------------------------------------------
# Finding types that can be replayed from JSON alone (one HTTP request +
# semantic check).  Other types need scanner-side state (OOB listener,
# stored-view roundtrip, real browser) and are skipped.
_REPLAYABLE_TYPES = {
    "reflected", "dom", "postmessage_xss", "prototype_pollution",
    "service_worker_xss", "web_worker_xss", "header_xss", "path_xss",
    "cookie_xss", "error_page_xss",
    "dom_clobber", "mutation_xss", "markdown_xss", "jsonp_xss",
    "open_redirect_xss",
    # Phase 26: GraphQL endpoint findings can be replayed by re-sending
    # the GraphQL probe.  WebSocket findings are skipped (no static-scan
    # replay path) -- the scanner context is required.
    "graphql_xss", "graphql_introspection",
}

# Type prefixes that are replayable (e.g. "framework_react_xss",
# "framework_vue_xss").  Any finding whose type starts with one of these
# prefixes can be replayed.
_REPLAYABLE_PREFIXES = ("framework_", "template_ssti_")

#: A password field is what a sign-in page has and a vulnerable result page
#: does not.  Deliberately narrow: a false positive here can only downgrade a
#: verdict to "cannot judge", never promote it to "fixed", so the failure
#: direction is safe.  It exists so a session-expired replay is not reported as
#: a successful remediation.
_AUTH_PAGE_RE = re.compile(r"""type\s*=\s*["']password["']""", re.I)


def _is_replayable(ftype: str | None) -> bool:
    if not ftype:
        return False
    f = ftype.lower()
    if f in _REPLAYABLE_TYPES:
        return True
    return any(f.startswith(p) for p in _REPLAYABLE_PREFIXES)


def classify_finding(finding: dict) -> str:
    """Classify a finding as 'replayable' or 'skipped' without making a request.

    Returns ``"skipped"`` if the finding type cannot be replayed from JSON
    alone (static analysis, requires scanner context, or has no payload).
    Returns ``"replayable"`` if the finding type has a concrete payload and
    can be re-verified by re-sending the request.
    """
    ftype = (finding.get("type") or "reflected").lower()
    if not _is_replayable(ftype):
        return "skipped"
    payload = _extract_payload(finding)
    if not payload:
        return "skipped"
    return "replayable"


def _extract_payload(finding: dict) -> str | None:
    """Pull the original payload string out of a finding dict.

    Findings store the payload in ``payload`` and may also carry a proof
    dict with the raw request.  We prefer the explicit ``payload`` field.
    """
    p = finding.get("payload")
    if isinstance(p, str) and p.strip():
        # Skip placeholder payloads like "(postMessage listener)".
        if p.startswith("(") and p.endswith(")"):
            return None
        return p
    # Some advanced findings use a placeholder; fall back to proof.
    proof = finding.get("proof")
    if isinstance(proof, dict):
        pp = proof.get("payload")
        if isinstance(pp, str) and pp.strip():
            return pp
    return None


def _replay_request(requester, finding: dict, payload: str) -> dict:
    """Re-send the original payload and return a result dict.

    Returns ``{"status": str, "detail": str, "response": resp | None,
    "context": str | None}``.
    """
    from . import verifier
    from urllib.parse import quote, unquote

    url = finding.get("url")
    method = (finding.get("method") or "GET").upper()
    param = finding.get("param")
    ftype = (finding.get("type") or "reflected").lower()

    if not url:
        return {"status": "error", "detail": "no URL in finding",
                "response": None, "context": None}

    # Inject a fresh token so we can confirm execution (not just echo).
    token = "vfix_" + secrets.token_hex(4)
    try:
        marked_payload = verifier.mark(payload, token)
    except Exception:
        marked_payload = payload

    params: dict = {}
    data: dict = {}
    headers: dict = {}

    # Carry the URL's own query into ``params`` and keep it out of the URL.
    # A finding's URL routinely holds the very parameter we are about to
    # inject (``...?q=test`` -- that is just what a scan emits), and handing
    # that URL to requests *alongside* ``params={"q": marked}`` appends a
    # SECOND ``q=``.  Servers read the first, so the payload never reaches the
    # target parameter, nothing reflects, and the replay concludes "no longer
    # reflected" -- i.e. FIXED.  Observed live: a reflector that echoes every
    # input was reported as fixed, which is the worst failure mode a
    # remediation report has (the client is told an open hole is closed).
    # Seeding ``params`` from the query turns the injection into an overwrite
    # and leaves every OTHER query parameter intact.
    from urllib.parse import parse_qsl, urlsplit, urlunsplit
    _parts = urlsplit(url)
    if _parts.query:
        for _k, _v in parse_qsl(_parts.query, keep_blank_values=True):
            params.setdefault(_k, _v)
        url = urlunsplit((_parts.scheme, _parts.netloc, _parts.path, "", ""))

    # -- non-query carriers ------------------------------------------------
    # Findings store the carrier in the param marker -- "(header:User-Agent)"
    # / "(cookie:sid)" -- or use the bare param name as the legacy header /
    # cookie name.  Parse the marker first so a header finding replays its
    # payload on the real header (a query-slot replay could never re-confirm
    # a header echo).
    import re as _re
    hdr_name = None
    ck_name = None
    if param:
        m = _re.match(r"^\(header:([^)]+)\)$", param, _re.I)
        if m:
            hdr_name = m.group(1)
        else:
            m = _re.match(r"^\(cookie:([^)]+)\)$", param, _re.I)
            if m:
                ck_name = m.group(1)
    if ftype == "header_xss" and hdr_name is None and ck_name is None \
            and param and not param.startswith("("):
        hdr_name = param                    # legacy bare-name header
    if ftype == "cookie_xss" and hdr_name is None and ck_name is None \
            and param and not param.startswith("("):
        ck_name = param                     # legacy bare-name cookie

    # Snapshot any pre-existing cookie value BEFORE the probe overwrites
    # it, so the restore below puts the session back exactly as found.
    saved_cookie = None
    if ck_name is not None:
        try:
            jar = requester.session.cookies
            saved_cookie = jar.get(ck_name)
        except Exception:
            saved_cookie = None

    # -- path-based findings: payload is embedded in the URL path itself.
    #    Replace the old payload in the URL with the freshly-tokenized
    #    version so we can confirm execution (not just echo).
    if ftype in ("path_xss", "error_page_xss"):
        # The original URL contains the URL-encoded payload.  Replace it
        # with the encoded marked payload.
        try:
            decoded_url = unquote(url)
            if payload in decoded_url:
                url = decoded_url.replace(payload, marked_payload)
            else:
                # Payload not found verbatim -- append it to the path.
                base = url.rstrip("/")
                url = f"{base}/{quote(marked_payload)}"
        except Exception:
            base = url.rstrip("/")
            url = f"{base}/{quote(marked_payload)}"
    elif hdr_name is not None:
        # Header injection: set on session (restored after request).
        headers[hdr_name] = marked_payload
    elif ck_name is not None:
        # Cookie injection: set on session (restored after request).
        try:
            requester.session.cookies.set(ck_name, marked_payload)
        except Exception:
            pass
    # -- param-based: inject into the query/body param.
    else:
        if param and not param.startswith("("):
            if method == "POST":
                data[param] = marked_payload
            else:
                params[param] = marked_payload
        else:
            # No real param -- payload goes into a probe query slot.
            params["_"] = marked_payload

    try:
        # Requester.request() does not accept per-call headers; for header
        # and cookie injection we set them on the underlying session, then
        # restore afterwards so we don't leak state across findings.
        #
        # cache_get=False on EVERY replay: the GET cache keys on the URL and
        # cannot see session-level header/cookie injection, so the SECOND
        # finding targeting the same URL would read the FIRST finding's
        # response.  A fresh token is minted per replay, so the cached body can
        # never contain it -- the match fails and a still-exploitable hole is
        # reported as fixed.  (Found by tests/test_verify_carriers_live.py:
        # per-carrier replays passed in isolation, and two of them flipped to
        # "fixed" the moment they ran through verify_findings on one session.)
        if headers:
            saved = {k: requester.session.headers.get(k) for k in headers}
            try:
                requester.session.headers.update(headers)
                resp = requester.request(method, url,
                                         params=params or None,
                                         data=data or None,
                                         cache_get=False)
            finally:
                for k, v in saved.items():
                    if v is None:
                        requester.session.headers.pop(k, None)
                    else:
                        requester.session.headers[k] = v
        else:
            resp = requester.request(method, url,
                                     params=params or None,
                                     data=data or None,
                                     cache_get=False)
    except Exception as e:
        _restore_cookie(requester, ck_name, saved_cookie)
        return {"status": "error", "detail": f"request failed: {e}",
                "response": None, "context": None}

    _restore_cookie(requester, ck_name, saved_cookie)
    text = resp.text or ""

    # Semantic confirmation: did the token reflect in an executable
    # context?
    verify = verifier.verify_semantic(text, token,
                                      response_headers=dict(resp.headers))
    if verify.get("confirmed"):
        return {"status": "still_vuln",
                "detail": f"payload still executes: {verify['detail']}",
                "response": resp, "context": verify.get("context")}

    # If the token doesn't reflect at all, the input is no longer reflected.
    # "No reflection" is NOT by itself a fix though -- the three checks inside
    # this branch (Phase 176e) separate "remediated" from "never got an answer
    # worth judging".  The comment here used to read "fixed (or the endpoint
    # changed)": the parenthetical was the whole problem, because the report
    # rendered both outcomes as the same word.
    if token not in text:
        # Check the raw payload too (some payloads don't get tokenized).
        if payload and payload not in text:
            # Our input never came back -- but "we saw nothing" has several
            # causes and only ONE of them is a fix.  A 404 means the endpoint
            # moved, a 403 means a WAF or auth layer answered instead of the
            # app, a 5xx means the app is down: all of them produce a body with
            # no payload in it and used to be reported as "fixed" with the SAME
            # detail string as a genuine fix.  That left the report unable to
            # tell "remediated" from "never tested", and since the CI gate only
            # fails on still_vuln it passed those straight through.  The old
            # comment said it out loud: "fixed (or the endpoint changed)".
            #
            # This check lives inside the "nothing came back" branch on
            # purpose: error_page_xss and path_xss legitimately answer 404/500
            # WHILE reflecting the payload, so they never reach here.
            if resp.status_code >= 400:
                return {"status": "error",
                        "detail": f"HTTP {resp.status_code}: the replay did "
                                  f"not reach a working endpoint, so "
                                  f"remediation cannot be judged",
                        "response": resp, "context": None}
            if _AUTH_PAGE_RE.search(text):
                return {"status": "error",
                        "detail": "response looks like a sign-in page (the "
                                  "session was probably expired) -- nothing "
                                  "was tested",
                        "response": resp, "context": None}
            return {"status": "fixed",
                    "detail": "payload no longer reflected in response",
                    "response": resp, "context": None}
        # Payload reflected but tokenized form didn't -- means the app
        # now escapes/breaks the payload.  Treat as fixed.
        return {"status": "fixed",
                "detail": "payload reflected but escaped/broken "
                          "(not executable)",
                "response": resp, "context": None}

    # Token reflected but not in an executable context -> the app now
    # escapes it properly.  Fixed.
    return {"status": "fixed",
            "detail": f"token reflected but not executable "
                      f"(context: {verify.get('context') or 'escaped'})",
            "response": resp, "context": verify.get("context")}


def _restore_cookie(requester, name, previous) -> None:
    """Put a cookie back the way it was before a cookie-replay probe."""
    if name is None:
        return
    try:
        jar = requester.session.cookies
        if previous is None:
            jar.clear(name)
        else:
            jar.set(name, previous)
    except Exception:
        pass


def verify_findings(findings: list[dict], requester,
                    verbose: bool = False) -> list[dict]:
    """Re-verify a list of findings and return annotated results.

    Each result dict carries the original finding plus a ``verify`` key
    with ``status``, ``detail``, and ``checked_at``.
    """
    results: list[dict] = []
    total = len(findings)
    for i, f in enumerate(findings, 1):
        ftype = (f.get("type") or "reflected").lower()
        payload = _extract_payload(f)
        if verbose:
            print(f"  [{i}/{total}] {ftype} @ {f.get('url')} "
                  f"param={f.get('param')}")

        if not _is_replayable(ftype):
            results.append({**f, "verify": {
                "status": "skipped",
                "detail": f"finding type '{ftype}' requires scanner context "
                          f"(OOB/stored/DOM-dynamic) and cannot be replayed "
                          f"from a JSON report alone",
                "checked_at": datetime.now().isoformat(timespec="seconds"),
            }})
            continue

        if not payload:
            results.append({**f, "verify": {
                "status": "skipped",
                "detail": "no concrete payload recorded (placeholder only)",
                "checked_at": datetime.now().isoformat(timespec="seconds"),
            }})
            continue

        res = _replay_request(requester, f, payload)
        results.append({**f, "verify": {
            "status": res["status"],
            "detail": res["detail"],
            "context": res.get("context"),
            "checked_at": datetime.now().isoformat(timespec="seconds"),
        }})
    return results


# ---------------------------------------------------------------------------
# In-scan PoC self-verification (Phase 135)
# ---------------------------------------------------------------------------
def _poc_verdict(verified, status: str, detail: str,
                 context: str | None = None) -> dict:
    return {
        "verified": verified,
        "status": status,
        "detail": detail,
        "context": context,
        "checked_at": datetime.now().isoformat(timespec="seconds"),
    }


def verify_poc(requester, finding: dict, verbose: bool = False) -> dict:
    """Replay a finding's own payload once; report whether it reproduced.

    ``attach_pocs()`` has always *generated* curl / browser-URL / HTML PoCs
    but never ran one, so "reproducible PoC" meant "a string you can copy"
    rather than "a request we confirmed reproduces the finding".  Nothing
    in the report told the two apart -- not even the case where the
    exported PoC cannot work at all because ``--poc-include-auth`` is off
    and the target needs a session.

    ``_replay_request`` already does the hard part (fresh token marking,
    header / cookie / multipart carriers, semantic confirmation), so this
    is a thin verdict layer over it.  The replay goes through the scanner's
    own Requester, i.e. it re-verifies *the finding* with the session the
    scan used.

    ``verified`` is ``True`` only when the replay confirmed the finding;
    ``False`` when it did not; ``None`` when a replay was not applicable
    (no headless replay path, or no concrete payload).
    """
    ftype = (finding.get("type") or "reflected").lower()
    if not _is_replayable(ftype):
        return _poc_verdict(
            None, "skipped",
            f"finding type '{ftype}' has no headless replay path")
    payload = _extract_payload(finding)
    if not payload:
        return _poc_verdict(None, "skipped", "no concrete payload recorded")

    try:
        res = _replay_request(requester, finding, payload)
    except Exception as e:                       # never fail the scan for this
        return _poc_verdict(False, "error", f"{type(e).__name__}: {e}")

    status = res.get("status")
    if status == "still_vuln":
        return _poc_verdict(True, "verified", res.get("detail") or "",
                            context=res.get("context"))
    if status == "fixed":
        return _poc_verdict(False, "not_reproduced", res.get("detail") or "",
                            context=res.get("context"))
    return _poc_verdict(False, status or "error", res.get("detail") or "")


# ---------------------------------------------------------------------------
# Summary + reporting
# ---------------------------------------------------------------------------
def summarize(results: list[dict]) -> dict:
    counts = {"fixed": 0, "still_vuln": 0, "error": 0, "skipped": 0}
    for r in results:
        v = r.get("verify") or {}
        s = v.get("status", "error")
        counts[s] = counts.get(s, 0) + 1
    return {
        "total": len(results),
        "counts": counts,
        "fixed": counts["fixed"],
        "still_vuln": counts["still_vuln"],
        "error": counts["error"],
        "skipped": counts["skipped"],
        "generated": datetime.now().isoformat(timespec="seconds"),
    }


def build_html(results: list[dict], source_report: str,
               target: str | None = None,
               ai_report: dict | None = None) -> str:
    """Render a verification report as HTML.

    ``ai_report`` is a ``report_ai.AIReport.to_meta()`` dict (Phase 176),
    supplied only when ``--ai-report`` ran.  Absent means no section -- which
    is byte-for-byte the pre-Phase-176 output.
    """
    import html as _html
    s = summarize(results)

    # Phase 176: the AI narrative section (already escaped inside report_ai).
    ai_section = ""
    if isinstance(ai_report, dict):
        try:
            from . import report_ai
            ai_section = report_ai.ai_section_html(ai_report)
        except Exception:
            ai_section = ""

    c = s["counts"]
    rows = []
    for i, r in enumerate(results, 1):
        v = r.get("verify") or {}
        status = v.get("status", "error")
        status_cls = {
            "fixed": "st-fixed", "still_vuln": "st-vuln",
            "error": "st-err", "skipped": "st-skip",
        }.get(status, "st-err")
        rows.append(f"""
        <tr class="{status_cls}">
          <td>{i}</td>
          <td><span class="status-badge {status_cls}">{_html.escape(status)}</span></td>
          <td>{_html.escape(r.get('type') or '')}</td>
          <td>{_html.escape(r.get('url') or '')}</td>
          <td>{_html.escape(r.get('method') or '')}</td>
          <td>{_html.escape(r.get('param') or '')}</td>
          <td><code>{_html.escape(r.get('payload') or '')[:120]}</code></td>
          <td>{_html.escape(r.get('severity') or '')}</td>
          <td>{_html.escape(v.get('detail') or '')}</td>
          <td>{_html.escape(v.get('checked_at') or '')}</td>
        </tr>""")
    rows_html = "\n".join(rows) if rows else \
        '<tr><td colspan="10">No findings to verify.</td></tr>'
    tgt = target or "(from report)"
    return f"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<title>XSSentinel Verify-Fix Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7fb;color:#1f2430}}
 header{{background:#1f2430;color:#fff;padding:20px 28px}}
 header h1{{margin:0;font-size:20px}}
 .meta{{color:#9aa3b2;font-size:13px;margin-top:4px}}
 .summary{{display:flex;gap:14px;padding:18px 28px;flex-wrap:wrap}}
 .card{{background:#fff;border-radius:10px;padding:14px 18px;box-shadow:0 1px 3px rgba(0,0,0,.08);min-width:120px}}
 .card .n{{font-size:26px;font-weight:700}}
 .card.fixed .n{{color:#3bb968}} .card.vuln .n{{color:#e5484d}}
 .card.err .n{{color:#f5a623}} .card.skip .n{{color:#9aa3b2}}
 table{{width:96%;margin:0 auto 30px;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 th,td{{padding:9px 10px;border-bottom:1px solid #eef0f4;font-size:12px;text-align:left;vertical-align:top}}
 th{{background:#f0f2f7;position:sticky;top:0}}
 code{{background:#f3f4f8;padding:2px 4px;border-radius:4px;word-break:break-all}}
 .st-fixed{{border-left:4px solid #3bb968}}
 .st-vuln{{border-left:4px solid #e5484d}}
 .st-err{{border-left:4px solid #f5a623}}
 .st-skip{{border-left:4px solid #9aa3b2}}
 .status-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;color:#fff}}
 .status-badge.st-fixed{{background:#3bb968}}
 .status-badge.st-vuln{{background:#e5484d}}
 .status-badge.st-err{{background:#f5a623}}
 .status-badge.st-skip{{background:#9aa3b2}}
 .ai-report{{padding:0 28px 24px}}
 .ai-report h2{{font-size:16px;margin:0 0 10px}}
 .ai-report h3{{font-size:14px;margin:16px 0 6px}}
 .ai-report h4{{font-size:13px;margin:12px 0 5px}}
 .ai-report p{{font-size:13px;color:#3a4150;line-height:1.65;margin:8px 0}}
 .ai-report ul,.ai-report ol{{font-size:13px;color:#3a4150;padding-left:22px;margin:8px 0}}
 .ai-report li{{margin:3px 0}}
 .ai-report blockquote{{margin:8px 0;padding:8px 12px;background:#f0f2f7;border-left:3px solid #9aa3b2;color:#5b6473;font-size:12px}}
 .ai-report code{{background:#f3f4f8;padding:2px 4px;border-radius:4px;word-break:break-all}}
 .ai-report table.ai-table{{width:100%;margin:10px 0;box-shadow:none;border-radius:8px;overflow:hidden}}
 .ai-report table.ai-table td{{padding:6px 10px;border-bottom:1px solid #eef0f4;font-size:12px;background:#fff}}
 .ai-report.degraded{{border-left:4px solid #f5a623}}
 footer{{padding:14px 28px;color:#9aa3b2;font-size:12px}}
</style></head>
<body>
<header><h1>XSSentinel — Verify-Fix Report</h1>
<div class="meta">Source: {_html.escape(source_report)} · Target: {_html.escape(tgt)} · Generated: {s['generated']}</div>
</header>
<div class="summary">
  <div class="card fixed"><div class="n">{c['fixed']}</div><div>Fixed</div></div>
  <div class="card vuln"><div class="n">{c['still_vuln']}</div><div>Still Vulnerable</div></div>
  <div class="card err"><div class="n">{c['error']}</div><div>Error</div></div>
  <div class="card skip"><div class="n">{c['skipped']}</div><div>Skipped</div></div>
</div>
{ai_section}
<table>
<tr><th>#</th><th>Status</th><th>Type</th><th>URL</th><th>Method</th><th>Param</th><th>Payload</th><th>Severity</th><th>Detail</th><th>Checked At</th></tr>
{rows_html}
</table>
<footer>Generated by XSSentinel verify-fix. Replays original payloads to confirm remediation.</footer>
</body></html>"""


def build_json(results: list[dict], source_report: str,
               target: str | None = None,
               ai_report: dict | None = None) -> str:
    s = summarize(results)
    out = {
        "tool": "XSSentinel",
        "mode": "verify-fix",
        "source_report": source_report,
        "target": target,
        "generated": s["generated"],
        "summary": s,
        "findings": results,
    }
    # Phase 176: the AI section metadata, when --ai-report ran.  The html
    # rendering is dropped -- consumers of this file want the markdown, and
    # shipping both would double the payload for nothing.
    if isinstance(ai_report, dict):
        out["ai_report"] = {k: v for k, v in ai_report.items() if k != "html"}
    return json.dumps(out, ensure_ascii=False, indent=2)
