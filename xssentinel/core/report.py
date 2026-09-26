"""Report generation: HTML (human) and JSON (machine)."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime

from .findings import EVIDENCE_OOB
from .logger import get_logger

_log = get_logger("report")


def _esc(s) -> str:
    return html.escape(str(s)) if s is not None else ""


def _safe_url(url: str) -> str:
    """Return the URL if it uses a safe http(s) scheme, else "".

    Prevents the report itself from becoming an XSS vector: a finding
    whose payload is ``javascript:alert(...)`` would otherwise be written
    into ``<a href="javascript:...">`` and execute when a reviewer clicks
    the link in the HTML report.  Only http/https URLs are rendered as
    clickable links; everything else is returned as empty so the caller
    falls back to displaying the raw (escaped) text.
    """
    if not url:
        return ""
    s = str(url).strip()
    low = s.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return s
    return ""


def build_html(findings: list, target: str, meta: dict) -> str:
    # Egress status, stated once at the top of the human deliverable.  A reader
    # who sees only "0 findings" cannot tell a hardened target from one that was
    # never reached, and that distinction is the whole point of the counters in
    # `Requester._send`.
    _st = scan_status(meta)
    _att, _fail = meta.get("requests_attempted"), meta.get("requests_failed")
    status_banner = (
        "" if _st in ("completed", "unknown") else
        f'<br><b>SCAN INCOMPLETE ({_st}): '
        f'{_fail if _fail is not None else "?"} of '
        f'{_att if _att is not None else "?"} requests never received a response. '
        'Zero findings in this report is not evidence of absence.</b>')
    # A bounded read is a DIFFERENT blind spot from a missing response, and it
    # used to be invisible here: `responses_truncated` had exactly one consumer
    # in the whole codebase -- the JSON at `build_json` -- so a report handed to
    # a client said nothing about bodies it had only half looked at, while the
    # machine-readable sibling did.  Deliberately not folded into `scan_status`:
    # every endpoint WAS reached and answered here, so calling that "partial"
    # would move the exit code of an otherwise-complete scan.  `--truncation-hint`
    # is unrelated (it shortens the request body we send, not what we read back).
    _trunc = meta.get("responses_truncated")
    if _trunc:
        status_banner += (
            f'<br><b>BOUNDED READ: {_trunc} response(s) exceeded '
            '--max-response-bytes, so only their leading bytes were examined. '
            'A reflection past that point was not testable in this run.</b>')
    # Phase 20-3: coverage section (when a coverage tracker is supplied).
    coverage_section = ""
    cov = meta.get("coverage")
    if cov is not None:
        try:
            coverage_section = cov.to_html()
        except Exception as e:
            _log.debug("coverage to_html failed: %s", e)
            coverage_section = ""
    # Compliance badges lookup is module-level (avoid re-importing inside the
    # per-finding loop).
    comp_mod = None
    try:
        from . import compliance as comp_mod
    except Exception as e:
        _log.debug("compliance module unavailable: %s", e)
        comp_mod = None
    rows = []
    for i, f in enumerate(findings, 1):
        d = f.data if hasattr(f, "data") else f
        sev = d.get("severity", "info")
        hclass = {"critical": "sev-crit", "high": "sev-high", "medium": "sev-med", "low": "sev-low"}.get(sev, "sev-info")
        headless = d.get("headless") or {}
        # Three states, named.  `confirmed: False` used to render as "not fired"
        # whether or not the browser ever looked, which told the reader "we
        # checked and it is quiet" when the truth was "we could not check".
        _out = headless.get("outcome") or (
            "fired" if headless.get("confirmed")
            else "unavailable" if not headless.get("available")
            else "not-fired")
        hstatus = {"fired": "browser executed",
                   "not-fired": "browser did NOT reproduce",
                   "errored": "browser errored",
                   "unavailable": "no browser check"}.get(_out, "n/a")
        # A stated tier outranks this inferred phrase.  An out-of-band callback
        # finding has no headless dialog to report and would otherwise read
        # "no browser check" in the same row that says the victim browser
        # fetched the URL -- the two lines would contradict each other, and the
        # weaker one would win in whoever's triage is skimming the column.
        if d.get("evidence_class") == EVIDENCE_OOB:
            hstatus = "executed out-of-band (callback hit, no dialog check)"
        poc = d.get("poc") or {}
        poc_curl = _esc(poc.get("curl", ""))
        poc_html = _esc(poc.get("html", ""))
        # Phase 23-2: only render http(s) URLs as clickable links.  A
        # ``javascript:`` payload would otherwise turn the report's own
        # <a href="javascript:..."> into an XSS vector against the report
        # reader.  Non-http(s) URLs are shown as escaped plain text.
        raw_poc_url = poc.get("url", "")
        safe_poc_url = _esc(_safe_url(raw_poc_url))
        poc_cell = ""
        if safe_poc_url:
            poc_cell += f'<a href="{safe_poc_url}" target="_blank" rel="noopener noreferrer">open URL</a><br>'
        elif raw_poc_url:
            # Non-http(s) scheme: display as escaped text, NOT a link.
            poc_cell += f'<code>{_esc(raw_poc_url)}</code><br>'
        if poc_curl:
            poc_cell += f'<code>{poc_curl}</code>'
        if poc_html:
            poc_cell += (f'<details><summary>HTML PoC</summary>'
                         f'<pre>{poc_html}</pre></details>')
        # Compliance badges (Phase 14b): show the primary CWE/OWASP IDs.
        compliance_badges = ""
        if comp_mod is not None:
            try:
                entries = comp_mod.compliance_for_finding(d)
                if entries:
                    # Show only the short IDs (CWE-79, A03:2021, etc.)
                    short_ids = [e["requirement_id"] for e in entries[:3]]
                    compliance_badges = (
                        '<div class="comp-badges">'
                        + " ".join(f'<span class="badge">{_esc(r)}</span>' for r in short_ids)
                        + "</div>"
                    )
            except Exception as e:
                _log.debug("compliance lookup failed for finding %d: %s", i, e)
        # Phase 46 (pentest-readiness): the HTML report is THE client
        # deliverable -- render the CVSS v3.1 score/vector (already
        # computed into each finding by attach_pocs) next to the severity,
        # and embed the headless-confirmation screenshot when present.
        sev_cell = _esc(d.get('severity'))
        if d.get("cvss_score") is not None:
            sev_cell += (f'<div class="cvss"><b>{_esc(d.get("cvss_score"))}</b>'
                         f' <code>{_esc(d.get("cvss_vector") or "")}</code></div>')
        # How sure we are, stated next to how bad it would be.  Severity and
        # confidence were the same word for the same reason a client mis-triages:
        # a browser-refuted finding looked exactly as loud as a browser-executed
        # one.  `evidence_class` names the strongest class actually obtained; the
        # PoC replay verdict rides along because a PoC that does not replay is a
        # different deliverable from one that does, and that fact used to live
        # only in the optional --poc-dir INDEX.md.
        _cls = d.get("evidence_class")
        _ev = d.get("evidence")
        _bits = []
        if _cls:
            _bits.append(f'evidence: {_esc(_cls)}')
        if _ev:
            # A different thing from the tier: the text that proves the
            # reflection.  Clip BEFORE escaping -- slicing an escaped string can
            # cut `&amp;` in half and emit broken markup into the deliverable.
            _bits.append(f'excerpt: {_esc(str(_ev)[:160])}')
        _cf = d.get("confidence")
        if _cf:
            _bits.append(f'confidence: {_esc(_cf)}')
        _pv = d.get("poc_verified")
        if _pv is True:
            _bits.append("PoC replay: verified")
        elif _pv is False:
            _bits.append("PoC replay: DID NOT replay (treat as unproven)")
        if _bits:
            sev_cell += ('<div class="evid" style="margin-top:4px;font-size:11px;'
                         'color:#5b6473">' + "<br>".join(_bits) + "</div>")
        shot_html = ""
        shot = (headless or {}).get("screenshot_b64")
        if headless and headless.get("confirmed") and shot:
            shot_html = (f'<details class="shot"><summary>screenshot '
                         f'(headless confirmation)</summary>'
                         f'<img src="data:image/png;base64,{shot}" '
                         f'alt="execution screenshot" style="max-width:320px;'
                         f'border:1px solid #eef0f4;border-radius:4px"></details>')
        rows.append(f"""
        <tr class="{hclass}">
          <td>{i}</td>
          <td>{_esc(d.get('type'))}</td>
          <td>{_esc(d.get('url'))}</td>
          <td>{_esc(d.get('method'))}</td>
          <td>{_esc(d.get('param'))}</td>
          <td>{_esc(d.get('context'))}</td>
          <td><code>{_esc(d.get('payload'))}</code></td>
          <td>{_esc(','.join(d.get('transform') or []))}</td>
          <td>{sev_cell}</td>
          <td>{_esc(d.get('confidence'))}</td>
          <td>{_esc(hstatus)}</td>
          <td>{_esc(d.get('detail'))}{compliance_badges}{shot_html}</td>
          <td class="poc">{poc_cell}</td>
        </tr>""")
    rows_html = "\n".join(rows) if rows else \
        '<tr><td colspan="13">No vulnerabilities found.</td></tr>'

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        d = f.data if hasattr(f, "data") else f
        s = d.get("severity")
        if s in counts:
            counts[s] += 1

    # Compliance summary table (Phase 14b).
    compliance_section = ""
    try:
        from . import compliance as comp_mod
        compliance_html = comp_mod.compliance_table_html(findings)
        if compliance_html and "<table" in compliance_html:
            compliance_section = (
                '<section class="compliance-section">'
                '<h2>Compliance Mapping</h2>'
                + compliance_html +
                '</section>'
            )
    except Exception as e:
        _log.debug("compliance section build failed: %s", e)

    # Remediation advice (Phase 20): actionable fix per finding type.
    remediation_section = ""
    try:
        from . import fix_advice
        remediation_section = fix_advice.advice_summary_html(findings)
    except Exception as e:
        _log.debug("remediation section build failed: %s", e)

    # Phase 176: AI narrative section, present only when --ai-report ran.  Its
    # HTML is produced by report_ai (already escaped there: the text is full of
    # live payloads, so the report itself must not become a vector).
    ai_section = ""
    try:
        from . import report_ai
        ai_section = report_ai.ai_section_html(meta.get("ai_report"))
    except Exception as e:
        _log.debug("ai section build failed: %s", e)

    return f"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<title>XSSentinel Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7fb;color:#1f2430}}
 header{{background:#1f2430;color:#fff;padding:20px 28px}}
 header h1{{margin:0;font-size:20px}}
 .meta{{color:#9aa3b2;font-size:13px;margin-top:4px}}
 .summary{{display:flex;gap:14px;padding:18px 28px}}
 .card{{background:#fff;border-radius:10px;padding:14px 18px;box-shadow:0 1px 3px rgba(0,0,0,.08);min-width:120px}}
 .card .n{{font-size:26px;font-weight:700}}
 .card.high .n{{color:#e5484d}} .card.crit .n{{color:#b91c1c}} .card.med .n{{color:#f5a623}} .card.low .n{{color:#3b82f6}}
 table{{width:96%;margin:0 auto 30px;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 th,td{{padding:9px 10px;border-bottom:1px solid #eef0f4;font-size:12px;text-align:left;vertical-align:top}}
 th{{background:#f0f2f7;position:sticky;top:0}}
 code{{background:#f3f4f8;padding:2px 4px;border-radius:4px;word-break:break-all}}
 .sev-crit{{border-left:4px solid #b91c1c}}
 .sev-high{{border-left:4px solid #e5484d}}
 .sev-med{{border-left:4px solid #f5a623}}
 .sev-low{{border-left:4px solid #3b82f6}}
 .poc code{{display:block;white-space:pre-wrap;word-break:break-all;margin-bottom:4px;background:#f3f4f8;padding:2px 4px;border-radius:4px}}
 .poc details{{margin-top:4px}}
 .poc summary{{cursor:pointer;color:#3b82f6;font-size:11px}}
 .poc pre{{background:#1f2430;color:#e6e6e6;padding:6px;border-radius:4px;white-space:pre-wrap;word-break:break-all;max-height:160px;overflow:auto;font-size:11px}}
 .comp-badges{{margin-top:4px}}
 .badge{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;background:#eef0f4;color:#5b6473;margin-right:3px}}
 .cvss{{margin-top:3px;font-size:11px}}
 .cvss b{{color:#b91c1c}}
 .cvss code{{font-size:10px}}
 .shot summary{{cursor:pointer;color:#3b82f6;font-size:11px;margin-top:4px}}
 .shot img{{margin-top:4px}}
 .compliance-section{{padding:0 28px 24px}}
 .compliance-section h2{{font-size:16px;margin:0 0 10px}}
 .compliance{{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08);border-radius:8px;overflow:hidden;font-size:12px}}
 .compliance th,.compliance td{{padding:6px 10px;border-bottom:1px solid #eef0f4;text-align:left}}
 .compliance th{{background:#f0f2f7}}
 .remediation{{padding:0 28px 24px}}
 .remediation h2{{font-size:16px;margin:0 0 10px}}
 .advice-block{{background:#fff;border-radius:8px;padding:14px 18px;margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #3b82f6}}
 .advice-block h4{{margin:0 0 6px;font-size:14px}}
 .advice-count{{color:#9aa3b2;font-size:12px;font-weight:normal}}
 .advice-headline{{margin:4px 0 8px;font-size:13px}}
 .advice-block p{{font-size:12px;color:#3a4150;margin:6px 0}}
 .advice-block details{{margin:6px 0}}
 .advice-block summary{{cursor:pointer;color:#3b82f6;font-size:11px}}
 .advice-block pre{{background:#1f2430;color:#e6e6e6;padding:8px;border-radius:4px;white-space:pre-wrap;word-break:break-all;max-height:240px;overflow:auto;font-size:11px}}
 .advice-block code{{background:transparent;padding:0;color:inherit}}
 .also-consider{{margin:6px 0 0;padding-left:18px;font-size:12px;color:#3a4150}}
 .also-consider li{{margin:2px 0}}
 .coverage{{padding:0 28px 24px}}
 .coverage h2{{font-size:16px;margin:0 0 10px}}
 .coverage h3{{font-size:13px;margin:14px 0 6px;color:#3a4150}}
 .cov-overview{{display:flex;gap:18px;align-items:center;margin-bottom:14px;background:#fff;padding:14px 18px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 .cov-overall{{text-align:center;min-width:120px}}
 .cov-overall-label{{font-size:11px;color:#9aa3b2;margin-bottom:2px}}
 .cov-overall-score{{font-size:28px;font-weight:700}}
 .cov-stats{{display:flex;flex-wrap:wrap;gap:10px;font-size:12px;color:#3a4150}}
 .cov-stats span{{background:#f3f4f8;padding:3px 8px;border-radius:4px}}
 .cov-layer-table,.cov-ep-table,.param-table{{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08);border-radius:8px;overflow:hidden;font-size:12px;margin-bottom:14px}}
 .cov-layer-table th,.cov-layer-table td,.cov-ep-table th,.cov-ep-table td,.param-table th,.param-table td{{padding:6px 10px;border-bottom:1px solid #eef0f4;text-align:left}}
 .cov-layer-table th,.cov-ep-table th,.param-table th{{background:#f0f2f7}}
 .phase-row td{{background:#fafbfc;font-size:11px;color:#5b6473}}
 .cov-bar{{display:inline-block;width:80px;height:8px;background:#eef0f4;border-radius:4px;vertical-align:middle;margin-right:6px;overflow:hidden}}
 .cov-fill{{height:100%;border-radius:4px}}
 .cov-fill.cov-high{{background:#3bb968}}
 .cov-fill.cov-med{{background:#f5a623}}
 .cov-fill.cov-low{{background:#e5484d}}
 .cov-pct{{font-size:11px;color:#5b6473}}
 .cov-overall-score.cov-high{{color:#3bb968}}
 .cov-overall-score.cov-med{{color:#f5a623}}
 .cov-overall-score.cov-low{{color:#e5484d}}
 .badge-crawled{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;background:#dbeafe;color:#1e40af;margin-left:4px}}
 .param-loc{{display:inline-block;padding:0 4px;border-radius:3px;font-size:10px;background:#eef0f4;color:#5b6473;margin-left:4px}}
 .refl-yes{{color:#3bb968;font-weight:600}}
 .refl-no{{color:#9aa3b2}}
 .conf-yes{{color:#e5484d;font-weight:600;font-size:10px}}
 .param-detail{{margin-bottom:10px;background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 .param-detail summary{{cursor:pointer;padding:8px 14px;font-size:12px;color:#3b82f6}}
 .param-detail .param-table{{margin:0;border-radius:0;box-shadow:none}}
 .cov-help{{font-size:11px;color:#9aa3b2;margin-top:10px;padding:10px;background:#fafbfc;border-radius:6px;line-height:1.5}}
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
 .muted{{color:#9aa3b2;font-size:12px;padding:8px 0}}
 footer{{padding:14px 28px;color:#9aa3b2;font-size:12px}}
</style></head>
<body>
<header><h1>XSSentinel — XSS Detection Report</h1>
<div class="meta">Target: {_esc(target)} · Generated: {_esc(meta.get('generated'))} · Requests: {_esc(meta.get('requests'))} · WAF: {_esc(meta.get('waf') or 'none detected')} · Status: {_esc(_st)}{status_banner}</div>
</header>
<div class="summary">
  <div class="card crit"><div class="n">{counts['critical']}</div><div>Critical</div></div>
  <div class="card high"><div class="n">{counts['high']}</div><div>High</div></div>
  <div class="card med"><div class="n">{counts['medium']}</div><div>Medium</div></div>
  <div class="card low"><div class="n">{counts['low']}</div><div>Low</div></div>
</div>
{ai_section}
{compliance_section}
<table>
<tr><th>#</th><th>Type</th><th>URL</th><th>Method</th><th>Param</th><th>Context</th><th>Payload</th><th>Transform</th><th>Severity</th><th>Confidence</th><th>Headless</th><th>Detail</th><th>PoC</th></tr>
{rows_html}
</table>
{remediation_section}
{coverage_section}
<footer>Generated by XSSentinel. Use only on systems you are authorized to test.</footer>
</body></html>"""


def scan_status(meta: dict) -> str:
    """What the numbers actually say the scan did.

    `findings: []` is one string, but it covers two opposite outcomes: the
    target was tested and held, and the target was never reached at all.  Before
    this existed both produced the same artifact and the same exit code, so a
    dead host, a TLS failure or a WAF black-hole could be delivered as "clean".
    """
    attempted = meta.get("requests_attempted")
    failed = meta.get("requests_failed")
    if attempted is None:
        return "unknown"
    if attempted == 0:
        return "not_tested"
    if failed:
        if failed >= attempted:
            return "unreachable"
        return "partial"
    return "completed"


def build_json(findings: list, target: str, meta: dict) -> str:
    out = {
        "tool": "XSSentinel",
        "target": target,
        "generated": meta.get("generated"),
        "requests": meta.get("requests"),
        # Egress truth, not effort accounting: how many requests the scanner
        # asked for, how many never came back with a response, and the one-word
        # verdict a CI job can gate on.  See `scan_status`.
        "requests_attempted": meta.get("requests_attempted"),
        "requests_failed": meta.get("requests_failed"),
        # Response bodies shortened by --max-response-bytes.  A reflection that
        # sat past the cap could not be seen, so a bounded scan must be able to
        # say it was bounded.
        "responses_truncated": meta.get("responses_truncated"),
        "scan_status": scan_status(meta),
        # Imported endpoints the scope check refused to probe.  Recorded here so
        # "0 findings" cannot be read as "the whole HAR/spec was covered".
        "scope_dropped": meta.get("scope_dropped"),
        "scope_dropped_count": meta.get("scope_dropped_count"),
        "waf": meta.get("waf"),
        "findings": [f.data if hasattr(f, "data") else f for f in findings],
    }
    # Phase 20-3: include coverage data when a tracker is supplied.
    cov = meta.get("coverage")
    if cov is not None:
        try:
            out["coverage"] = cov.to_json_dict()
        except Exception as e:
            _log.debug("coverage to_json failed: %s", e)
    # Phase 176: AI narrative section (present only when --ai-report ran).
    # The html rendering is dropped -- tools consuming this file want the
    # markdown, and shipping both would double the report size for nothing.
    ai = meta.get("ai_report")
    if isinstance(ai, dict):
        out["ai_report"] = {k: v for k, v in ai.items() if k != "html"}
    return json.dumps(out, ensure_ascii=False, indent=2)


def build_csv(findings: list, target: str, meta: dict) -> str:
    """Flat CSV — handy for spreadsheets / quick triage."""
    import csv
    import io
    buf = io.StringIO()
    cols = ["type", "url", "method", "param", "context", "payload",
            "transform", "severity", "confidence", "detail", "poc_curl", "poc_url"]
    w = csv.writer(buf)
    w.writerow(cols)
    for f in findings:
        d = f.data if hasattr(f, "data") else f
        poc = d.get("poc") or {}
        w.writerow([
            d.get("type", ""), d.get("url", ""), d.get("method", ""),
            d.get("param", ""), d.get("context", ""),
            d.get("payload", ""), ",".join(d.get("transform") or []),
            d.get("severity", ""), d.get("confidence", ""), d.get("detail", ""),
            poc.get("curl", ""), poc.get("url", ""),
        ])
    return buf.getvalue()


def build_sarif(findings: list, target: str, meta: dict) -> str:
    """SARIF 2.1.0 — industry-standard, CI/issue-tracker integrable (like ZAP,
    Semgrep, CodeQL). Each XSS *type* gets its own rule id so issue trackers
    can triage reflected / stored / DOM / blind separately. Severity maps to a
    result level (high->error, medium->warning, low/info->note)."""
    sev_to_level = {"critical": "error", "high": "error", "medium": "warning",
                    "low": "note", "info": "note"}
    # Phase 22-2: expanded type->rule mapping so every XSS subclass gets a
    # distinct rule id in GitHub Code Scanning / SARIF consumers.  Framework
    # and template types use a prefix wildcard (handled below).
    type_rule = {
        "reflected":            "XSSENTINEL-XSS-REFLECTED",
        "stored":               "XSSENTINEL-XSS-STORED",
        "second_order":         "XSSENTINEL-XSS-SECOND-ORDER",
        "dom":                  "XSSENTINEL-XSS-DOM",
        "dom_dynamic":          "XSSENTINEL-XSS-DOM-DYNAMIC",
        "blind":                "XSSENTINEL-XSS-BLIND",
        "mutation_xss":         "XSSENTINEL-XSS-MUTATION",
        "dom_clobber":          "XSSENTINEL-XSS-DOM-CLOBBER",
        "template_ssti_angularjs": "XSSENTINEL-XSS-SSTI-ANGULARJS",
        "template_ssti_vue":    "XSSENTINEL-XSS-SSTI-VUE",
        "template_ssti":        "XSSENTINEL-XSS-SSTI",
        "jsonp_xss":            "XSSENTINEL-XSS-JSONP",
        "jsonpcallback":        "XSSENTINEL-XSS-JSONP",
        "csp_bypass":           "XSSENTINEL-XSS-CSP-BYPASS",
        "polyglot_reflection":  "XSSENTINEL-XSS-POLYGLOT",
        "postmessage_xss":      "XSSENTINEL-XSS-POSTMESSAGE",
        "prototype_pollution":  "XSSENTINEL-XSS-PROTOTYPE",
        "service_worker_xss":   "XSSENTINEL-XSS-SERVICE-WORKER",
        "web_worker_xss":       "XSSENTINEL-XSS-WEB-WORKER",
        "open_redirect_xss":    "XSSENTINEL-XSS-OPEN-REDIRECT",
        "framework_xss":        "XSSENTINEL-XSS-FRAMEWORK",
        "header_xss":           "XSSENTINEL-XSS-HEADER",
        "path_xss":             "XSSENTINEL-XSS-PATH",
        "cookie_xss":           "XSSENTINEL-XSS-COOKIE",
        "error_page_xss":       "XSSENTINEL-XSS-ERROR-PAGE",
        "cors_misconfig":       "XSSENTINEL-CORS-MISCONFIG",
        "xs_leak_surface":      "XSSENTINEL-XSLEAK-SURFACE",
        "markdown_xss":         "XSSENTINEL-XSS-MARKDOWN",
        "time_based_xss":       "XSSENTINEL-XSS-TIME-BASED",
        "fuzzer_triage":        "XSSENTINEL-XSS-FUZZER-TRIAGE",
        "bav":                  "XSSENTINEL-BAV-ADJACENT",
    }
    # Human-readable rule names keyed by finding type (not rule-id suffix).
    type_name = {
        "reflected":            "Reflected XSS",
        "stored":               "Stored XSS",
        "second_order":         "Second-Order XSS",
        "dom":                  "DOM-based XSS (static heuristic)",
        "dom_dynamic":          "DOM-based XSS (real-browser confirmed)",
        "blind":                "Blind XSS (OOB-confirmed)",
        "mutation_xss":         "Mutation XSS (mXSS)",
        "dom_clobber":          "DOM Clobbering XSS",
        "template_ssti_angularjs": "AngularJS Template SSTI",
        "template_ssti_vue":    "Vue Template SSTI",
        "template_ssti":        "Template SSTI",
        "jsonp_xss":            "JSONP Callback XSS",
        "jsonpcallback":        "JSONP Callback XSS",
        "csp_bypass":           "CSP Bypass Analysis",
        "polyglot_reflection":  "Polyglot XSS Reflection",
        "postmessage_xss":      "postMessage XSS",
        "prototype_pollution":  "Prototype Pollution XSS",
        "service_worker_xss":   "Service Worker XSS",
        "web_worker_xss":       "Web Worker XSS",
        "open_redirect_xss":    "Open Redirect to XSS",
        "framework_xss":        "Framework DOM XSS",
        "header_xss":           "Header Reflection XSS",
        "path_xss":             "Path Reflection XSS",
        "cookie_xss":           "Cookie Reflection XSS",
        "error_page_xss":       "Error Page XSS",
        "cors_misconfig":       "CORS Misconfiguration",
        "xs_leak_surface":      "XS-Leaks Surface (no isolation headers)",
        "markdown_xss":         "Markdown/BBCode XSS",
        "time_based_xss":       "Time-Based XSS (side-channel)",
        "fuzzer_triage":        "Fuzzer Triage (injectable param)",
        "bav":                  "BAV Adjacent Vulnerability (SSTI / open-redirect / CRLF)",
    }
    results = []
    seen_rule_types: set[str] = set()  # finding types that appeared
    for f in findings:
        d = f.data if hasattr(f, "data") else f
        sev = d.get("severity", "info")
        ftype = d.get("type", "reflected")
        # Framework types are dynamic: "framework_react_xss" etc.
        # Map them to the generic framework rule but keep the type name.
        if ftype.startswith("framework_") and ftype not in type_rule:
            rule_id = "XSSENTINEL-XSS-FRAMEWORK"
            display_type = "framework_xss"
        elif ftype.startswith("template_ssti_") and ftype not in type_rule:
            rule_id = "XSSENTINEL-XSS-SSTI"
            display_type = "template_ssti"
        else:
            rule_id = type_rule.get(ftype, "XSSENTINEL-XSS")
            display_type = ftype
        seen_rule_types.add(display_type)
        msg = (f"{ftype} in {d.get('context', 'n/a')} context"
               + (f" via param '{d.get('param')}'" if d.get("param") else "")
               + f" — {d.get('detail', '')}")
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": d.get("url", target)},
            }
        }
        if d.get("param"):
            loc["properties"] = {"param": d.get("param"),
                                 "attackPayload": d.get("payload", "")}
        results.append({
            "ruleId": rule_id,
            "level": sev_to_level.get(sev, "note"),
            "message": {"text": msg},
            "locations": [loc],
            "properties": {
                "xssType": ftype,
                "context": d.get("context"),
                "confidence": d.get("confidence"),
                "severity": sev,
                "poc": d.get("poc") or {},
            },
        })
    rules = [{
        "id": type_rule.get(dt, "XSSENTINEL-XSS") if dt in type_rule
              else ("XSSENTINEL-XSS-FRAMEWORK" if dt == "framework_xss"
                    else "XSSENTINEL-XSS-SSTI" if dt == "template_ssti"
                    else "XSSENTINEL-XSS"),
        "name": type_name.get(dt, "CrossSiteScripting"),
        "shortDescription": {"text": type_name.get(dt, "Cross-Site Scripting (XSS)")},
        "fullDescription": {
            "text": "XSSentinel detected a cross-site scripting sink of this "
                    "type. Review the location and payload."
        },
        "helpUri": "https://owasp.org/www-community/attacks/xss/",
        "properties": {"tags": ["security", "xss"]},
    } for dt in seen_rule_types] or [{
        "id": "XSSENTINEL-XSS",
        "name": "CrossSiteScripting",
        "shortDescription": {"text": "Cross-Site Scripting (XSS)"},
        "fullDescription": {"text": "XSSentinel detected a cross-site scripting "
                                    "sink. Review the location and payload."},
        "helpUri": "https://owasp.org/www-community/attacks/xss/",
        "properties": {"tags": ["security", "xss"]},
    }]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "XSSentinel",
                    "informationUri": "https://xssentinel.local",
                    "version": "1.0",
                    "rules": rules,
                }
            },
            "originalUriBaseIds": {},
            "results": results,
            "properties": {
                "target": target,
                "requests": meta.get("requests"),
                "waf": meta.get("waf"),
            },
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Phase 17: JUnit XML + Markdown report formats
# ---------------------------------------------------------------------------

def build_junit(findings: list, target: str, meta: dict) -> str:
    """JUnit XML format for CI test-result display.

    Each finding becomes a <testcase> with a <failure> child.  CI systems
    (GitLab CI, Jenkins, GitHub Actions test reporters) render this as a
    failed test, making XSS findings visible directly in the CI pipeline
    UI without parsing the report file.
    """
    from xml.sax.saxutils import escape as xml_escape

    total = len(findings)
    failures = sum(1 for f in findings
                   if (f.data if hasattr(f, "data") else f).get("severity")
                   in ("high", "critical"))
    errors = 0  # XSS findings are failures, not errors
    skipped = 0

    cases: list[str] = []
    for i, f in enumerate(findings, 1):
        d = f.data if hasattr(f, "data") else f
        ftype = d.get("type", "unknown")
        param = d.get("param") or "(none)"
        severity = d.get("severity", "info")
        url = d.get("url") or target
        method = d.get("method", "GET")
        payload = d.get("payload") or ""
        detail = d.get("detail") or d.get("evidence") or ""

        # Test name: "xss_reflected_param_q"
        test_name = f"xss_{ftype}_{param}_{i}"
        classname = "XSSentinel"

        if severity in ("high", "critical"):
            # Failure with full detail.
            failure_msg = (
                f"[{severity.upper()}] {ftype} XSS on {method} {url} "
                f"param={param}\n"
                f"Payload: {payload}\n"
                f"Detail: {detail}"
            )
            cases.append(
                f'  <testcase name="{xml_escape(test_name)}" '
                f'classname="{xml_escape(classname)}" time="0">\n'
                f'    <failure type="{xml_escape(ftype + "_xss")}" '
                f'message="{xml_escape(f"[{severity}] {ftype} on {param}")}">\n'
                f'      {xml_escape(failure_msg)}\n'
                f'    </failure>\n'
                f'  </testcase>'
            )
        else:
            # Medium/low/info: report as skipped (not a hard failure).
            cases.append(
                f'  <testcase name="{xml_escape(test_name)}" '
                f'classname="{xml_escape(classname)}" time="0">\n'
                f'    <skipped type="{xml_escape(ftype + "_xss")}" '
                f'message="{xml_escape(f"[{severity}] {ftype} on {param}")}" />\n'
                f'  </testcase>'
            )

    # Build the full JUnit XML document.
    testsuite_name = f"XSSentinel scan: {target}"
    body = "\n".join(cases)
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuites>\n'
        f'  <testsuite name="{xml_escape(testsuite_name)}" '
        f'tests="{total}" failures="{failures}" '
        f'errors="{errors}" skipped="{skipped}" '
        f'time="0">\n'
        f'{body}\n'
        f'  </testsuite>\n'
        f'</testsuites>\n'
    )


def _md_cell(s) -> str:
    """Make a string safe inside a GFM table cell.

    A raw ``|`` spawns a column, a raw newline spawns a row, and a
    backtick closes the inline code span the cell is wrapped in -- a
    reflected payload that rides the URL (path/header findings) carries
    all three, and the summary table it lands in is the client-facing
    deliverable.
    """
    return (str(s).replace("\\", "\\\\").replace("|", "\\|")
            .replace("`", "'").replace("\r", " ").replace("\n", " "))


def _md_fence(*blocks: str) -> str:
    """A code fence LONGER than any backtick run in the block contents.

    A payload containing ``` would close a fixed three-backtick fence and
    render the rest of the payload as live markdown -- the scan report
    injected by the very payloads it reports.  GFM closes a fence on a
    run of AT LEAST the opening length, so longest_run + 1 can never be
    closed by the content.
    """
    longest = 0
    for block in blocks:
        run = 0
        for ch in str(block):
            run = run + 1 if ch == "`" else 0
            if run > longest:
                longest = run
    return "`" * max(3, longest + 1)


def build_markdown(findings: list, target: str, meta: dict) -> str:
    """Markdown format for GitHub PR comments / issue tracking.

    Produces a concise summary table + per-finding detail sections,
    suitable for posting as a PR comment via GitHub Actions.
    """
    # Phase 176: AI narrative section, present only when --ai-report ran.
    ai_section = ""
    try:
        from . import report_ai
        ai_section = report_ai.ai_section_markdown(meta.get("ai_report"))
    except Exception as e:
        _log.debug("ai markdown section build failed: %s", e)

    if not findings:
        return (
            f"# XSSentinel Scan Report\n\n"
            f"**Target:** {target}  \n"
            f"**Generated:** {meta.get('generated', '')}  \n"
            f"**Requests:** {meta.get('requests', 0)}  \n"
            f"**WAF:** {meta.get('waf', 'none detected')}\n\n"
            f"## Results\n\n"
            f"No XSS vulnerabilities found. ✅\n"
            + (f"\n{ai_section}" if ai_section else "")
        )

    # Summary counts.
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for f in findings:
        d = f.data if hasattr(f, "data") else f
        sev = d.get("severity", "info")
        ftype = d.get("type", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_type[ftype] = by_type.get(ftype, 0) + 1

    sev_summary = " · ".join(
        f"**{sev}**: {count}" for sev, count in sorted(by_severity.items())
    )
    type_summary = " · ".join(
        f"`{ftype}`: {count}" for ftype, count in sorted(by_type.items())
    )

    # Summary table.
    lines: list[str] = [
        f"# XSSentinel Scan Report\n",
        f"**Target:** {target}  ",
        f"**Generated:** {meta.get('generated', '')}  ",
        f"**Requests:** {meta.get('requests', 0)}  ",
        f"**WAF:** {meta.get('waf', 'none detected')}  ",
        f"**Findings:** {len(findings)} ({sev_summary})\n",
        f"**By type:** {type_summary}\n",
    ]
    # AI narrative goes right after the summary block, before the raw table:
    # the reader gets the explanation before the evidence dump.
    if ai_section:
        lines.append(ai_section)
    lines.extend([
        f"## Summary Table\n",
        f"| # | Severity | Type | URL | Param | Context |",
        f"|---|----------|------|-----|-------|---------|",
    ])

    for i, f in enumerate(findings, 1):
        d = f.data if hasattr(f, "data") else f
        sev = d.get("severity", "info")
        ftype = d.get("type", "?")
        url = d.get("url", "")
        param = d.get("param") or "-"
        context = d.get("context", "-")
        # Truncate URL for table readability.
        url_short = url if len(url) <= 60 else url[:57] + "..."
        lines.append(
            f"| {i} | {_md_cell(sev)} | {_md_cell(ftype)} | "
            f"`{_md_cell(url_short)}` | "
            f"{_md_cell(param)} | {_md_cell(context)} |"
        )

    # Per-finding detail sections.
    lines.append("\n## Details\n")
    for i, f in enumerate(findings, 1):
        d = f.data if hasattr(f, "data") else f
        sev = d.get("severity", "info")
        ftype = d.get("type", "?")
        url = d.get("url", "")
        method = d.get("method", "GET")
        param = d.get("param") or "(none)"
        context = d.get("context", "-")
        payload = d.get("payload") or ""
        detail = d.get("detail") or d.get("evidence") or ""
        poc = d.get("poc") or {}
        poc_curl = poc.get("curl", "")

        lines.append(f"### {i}. [{sev.upper()}] {ftype} on `{param}`\n")
        lines.append(f"- **URL:** `{url}`")
        lines.append(f"- **Method:** `{method}`")
        lines.append(f"- **Parameter:** `{param}`")
        lines.append(f"- **Context:** `{context}`")
        if payload:
            fence = _md_fence(payload)
            lines.append(f"- **Payload:**")
            lines.append(f"  {fence}")
            lines.append(f"  {payload}")
            lines.append(f"  {fence}")
        if detail:
            lines.append(f"- **Detail:** {_md_cell(detail)}")
        if poc_curl:
            fence = _md_fence(poc_curl)
            lines.append(f"- **PoC (curl):**")
            lines.append(f"  {fence}bash")
            lines.append(f"  {poc_curl}")
            lines.append(f"  {fence}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Phase 49: ecosystem interop -- Burp Suite XML + nuclei YAML templates
# (pentest audit gap: findings were trapped inside XSSentinel's own formats,
# so a consultant could not drop them into a Burp project or re-verify them
# with nuclei.  Both exporters replay the EXACT confirmed request.)
# ---------------------------------------------------------------------------

# Burp XML: extension/custom issue type.  Burp itself uses per-issue-type
# integers; 134217728 is the type emitted for extension-reported issues and
# every major importer (Dradis, nuclei -burpout consumers, ...) keys on the
# <name> element rather than this number, so a single well-known value is the
# interoperable choice for a tool that is not Burp.
_BURP_TYPE_CUSTOM = 134217728

_BURP_SEVERITY = {"critical": "High", "high": "High", "medium": "Medium",
                  "low": "Low", "info": "Information"}
_BURP_CONFIDENCE = {"certain": "Certain", "high": "Certain", "firm": "Firm",
                    "medium": "Firm", "low": "Tentative", "info": "Tentative"}

# Human-readable names for the interop exporters (subset of the SARIF name
# table; unknown types fall back to a readable slug).
_INTEROP_TYPE_NAME = {
    "reflected": "Cross-site scripting (reflected)",
    "stored": "Cross-site scripting (stored)",
    "second_order": "Second-order cross-site scripting",
    "dom": "Cross-site scripting (DOM-based)",
    "dom_dynamic": "Cross-site scripting (DOM-based, browser-confirmed)",
    "blind": "Blind cross-site scripting (out-of-band)",
    "mutation_xss": "Mutation cross-site scripting (mXSS)",
    "dom_clobber": "DOM clobbering cross-site scripting",
    "template_ssti_angularjs": "AngularJS template injection (SSTI)",
    "template_ssti_vue": "Vue template injection (SSTI)",
    "template_ssti": "Server-side template injection (SSTI)",
    "jsonp_xss": "JSONP callback cross-site scripting",
    "jsonpcallback": "JSONP callback cross-site scripting",
    "csp_bypass": "CSP bypass / policy weakness",
    "polyglot_reflection": "Polyglot XSS payload reflection",
    "postmessage_xss": "postMessage cross-site scripting",
    "prototype_pollution": "Prototype-pollution cross-site scripting",
    "service_worker_xss": "Service-worker cross-site scripting",
    "web_worker_xss": "Web-worker cross-site scripting",
    "open_redirect_xss": "Open redirect to cross-site scripting",
    "framework_xss": "Framework DOM cross-site scripting",
    "header_xss": "HTTP header reflection XSS",
    "path_xss": "URL path reflection XSS",
    "cookie_xss": "Cookie reflection cross-site scripting",
    "error_page_xss": "Error-page cross-site scripting",
    "cors_misconfig": "Cross-origin resource sharing (CORS) misconfiguration",
    "xs_leak_surface": "XS-Leaks surface (missing cross-origin isolation)",
    "markdown_xss": "Markdown / BBCode cross-site scripting",
    "time_based_xss": "Time-based XSS (side-channel)",
    "bav": "Adjacent vulnerability confirmed by a BAV probe (SSTI, "
           "open redirect, or CRLF header injection)",
    "upload_xss": "Cross-site scripting via uploaded filename",
    "stored_upload": "Stored cross-site scripting (uploaded file)",
    "fuzzer_triage": "Fuzzer triage (injectable parameter)",
}


def _interop_type_name(ftype: str) -> str:
    """Resolve a finding type to a display name; framework/template subtypes
    (``framework_react_xss``, ...) collapse to their generic family."""
    if ftype in _INTEROP_TYPE_NAME:
        return _INTEROP_TYPE_NAME[ftype]
    if ftype.startswith("framework_"):
        return _INTEROP_TYPE_NAME["framework_xss"]
    if ftype.startswith("template_ssti_"):
        return _INTEROP_TYPE_NAME["template_ssti"]
    return f"{ftype.replace('_', ' ')} (XSS)"


def _finding_dict(f):
    return f.data if hasattr(f, "data") else f


def _cdata(s) -> str:
    """Wrap ``s`` in a CDATA section that cannot be broken by its content.

    An XSS payload may itself contain ``]]>`` (a CDATA terminator used by
    some XML-context payloads); embedding it verbatim would corrupt the
    whole Burp import file.  The standard escape splits the terminator.
    """
    return "<![CDATA[" + str(s).replace("]]>", "]]]]><![CDATA[>") + "]]>"


def _raw_request(d: dict) -> str:
    """Best-effort reconstruction of the original HTTP request that produced
    ``d`` (method, target with the confirmed payload injected at ``param``,
    Host header, and a form/query body).  Faithful enough to replay the
    finding in Burp Repeater / a proxy.

    Phase 56: non-query families travel the way they were confirmed --
    ``(header:X)`` payloads are placed on the request header ``X`` and
    ``(cookie:N)`` payloads in a ``Cookie: N=...`` line, instead of being
    injected into the query string where the origin never saw them."""
    from urllib.parse import urlencode, urlparse

    url = d.get("url") or ""
    method = (d.get("method") or "GET").upper()
    param = d.get("param") or ""
    payload = d.get("payload") or ""
    p = urlparse(url)
    host = p.netloc or ""
    path = p.path or "/"
    # Existing query, with the confirmed parameter overwritten -- EXCEPT for
    # non-query carriers (param "(header:X)" etc.), which never touched the
    # query string in the first place.
    qs = dict(x.split("=", 1) for x in p.query.split("&") if "=" in x)
    hdr_m = _NONQUERY_HEADER_RE.match(param)
    ck_m = _NONQUERY_COOKIE_RE.match(param)
    if not (hdr_m or ck_m) and param:
        qs[param] = payload
    lines = [f"{method} {path}?{urlencode(qs)} HTTP/1.1"
             if qs else f"{method} {path} HTTP/1.1",
             f"Host: {host}"]
    if hdr_m:
        lines.append(f"{hdr_m.group(1)}: {payload}")
    elif ck_m:
        lines.append(f"Cookie: {ck_m.group(1)}={payload}")
    if method in ("POST", "PUT", "PATCH"):
        body = urlencode(qs)
        lines += ["Content-Type: application/x-www-form-urlencoded",
                  f"Content-Length: {len(body)}",
                  "", body]
    else:
        lines += ["", ""]
    return "\r\n".join(lines)


def build_burp_xml(findings: list, target: str, meta: dict) -> str:
    """Burp Suite "Export issue data" XML (``<issues>``) for import into Burp
    projects / Dradis / other report frameworks.

    Mirrors the interchange schema consumers expect: every finding becomes an
    ``<issue>`` with serialNumber (stable per url+type+param so re-exports
    dedup), the extension issue type 134217728, a precise name, host/path/
    location split the way Burp does it (path WITHOUT the query string),
    severity/confidence in Burp's vocabulary, a base64-encoded reconstructed
    request, and CWE-79 classification.  The evidence excerpt is embedded as
    the (base64) response so a reviewer sees what echoed.
    """
    from datetime import datetime
    import base64
    import hashlib
    from urllib.parse import urlparse

    export_time = meta.get("generated") or datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S")
    issues = []
    for f in findings:
        d = _finding_dict(f)
        url = d.get("url") or target
        ftype = d.get("type", "reflected")
        param = d.get("param") or ""
        payload = d.get("payload") or ""
        sev = _BURP_SEVERITY.get(d.get("severity", "info"), "Information")
        conf = _BURP_CONFIDENCE.get(
            d.get("confidence", "medium"), "Tentative")
        p = urlparse(url)
        host = f"{p.scheme}://{p.netloc}"
        path = p.path or "/"
        loc = path
        if param:
            loc = f"{path}?{param}="  # entry point marker (no payload)
        ser = int(hashlib.md5(
            f"{url}|{ftype}|{param}".encode("utf-8")).hexdigest()[:15], 16)
        req_raw = _raw_request(d).encode("utf-8")
        req_b64 = base64.b64encode(req_raw).decode("ascii")
        # Burp's evidence pane wants the PROVING TEXT, not a tier label.  The
        # sync scanner keeps that in `proof["snippet"]` (the reflected markup
        # around the payload) and never set `evidence`, so this export used to
        # ship an empty response body for exactly the findings whose reflection
        # we verified.
        _pr = d.get("proof")
        evidence = (d.get("evidence")
                    or (_pr.get("snippet") if isinstance(_pr, dict) else "")
                    or "")
        resp_b64 = ""
        if evidence:
            resp_b64 = base64.b64encode(
                evidence.encode("utf-8")).decode("ascii")
        detail = (d.get("detail") or "").strip()
        if not detail:
            detail = f"{ftype} in {d.get('context', 'unknown')} context"
        transforms = ",".join(d.get("transform") or [])
        if transforms:
            detail += f" (transform ladder: {transforms})"
        poc = d.get("poc") or {}
        # Precompute every CDATA payload so the f-string below contains NO
        # backslash / nested-f-string inside an expression part (Python 3.9
        # forbids both).
        bg = ("Cross-site scripting (XSS) allows an attacker to inject "
              "client-side script into pages viewed by other users. This "
              "finding was confirmed by XSSentinel (payload reflection "
              "verified in an executable context).")
        remed_bg = ("Validate input on arrival and encode all output for the "
                    "context it is written into (HTML entity / attribute / "
                    "JS / CSS as appropriate). See the OWASP XSS Prevention "
                    "Cheat Sheet.")
        detail_body = "\n".join([
            "Type: " + ftype, "Parameter: " + param,
            "Context: " + str(d.get("context", "n/a")),
            "Method: " + str(d.get("method", "GET")),
            "Payload: " + payload, "Evidence: " + evidence,
            "Detail: " + detail])
        remed_detail = ("Re-run the confirmed payload (see PoC below) after "
                        "applying output encoding; the request is reproduced "
                        "by the embedded request message.")
        issues.append(
            f"""  <issue>
    <serialNumber>{ser}</serialNumber>
    <type>{_BURP_TYPE_CUSTOM}</type>
    <name>{_esc(_interop_type_name(ftype))}</name>
    <host>{_esc(host)}</host>
    <path>{_cdata(path)}</path>
    <location>{_cdata(loc)}</location>
    <severity>{sev}</severity>
    <confidence>{conf}</confidence>
    <issueBackground>{_cdata(bg)}</issueBackground>
    <remediationBackground>{_cdata(remed_bg)}</remediationBackground>
    <issueDetail>{_cdata(detail_body)}</issueDetail>
    <remediationDetail>{_cdata(remed_detail)}</remediationDetail>
    <vulnerabilityClassifications>{_cdata("CWE-79")}</vulnerabilityClassifications>
    <references>{_cdata("https://owasp.org/www-community/attacks/xss/")}</references>
    <request base64="true">{req_b64}</request>""" + (
        f'\n    <response base64="true">{resp_b64}</response>' if resp_b64
        else "") + "\n  </issue>")
    body = "\n".join(issues) if issues else ""
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<issues burpVersion="2.1" exportTime="{_esc(export_time)}">\n'
            f'{body}\n'
            f'</issues>\n')


# Marker tokens (xssm_1a2b, xssp_, xssup_, q_-style overrides, ...) are
# random per probe, but a finding stores the EXACT payload that produced its
# echo, and a nuclei template replays that payload -- request and matcher
# therefore share the same token and stay self-consistent.  Skeleton
# normalisation is only a fallback for oversized payloads (where a word the
# server may trim is matched on its stable markup core).
_MARKER_TOKEN_RE = re.compile(r"(?:xss[a-z]*_|xserr_|xssup_)[0-9a-f]{2,}", re.I)

# Findings whose confirmation travels OUTSIDE the query string encode the
# carrier in the param marker: "(header:User-Agent)", "(cookie:sid)",
# "(path)", "(error_path)".  The nuclei exporter must replay those through
# the right transport (a request header / Cookie / percent-encoded path)
# instead of injecting the marker into a query parameter -- a header XSS
# replayed as "?%28header..." can never match anything.
_NONQUERY_HEADER_RE = re.compile(r"^\(header:([^)]+)\)$", re.I)
_NONQUERY_COOKIE_RE = re.compile(r"^\(cookie:([^)]+)\)$", re.I)


def _matcher_skeleton(payload: str) -> str:
    """A stable substring of ``payload`` that survives marker-token churn."""
    if not payload:
        return "xssentinel"
    stable = _MARKER_TOKEN_RE.sub("XSSENTINEL", payload)
    return stable if len(stable) <= 80 else stable[:80]


def _nuclei_slug(s: str) -> str:
    """nuclei-safe id fragment (lowercase [a-z0-9-])."""
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "xss"


def _nuclei_severity(sev: str) -> str:
    return sev if sev in ("critical", "high", "medium", "low", "info") \
        else "info"


def _request_target(d: dict) -> tuple[str, dict]:
    """Return (path, query-dict) with the confirmed payload placed at param.
    Used to rebuild a runnable nuclei request from a finding."""
    from urllib.parse import urlparse

    p = urlparse(d.get("url") or "")
    qs = {}
    if p.query:
        for pair in p.query.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                qs.setdefault(k, v)  # keep first like the original send
    param = d.get("param") or ""
    if param:
        qs[param] = d.get("payload") or ""
    return (p.path or "/", qs)


def _nuclei_template(f: dict, target: str) -> dict:
    """Build ONE nuclei YAML template string for a finding.  Returns
    {"id": ..., "yaml": ...}."""
    import hashlib
    from urllib.parse import urlencode

    d = _finding_dict(f)
    ftype = d.get("type", "reflected")
    param = d.get("param") or ""
    payload = d.get("payload") or ""
    method = (d.get("method") or "GET").upper()
    url = d.get("url") or target
    path, qs = _request_target(d)
    sev = _nuclei_severity(d.get("severity", "info"))
    tname = _interop_type_name(ftype)
    skeleton = _matcher_skeleton(payload)
    stem = hashlib.md5(f"{url}|{param}|{ftype}".encode("utf-8")).hexdigest()[:10]
    tid = f"xssentinel-{_nuclei_slug(ftype)}-{stem}"
    detail = (d.get("detail") or f"{tname} confirmed by XSSentinel").strip()
    # Findings whose confirmation lives OUTSIDE the response body cannot be
    # re-verified by a plain HTTP body matcher -- blind (OOB beacon) and
    # cors_misconfig (response-header grant) findings are emitted as
    # documentation templates (no false-positive risk when run).
    is_upload = ftype in ("upload_xss", "stored_upload")
    is_ob = ftype in ("blind",)
    # Phase 85: placeholder payloads ("(SRI: ...)", "(postMessage listener)",
    # ...) are not runnable HTTP attacks -- export as documentation
    # templates instead of polluting the nuclei directory with
    # never-matching bodies (same guard verify_fix applies).
    if payload.startswith("(") and payload.endswith(")"):
        is_ob = True
    is_doc = is_ob or ftype in ("cors_misconfig", "xs_leak_surface")
    doc_tag = ("oob" if is_ob
               else "cors" if ftype == "cors_misconfig"
               else "xsleak" if ftype == "xs_leak_surface" else "")

    header = [
        f"id: {tid}",
        "info:",
        f"  name: {_yaml_dq(tname)}",
        "  author: XSSentinel",
        f"  severity: {sev}",
        f"  description: {_yaml_dq(detail)}",
        "  reference:",
        "    - https://owasp.org/www-community/attacks/xss/",
        "  tags: xss,xssentinel" + (f",{doc_tag}" if doc_tag else ""),
    ]
    if is_doc:
        return {"id": tid, "yaml": "\n".join(header) + "\n"}

    # --- request block -----------------------------------------------------
    lines: list[str] = []
    if is_upload:
        field = param.split("[")[0] if "[" in param else param
        # Reproduce the multipart the live probe sent (requests ``files=``):
        # the Content-Type boundary is the bare token and every body
        # delimiter is ``--<token>``.  (A previous draft wrote
        # ``------<dashed-token>`` -- 10 dashes -- which no server parser
        # recognises, so the replayed upload silently did nothing.)
        boundary = "xssentinelb"
        dash = "--" + boundary
        body = (f"{dash}\r\n"
                f'Content-Disposition: form-data; name="{field}"; '
                f'filename="{payload}"\r\n'
                "Content-Type: text/plain\r\n\r\n"
                "xssentinel upload probe\r\n"
                f"{dash}--")
        # The closing delimiter ends the body; Content-Length counts exactly
        # the bytes after the header blank line (no trailing CRLF, so the
        # block scalar round-trips byte-for-byte).
        raw_text = (f"POST {path} HTTP/1.1\r\n"
                    "Host: {{Hostname}}\r\n"
                    f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                    f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                    "\r\n" + body)
        lines += ["http:",
                  "  - raw:",
                  "      - |"]
        for ln in raw_text.split("\r\n"):
            # Empty raw lines stay empty inside the literal block (padding
            # them with spaces would corrupt the HTTP blank-line delimiter).
            lines.append(f"        {ln}" if ln else "")
    _hdr = _NONQUERY_HEADER_RE.match(param or "")
    _ck = _NONQUERY_COOKIE_RE.match(param or "")
    if _hdr or _ck:
        # Header / cookie replay: the payload must travel in a request
        # header (or Cookie), NOT a query parameter.
        from urllib.parse import quote, urlparse as _u
        m = _hdr or _ck
        carrier_name = m.group(1)
        p0 = _u(url)
        target0 = p0.path or "/"
        if p0.query:
            target0 += "?" + p0.query
        if _hdr:
            carrier_line = f"{carrier_name}: {payload}"
        else:
            carrier_line = f"Cookie: {carrier_name}={payload}"
        raw_text = (f"{method} {target0} HTTP/1.1\r\n"
                    "Host: {{Hostname}}\r\n"
                    f"{carrier_line}\r\n"
                    "\r\n")
        lines += ["http:",
                  "  - raw:",
                  "      - |"]
        for ln in raw_text.split("\r\n"):
            lines.append(f"        {ln}" if ln else "")
    elif (param or "").startswith("(") or \
            ftype in ("path_xss", "error_page_xss"):
        # Path / error-page replay: the payload rides in the URL PATH (the
        # finding URL already carries it).  Percent-encode the path exactly
        # like the wire did; the server decodes it back and echoes the
        # payload, which the matcher word then confirms.
        from urllib.parse import quote, urlparse as _u
        p0 = _u(url)
        enc_path = quote(p0.path or "/", safe="/:@-._~!$&'()*+,;=%")
        target0 = enc_path + (f"?{p0.query}" if p0.query else "")
        raw_text = (f"{method} {target0} HTTP/1.1\r\n"
                    "Host: {{Hostname}}\r\n"
                    "\r\n")
        lines += ["http:",
                  "  - raw:",
                  "      - |"]
        for ln in raw_text.split("\r\n"):
            lines.append(f"        {ln}" if ln else "")
    elif method == "POST":
        # Form body: CSRF/hidden fields ride along when recorded.
        body_pairs = dict(d.get("csrf_fields") or {})
        body_pairs[param] = payload
        body_qs = urlencode(body_pairs)
        lines += ["http:",
                  "  - method: POST",
                  f"    path:\n      - \"{{{{BaseURL}}}}{path}\"",
                  "    headers:",
                  "      Content-Type: application/x-www-form-urlencoded",
                  f"    body: {_yaml_dq(body_qs)}"]
    else:
        url_with_q = urlencode(qs)
        target_line = f"{path}?{url_with_q}" if url_with_q else path
        lines += ["http:",
                  "  - method: GET",
                  f"    path:\n      - \"{{{{BaseURL}}}}{target_line}\""]
    # --- matcher -----------------------------------------------------------
    # The template replays the EXACT stored payload, so the matcher word is
    # that payload verbatim: the echo of a still-vulnerable target contains
    # the same marker token the request carries (normalising the token away,
    # as an early draft did, makes the word never match the actual echo).
    # Only oversized payloads fall back to a token-stable skeleton.
    word = payload if len(payload) <= 200 else skeleton
    lines += ["    matchers-condition: and",
              "    matchers:",
              "      - type: word",
              "        part: body",
              "        words:",
              f"          - {_yaml_dq(word)}"]
    return {"id": tid, "yaml": "\n".join(header) + "\n"
            + "\n".join(lines) + "\n"}


def _yaml_dq(s: str) -> str:
    """Render ``s`` as a safe double-quoted YAML scalar (JSON-style
    escaping is valid YAML)."""
    return json.dumps(s, ensure_ascii=False)


def build_nuclei_yaml(findings: list, target: str, meta: dict) -> str:
    """Render every finding as nuclei YAML templates (``---`` separated).
    Useful for the API / embedding; the CLI path writes one file per template
    into a directory via :func:`write_nuclei_dir`."""
    parts = []
    for f in findings:
        t = _nuclei_template(f, target)
        parts.append(t["yaml"])
    return "\n---\n".join(parts)


def _slug(text: str) -> str:
    """Filesystem-safe stem for a PoC artifact (Phase 139)."""
    import re as _re
    s = _re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")
    return (s or "finding")[:60]


def write_poc_dir(findings: list, target: str, meta: dict,
                  out_dir: str) -> list[str]:
    """Write one runnable PoC artifact per finding into ``out_dir``.

    Phase 139 -- "reproducible PoC" was half-built: ``poc.build_poc()`` has
    produced curl/URL/HTML PoCs for a long time (and Phase 135 even RUNS
    them for verification), but nothing ever wrote them to disk --
    ``replay.write_poc_file()`` existed and had **zero callers**.  A PoC you
    cannot hand to a human, or open in a browser, is not reproducible.

    Per finding:
      * ``<stem>.html`` -- self-contained page (GET: direct URL / POST:
        auto-submitting form / DOM XSS: hash or search carrier);
      * ``<stem>.sh``   -- the curl replay for the same finding;
      * ``INDEX.md``    -- one row per finding (type, severity, verified,
        param, artifacts) so a directory of 40 files stays navigable.

    Findings without a PoC (audit-style observations such as a missing
    header) are skipped AND counted in the index: silence there would look
    like a bug.
    """
    import os

    os.makedirs(out_dir, exist_ok=True)
    seen: dict[str, int] = {}
    written: list[str] = []
    rows: list[str] = []
    skipped = 0

    for f in findings:
        data = f.get("data", f) if isinstance(f, dict) else {}
        poc = data.get("poc") or {}
        html = poc.get("html") or ""
        curl = poc.get("curl") or ""
        if not html and not curl:
            skipped += 1
            continue
        base = _slug(str(data.get("type") or "finding"))
        n = seen.get(base, 0)
        seen[base] = n + 1
        stem = f"{base}-{n + 1}" if n else base
        links = []
        if html:
            path = os.path.join(out_dir, stem + ".html")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(html)
            written.append(path)
            links.append(f"[`{stem}.html`]({stem}.html)")
        if curl:
            path = os.path.join(out_dir, stem + ".sh")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\n"
                         "# Auto-generated PoC replay (XSSentinel).\n"
                         + curl + "\n")
            written.append(path)
            links.append(f"[`{stem}.sh`]({stem}.sh)")
        rows.append("| {t} | {s} | {v} | `{p}` | {a} |".format(
            t=str(data.get("type") or "-"),
            s=str(data.get("severity") or "-"),
            v="yes" if data.get("poc_verified") else "no",
            p=str(data.get("param") or "-"),
            a=", ".join(links)))

    index = [
        "# PoC artifacts",
        "",
        f"- target: `{target}`",
        f"- generated: {meta.get('generated', '-')}",
        f"- findings: {len(findings)} "
        f"(with PoC: {len(rows)}, without: {skipped})",
        "",
        "| type | severity | verified | param | artifacts |",
        "|---|---|---|---|---|",
    ] + rows
    if skipped:
        index += ["",
                  f"{skipped} finding(s) carry no PoC (audit-style "
                  f"observations, e.g. a missing header) -- expected."]
    idx = os.path.join(out_dir, "INDEX.md")
    with open(idx, "w", encoding="utf-8") as fh:
        fh.write("\n".join(index) + "\n")
    written.append(idx)
    return written


def write_nuclei_dir(findings: list, target: str, meta: dict,
                     out_dir: str) -> list[str]:
    """Write one nuclei template per finding into ``out_dir`` (created if
    missing).  Returns the written file paths.  Empty findings => empty dir."""
    import os

    os.makedirs(out_dir, exist_ok=True)
    seen: dict[str, int] = {}
    written = []
    for f in findings:
        t = _nuclei_template(f, target)
        tid = t["id"]
        n = seen.get(tid, 0)
        seen[tid] = n + 1
        fname = f"{tid}-{n + 1}.yaml" if n else f"{tid}.yaml"
        path = os.path.join(out_dir, fname)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(t["yaml"])
        written.append(path)
    return written
