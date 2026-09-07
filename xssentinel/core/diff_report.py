"""Diff report generator (Phase 14c).

Compares two scan reports (a baseline and a current run) and produces a
diff report showing:
  * NEW findings       -- present in current but not in baseline
  * FIXED findings     -- present in baseline but not in current
  * UNCHANGED findings -- present in both (unchanged severity)
  * REGRESSED findings -- present in both but severity increased

This is essential for CI/CD pipelines where you want to FAIL the build
only when NEW XSS issues are introduced, not when pre-existing issues
remain unchanged.

The diff is based on the finding's "identity key":
    (type, normalized_url, param, context)

Two findings with the same key are considered the SAME issue.  Severity
changes within the same key are reported as REGRESSED (worse) or
IMPROVED (better).
"""
from __future__ import annotations
import json


def _norm_url(url: str) -> str:
    """Normalize a URL for comparison: strip fragment, default port,
    lowercase scheme+host.  Query string is kept but not sorted."""
    from urllib.parse import urlparse, urlunparse
    if not url:
        return ""
    p = urlparse(url)
    scheme = p.scheme.lower()
    netloc = p.netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    return urlunparse((scheme, netloc, p.path or "/", p.params, p.query, ""))


def _finding_key(d: dict) -> tuple:
    """Identity key for a finding.  Two findings with the same key are
    considered the same issue."""
    return (
        d.get("type", ""),
        _norm_url(d.get("url", "")),
        d.get("param") or "",
        d.get("context") or "",
    )


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(s: str) -> int:
    return _SEVERITY_RANK.get((s or "info").lower(), 0)


def load_report(path: str) -> list[dict]:
    """Load a JSON scan report and return its findings list."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("findings", [])


def diff_findings(baseline: list[dict],
                  current: list[dict]) -> dict:
    """Compute the diff between baseline and current findings.

    Returns a dict with keys:
        "new":        list of finding dicts (present in current, not baseline)
        "fixed":      list of finding dicts (present in baseline, not current)
        "unchanged":  list of (baseline, current) tuples (same key, same severity)
        "regressed":  list of (baseline, current) tuples (same key, worse severity)
        "improved":   list of (baseline, current) tuples (same key, better severity)
        "summary":    dict with counts
    """
    baseline_by_key: dict = {}
    for f in baseline:
        d = f.data if hasattr(f, "data") else f
        baseline_by_key[_finding_key(d)] = d
    current_by_key: dict = {}
    for f in current:
        d = f.data if hasattr(f, "data") else f
        current_by_key[_finding_key(d)] = d

    new_findings: list = []
    fixed_findings: list = []
    unchanged: list = []
    regressed: list = []
    improved: list = []

    # New = in current, not in baseline.
    for key, d in current_by_key.items():
        if key not in baseline_by_key:
            new_findings.append(d)
        else:
            b = baseline_by_key[key]
            bsev = _severity_rank(b.get("severity"))
            csev = _severity_rank(d.get("severity"))
            if csev > bsev:
                regressed.append((b, d))
            elif csev < bsev:
                improved.append((b, d))
            else:
                unchanged.append((b, d))

    # Fixed = in baseline, not in current.
    for key, d in baseline_by_key.items():
        if key not in current_by_key:
            fixed_findings.append(d)

    return {
        "new": new_findings,
        "fixed": fixed_findings,
        "unchanged": unchanged,
        "regressed": regressed,
        "improved": improved,
        "summary": {
            "baseline_total": len(baseline),
            "current_total": len(current),
            "new": len(new_findings),
            "fixed": len(fixed_findings),
            "unchanged": len(unchanged),
            "regressed": len(regressed),
            "improved": len(improved),
        },
    }


def diff_report_html(baseline: list[dict],
                     current: list[dict],
                     target: str = "",
                     baseline_label: str = "baseline",
                     current_label: str = "current") -> str:
    """Render the diff as a standalone HTML report.

    The report has four sections:
      1. Summary cards (new / fixed / regressed / unchanged counts).
      2. New findings table (the ones that would FAIL a CI build).
      3. Regressed findings table (also FAILs a CI build).
      4. Fixed findings table (informational).
    """
    diff = diff_findings(baseline, current)
    s = diff["summary"]

    def _esc(x):
        import html as _h
        return _h.escape(str(x)) if x is not None else ""

    def _row(d, extra=""):
        return (
            f"<tr{extra}><td>{_esc(d.get('type'))}</td>"
            f"<td>{_esc(d.get('url'))}</td>"
            f"<td>{_esc(d.get('param'))}</td>"
            f"<td>{_esc(d.get('context'))}</td>"
            f"<td>{_esc(d.get('severity'))}</td>"
            f"<td><code>{_esc(d.get('payload'))}</code></td></tr>"
        )

    new_rows = "".join(_row(d) for d in diff["new"])
    reg_rows = "".join(
        _row(b) + _row(c, ' class="regressed-detail"')
        for b, c in diff["regressed"])
    fixed_rows = "".join(_row(d) for d in diff["fixed"])

    # CI verdict: FAIL if any new or regressed findings.
    ci_verdict = "PASS" if (s["new"] == 0 and s["regressed"] == 0) else "FAIL"
    ci_class = "pass" if ci_verdict == "PASS" else "fail"

    return f"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<title>XSSentinel Diff Report — {target or 'scan'}</title>
<style>
 body {{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7fb;color:#1f2430}}
 header {{background:#1f2430;color:#fff;padding:20px 28px}}
 header h1 {{margin:0;font-size:20px}}
 .meta {{color:#9aa3b2;font-size:13px;margin-top:4px}}
 .verdict {{display:inline-block;padding:6px 14px;border-radius:6px;font-weight:700;font-size:14px;margin-left:12px}}
 .verdict.pass {{background:#3bb273;color:#fff}}
 .verdict.fail {{background:#e5484d;color:#fff}}
 .summary {{display:flex;gap:14px;padding:18px 28px;flex-wrap:wrap}}
 .card {{background:#fff;border-radius:10px;padding:14px 18px;box-shadow:0 1px 3px rgba(0,0,0,.08);min-width:120px}}
 .card .n {{font-size:26px;font-weight:700}}
 .card.new .n {{color:#e5484d}}
 .card.fixed .n {{color:#3bb273}}
 .card.regressed .n {{color:#f5a623}}
 .card.unchanged .n {{color:#9aa3b2}}
 section {{padding:0 28px 24px}}
 section h2 {{font-size:16px;margin:0 0 10px}}
 table {{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08);border-radius:8px;overflow:hidden}}
 th,td {{padding:9px 10px;border-bottom:1px solid #eef0f4;font-size:12px;text-align:left;vertical-align:top}}
 th {{background:#f0f2f7}}
 code {{background:#f3f4f8;padding:2px 4px;border-radius:4px;word-break:break-all}}
 .regressed-detail {{background:#fff8e1}}
 .empty {{padding:20px;text-align:center;color:#9aa3b2}}
 footer {{padding:14px 28px;color:#9aa3b2;font-size:12px}}
</style></head>
<body>
<header>
  <h1>XSSentinel Diff Report
    <span class="verdict {ci_class}">CI: {ci_verdict}</span>
  </h1>
  <div class="meta">Target: {_esc(target)} · Baseline: {_esc(baseline_label)} → Current: {_esc(current_label)}</div>
</header>
<div class="summary">
  <div class="card new"><div class="n">{s['new']}</div><div>New</div></div>
  <div class="card regressed"><div class="n">{s['regressed']}</div><div>Regressed</div></div>
  <div class="card fixed"><div class="n">{s['fixed']}</div><div>Fixed</div></div>
  <div class="card unchanged"><div class="n">{s['unchanged']}</div><div>Unchanged</div></div>
</div>

<section>
  <h2>New Findings ({s['new']})</h2>
  {'<table><thead><tr><th>Type</th><th>URL</th><th>Param</th><th>Context</th><th>Severity</th><th>Payload</th></tr></thead><tbody>' + new_rows + '</tbody></table>' if new_rows else '<div class="empty">No new findings — no new XSS issues introduced since the baseline.</div>'}
</section>

<section>
  <h2>Regressed Findings ({s['regressed']})</h2>
  {'<table><thead><tr><th>Type</th><th>URL</th><th>Param</th><th>Context</th><th>Severity</th><th>Payload</th></tr></thead><tbody>' + reg_rows + '</tbody></table>' if reg_rows else '<div class="empty">No regressions — no existing issue got worse.</div>'}
</section>

<section>
  <h2>Fixed Findings ({s['fixed']})</h2>
  {'<table><thead><tr><th>Type</th><th>URL</th><th>Param</th><th>Context</th><th>Severity</th><th>Payload</th></tr></thead><tbody>' + fixed_rows + '</tbody></table>' if fixed_rows else '<div class="empty">No fixes — no baseline issue was resolved in this run.</div>'}
</section>

<footer>Generated by XSSentinel Diff Report. CI verdict is PASS only when
both new and regressed counts are zero.</footer>
</body></html>"""


def diff_report_json(baseline: list[dict],
                     current: list[dict],
                     target: str = "",
                     baseline_label: str = "baseline",
                     current_label: str = "current") -> str:
    """Render the diff as JSON (for CI/CD programmatic consumption)."""
    diff = diff_findings(baseline, current)
    out = {
        "tool": "XSSentinel",
        "target": target,
        "baseline_label": baseline_label,
        "current_label": current_label,
        "summary": diff["summary"],
        "ci_verdict": "PASS" if (diff["summary"]["new"] == 0
                                 and diff["summary"]["regressed"] == 0) else "FAIL",
        "new": diff["new"],
        "fixed": diff["fixed"],
        "regressed": [
            {"baseline": b, "current": c}
            for b, c in diff["regressed"]
        ],
        "improved": [
            {"baseline": b, "current": c}
            for b, c in diff["improved"]
        ],
    }
    return json.dumps(out, ensure_ascii=False, indent=2)
