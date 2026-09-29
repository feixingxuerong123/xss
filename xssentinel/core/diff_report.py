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
    """Load a JSON scan report and return its findings list.

    Phase 105: this used to be ``data.get("findings", [])`` -- feed it
    anything else (a benchmark result with ``cases[]``, an unrelated
    JSON, a report from another tool) and it silently returned [] , so
    --diff cheerfully reported "0 new, 0 fixed, 0 regressed" and a build
    passed on a comparison that never happened.  A re-test report saying
    "nothing changed" when it read nothing is worse than an error, so
    the shape is now validated and wrong input fails loudly.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(
            f"{path}: expected a JSON object at the top level, got "
            f"{type(data).__name__}")
    if "findings" in data:
        findings = data["findings"]
        if not isinstance(findings, list):
            raise ValueError(
                f"{path}: 'findings' must be a list, got "
                f"{type(findings).__name__}")
        return findings
    # The realistic mistake: benchmark/results/*.json carries case
    # verdicts under "cases", not findings.
    if "cases" in data and isinstance(data["cases"], list):
        raise ValueError(
            f"{path}: this looks like a BENCHMARK RESULT (cases[]), not a "
            "scan report (findings[]).  --diff compares two SCAN reports "
            "(the JSON produced by -o), not benchmark runs.")
    raise ValueError(
        f"{path}: no 'findings' array -- not an XSSentinel scan report "
        "(keys: " + ", ".join(sorted(data)[:6]) + ")")


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

    # Diff-specific chrome on top of the shared theme: regressed row
    # highlight + dashed empty-state panel.
    from .report_theme import (BRAND_SVG, base_css, interactive_js,
                               theme_boot_script, theme_toggle_button)
    _extra_css = """
 .regressed-detail td{background:var(--sev-med-weak)}
 .empty{padding:22px;text-align:center;color:var(--text-faint);
        background:var(--surface);border:1px dashed var(--border-strong);
        border-radius:10px;font-size:13px}
 .table-wrap{max-height:none}
"""
    return f"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>XSSentinel Diff Report — {target or 'scan'}</title>
{theme_boot_script()}
<style>{base_css(_extra_css)}</style>
</head>
<body>
<header>
  <h1>{BRAND_SVG}XSSentinel &mdash; Diff Report
    <span class="verdict {ci_class}">CI: {ci_verdict}</span>
  </h1>
  <div class="head-tools">{theme_toggle_button()}</div>
  <div class="meta">Target: {_esc(target)} · Baseline: {_esc(baseline_label)} → Current: {_esc(current_label)}</div>
</header>
<div class="summary">
  <div class="card new"><div class="n">{s['new']}</div><div class="lbl">New</div></div>
  <div class="card regressed"><div class="n">{s['regressed']}</div><div class="lbl">Regressed</div></div>
  <div class="card fixed"><div class="n">{s['fixed']}</div><div class="lbl">Fixed</div></div>
  <div class="card unchanged"><div class="n">{s['unchanged']}</div><div class="lbl">Unchanged</div></div>
</div>

<section>
  <h2>New Findings ({s['new']})</h2>
  {'<div class="table-wrap"><table><thead><tr><th>Type</th><th>URL</th><th>Param</th><th>Context</th><th>Severity</th><th>Payload</th></tr></thead><tbody>' + new_rows + '</tbody></table></div>' if new_rows else '<div class="empty">No new findings — no new XSS issues introduced since the baseline.</div>'}
</section>

<section>
  <h2>Regressed Findings ({s['regressed']})</h2>
  {'<div class="table-wrap"><table><thead><tr><th>Type</th><th>URL</th><th>Param</th><th>Context</th><th>Severity</th><th>Payload</th></tr></thead><tbody>' + reg_rows + '</tbody></table></div>' if reg_rows else '<div class="empty">No regressions — no existing issue got worse.</div>'}
</section>

<section>
  <h2>Fixed Findings ({s['fixed']})</h2>
  {'<div class="table-wrap"><table><thead><tr><th>Type</th><th>URL</th><th>Param</th><th>Context</th><th>Severity</th><th>Payload</th></tr></thead><tbody>' + fixed_rows + '</tbody></table></div>' if fixed_rows else '<div class="empty">No fixes — no baseline issue was resolved in this run.</div>'}
</section>

<footer>Generated by XSSentinel Diff Report. CI verdict is PASS only when
both new and regressed counts are zero.</footer>
{interactive_js()}
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
