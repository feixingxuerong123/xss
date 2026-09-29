#!/usr/bin/env python
"""XSSentinel Benchmark Report Generator.

Reads benchmark result JSON files and produces:
  - JSON summary (machine-readable, for CI integration)
  - HTML report (human-readable, with tables and breakdowns)

Usage:
    python benchmark/report.py results/benchmark_XXXX.json
    python benchmark/report.py --latest   # pick the newest result file
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_RESULTS_DIR = _HERE / "results"

# Standalone script -> make the repo root importable so the shared report
# theme (one design system for every XSSentinel HTML deliverable) resolves
# no matter the caller's cwd.
_REPO_ROOT = _HERE.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from xssentinel.core.report_theme import (BRAND_SVG, base_css, interactive_js,  # noqa: E402
                                          theme_boot_script, theme_toggle_button)


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------

def compute_bucket_metrics(stats: dict) -> dict:
    """Compute recall/precision/fpr for a bucket of TP/FP/TN/FN counts."""
    tp = stats.get("tp", 0)
    fp = stats.get("fp", 0)
    tn = stats.get("tn", 0)
    fn = stats.get("fn", 0)
    total = tp + fp + tn + fn
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    fpr = fp / (fp + tn) if (fp + tn) > 0 else None
    return {
        "total": total,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": round(recall, 4) if recall is not None else None,
        "precision": round(precision, 4) if precision is not None else None,
        "fpr": round(fpr, 4) if fpr is not None else None,
    }


def summarize_result(data: dict) -> dict:
    """Produce a compact summary dict from a full benchmark result."""
    summary = {
        "tool": data.get("tool", "XSSentinel"),
        "timestamp": data.get("timestamp", ""),
        "total_cases": data.get("total_cases", 0),
        "total_time_s": data.get("total_time_s", 0),
        "metrics": {
            "tp": data.get("tp", 0),
            "fp": data.get("fp", 0),
            "tn": data.get("tn", 0),
            "fn": data.get("fn", 0),
            "recall": data.get("recall", 0),
            "precision": data.get("precision", 0),
            "fpr": data.get("fpr", 0),
            "f1": data.get("f1", 0),
        },
        "by_context": {},
        "by_difficulty": {},
        "fp_count": len(data.get("false_positives", [])),
        "fn_count": len(data.get("false_negatives", [])),
    }
    for ctx, stats in data.get("by_context", {}).items():
        summary["by_context"][ctx] = compute_bucket_metrics(stats)
    for diff, stats in data.get("by_difficulty", {}).items():
        summary["by_difficulty"][diff] = compute_bucket_metrics(stats)
    return summary


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def _pct(v) -> str:
    """Format a ratio as percentage string."""
    if v is None:
        return "N/A"
    return f"{v:.1%}"


def generate_html(data: dict) -> str:
    """Generate a full HTML report from benchmark result data."""
    tp = data.get("tp", 0)
    fp = data.get("fp", 0)
    tn = data.get("tn", 0)
    fn = data.get("fn", 0)
    recall = data.get("recall", 0)
    precision = data.get("precision", 0)
    fpr = data.get("fpr", 0)
    f1 = data.get("f1", 0)
    total_time = data.get("total_time_s", 0)
    total_cases = data.get("total_cases", 0)
    timestamp = data.get("timestamp", "")

    fps = data.get("false_positives", [])
    fns = data.get("false_negatives", [])

    # Build context table rows
    ctx_rows = ""
    for ctx, stats in sorted(data.get("by_context", {}).items()):
        m = compute_bucket_metrics(stats)
        ctx_rows += (
            f"<tr><td>{ctx}</td><td>{m['total']}</td>"
            f"<td>{m['tp']}</td><td>{m['fp']}</td>"
            f"<td>{m['tn']}</td><td>{m['fn']}</td>"
            f"<td>{_pct(m['recall'])}</td><td>{_pct(m['fpr'])}</td></tr>\n")

    # Build difficulty table rows
    diff_rows = ""
    for diff in ["easy", "medium", "hard"]:
        stats = data.get("by_difficulty", {}).get(diff)
        if not stats:
            continue
        m = compute_bucket_metrics(stats)
        diff_rows += (
            f"<tr><td>{diff}</td><td>{m['total']}</td>"
            f"<td>{m['tp']}</td><td>{m['fp']}</td>"
            f"<td>{m['tn']}</td><td>{m['fn']}</td>"
            f"<td>{_pct(m['recall'])}</td><td>{_pct(m['fpr'])}</td></tr>\n")

    # FP detail rows
    fp_rows = ""
    for item in fps:
        details = item.get("note", [])
        detail_str = ""
        if isinstance(details, list) and details:
            d = details[0]
            detail_str = f"{d.get('payload', '')[:60]} ({d.get('context', '')})"
        fp_rows += (
            f"<tr class='fp'><td>{item['id']}</td>"
            f"<td>{item.get('mode', '')}</td>"
            f"<td>{item.get('context', '')}</td>"
            f"<td class='detail'>{detail_str}</td></tr>\n")

    # FN detail rows
    fn_rows = ""
    for item in fns:
        fn_rows += (
            f"<tr class='fn'><td>{item['id']}</td>"
            f"<td>{item.get('mode', '')}</td>"
            f"<td>{item.get('context', '')}</td>"
            f"<td>{item.get('difficulty', '')}</td></tr>\n")

    # Quality verdict
    if fpr <= 0.05 and recall >= 0.90:
        verdict = "EXCELLENT"
        verdict_class = "pass"
    elif fpr <= 0.10 and recall >= 0.80:
        verdict = "GOOD"
        verdict_class = "pass"
    elif fpr <= 0.20 and recall >= 0.60:
        verdict = "NEEDS IMPROVEMENT"
        verdict_class = "warn"
    else:
        verdict = "POOR"
        verdict_class = "fail"

    # Benchmark-specific chrome on top of the shared theme: a centered
    # document layout, metric cards, bordered tables, FP/FN row tints.
    _extra_css = """
 body{max-width:1100px;margin:0 auto;padding:0 16px}
 header{margin:0 -16px;padding:22px 16px 20px;border-bottom:3px solid var(--accent)}
 .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
          gap:14px;margin:18px 0}
 .metric-card{background:var(--surface);border:1px solid var(--border);
              border-radius:12px;padding:16px;text-align:center;box-shadow:var(--shadow)}
 .metric-card .value{font-size:1.9rem;font-weight:700;color:var(--accent);
                     font-variant-numeric:tabular-nums}
 .metric-card .label{font-size:.85rem;color:var(--text-muted);margin-top:.3rem}
 table{margin:1rem 0}
 th,td{border:1px solid var(--border)}
 tr.fp td{background:var(--sev-med-weak)}
 tr.fn td{background:var(--sev-crit-weak)}
 .detail{font-family:ui-monospace,Consolas,Menlo,monospace;font-size:.8rem;word-break:break-all}
 footer{margin-top:2.5rem;border-top:1px solid var(--border);padding-top:14px}
 @media print{header{margin:0;padding:0 0 12px}}
"""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>XSSentinel Benchmark Report</title>
{theme_boot_script()}
<style>{base_css(_extra_css)}</style>
</head>
<body>
<header><h1>{BRAND_SVG}XSSentinel Accuracy Benchmark Report</h1>
<div class="head-tools">{theme_toggle_button()}</div>
<div class="meta">Generated: {timestamp} · Cases: {total_cases} · Duration: {total_time:.1f}s</div>
</header>
<p style="margin-top:14px">Quality Verdict: <span class="verdict {verdict_class}">{verdict}</span></p>

<div class="metrics">
  <div class="metric-card"><div class="value">{_pct(recall)}</div><div class="label">Recall (Detection Rate)</div></div>
  <div class="metric-card"><div class="value">{_pct(precision)}</div><div class="label">Precision</div></div>
  <div class="metric-card"><div class="value">{_pct(fpr)}</div><div class="label">False Positive Rate</div></div>
  <div class="metric-card"><div class="value">{f1:.4f}</div><div class="label">F1 Score</div></div>
</div>

<h2>Confusion Matrix</h2>
<table>
<tr><th></th><th>Detected</th><th>Not Detected</th></tr>
<tr><td><b>Vulnerable (GT)</b></td><td>TP = {tp}</td><td>FN = {fn}</td></tr>
<tr><td><b>Safe (GT)</b></td><td>FP = {fp}</td><td>TN = {tn}</td></tr>
</table>

<h2>By Difficulty</h2>
<table>
<tr><th>Difficulty</th><th>Total</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th><th>Recall</th><th>FPR</th></tr>
{diff_rows}</table>

<h2>By Context</h2>
<table>
<tr><th>Context</th><th>Total</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th><th>Recall</th><th>FPR</th></tr>
{ctx_rows}</table>

<h2>False Positives ({len(fps)})</h2>
{"<table><tr><th>Case ID</th><th>Mode</th><th>Context</th><th>Finding Detail</th></tr>" + fp_rows + "</table>" if fps else "<p>None — excellent!</p>"}

<h2>False Negatives ({len(fns)})</h2>
{"<table><tr><th>Case ID</th><th>Mode</th><th>Context</th><th>Difficulty</th></tr>" + fn_rows + "</table>" if fns else "<p>None — perfect recall!</p>"}

<footer>
XSSentinel Benchmark Suite v1.0 — Independent accuracy evaluation.<br>
Metrics: Recall = TP/(TP+FN), Precision = TP/(TP+FP), FPR = FP/(FP+TN), F1 = 2·P·R/(P+R)
</footer>
{interactive_js()}
</body></html>"""
    return html


# ---------------------------------------------------------------------------
# Comparison report (for Phase 4 multi-tool comparison)
# ---------------------------------------------------------------------------

def generate_comparison_html(tool_results: list[dict]) -> str:
    """Generate a side-by-side comparison HTML for multiple tools.

    Args:
        tool_results: List of benchmark result dicts (each must have
                      'tool', 'recall', 'precision', 'fpr', 'f1',
                      'total_time_s'; optional 'errors'/'completed').
    """
    rows = ""
    for r in tool_results:
        tool = r.get("tool", "?")
        recall = r.get("recall", 0)
        precision = r.get("precision", 0)
        fpr = r.get("fpr", 0)
        f1 = r.get("f1", 0)
        t = r.get("total_time_s", 0)
        err = r.get("errors") or 0
        completed = r.get("completed")
        comp_txt = f"{completed}" if completed is not None else "-"
        err_cell = f'<td style="color:#b33">{err}</td>' if err else "<td>0</td>"
        rows += (
            f"<tr><td><b>{tool}</b></td>"
            f"<td>{_pct(recall)}</td><td>{_pct(precision)}</td>"
            f"<td>{_pct(fpr)}</td><td>{f1:.4f}</td>"
            f"{err_cell}<td>{comp_txt}</td>"
            f"<td>{t:.1f}s</td></tr>\n")

    _extra_css = """
 body{max-width:900px;margin:0 auto;padding:24px 16px}
 table{margin:1.25rem 0}
 th,td{border:1px solid var(--border);text-align:center}
 th{color:var(--text-muted)}
 footer{margin-top:2.5rem;border-top:1px solid var(--border);padding-top:14px}
"""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>XSS Tool Comparison</title>
{theme_boot_script()}
<style>{base_css(_extra_css)}</style>
</head>
<body>
<h1>XSS Scanner Comparison</h1>
<div class="head-tools">{theme_toggle_button()}</div>
<p>Same benchmark suite, same conditions. ERR = runs that did not complete
(timeout/crash); they are excluded from Recall/FPR. Completed = cases scored.</p>
<table>
<tr><th>Tool</th><th>Recall</th><th>Precision</th><th>FPR</th><th>F1</th>
<th>ERR</th><th>Completed</th><th>Time</th></tr>
{rows}</table>
<footer>Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
{interactive_js()}
</body></html>"""
    return html


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def save_json_summary(data: dict, path: Path) -> Path:
    """Save a compact JSON summary."""
    summary = summarize_result(data)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    return path


def save_html_report(data: dict, path: Path) -> Path:
    """Save the HTML report."""
    html = generate_html(data)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def find_latest_result() -> Path | None:
    """Find the most recent benchmark result JSON."""
    if not _RESULTS_DIR.exists():
        return None
    files = sorted(_RESULTS_DIR.glob("benchmark_*.json"), reverse=True)
    return files[0] if files else None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Generate benchmark report")
    ap.add_argument("input", nargs="?", default=None,
                    help="Benchmark result JSON file")
    ap.add_argument("--latest", action="store_true",
                    help="Use the latest result file")
    ap.add_argument("--html", default=None,
                    help="Output HTML path")
    ap.add_argument("--json-summary", default=None,
                    help="Output JSON summary path")
    args = ap.parse_args()

    # Determine input file
    input_path = None
    if args.input:
        input_path = Path(args.input)
    elif args.latest:
        input_path = find_latest_result()
        if not input_path:
            print("[!] No benchmark results found", file=sys.stderr)
            return 1
    else:
        input_path = find_latest_result()
        if not input_path:
            print("[!] No input specified and no results found", file=sys.stderr)
            return 1

    print(f"[*] Reading: {input_path}")
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Generate outputs
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    html_path = Path(args.html) if args.html else \
        input_path.with_suffix(".html")
    save_html_report(data, html_path)
    print(f"[+] HTML report: {html_path}")

    json_path = Path(args.json_summary) if args.json_summary else \
        input_path.with_name(input_path.stem + "_summary.json")
    save_json_summary(data, json_path)
    print(f"[+] JSON summary: {json_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
