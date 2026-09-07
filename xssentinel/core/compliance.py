"""Compliance mapping engine (OWASP / CWE / PCI DSS / ISO 27001 / NIST).

Historically this module was ~660 lines of literal tuples.  The corpus now
lives in ``data/compliance.json`` — edit THAT file to add or adjust
entries — and this module is a thin, cached loader exposing the exact same
public API (contract guarded by tests/test_units.py and tests/test_p27.py):

    compliance_for_finding(finding) -> list[dict]
    compliance_summary(findings) -> dict
    compliance_table_html(findings) -> str
    supported_finding_types() -> list[str]
    supported_frameworks() -> list[str]

``_FINDING_TYPE_MAP`` / ``_DEFAULT_MAP`` remain available as module
attributes (populated once at import from the JSON) for backwards
compatibility.
"""
from __future__ import annotations

import json
import os
import threading

_DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "data", "compliance.json")

_cache: dict | None = None
_cache_lock = threading.Lock()


def _load() -> dict:
    """Load and cache the compliance corpus (double-checked lock)."""
    global _cache
    if _cache is None:
        with _cache_lock:
            if _cache is None:
                with open(_DATA_FILE, encoding="utf-8") as f:
                    raw = json.load(f)
                # Tuples -> lists are interchangeable for the unpacking
                # loops below; keep lists (JSON-native).
                _cache = {
                    "finding_type_map": raw["finding_type_map"],
                    "default_map": raw["default_map"],
                }
    return _cache


# Backwards-compatible module attributes (populated once at import).
_FINDING_TYPE_MAP: dict = _load()["finding_type_map"]
_DEFAULT_MAP: list = _load()["default_map"]


def compliance_for_finding(finding) -> list[dict]:
    """Return the list of compliance entries for a finding.

    Each entry is a dict:
        {"framework": str, "requirement_id": str, "title": str, "url": str}

    Args:
        finding: a Finding object (with .data) or a plain dict.
    """
    d = finding.data if hasattr(finding, "data") else finding
    ftype = d.get("type", "reflected")
    # Phase 22-5: handle dynamic framework_*/template_ssti_* types that
    # don't have their own explicit mapping -- fall back to the generic
    # "framework_xss" / "template_ssti" mapping.
    entries = _FINDING_TYPE_MAP.get(ftype)
    if entries is None:
        if ftype.startswith("framework_"):
            entries = _FINDING_TYPE_MAP.get("framework_xss", _DEFAULT_MAP)
        elif ftype.startswith("template_ssti_"):
            entries = _FINDING_TYPE_MAP.get("template_ssti", _DEFAULT_MAP)
        elif ftype.startswith("svg_xss_"):
            # Generic SVG XSS fallback -- covers any svg_xss_<vector> not
            # explicitly listed in _FINDING_TYPE_MAP.
            entries = _FINDING_TYPE_MAP.get(
                "svg_xss_svg_onload", _DEFAULT_MAP)
        else:
            entries = _DEFAULT_MAP
    return [
        {"framework": fw, "requirement_id": req, "title": title, "url": url}
        for fw, req, title, url in entries
    ]


def compliance_summary(findings: list) -> dict:
    """Aggregate compliance mapping across all findings.

    Returns a dict keyed by framework name, where each value is a dict of
    requirement_id -> {"title": str, "count": int, "url": str}.

    Useful for building a "compliance dashboard" section of the report.
    """
    summary: dict[str, dict] = {}
    for f in findings:
        for entry in compliance_for_finding(f):
            fw = entry["framework"]
            req = entry["requirement_id"]
            if fw not in summary:
                summary[fw] = {}
            if req not in summary[fw]:
                summary[fw][req] = {
                    "title": entry["title"],
                    "url": entry["url"],
                    "count": 0,
                }
            summary[fw][req]["count"] += 1
    return summary


def compliance_table_html(findings: list) -> str:
    """Render the compliance summary as an HTML table for embedding in
    the report.  Each row is one (framework, requirement) pair."""
    summary = compliance_summary(findings)
    if not summary:
        return "<p>No compliance mappings available.</p>"
    rows = []
    for fw in sorted(summary.keys()):
        for req in sorted(summary[fw].keys()):
            info = summary[fw][req]
            rows.append(
                f"<tr><td>{fw}</td><td>{req}</td>"
                f"<td>{info['title']}</td>"
                f"<td>{info['count']}</td>"
                f"<td><a href=\"{info['url']}\" target=\"_blank\">link</a></td></tr>"
            )
    return (
        "<table class=\"compliance\"><thead><tr>"
        "<th>Framework</th><th>Requirement</th><th>Title</th>"
        "<th>Findings</th><th>Reference</th>"
        "</tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def supported_finding_types() -> list[str]:
    """Return the list of finding types that have compliance mappings."""
    return list(_FINDING_TYPE_MAP.keys())


def supported_frameworks() -> list[str]:
    """Return the list of compliance frameworks covered."""
    seen = []
    for entries in _FINDING_TYPE_MAP.values():
        for fw, _, _, _ in entries:
            if fw not in seen:
                seen.append(fw)
    return seen
