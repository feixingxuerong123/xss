"""Remediation advice engine (Phase 39).

Historically this module was a ~3000-line literal dict.  The corpus now
lives in ``data/fix_advice.json`` — edit THAT file to add or adjust
entries — and this module is a thin, cached loader exposing the exact
same public API (contract guarded by tests/test_p25.py):

    get_advice(ftype) -> dict
    advice_for_finding(finding) -> dict
    supported_finding_types() -> list[str]
    advice_summary_html(findings) -> str

``_ADVICE`` / ``_DEFAULT_ADVICE`` remain available as module attributes
(populated once at import from the JSON) for backwards compatibility.
"""
from __future__ import annotations

import html as _html
import json
import os
import threading

_DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "data", "fix_advice.json")

_cache: dict | None = None
_cache_lock = threading.Lock()


def _load() -> dict:
    """Load and cache the advice corpus (double-checked locking, same
    pattern as payloads.py)."""
    global _cache
    if _cache is None:
        with _cache_lock:
            if _cache is None:
                with open(_DATA_FILE, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                _cache = {
                    "advice": raw.get("advice", {}),
                    "default": raw.get("default_advice", {}),
                }
    return _cache


def _reload(path: str | None = None) -> None:
    """Reload the corpus (custom JSON hook, mirrors payloads.reload)."""
    global _cache, _DATA_FILE
    with _cache_lock:
        if path:
            _DATA_FILE = path
        _cache = None
    _load()


_ADVICE = _load()["advice"]
_DEFAULT_ADVICE = _load()["default"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_advice(ftype: str) -> dict:
    """Return remediation advice for a finding type string.

    Convenience wrapper around ``advice_for_finding`` for callers that
    only have the type name (e.g. ``"graphql_xss"``) rather than a full
    finding dict.

    Returns a dict:
        {"headline": str, "detail": str, "code_example": str,
         "primary_cwe": str, "also_consider": list[str]}
    """
    return _ADVICE.get(ftype, _DEFAULT_ADVICE)


def advice_for_finding(finding) -> dict:
    """Return remediation advice for a finding.

    Returns a dict:
        {"headline": str, "detail": str, "code_example": str,
         "primary_cwe": str, "also_consider": list[str]}

    Args:
        finding: a Finding object (with .data) or a plain dict.
    """
    d = finding.data if hasattr(finding, "data") else finding
    ftype = d.get("type", "reflected")
    return _ADVICE.get(ftype, _DEFAULT_ADVICE)


def supported_finding_types() -> list[str]:
    """Return the list of finding types that have dedicated advice."""
    return list(_ADVICE.keys())


def advice_summary_html(findings: list) -> str:
    """Render a remediation summary section for the HTML report.

    Deduplicates by finding type so each unique vulnerability class gets
    one advice block, regardless of how many instances were found.
    """
    seen_types: dict[str, int] = {}
    for f in findings:
        d = f.data if hasattr(f, "data") else f
        t = d.get("type", "reflected")
        seen_types[t] = seen_types.get(t, 0) + 1

    blocks = []
    for ftype, count in seen_types.items():
        adv = _ADVICE.get(ftype, _DEFAULT_ADVICE)
        also = "".join(f"<li>{_html.escape(a)}</li>" for a in adv["also_consider"])
        blocks.append(f"""
        <div class="advice-block">
          <h4>{_html.escape(ftype)} <span class="advice-count">({count} finding{'s' if count != 1 else ''})</span></h4>
          <p class="advice-headline"><strong>Fix:</strong> {_html.escape(adv['headline'])}</p>
          <p>{_html.escape(adv['detail'])}</p>
          <details><summary>Code example</summary><pre><code>{_html.escape(adv['code_example'])}</code></pre></details>
          <p><strong>Primary CWE:</strong> {_html.escape(adv['primary_cwe'])}</p>
          <ul class="also-consider">{also}</ul>
        </div>""")
    return (
        '<section class="remediation"><h2>Remediation Advice</h2>'
        + "\n".join(blocks)
        + "</section>"
    )
