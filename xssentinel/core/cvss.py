"""CVSS v3.1 scoring for XSS findings.

Maps an XSS finding's characteristics to a CVSS 3.1 base score and
severity rating.  This gives the auditor a defensible, standardized
severity instead of a hand-waved "high".

XSS base vector (per CVSS standards):
  AV:N (network access)
  AC:L (low complexity -- XSS is trivial to exploit once found)
  PR:N or PR:L (no privileges for reflected; low for stored/auth-context)
  UI:R (user interaction required -- victim must click/load)
  S:U or S:C (scope: changed if the XSS escapes the origin, e.g. via
              admin panel XSS that compromises the admin session)
  C:L (confidentiality impact: low -- attacker reads DOM, not full DB)
  I:L (integrity impact: low -- attacker can write DOM, modify content)
  A:N (availability impact: none for typical XSS)

Score adjustments:
  * Stored XSS: +0.5 (persists, wider impact).
  * DOM-based with admin context: S:C, C:H, I:H (admin compromise).
  * Blind/OOB-confirmed: +0.3 (execution proven, not just reflected).
  * CSP bypass required: AC:L stays; if no bypass exists, severity drops.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class CVSSVector:
    av: str = "N"   # Attack Vector: N/L/A/P
    ac: str = "L"   # Attack Complexity: L/H
    pr: str = "N"   # Privileges Required: N/L/H
    ui: str = "R"   # User Interaction: N/R
    s:  str = "U"   # Scope: U/C
    c:  str = "L"   # Confidentiality: H/L/N
    i:  str = "L"   # Integrity: H/L/N
    a:  str = "N"   # Availability: H/L/N

    def to_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}"
                f"/UI:{self.ui}/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}")


def _metric_value(metric: str, value: str) -> float:
    """Lookup table for CVSS 3.1 metric values."""
    tables = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # for Scope: U
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    return tables.get(metric, {}).get(value, 0.0)


def _pr_value_for_scope(pr: str, scope: str) -> float:
    """PR values differ between Scope:U and Scope:C."""
    if scope == "C":
        return {"N": 0.85, "L": 0.68, "H": 0.50}.get(pr, 0.0)
    return _metric_value("PR", pr)


def calculate_score(vec: CVSSVector) -> float:
    """Compute CVSS 3.1 base score from a vector."""
    iss = 1 - ((1 - _metric_value("C", vec.c))
               * (1 - _metric_value("I", vec.i))
               * (1 - _metric_value("A", vec.a)))
    impact = 0.0
    if vec.s == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * _metric_value("AV", vec.av) \
        * _metric_value("AC", vec.ac) \
        * _pr_value_for_scope(vec.pr, vec.s) \
        * _metric_value("UI", vec.ui)
    if impact <= 0:
        return 0.0
    if vec.s == "C":
        return min(10.0, 1.08 * (impact + exploitability))
    return min(10.0, impact + exploitability)


def severity_from_score(score: float) -> str:
    """Map CVSS score to severity label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def score_finding(finding: dict) -> tuple[float, str, str]:
    """Compute (score, severity, vector_string) for an XSS finding.

    `finding` is the dict form (Finding.to_dict()) with keys like:
        type, severity, url, param, payload, context, etc.
    """
    vec = CVSSVector()
    ftype = finding.get("type", "reflected")
    fsev = finding.get("severity", "high")
    context = finding.get("context", "html_element")

    # Base: XSS is network, low complexity, requires user interaction.
    vec.av = "N"
    vec.ac = "L"
    vec.ui = "R"

    # Privileges: default no privileges.
    vec.pr = "N"

    # Scope & impact: default U/L/L/N (typical reflected XSS).
    vec.s = "U"
    vec.c = "L"
    vec.i = "L"
    vec.a = "N"

    # Adjust for finding type.
    if ftype.startswith("stored") or ftype == "second_order":
        # Stored XSS: persists, wider impact. Bump integrity.
        vec.i = "H"
    if "blind" in ftype or "oob" in ftype:
        # Blind XSS: confirmed execution via OOB callback. Often admin panel.
        vec.s = "C"
        vec.c = "H"
        vec.i = "H"
    if "dom" in ftype:
        # DOM XSS: often client-side only, but if it touches sensitive
        # pages (admin), can be severe. Keep defaults.
        pass
    if "mutation" in ftype or "mxss" in ftype:
        # mXSS bypasses sanitizers -> higher integrity impact.
        vec.i = "H"
    if "clobber" in ftype:
        # DOM clobbering: often leads to auth bypass / admin actions.
        vec.s = "C"
        vec.c = "H"
    if "template" in ftype or "ssti" in ftype:
        # SSTI -> XSS: usually means RCE on server. Treat as critical.
        vec.s = "C"
        vec.c = "H"
        vec.i = "H"
        vec.a = "H"
    if "jsonp" in ftype:
        # JSONP XSS: arbitrary script execution in origin context.
        vec.i = "H"

    # Severity hint from scanner.
    if fsev == "critical":
        vec.s = "C"
        vec.c = "H"
        vec.i = "H"
    elif fsev == "info":
        return (0.0, "info", vec.to_string())

    score = calculate_score(vec)
    sev = severity_from_score(score)
    return (score, sev, vec.to_string())


def enrich_finding(finding: dict) -> dict:
    """Add cvss_score, cvss_severity, cvss_vector to a finding dict."""
    score, sev, vec = score_finding(finding)
    out = dict(finding)
    out["cvss_score"] = round(score, 1)
    out["cvss_severity"] = sev
    out["cvss_vector"] = vec
    return out
