"""SQLi error-reflection grep engine (Phase 44) -- learned from dalfox's
grep engine and xray's sqldet module.

A low-footprint *fast* check: inject a handful of syntax-breaking probes
(`, ", `), `") and look for database error strings in the response.  When
a DB error echoes back, the endpoint is very likely passing user input
straight into a SQL statement -- a high-value lead even though XSSentinel's
primary focus is XSS.  No boolean/time blind injection is attempted (that
stays out of scope for a passive, low-intrusion check).

Design:
  * ~7 probes that reliably break single/double-quoted SQL literals.
  * Per-DB fingerprint regexes (MySQL / PostgreSQL / MSSQL / Oracle /
    SQLite / generic ODBC), matched case-insensitively on a bounded
    response excerpt.
  * Severity: medium.  The finding carries the matched DB family and the
    echoing snippet so a human can confirm quickly.
"""
from __future__ import annotations

import re

# (name, probe) -- order matters: quotes first (cheap, highest yield).
PROBES = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("single_quote_paren", "')"),
    ("double_quote_paren", '")'),
    ("single_quote_comment", "'-- "),
    ("double_quote_comment", '"-- '),
    ("backtick", "`"),
]

# Per-family fingerprint regexes.  Each matches a distinctive substring of
# the DB's error page.  Keys are stable family names used in reports.
_FINGERPRINTS = [
    # MySQL / MariaDB
    ("mysql", re.compile(
        r"(you have an error in your sql syntax|"
        r"mysql_fetch_assoc|mysql_fetch_array|"
        r"supplied argument is not a valid mysql|"
        r"mysqli?_[a-z_]+\s*\(\):\s*syntax|"
        r"sqlstate\[[0-9]{5}\].*at line\s+\d)", re.I)),
    # PostgreSQL
    ("postgresql", re.compile(
        r"(postgresql|pg_query|pg_exec|"
        r"error:\s+syntax error at or near|"
        r"invalid input syntax for (integer|type)|"
        r"relation \"[^\"]+\" does not exist|"
        r"column \"[^\"]+\" does not exist)", re.I)),
    # Microsoft SQL Server / ODBC
    ("mssql", re.compile(
        r"(unclosed quotation mark|"
        r"microsoft ole db|sqlserver|sql server native client|"
        r"odbc sql server driver|"
        r"incorrect syntax near)", re.I)),
    # Oracle
    ("oracle", re.compile(
        r"(ora-\d{4,5}|oracle error|java\.sql\.sqlexception)", re.I)),
    # SQLite
    ("sqlite", re.compile(
        r"(sqlite3?\.(operationalerror|syntaxerror)|"
        r"near \"[^\"]*\": syntax error|"
        r"unrecognized token)", re.I)),
]

# Generic fallback: a SQL error page that doesn't name the engine.  Lower
# confidence than a family match, still worth reporting.
_GENERIC = re.compile(
    r"(sql (syntax )?error|syntax error in query|invalid query|"
    r"query failed|db error|database error|sqlstate)", re.I)


def detect_db_error(response_text: str | None) -> tuple[str | None, str | None]:
    """Match a DB error fingerprint in ``response_text``.

    Returns (family, matched_snippet) or (None, None).  ``family`` is one
    of the keys above or "unknown_db"; ``matched_snippet`` is a short
    excerpt around the first match (for evidence).
    """
    if not response_text:
        return None, None
    excerpt = response_text[:8000]
    for family, rx in _FINGERPRINTS:
        m = rx.search(excerpt)
        if m:
            start = max(0, m.start() - 30)
            snippet = excerpt[start:m.end() + 40].replace("\n", " ")
            return family, snippet
    m = _GENERIC.search(excerpt)
    if m:
        start = max(0, m.start() - 30)
        snippet = excerpt[start:m.end() + 40].replace("\n", " ")
        return "unknown_db", snippet
    return None, None


def run_sqli_check(requester, url: str, method: str = "GET",
                   params: dict | None = None, data: dict | None = None,
                   max_probes: int | None = None) -> list[dict]:
    """Inject probes into every reflected/available param and report DB
    error echoes.

    ``requester``: a Requester-like with get()/post().
    Returns a list of finding dicts::

        {
          "url": ..., "method": ..., "param": ..., "probe": ...,
          "db": "mysql"|..., "evidence": "...", "severity": "medium",
          "type": "sqli_error_based",
        }

    An endpoint whose *baseline* (no probe) already contains a DB error is
    skipped (the error predates us; not a finding).
    """
    params = dict(params or {})
    data = dict(data or {})
    if not params and not data:
        return []

    findings: list[dict] = []
    baseline_text = ""
    try:
        if method == "POST" and data:
            baseline_text = requester.post(url, data=data).text or ""
        else:
            baseline_text = requester.get(url, params=params).text or ""
    except Exception:
        return []
    baseline_hit = detect_db_error(baseline_text)[0] is not None
    if baseline_hit:
        return []  # pre-existing DB error page; not injectable evidence

    items = [(p, False) for p in params] + [(p, True) for p in data]
    probe_list = PROBES
    if max_probes:
        probe_list = probe_list[:max_probes]

    for param, is_body in items:
        for pname, probe in probe_list:
            try:
                if is_body:
                    d2 = dict(data)
                    d2[param] = probe
                    resp = requester.post(url, data=d2)
                else:
                    p2 = dict(params)
                    p2[param] = probe
                    resp = requester.get(url, params=p2)
            except Exception:
                continue
            family, snippet = detect_db_error(resp.text)
            if family is None:
                continue
            findings.append({
                "url": url,
                "method": method,
                "param": param,
                "probe": pname,
                "db": family,
                "evidence": snippet,
                "severity": "medium",
                "type": "sqli_error_based",
                "confidence": "high" if family != "unknown_db" else "medium",
            })
            break  # one finding per param is enough
    return findings
