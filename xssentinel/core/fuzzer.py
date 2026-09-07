"""Fuzzer mode: response-difference scoring to identify injectable params.

Inspired by XSStrike's ``--fuzz`` mode, this module probes each parameter
with a benign marker and scores the response across MULTIPLE dimensions
to decide whether the parameter is a good injection candidate BEFORE
sending actual XSS payloads.  This dramatically reduces the number of
payloads sent (only high-scoring params get the full payload battery),
which is critical for large targets with many parameters.

Scoring dimensions (each contributes 0-N points):
  1. **Reflection** -- marker appears in response body (basic).
  2. **Reflection context** -- marker is in an executable context
     (script block, event handler, attribute, URL) -- weighted higher
     than plain HTML text reflection.
  3. **Length delta** -- response length changed when marker was added
     (indicates server-side processing beyond echo).
  4. **Status delta** -- HTTP status code changed (e.g. 500 on special
     chars -- strong injection signal).
  5. **Encoding traces** -- response shows evidence of encoding/decoding
     (e.g. marker appears URL-decoded, HTML-encoded, or JS-escaped) --
     indicates the app transforms input, which is a precondition for
     filter-bypass chains.
  6. **Error leakage** -- response contains error messages mentioning
     the marker or SQL/JS/template syntax errors -- strong signal.
  7. **Header reflection** -- marker appears in a response header
     (Set-Cookie, Location, X-*) -- header injection vector.

Total score >= ``threshold`` (default 30) marks the param as
"injectable candidate" and the scanner will send the full payload
battery; below threshold, only a minimal probe set is sent.

This is NOT a vulnerability detector -- it's a TRIAGE layer that
prioritizes which params deserve deep testing.
"""
from __future__ import annotations
import re
import html as html_mod
from urllib.parse import unquote


# Probes sent during fuzzing.  Each probe is designed to elicit a
# distinct response signature:
#   * "xsstest123"          -- benign alphanumeric marker (baseline reflection)
#   * "<>\"'{}"             -- special chars that break out of contexts
#   * "javascript:alert(1)" -- payload-shaped string (triggers WAF/sanitizer)
#   * "' OR 1=1--"          -- SQLi-shaped string (triggers DB errors)
#   * "{{7*7}}"             -- template-shaped string (triggers SSTI)
#   * "${7*7}"              -- EL-shaped string (triggers template injection)
FUZZ_PROBES: list[tuple[str, str]] = [
    ("benign",      "xsstest123"),
    ("special",     "<>\"'{}()[]"),
    ("js_payload",  "javascript:alert(1)"),
    ("sqli_shape",  "' OR 1=1--"),
    ("ssti_shape",  "{{7*7}}"),
    ("el_shape",    "${7*7}"),
]


# Weights for each scoring dimension.
WEIGHTS: dict[str, int] = {
    "reflection":        10,   # marker in body
    "executable_context": 25,  # marker in script/event/attr/URL context
    "length_delta":      5,   # |delta| > 50 bytes
    "status_delta":      20,  # status code changed
    "encoding_trace":    15,  # encoding/decoding evidence
    "error_leakage":     30,  # error message with marker/syntax
    "header_reflection": 20,  # marker in response header
}


def fuzz_param(requester, url: str, method: str, param: str,
               existing_params: dict | None = None,
               existing_data: dict | None = None,
               is_body: bool = False,
               verbose: bool = False) -> dict:
    """Fuzz a single parameter and return a score report.

    Returns a dict with:
      * ``score``: total score (int)
      * ``injectable``: bool (score >= threshold)
      * ``reflected``: bool
      * ``context``: detected reflection context (str)
      * ``encoding_traces``: list of encoding evidence (list[str])
      * ``details``: per-dimension breakdown (dict)
      * ``probe_responses``: per-probe response summary (dict)
    """
    existing_params = existing_params or {}
    existing_data = existing_data or {}

    # 1) Baseline request (no marker).
    try:
        if method.upper() == "POST":
            base_resp = requester.request(method, url,
                                          params=existing_params,
                                          data=existing_data)
        else:
            base_resp = requester.request(method, url,
                                          params=existing_params,
                                          data=existing_data)
        baseline_len = len(base_resp.text or "")
        baseline_status = getattr(base_resp, "status_code", 0)
        baseline_text = base_resp.text or ""
    except Exception as e:
        if verbose:
            print(f"    [fuzzer] baseline failed for {param}: {e}")
        return {"score": 0, "injectable": False, "error": str(e)}

    # 2) Send each fuzz probe and collect response signatures.
    probe_results: dict[str, dict] = {}
    for probe_name, probe_value in FUZZ_PROBES:
        params = dict(existing_params)
        data = dict(existing_data)
        if is_body:
            data[param] = probe_value
        else:
            params[param] = probe_value
        try:
            resp = requester.request(method, url, params=params, data=data)
            text = resp.text or ""
            status = getattr(resp, "status_code", 0)
            resp_headers = dict(resp.headers) if hasattr(resp, "headers") else {}
            probe_results[probe_name] = {
                "reflected": probe_value in text,
                "length": len(text),
                "status": status,
                "text": text,
                "headers": resp_headers,
            }
        except Exception:
            probe_results[probe_name] = {
                "reflected": False, "length": 0, "status": 0,
                "text": "", "headers": {},
            }

    # 3) Score each dimension.
    details: dict[str, int] = {}
    encoding_traces: list[str] = []

    # 3a) Reflection -- benign marker in response.
    benign = probe_results["benign"]
    reflected = benign["reflected"]
    if reflected:
        details["reflection"] = WEIGHTS["reflection"]

    # 3b) Executable context -- use context classifier on benign marker.
    context = "html_element"
    if reflected:
        try:
            from . import context as ctx_mod
            idx = benign["text"].find("xsstest123")
            info = ctx_mod._analyze_at(benign["text"], idx, "xsstest123")
            if info:
                context = info["context"]
                if context in ("script_block", "script_string_dq",
                               "script_string_sq", "event_handler",
                               "url_javascript", "svg_context",
                               "meta_refresh", "template_angular"):
                    details["executable_context"] = WEIGHTS["executable_context"]
        except Exception:
            pass

    # 3c) Length delta -- special chars probe should change length.
    special = probe_results["special"]
    special_delta = abs(special["length"] - baseline_len)
    if special_delta > 50:
        details["length_delta"] = WEIGHTS["length_delta"]

    # 3d) Status delta -- status changed on any probe.
    status_changed = any(
        pr["status"] != baseline_status and pr["status"] != 0
        for pr in probe_results.values()
    )
    if status_changed:
        details["status_delta"] = WEIGHTS["status_delta"]

    # 3e) Encoding traces -- marker appears encoded/decoded in response.
    marker = "xsstest123"
    for probe_name, pr in probe_results.items():
        text = pr["text"]
        # URL-decoded marker (app decoded %xx but didn't re-encode).
        if marker in unquote(text) and marker not in text:
            encoding_traces.append(f"{probe_name}: URL-decoded reflection")
        # HTML-encoded marker (app applied html.escape).
        if html_mod.escape(marker) in text and marker not in text:
            encoding_traces.append(f"{probe_name}: HTML-encoded reflection")
        # JS-escaped marker (app applied JSON.stringify-style escaping).
        if f"\\u{ord(marker[0]):04x}" in text.lower():
            encoding_traces.append(f"{probe_name}: JS-unicode-escaped reflection")
        # Lowercased/uppercased marker (normalization).
        if marker.lower() in text.lower() and marker not in text:
            encoding_traces.append(f"{probe_name}: case-normalized reflection")
    if encoding_traces:
        details["encoding_trace"] = WEIGHTS["encoding_trace"]

    # 3f) Error leakage -- error messages in response.
    error_patterns = [
        r"SQLITE_ERROR|mysql_fetch|ORA-\d+|PostgreSQL.*ERROR",
        r"Traceback \(most recent call last\)",
        r"Exception in thread",
        r"ReferenceError:|TypeError:|SyntaxError:",
        r"unterminated string literal",
        r"unexpected token",
        r"<b>Warning</b>:.*\\1",
        r"Fatal error:",
        r"You have an error in your SQL syntax",
    ]
    for probe_name, pr in probe_results.items():
        for pat in error_patterns:
            if re.search(pat, pr["text"], re.I):
                details["error_leakage"] = WEIGHTS["error_leakage"]
                encoding_traces.append(f"{probe_name}: error pattern {pat!r}")
                break
        if "error_leakage" in details:
            break

    # 3g) Header reflection -- marker in response headers.
    for probe_name, pr in probe_results.items():
        for hname, hval in pr["headers"].items():
            if marker in str(hval):
                details["header_reflection"] = WEIGHTS["header_reflection"]
                encoding_traces.append(
                    f"{probe_name}: reflected in header {hname}")
                break
        if "header_reflection" in details:
            break

    # 4) Total score.
    score = sum(details.values())
    threshold = 30
    injectable = score >= threshold

    if verbose:
        print(f"    [fuzzer] {param}: score={score} ctx={context} "
              f"reflected={reflected} traces={len(encoding_traces)} "
              f"injectable={injectable}")

    return {
        "score": score,
        "injectable": injectable,
        "reflected": reflected,
        "context": context,
        "encoding_traces": encoding_traces,
        "details": details,
        "probe_responses": {
            name: {"reflected": pr["reflected"],
                   "length": pr["length"],
                   "status": pr["status"]}
            for name, pr in probe_results.items()
        },
        "baseline_length": baseline_len,
        "baseline_status": baseline_status,
    }


def fuzz_endpoint(requester, url: str, method: str = "GET",
                  params: dict | None = None,
                  data: dict | None = None,
                  candidate_names: list[str] | None = None,
                  max_params: int = 50,
                  threshold: int = 30,
                  verbose: bool = False) -> list[dict]:
    """Fuzz all parameters of an endpoint and return ranked candidates.

    Args:
        candidate_names: if provided, fuzz these param names (hidden param
            mining); if None, only fuzz existing params in ``params``/``data``.
        max_params: max number of params to fuzz.
        threshold: minimum score to mark a param as injectable.

    Returns a list of dicts sorted by score (descending), each with the
    ``fuzz_param`` output plus ``name`` and ``is_body`` fields.
    """
    params = params or {}
    data = data or {}
    results: list[dict] = []

    # Build the list of params to fuzz.
    fuzz_list: list[tuple[str, bool]] = []
    for p in params:
        fuzz_list.append((p, False))
    for p in data:
        fuzz_list.append((p, True))
    # If candidate_names given, add them as query params (hidden param mining).
    if candidate_names:
        for name in candidate_names:
            if name not in params and name not in data:
                fuzz_list.append((name, False))

    # Limit to max_params.
    fuzz_list = fuzz_list[:max_params]

    for param, is_body in fuzz_list:
        report = fuzz_param(requester, url, method, param,
                            existing_params=params, existing_data=data,
                            is_body=is_body, verbose=verbose)
        report["name"] = param
        report["is_body"] = is_body
        results.append(report)

    # Sort by score descending.
    results.sort(key=lambda r: r.get("score", 0), reverse=True)
    return results


def select_top_candidates(fuzz_results: list[dict],
                          top_n: int = 5) -> list[str]:
    """Select the top-N param names worth deep payload testing.

    Params with ``injectable=True`` are prioritized; if fewer than
    ``top_n`` are injectable, the highest-scoring non-injectable params
    are added as fallback.
    """
    injectable = [r for r in fuzz_results if r.get("injectable")]
    non_injectable = [r for r in fuzz_results if not r.get("injectable")]
    selected = injectable[:top_n]
    if len(selected) < top_n:
        remaining = top_n - len(selected)
        selected.extend(non_injectable[:remaining])
    return [r["name"] for r in selected]
