"""Declarative multi-step detection scenarios (Phase 41, Nuclei-inspired).

A *scenario* is a small JSON recipe that chains HTTP steps into a
detection flow which the plain reflect-probe loop cannot express — the
canonical example being stored XSS: step 1 POSTs a token-marked payload
to a write endpoint, step 2 GETs a read endpoint and semantic-verifies
the token in the rendered page.

File format (``--scenarios`` / ``Scanner(scenario_file=...)``)::

    {
      "scenarios": [
        {
          "id": "comment-stored-xss",
          "title": "Stored XSS via comment field",
          "match": {"param_names": ["comment", "message", "content"]},
          "steps": [
            {"name": "inject", "method": "POST", "path": "/comment",
             "param": "{param}", "payload": "<script>alert('{token}')</script>"},
            {"name": "check",  "method": "GET",  "path": "/comments"}
          ]
        }
      ]
    }

Placeholders substituted per run:
  * ``{token}``  unique verification token (verifier-confirmed)
  * ``{param}``  the reflected parameter name
Scenario semantics:
  * steps run in order; a transport error aborts the scenario
  * after the LAST step the token is semantic-verified in that response
    (callers may also verify after any step via ``"verify": true``)
  * confirmed -> Finding(type="scenario", scenario_id=..., high/high)
"""
from __future__ import annotations

import json
import secrets
import threading

from . import verifier
from .logger import get_logger

_log = get_logger("scenarios")

_cache: dict | None = None
_cache_lock = threading.Lock()


def load_scenarios(path: str) -> list[dict]:
    """Load + validate a scenario file.  Returns the scenarios list."""
    global _cache
    with _cache_lock:
        if _cache is not None and _cache.get("path") == path:
            return _cache["scenarios"]
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    scenarios = []
    for sc in raw.get("scenarios", []):
        if not sc.get("id") or not sc.get("steps"):
            _log.warning("scenario missing id/steps, skipped: %r", sc)
            continue
        for st in sc["steps"]:
            if "method" not in st or "path" not in st:
                _log.warning("scenario %s has an incomplete step, skipped",
                             sc.get("id"))
                break
        else:
            scenarios.append(sc)
    _cache = {"path": path, "scenarios": scenarios}
    return scenarios


def scenario_matches(sc: dict, param: str) -> bool:
    """True when the scenario's param_names filter accepts this param
    (absent filter -> always matches)."""
    names = (sc.get("match") or {}).get("param_names")
    if not names:
        return True
    return param in names


def run_scenario(scanner, req, base_url: str, param: str, is_body: bool,
                 sc: dict) -> bool:
    """Execute one scenario; confirm via semantic verification.

    Returns True and records a Finding when the token lands in an
    executable position on a verified step.
    """
    token = "xssv_" + secrets.token_hex(4)
    # Step paths are SITE-level (e.g. /comment, /comments): they resolve
    # against the ORIGIN of the scanned URL, not the page URL (whose path
    # would otherwise be duplicated onto the step endpoint).
    from urllib.parse import urlparse
    p = urlparse(base_url)
    origin = f"{p.scheme}://{p.netloc}"
    last_resp = None
    last_text = ""
    for st in sc.get("steps", []):
        method = str(st.get("method", "GET")).upper()
        path = str(st.get("path", "/")).replace("{param}", param)
        url = origin + path
        payload = str(st.get("payload", "{token}")).replace(
            "{token}", token).replace("{param}", param)
        # Field name: the scanned param by default; a step may override it
        # ("param": "q") when the write endpoint expects a different name.
        fname = str(st.get("param", param))
        p_params: dict = {}
        p_data: dict = {}
        if method == "POST" or is_body:
            p_data[fname] = payload
        else:
            p_params[fname] = payload
        try:
            resp = req.request(method, url, params=p_params or None,
                               data=p_data or None)
            scanner._bump()
            scanner.coverage.record_request(url, method)
        except Exception:
            return False
        last_resp = resp
        last_text = resp.text or ""
        if st.get("verify"):
            v = verifier.verify_semantic(last_text, token,
                                         response_headers=dict(resp.headers))
            if v["confirmed"]:
                return _record(scanner, url, param, sc, v, last_text,
                               token, resp, payload)
    # Default: verify the token against the final response.
    if last_resp is None:
        return False
    v = verifier.verify_semantic(last_text, token,
                                 response_headers=dict(last_resp.headers))
    if v["confirmed"]:
        return _record(scanner, base_url, param, sc, v, last_text, token,
                       last_resp, payload)
    return False


def _record(scanner, url, param, sc, v, text, token, resp, payload):
    scanner._add(_mk_finding(
        url=url, param=param, sc=sc, v=v, text=text, token=token,
        resp=resp, payload=payload))
    scanner.coverage.record_finding(url, "GET")
    if scanner.verbose:
        _log.debug("scenario %s confirmed", sc.get("id"))
    return True


def _mk_finding(url, param, sc, v, text, token, resp, payload):
    from .scanner import Finding
    idx = text.find(token)
    return Finding(
        url=url, method="GET", param=param,
        type="scenario", context=v.get("context") or "html_element",
        payload=payload, transform=[f"scenario:{sc.get('id')}"],
        severity="high", confidence="high",
        detail=(f"scenario '{sc.get('id')}' confirmed: {v.get('detail')}"),
        headless=None,
        proof={"scenario": sc.get("id"), "token": token,
               "snippet": text[max(0, idx - 40): idx + len(token) + 40]
               if idx >= 0 else ""},
    )
