"""Marker-based arbitrary-position injection (DalFox ``FUZZ`` style).

Many injection points are NOT parameters: a value embedded in a JWT, an
XML node, a deeply nested JSON leaf, a URL the client rewrites.  The
normal parameter-driven pipeline cannot reach them.  This module takes a
body template containing a marker token (default ``FUZZ``), replaces
EVERY occurrence with each candidate payload, sends the result, and
classifies the response (raw reflection vs. semantically-confirmed
execution) so the operator sees which marker positions actually execute.
"""
from __future__ import annotations
from urllib.parse import quote as _urlquote

import re as _re



# Payloads whose verbatim reflection constitutes execution potential:
# event handlers, script elements, javascript:/data: URIs.
_EXEC_SHAPE_RE = _re.compile(
    r"on\w+\s*=|<script\b|javascript:|data:text/html", _re.IGNORECASE)


def replace_marker(template: str, marker: str, payload: str) -> str:
    """Replace every occurrence of ``marker`` in ``template``.

    Raises ValueError when the marker is empty (it would replace every
    character of the template) or when the template does not contain the
    marker at all -- a silent no-op would look like a false "not
    vulnerable".
    """
    if not marker:
        raise ValueError("marker must be a non-empty token")
    if marker not in template:
        raise ValueError(
            f"marker {marker!r} not found in body template")
    return template.replace(marker, payload)


def fuzz_marker(requester, url: str, method: str, body_template: str,
                marker: str, payloads: list[str],
                headers: dict | None = None,
                params: dict | None = None) -> list[dict]:
    """Inject every ``payload`` at every ``marker`` position and classify.

    Returns a list of result dicts, one per payload:

        {"payload": str,
         "reflected": bool,      # payload text visible in the response
         "confirmed": bool,      # verify_semantic says executable
         "context": str,         # verifier context ("" when not reflected)
         "status": int}

    Both the raw and the URL-encoded form of the payload are checked for
    reflection (servers commonly echo the encoded form back).
    """
    out: list[dict] = []
    for payload in payloads:
        try:
            body = replace_marker(body_template, marker, payload)
        except ValueError:
            raise   # template/marker misconfiguration -- operator must see it
        try:
            resp = requester.request(method, url, params=params or None,
                                     data=body, headers=headers or None)
        except Exception:
            out.append({"payload": payload, "reflected": False,
                        "confirmed": False, "status": 0,
                        "error": "request failed"})
            continue
        text = resp.text or ""
        # Reflection: raw or URL-encoded form visible in the response.
        # verbatim raw presence implies the server did NOT entity-escape
        # the payload (escaped reflections come back as &lt;svg ...).
        reflected = (payload in text
                     or _urlquote(payload) in text
                     or _urlquote(payload, safe="") in text)
        # Execution shape: the payload itself carries an event handler /
        # script tag / dangerous scheme.  verify_semantic's token-lookup
        # does not apply here -- the payload IS the markup element, not a
        # token embedded inside one.
        confirmed = bool(reflected and _EXEC_SHAPE_RE.search(payload))
        out.append({"payload": payload, "reflected": reflected,
                    "confirmed": confirmed,
                    "status": getattr(resp, "status_code", 0)})
    return out


def fuzz_summary(results: list[dict]) -> dict:
    """Aggregate fuzz results into a compact summary for the CLI."""
    confirmed = [r for r in results if r["confirmed"]]
    reflected = [r for r in results if r["reflected"] and not r["confirmed"]]
    return {
        "total": len(results),
        "confirmed": len(confirmed),
        "reflected_only": len(reflected),
        "first_confirmed": (confirmed[0]["payload"]
                            if confirmed else None),
    }
