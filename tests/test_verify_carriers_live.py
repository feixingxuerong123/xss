"""Phase 176c: every replay carrier must actually DELIVER its payload.

Why this file exists
--------------------
The query carrier had a silent false negative.  ``_replay_request`` injected
the marked payload into ``params`` while still handing requests the finding's
URL -- and a scan finding's URL contains its own parameter in the NORMAL case
(``...?q=test``).  requests appends rather than replaces, so the wire carried
two ``q=``; a server reads the first, the payload never arrived, nothing
reflected, and the replay concluded "payload no longer reflected" => FIXED.
A reflector that echoes everything was reported as fixed, exit code 0.

That fix was verified by hand.  This file pins down ALL the carriers -- plain
query, multi-parameter query, POST body, header (marker and legacy forms),
cookie (marker and legacy), path and error-page -- against a lab that echoes
exactly one carrier back into the page.  A carrier that stops delivering shows
up here as ``fixed`` instead of ``still_vuln``.

The negative control matters: a target that echoes nothing must still report
``fixed``.  Without it, a test that always passes would be indistinguishable
from a test that works.

Loopback only (a lab on 127.0.0.1); skipped when this host's loopback is
degraded, like the suite's other live tests.
"""
from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

from xssentinel.core import verify_fix as vf
from xssentinel.core.requester import Requester

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

pytestmark = [
    pytest.mark.skipif(not SOCKETPAIR_OK, reason="loopback socketpair degraded"),
]

PAYLOAD = "<script>alert(1)</script>"


class _Lab(BaseHTTPRequestHandler):
    """Echoes exactly one carrier back, per path.

    ``/clean`` echoes nothing -- it is the negative control.
    """

    protocol_version = "HTTP/1.0"

    def _send(self, inner: str):
        body = ("<!doctype html><html><body><div id='out'>"
                + inner + "</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlsplit(self.path)
        if p.path == "/clean":
            return self._send("static content, nothing echoed")
        if p.path == "/hdr":
            seen = [f"HDR[{k}]={self.headers.get(k)}"
                    for k in ("User-Agent", "X-Test", "Referer")
                    if self.headers.get(k)]
            return self._send(" | ".join(seen))
        if p.path == "/ck":
            return self._send("COOKIE=" + (self.headers.get("Cookie") or ""))
        if p.path.startswith("/p/"):
            return self._send("PATH=" + unquote(p.path[3:]))
        # Default: the query, FIRST value only -- which is what a real server
        # does with a duplicated parameter, and how the original bug hid.
        return self._send("Q=" + parse_qs(p.query).get("q", [""])[0])

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        # Decode the form body the way a real server does.  Echoing the raw
        # wire form would show `%3Cscript%3E...` and legitimately fail the
        # "is this executable?" check -- the lab being wrong, not the replay.
        self._send("BODY[q]=" + parse_qs(raw).get("q", [""])[0])

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def lab():
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Lab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        yield base
    finally:
        srv.shutdown()
        srv.server_close()


def _case(name: str, base: str) -> dict:
    """Build the finding for one carrier."""
    if name == "query":
        return {"type": "reflected", "url": f"{base}/echo?q=test",
                "param": "q", "method": "GET", "payload": PAYLOAD}
    if name == "query-multi":
        return {"type": "reflected", "url": f"{base}/echo?id=7&q=old",
                "param": "q", "method": "GET", "payload": PAYLOAD}
    if name == "body-post":
        return {"type": "reflected", "url": f"{base}/echo?q=old",
                "param": "q", "method": "POST", "payload": PAYLOAD}
    if name == "header-marker":
        return {"type": "header_xss", "url": f"{base}/hdr",
                "param": "(header:X-Test)", "method": "GET",
                "payload": PAYLOAD}
    if name == "header-legacy":
        return {"type": "header_xss", "url": f"{base}/hdr",
                "param": "X-Test", "method": "GET", "payload": PAYLOAD}
    if name == "cookie-marker":
        return {"type": "cookie_xss", "url": f"{base}/ck",
                "param": "(cookie:sid)", "method": "GET", "payload": PAYLOAD}
    if name == "cookie-legacy":
        return {"type": "cookie_xss", "url": f"{base}/ck",
                "param": "sid", "method": "GET", "payload": PAYLOAD}
    if name == "path":
        return {"type": "path_xss", "url": f"{base}/p/{PAYLOAD}",
                "param": "", "method": "GET", "payload": PAYLOAD}
    if name == "error-page":
        return {"type": "error_page_xss", "url": f"{base}/p/{PAYLOAD}",
                "param": "", "method": "GET", "payload": PAYLOAD}
    raise AssertionError(f"unknown carrier {name!r}")


CARRIERS = ["query", "query-multi", "body-post", "header-marker",
            "header-legacy", "cookie-marker", "cookie-legacy", "path",
            "error-page"]


@pytest.mark.parametrize("name", CARRIERS)
def test_carrier_delivers_its_payload(name, lab):
    """Every carrier must land the payload on the target and confirm.

    A carrier that silently stops delivering reports ``fixed`` here -- which
    is exactly the failure mode that hid for the query carrier until a live
    lab exposed it.
    """
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    f = _case(name, lab)
    r = Requester(timeout=15, verify_ssl=False)      # fresh session per case
    out = vf._replay_request(r, f, PAYLOAD)
    assert out["status"] == "still_vuln", (
        f"{name}: payload did not reach the target "
        f"(status={out['status']!r}, detail={out.get('detail')!r})")


def test_negative_control_echoing_target_reports_fixed(lab):
    """The lab's /clean path echoes nothing, so the replay MUST say fixed.

    Without this the assertions above could pass for the wrong reason (e.g. a
    verifier that confirms everything).
    """
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    f = {"type": "reflected", "url": f"{lab}/clean?q=test", "param": "q",
         "method": "GET", "payload": PAYLOAD}
    r = Requester(timeout=15, verify_ssl=False)
    out = vf._replay_request(r, f, PAYLOAD)
    assert out["status"] == "fixed", (
        f"negative control failed: {out['status']!r} / {out.get('detail')!r}")


def test_session_state_change_is_not_served_from_the_get_cache(lab):
    """Locks the mechanism behind the second bug this file caught.

    The GET cache keys on the URL and can only see ``params`` / the
    per-request ``headers`` argument -- it is blind to anything the caller set
    on ``session``.  So a cached bare-URL GET shadows a later request whose
    meaning changed through the session, which is exactly what a replay does
    when it injects a header or a cookie.

    The first two assertions below document the trap; the third is the fix
    the replay now relies on (``cache_get=False``).
    """
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    r = Requester(timeout=15, verify_ssl=False)
    url = f"{lab}/hdr"

    r.session.headers["X-Test"] = "first"
    assert "first" in r.request("GET", url).text      # caches this URL

    r.session.headers["X-Test"] = "second"
    # Cache on: the stale body comes back even though the request changed.
    assert "first" in r.request("GET", url).text
    assert "second" not in r.request("GET", url).text

    # Cache off: the network is actually consulted.
    fresh = r.request("GET", url, cache_get=False).text
    assert "second" in fresh


def test_verify_findings_agrees_with_the_per_carrier_result(lab):
    """The public entry point must not swallow what the per-carrier path
    reports -- a mismatch would mean the verdicts users see differ from the
    verdicts this suite checks."""
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    findings = [_case(name, lab) for name in CARRIERS]
    r = Requester(timeout=15, verify_ssl=False)
    results = vf.verify_findings(findings, r, verbose=False)
    statuses = [(x.get("verify") or {}).get("status") for x in results]
    assert statuses.count("still_vuln") == len(CARRIERS), (
        f"expected every carrier to re-confirm, got {statuses}")
