# -*- coding: utf-8 -*-
"""Phase 98: PoC replay headers.

An authenticated API target guarded by ``Authorization: Bearer`` (or
X-API-Key / custom anti-bot headers) 401s every cookie-less curl PoC --
and cookies alone cannot carry the credential.  The session's
replay-worthy headers must ride along as ``-H`` args; transport-control
headers and Cookie (its own ``-b`` channel) must be filtered out.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core.poc import build_poc, _poc_headers


def _finding(**over):
    d = {"url": "https://api.example.com/items", "method": "GET",
         "param": "q", "type": "reflected", "payload": "<svg onload=x>",
         "context": "html_element", "severity": "high"}
    d.update(over)
    return d


def test_auth_header_lands_in_curl():
    poc = build_poc(_finding(), headers={"Authorization": "Bearer tk123"})
    assert "-H 'Authorization: Bearer tk123'" in poc["curl"]
    assert poc["replay_headers"] == {"Authorization": "Bearer tk123"}


def test_transport_control_headers_filtered():
    hdrs = {"Authorization": "Bearer tk", "Host": "api.example.com",
            "Content-Length": "17", "Connection": "keep-alive",
            "Accept": "*/*", "Accept-Encoding": "gzip",
            "Cookie": "sid=1", "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (compatible; XSSentinel)"}
    poc = build_poc(_finding(method="POST"), headers=hdrs)
    curl = poc["curl"]
    assert "-H 'Authorization: Bearer tk'" in curl
    assert "-H 'User-Agent: Mozilla/5.0 (compatible; XSSentinel)'" in curl
    for gone in ("Host:", "Content-Length:", "Connection:",
                 "Accept:", "Accept-Encoding:", "Cookie:",
                 "Content-Type:"):
        assert f"-H '{gone}" not in curl, gone


def test_post_body_poc_carries_headers():
    d = _finding(method="POST")
    poc = build_poc(d, headers={"X-API-Key": "k999"},
                    cookies={"sid": "abc"})
    assert "-H 'X-API-Key: k999'" in poc["curl"]
    assert "-b 'sid=abc'" in poc["curl"]
    assert "--data" in poc["curl"]


def test_transport_layer_finding_also_replays_headers():
    # header-carrier finding: the payload header is generated, but the
    # session's auth headers must ride along too
    d = _finding(param="(header:X-Pwn)", method="GET")
    poc = build_poc(d, headers={"Authorization": "Bearer tk"})
    assert "-H 'X-Pwn:" in poc["curl"]
    assert "-H 'Authorization: Bearer tk'" in poc["curl"]
    # no auth context -> unchanged behaviour
    poc2 = build_poc(_finding(param="(header:X-Pwn)"))
    assert "-H 'Authorization" not in poc2["curl"]


def test_no_headers_no_change():
    poc_none = build_poc(_finding())
    poc_empty = build_poc(_finding(), headers={})
    assert "replay_headers" not in poc_none
    assert "replay_headers" not in poc_empty
    assert poc_none["curl"] == poc_empty["curl"]


def test_poc_headers_none_values_dropped():
    out = _poc_headers({"A": "1", "B": None})
    assert out == {"A": "1"}


def test_upload_poc_carries_auth_header():
    d = _finding(method="POST", type="upload_xss",
                 param="avatar[filename]", payload="x<svg onload=y>")
    poc = build_poc(d, headers={"X-Auth": "t"})
    assert "-H 'X-Auth: t'" in poc["curl"]
    assert "-F 'avatar=@/dev/null;filename=" in poc["curl"]


# --------------------------------------------------------------------------
# Integration: the ASYNC CLI path must bridge its session credentials into
# the sync shim before attach_pocs.  Regression for the gap found in the
# Phase 98 review: Scanner(requester=None) had an EMPTY session, so both
# Phase 48 cookies and Phase 98 headers silently no-op'd on --async scans.
# --------------------------------------------------------------------------

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests.conftest import SOCKETPAIR_OK

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback degraded (security software/TCP state)")


class _EchoHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        # RAW reflection (pos-elem shape): an escaped echo would be a TN --
        # the escaped-reflection convergence correctly finds nothing there.
        body = f"<!DOCTYPE html><html><body><div>{q}</div></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())


def test_async_cli_poc_replays_credentials():
    from xssentinel.cli_runner import _run_async_scan
    from xssentinel.__main__ import build_parser

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        argv = [
            "--async", "-u", f"http://127.0.0.1:{port}/echo?q=probe",
            "-b", "sid=abc",
            "-H", "X-API-Key: k9",
            "--poc-auth", "--threads", "2", "--timeout", "15",
            "--max-payloads", "6", "--max-transforms", "4",
        ]
        args = build_parser().parse_args(argv)
        # NOTE: pass the FULL URL (query included), exactly like
        # __main__ does -- _run_async_scan parses the query of its
        # second argument into the scan params.
        shim = _run_async_scan(
            args, f"http://127.0.0.1:{port}/echo?q=probe",
            oob=None, progress=None, checkpoint=None)
        assert shim is not None and shim.findings, "async scan found nothing"
        curls = [f.data.get("poc", {}).get("curl", "")
                 for f in shim.findings if f.data.get("poc")]
        assert curls, "no PoC generated on the async path"
        assert any("-b 'sid=abc'" in c for c in curls), (
            f"session cookie missing from async PoCs: {curls[:1]}")
        assert any("-H 'X-API-Key: k9'" in c for c in curls), (
            f"session header missing from async PoCs: {curls[:1]}")
    finally:
        srv.shutdown()
