"""Phase 135: the scanner now RUNS each PoC instead of only building it.

``attach_pocs()`` generated curl / browser-URL / HTML PoCs but never
executed one, so "reproducible PoC" was an assertion, not a measurement.
Nothing in a report distinguished a PoC that works from one that does not
-- measured on the project's own case pos-clobber-01, the low-severity
``dom`` (static L3 hint) finding's PoC does NOT reproduce, and only the
self-check could say so.

These tests use stub requesters, so they need no network.
"""
from __future__ import annotations

import html
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import verify_fix  # noqa: E402
from xssentinel.core.scanner import Scanner  # noqa: E402


class _Jar:
    def __init__(self):
        self._d = {}

    def get_dict(self):
        return dict(self._d)

    def set(self, k, v):
        self._d[k] = v

    def clear(self, k=None):
        if k is None:
            self._d.clear()
        else:
            self._d.pop(k, None)

    def get(self, k, default=None):
        return self._d.get(k, default)


class _Session:
    def __init__(self):
        self.headers = {}
        self.cookies = _Jar()


class _Resp:
    """``text`` is an attribute -- that is what _replay_request reads."""

    def __init__(self, text, headers=None):
        self.text = text
        self.headers = dict(headers or {})
        self.status_code = 200


class _StubReq:
    """Echoes the injected value, raw or escaped, like a real echo endpoint."""

    def __init__(self, escape=False, raise_on_request=False):
        self.calls = 0
        self.escape = escape
        self.raise_on_request = raise_on_request
        self.session = _Session()

    def request(self, method, url, params=None, data=None):
        self.calls += 1
        if self.raise_on_request:
            raise RuntimeError("boom")
        val = ""
        for d in (params, data):
            if isinstance(d, dict):
                val += str(d.get("q", ""))
        body = html.escape(val, quote=True) if self.escape else val
        return _Resp(f"<html><body><div>{body}</div></body></html>")


def _finding(**kw):
    base = {"url": "http://t/x", "method": "GET", "param": "q",
            "type": "reflected", "payload": "<script>alert(1)</script>",
            "severity": "high", "confidence": "high"}
    base.update(kw)
    return base


# --------------------------------------------------------------------------
# 1. verdict mapping
# --------------------------------------------------------------------------

def test_reproduces_means_verified():
    v = verify_fix.verify_poc(_StubReq(), _finding())
    assert v["verified"] is True, v
    assert v["status"] == "verified"
    assert "still executes" in v["detail"]


def test_escaped_replay_means_not_reproduced():
    v = verify_fix.verify_poc(_StubReq(escape=True), _finding())
    assert v["verified"] is False, v
    assert v["status"] == "not_reproduced"


def test_unreplayable_type_is_skipped_not_failed():
    """A blind finding has no headless replay path -- that is 'skipped',
    not 'not reproducable'."""
    v = verify_fix.verify_poc(_StubReq(), _finding(type="blind"))
    assert v["verified"] is None, v
    assert v["status"] == "skipped"
    assert _StubReq().calls == 0


def test_placeholder_payload_is_skipped():
    v = verify_fix.verify_poc(_StubReq(),
                              _finding(payload="(postMessage listener)"))
    assert v["verified"] is None
    assert v["status"] == "skipped"


def test_failed_request_is_an_error_not_a_pass():
    v = verify_fix.verify_poc(_StubReq(raise_on_request=True), _finding())
    assert v["verified"] is False
    assert v["status"] == "error"
    assert "boom" in v["detail"]


def test_verdict_always_carries_a_timestamp():
    v = verify_fix.verify_poc(_StubReq(), _finding())
    assert v["checked_at"]


# --------------------------------------------------------------------------
# 2. attach_pocs() wiring
# --------------------------------------------------------------------------

def _scanner(poc_verify, escape=False):
    sc = Scanner(requester=_StubReq(escape=escape), verbose=False,
                 poc_verify=poc_verify)
    sc.findings = []
    return sc


def test_attach_pocs_records_the_verdict_on_the_finding():
    sc = _scanner(poc_verify=True)
    from xssentinel.core.findings import Finding
    sc.findings = [Finding(**_finding())]
    sc.attach_pocs()
    f = sc.findings[0]
    assert f.data.get("poc_verified") is True, f.data.get("poc_verify")
    assert f.data["poc_verify"]["status"] == "verified"


def test_attach_pocs_records_a_wrong_poc_honestly():
    """The interesting case: the PoC exists but does not reproduce."""
    sc = _scanner(poc_verify=True, escape=True)
    from xssentinel.core.findings import Finding
    sc.findings = [Finding(**_finding())]
    sc.attach_pocs()
    assert sc.findings[0].data.get("poc_verified") is False
    assert sc.findings[0].data["poc_verify"]["status"] == "not_reproduced"


def test_replay_requests_are_counted():
    sc = _scanner(poc_verify=True)
    from xssentinel.core.findings import Finding
    sc.findings = [Finding(**_finding())]
    before = sc.requests_made
    sc.attach_pocs()
    assert sc.findings[0].data.get("poc_verified") is True
    assert sc.requests_made > before, (
        "the PoC replay drives the Requester directly; its requests must "
        "still show up in the scan total")


def test_poc_verify_off_makes_no_extra_request():
    sc = _scanner(poc_verify=False)
    from xssentinel.core.findings import Finding
    sc.findings = [Finding(**_finding())]
    before = sc.requests_made
    sc.attach_pocs()
    assert sc.requests_made == before
    assert "poc_verified" not in sc.findings[0].data


def test_poc_is_still_generated_when_verification_is_off():
    """Verification is additive: the curl/URL/HTML PoC is unaffected."""
    sc = _scanner(poc_verify=False)
    from xssentinel.core.findings import Finding
    sc.findings = [Finding(**_finding())]
    sc.attach_pocs()
    poc = sc.findings[0].data.get("poc") or {}
    assert poc.get("curl"), poc
    assert poc.get("url"), poc
