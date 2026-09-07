"""Tests for core/marker_fuzz.py -- arbitrary-position FUZZ injection."""
from __future__ import annotations
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core.marker_fuzz import (
    fuzz_marker,
    fuzz_summary,
    replace_marker,
)


class _Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _EchoReq:
    """Echoes whatever body it receives back inside an HTML shell."""

    def __init__(self, escape=False):
        self.escape = escape
        self.bodies = []

    def request(self, method, url, params=None, data=None, headers=None):
        body = data.decode("utf-8", "replace") if isinstance(data, bytes) \
            else str(data or "")
        self.bodies.append(body)
        text = (body.replace("<", "&lt;") if self.escape else body)
        return _Resp(f"<html><div>{text}</div></html>")


TPL = '{"filter": FUZZ, "token": "abc"}'
PAYLOADS = ["<svg onload=alert(1)>", "plainmarker"]


class TestReplaceMarker:
    def test_replaces_every_occurrence(self):
        assert replace_marker("a-FUZZ-b-FUZZ", "FUZZ", "X") == "a-X-b-X"

    def test_empty_marker_raises(self):
        with pytest.raises(ValueError):
            replace_marker("tpl", "", "X")

    def test_marker_missing_raises(self):
        with pytest.raises(ValueError):
            replace_marker("no marker here", "FUZZ", "X")


class TestFuzzMarker:
    def test_reflected_payload_confirmed(self):
        req = _EchoReq()
        results = fuzz_marker(req, "http://t/api", "POST", TPL, "FUZZ",
                              PAYLOADS)
        assert len(results) == 2
        r0 = results[0]
        assert r0["payload"] == PAYLOADS[0]
        assert r0["reflected"] is True
        assert r0["confirmed"] is True       # svg onload is executable
        assert r0["confirmed"] is True

    def test_plain_marker_reflected_not_confirmed(self):
        req = _EchoReq()
        results = fuzz_marker(req, "http://t/api", "POST", TPL, "FUZZ",
                              PAYLOADS)
        r1 = results[1]
        assert r1["reflected"] is True
        assert r1["confirmed"] is False      # 'plainmarker' is inert text

    def test_bodies_carry_payload_not_marker(self):
        req = _EchoReq()
        fuzz_marker(req, "http://t/api", "POST", TPL, "FUZZ",
                    ["<b>x</b>"])
        assert "FUZZ" not in req.bodies[0]
        assert '"filter": <b>x</b>' in req.bodies[0]

    def test_missing_marker_raises_to_operator(self):
        req = _EchoReq()
        with pytest.raises(ValueError):
            fuzz_marker(req, "http://t/api", "POST", "no marker here",
                        "FUZZ", ["p"])

    def test_request_failure_recorded_not_raised(self):
        class _DeadReq:
            def request(self, *a, **kw):
                raise ConnectionError("killed")

        results = fuzz_marker(_DeadReq(), "http://t/", "POST", TPL, "FUZZ",
                              ["p"])
        assert results[0]["confirmed"] is False
        assert results[0]["error"] == "request failed"


class TestFuzzSummary:
    def test_summary_counts(self):
        results = [
            {"payload": "a", "reflected": True, "confirmed": True},
            {"payload": "b", "reflected": True, "confirmed": False},
            {"payload": "c", "reflected": False, "confirmed": False},
        ]
        s = fuzz_summary(results)
        assert s == {"total": 3, "confirmed": 1, "reflected_only": 1,
                     "first_confirmed": "a"}

    def test_empty(self):
        assert fuzz_summary([])["confirmed"] == 0
