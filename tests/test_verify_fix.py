"""Tests for verify-fix replay fidelity on non-query carriers.

verify-fix re-sends each confirmed finding to see whether it still fires.
Like the exporters, it must place (header:X)/(cookie:X) payloads on the
real header / Cookie instead of a query slot -- a query-slot replay can
never re-confirm a header echo and would report a still-vulnerable header
XSS as 'fixed'.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.verify_fix import _replay_request


class _Resp:
    def __init__(self, text=""):
        self._t = text
        self.headers = {}

    @property
    def text(self):
        return self._t


class _Jar:
    def __init__(self):
        self._d = {}

    def set(self, name, value):
        self._d[name] = value

    def get(self, name, default=None):
        return self._d.get(name, default)

    def clear(self, name):
        self._d.pop(name, None)

    def items(self):
        return list(self._d.items())


class _Session:
    def __init__(self):
        self.headers = {}
        self.cookies = _Jar()


class _FakeRequester:
    """Captures what a replay actually sends on the wire."""

    def __init__(self):
        self.session = _Session()
        self.calls = []

    def request(self, method, url, params=None, data=None, **kw):
        self.calls.append({
            "method": method, "url": url, "params": params or {},
            "data": data or {},
            "session_headers": dict(self.session.headers),
            "session_cookies": dict(self.session.cookies.items()),
        })
        return _Resp()


def _finding(ftype, param):
    return {
        "type": ftype, "url": "http://t/s", "method": "GET",
        "param": param, "payload": "<svg/onload=alert(1)>",
    }


class TestReplayCarriers:
    def test_header_marker_replays_on_the_header(self):
        r = _FakeRequester()
        _replay_request(r, _finding("header_xss", "(header:User-Agent)"),
                        "<svg/onload=alert(1)>")
        call = r.calls[-1]
        ua = call["session_headers"].get("User-Agent", "")
        assert "vfix_" in ua and "<svg" in ua      # marked payload on UA
        assert "(header" not in str(call["params"])  # never a query slot
        assert "_" not in call["params"]
        # header restored after the replay
        assert "User-Agent" not in r.session.headers

    def test_legacy_bare_header_name_still_works(self):
        r = _FakeRequester()
        _replay_request(r, _finding("header_xss", "User-Agent"),
                        "<svg/onload=alert(1)>")
        ua = r.calls[-1]["session_headers"].get("User-Agent", "")
        assert "vfix_" in ua

    def test_cookie_marker_sets_and_restores_the_cookie(self):
        r = _FakeRequester()
        _replay_request(r, _finding("cookie_xss", "(cookie:sid)"),
                        "<svg/onload=alert(1)>")
        cookies = r.calls[-1]["session_cookies"]
        assert "sid" in cookies and "vfix_" in cookies["sid"]
        # jar restored to its original (empty) state after the replay
        assert r.session.cookies.items() == []

    def test_cookie_restores_preexisting_value(self):
        r = _FakeRequester()
        r.session.cookies.set("sid", "original")
        _replay_request(r, _finding("cookie_xss", "(cookie:sid)"),
                        "<svg/onload=alert(1)>")
        assert r.session.cookies.get("sid") == "original"

    def test_query_finding_unchanged(self):
        r = _FakeRequester()
        _replay_request(r, _finding("reflected", "q"),
                        "<script>alert(1)</script>")
        q = r.calls[-1]["params"].get("q", "")
        assert q.startswith("<script>")

    def test_query_param_is_replaced_not_duplicated(self):
        """Regression (Phase 176c): a finding URL carrying the target
        parameter -- `?q=test`, exactly what a scan emits -- must not put TWO
        `q=` on the wire.  Servers read the first, so the payload never
        arrives, nothing reflects, and the replay wrongly reports the hole as
        FIXED.  Observed live against a reflector that echoes every input."""
        r = _FakeRequester()
        f = dict(_finding("reflected", "q"), url="http://t/s?q=test")
        _replay_request(r, f, "<script>alert(1)</script>")
        call = r.calls[-1]
        assert call["url"] == "http://t/s"           # query moved into params
        assert "?" not in call["url"]
        assert call["params"]["q"].startswith("<script>")
        assert call["params"]["q"] != "test"

    def test_sibling_query_params_survive_the_injection(self):
        """Only the target parameter is rewritten; the rest of the query still
        has to be sent, or the replay stops resembling the original request."""
        r = _FakeRequester()
        f = dict(_finding("reflected", "q"), url="http://t/s?id=7&q=test")
        _replay_request(r, f, "<script>alert(1)</script>")
        params = r.calls[-1]["params"]
        assert params["id"] == "7"
        assert params["q"].startswith("<script>")

    def test_post_body_injection_is_unaffected_by_url_query(self):
        r = _FakeRequester()
        f = dict(_finding("reflected", "q"), url="http://t/s?q=test",
                 method="POST")
        _replay_request(r, f, "<script>alert(1)</script>")
        call = r.calls[-1]
        assert call["data"]["q"].startswith("<script>")
        assert call["url"] == "http://t/s"
