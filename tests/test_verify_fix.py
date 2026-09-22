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
    """A stand-in for requests.Response.

    ``status_code`` matters: Phase 176e makes a replay that comes back 4xx/5xx
    unjudgeable rather than "fixed", so a stand-in without a status code stops
    standing in for the real object (it was an AttributeError waiting for the
    first replay that reflected nothing).
    """

    def __init__(self, text="", status_code=200):
        self._t = text
        self.status_code = status_code
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
    """Captures what a replay actually sends on the wire.

    ``response`` decides what the replay sees back.  Defaults to a 200 with an
    empty body (as before), so the carrier tests keep asserting on ``calls``
    alone; passing a response drives the "nothing reflected" branch that
    Phase 176e classifies.
    """

    def __init__(self, response=None):
        self.session = _Session()
        self.calls = []
        self.response = response

    def request(self, method, url, params=None, data=None, **kw):
        self.calls.append({
            "method": method, "url": url, "params": params or {},
            "data": data or {},
            "session_headers": dict(self.session.headers),
            "session_cookies": dict(self.session.cookies.items()),
        })
        if callable(self.response):
            # A callable is how a test echoes the freshly-tokenized payload
            # back: the token is minted per replay, so a fixed body cannot do
            # it.  See tests/test_p25.py for the same shape.
            return self.response(method, url, params, data)
        return self.response if self.response is not None else _Resp()


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


class TestUnjudgeableReplay:
    """Phase 176e -- "nothing came back" is not the same as "fixed".

    A 404 means the endpoint moved, a 403 means a WAF or auth layer answered
    instead of the app, a 5xx means the app is down, and a sign-in page means
    the session expired.  All four return a body with no payload in it, and all
    four used to be reported as "fixed" with the SAME detail string as a
    genuine remediation -- while the CI gate only fails on still_vuln, so a
    never-tested endpoint passed straight through as remediated.

    This is the third member of one family, and the reason each deserves a
    test: 176c (the URL already carried the parameter, so the payload never
    arrived), 176d (the GET cache served an earlier replay's body) and 176e
    (the replay never reached a working endpoint).  Every one of them produced
    the same lie -- "fixed" -- from a different cause.
    """

    @staticmethod
    def _replay(response):
        r = _FakeRequester(response=response)
        f = dict(_finding("reflected", "q"), url="http://t/s?q=test")
        out = _replay_request(r, f, "<script>alert(1)</script>")
        return r, out

    # -- the four "we never got to test it" shapes -------------------------

    def test_404_is_not_a_fix(self):
        _, out = self._replay(_Resp("<h1>Not Found</h1>", status_code=404))
        assert out["status"] == "error", out
        assert "404" in out["detail"]
        assert "cannot be judged" in out["detail"]

    def test_5xx_is_not_a_fix(self):
        _, out = self._replay(_Resp("<h1>Oops</h1>", status_code=503))
        assert out["status"] == "error", out
        assert "503" in out["detail"]

    def test_403_is_not_a_fix(self):
        _, out = self._replay(_Resp("Forbidden", status_code=403))
        assert out["status"] == "error", out

    def test_sign_in_page_is_not_a_fix(self):
        page = '<form action="/login"><input type="password" name="pw"></form>'
        _, out = self._replay(_Resp(page, status_code=200))
        assert out["status"] == "error", out
        assert "sign-in" in out["detail"]

    def test_sign_in_detection_tolerates_spacing_and_case(self):
        _, out = self._replay(_Resp("<input TYPE = 'PASSWORD' name=pw>",
                                    status_code=200))
        assert out["status"] == "error", out

    # -- the reverse direction: a genuine fix must survive -----------------

    def test_a_genuine_fix_is_still_fixed(self):
        """A 200 that simply no longer echoes the input IS the remediation
        signal; the new checks must not swallow it."""
        _, out = self._replay(_Resp("<p>You searched for: test</p>",
                                    status_code=200))
        assert out["status"] == "fixed", out
        assert "no longer reflected" in out["detail"]

    def test_the_word_password_alone_does_not_downgrade_a_fix(self):
        """The regex matches a password INPUT, not the word.  A result page
        that merely mentions "password" is a legitimate fix, and downgrading
        every page that says it would be its own false-negative machine."""
        _, out = self._replay(_Resp("<p>Your password was changed.</p>",
                                    status_code=200))
        assert out["status"] == "fixed", out

    # -- the layer below must not be pre-empted ----------------------------

    def test_a_404_that_still_reflects_is_still_vuln(self):
        """error_page_xss and path_xss legitimately answer 404/500 WHILE
        reflecting the payload.  The status check sits inside the "nothing
        reflected" branch precisely so it cannot pre-empt a live confirmation
        and report an open hole as merely unjudgeable."""
        def echo(method, url, params, data):
            p = (params or {}).get("q") or (data or {}).get("q") or ""
            return _Resp(f"<html><body>{p}</body></html>", status_code=404)

        r = _FakeRequester(response=echo)
        f = dict(_finding("reflected", "q"), url="http://t/s?q=test")
        out = _replay_request(r, f, "<script>alert('ORIG')</script>")
        assert out["status"] == "still_vuln", out

    def test_a_sign_in_page_that_still_reflects_is_still_vuln(self):
        """Same guard from the other side: an app that reflects inside a page
        which also happens to contain a password field is still exploitable --
        the session-expiry heuristic must not outrank a live confirmation."""
        def echo(method, url, params, data):
            p = (params or {}).get("q") or (data or {}).get("q") or ""
            return _Resp(f'<form><input type="password"></form>'
                         f"<body>{p}</body>", status_code=200)

        r = _FakeRequester(response=echo)
        f = dict(_finding("reflected", "q"), url="http://t/s?q=test")
        out = _replay_request(r, f, "<script>alert('ORIG')</script>")
        assert out["status"] == "still_vuln", out
