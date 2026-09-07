"""Tests for core/cookie_xss.py -- cookie-value XSS carrier.

Covers payload/cookie-name lists (cookie-safe transport constraint),
reflection detection, context classification (incl. the Phase 77
most-specific-first order: attribute must not be swallowed by html_tag,
script blocks must not be swallowed by the attribute regex), the
cookie-value encoder (unsafe chars encoded, HTML metachars preserved),
and the curl / HTML PoC builders (shell quoting, JS-string escaping,
XFO fallback link, empty-arg short-circuits).
"""
from __future__ import annotations
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.cookie_xss import (
    analyze_response,
    build_poc_curl,
    build_poc_html,
    candidate_cookies,
    cookie_payloads,
    detect_reflection,
)

M = "xssentinel1234"


class TestLists:
    def test_payloads_transport_safe_after_encoding(self):
        # Raw payloads may contain cookie-unsafe chars; the CONTRACT is
        # that the encoder makes them transport-safe (Phase 77).
        from xssentinel.core.cookie_xss import _cookie_encode_value
        assert cookie_payloads()
        for p in cookie_payloads():
            enc = _cookie_encode_value(p)
            assert ";" not in enc and " " not in enc and "," not in enc, p

    def test_candidate_cookies_common_names(self):
        cands = candidate_cookies()
        assert "theme" in cands and "lang" in cands
        assert len(cands) == len(set(cands))


class TestDetectReflection:
    def test_none_empty_missing(self):
        assert detect_reflection(None, M) is False
        assert detect_reflection("", M) is False
        assert detect_reflection("data", "") is False

    def test_verbatim(self):
        assert detect_reflection(f"v={M};", M) is True


class TestAnalyzeResponse:
    def test_not_reflected(self):
        r = analyze_response("<html>x</html>", M)
        assert r == {"reflected": False, "context": "none", "marker": M}

    def test_attribute_not_swallowed_by_html_tag(self):
        # Phase 77: marker inside an attribute VALUE must classify as
        # attribute, not html_tag.
        r = analyze_response(f'<div data-x="{M}">x</div>', M)
        assert r["reflected"] and r["context"] == "attribute"

    def test_script_block_not_swallowed_by_attribute_regex(self):
        # Phase 77: a JS assignment inside <script> looks like "attr ="
        # to the broad attribute regex -- script block must win.
        r = analyze_response(f"<script>var a = '{M}';</script>", M)
        assert r["context"] == "script"

    def test_comment_context(self):
        r = analyze_response(f"<!-- {M} -->", M)
        assert r["context"] == "comment"

    def test_text_fallback(self):
        r = analyze_response(f"plain {M} text", M)
        assert r["context"] == "text"


class TestCookieEncoder:
    def test_unsafe_chars_encoded(self):
        from xssentinel.core.cookie_xss import _cookie_encode_value
        v = _cookie_encode_value('a;b c,d"e\\f')
        assert ";" not in v and " " not in v and "," not in v
        assert '"' not in v and "\\" not in v

    def test_html_metachars_preserved(self):
        from xssentinel.core.cookie_xss import _cookie_encode_value
        v = _cookie_encode_value("<svg onload=alert(1)>")
        assert "<svg" in v and "onload" in v and ">" in v

    def test_empty(self):
        from xssentinel.core.cookie_xss import _cookie_encode_value
        assert _cookie_encode_value("") == ""


class TestPocBuilders:
    def test_curl_quotes_and_encodes(self):
        poc = build_poc_curl("http://t/page", "theme",
                             '<svg onload=alert(1)>;extra')
        assert poc.startswith("curl -i")
        assert "http://t/page" in poc
        assert "Cookie:" in poc
        # The raw semicolon cannot survive (would split the cookie).
        import re as _re
        m = _re.search(r"theme=([^']*)", poc)
        assert m and ";" not in m.group(1)

    def test_curl_empty_args(self):
        assert build_poc_curl("", "theme", "p") == ""
        assert build_poc_curl("http://t/", "", "p") == ""

    def test_html_poc_sets_cookie_and_iframe(self):
        poc = build_poc_html("http://t/page?a=1&b=2", "theme",
                             "<svg onload=alert(1)>")
        assert "document.cookie = " in poc
        assert "theme=" in poc
        assert "<iframe" in poc
        assert "http://t/page?a=1&amp;b=2" in poc   # attr-escaped URL
        assert "open http://t/page" in poc          # XFO fallback link

    def test_html_poc_escapes_js_quotes(self):
        poc = build_poc_html("http://t/", "theme", "x'y")
        assert "\\'" in poc                          # JS-string escaped

    def test_html_poc_empty_args(self):
        assert build_poc_html("", "theme", "p") == ""
        assert build_poc_html("http://t/", "", "p") == ""
