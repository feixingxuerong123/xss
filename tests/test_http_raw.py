"""Tests for core/http_raw.py -- raw HTTP request file parsing."""
from __future__ import annotations
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core.http_raw import RawRequestError, parse_raw_request


RAW_GET = (
    "GET /search?q=probe HTTP/1.1\r\n"
    "Host: target.test\r\n"
    "User-Agent: burp\r\n"
    "Cookie: session=abc123\r\n"
    "\r\n"
)

RAW_POST = (
    "POST /api/comment HTTP/1.1\r\n"
    "Host: target.test\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 12\r\n"
    "\r\n"
    "comment=hi!!"
)


class TestParseRawRequest:
    def test_get_with_host_and_cookie(self):
        r = parse_raw_request(RAW_GET)
        assert r["method"] == "GET"
        assert r["url"] == "http://target.test/search?q=probe"
        assert r["cookies"] == "session=abc123"
        assert r["headers"]["User-Agent"] == "burp"
        assert r["body"] == ""

    def test_post_body_preserved(self):
        r = parse_raw_request(RAW_POST)
        assert r["method"] == "POST"
        assert r["url"] == "http://target.test/api/comment"
        assert r["body"] == "comment=hi!!"
        assert "form-urlencoded" in r["content_type"]

    def test_absolute_form_target_wins(self):
        raw = ("GET https://other.test/p HTTP/1.1\r\n"
               "Host: target.test\r\n\r\n")
        assert parse_raw_request(raw)["url"] == "https://other.test/p"

    def test_https_from_port_443(self):
        raw = "GET /x HTTP/1.1\r\nHost: secure.test:443\r\n\r\n"
        assert parse_raw_request(raw)["url"].startswith("https://")

    def test_missing_host_raises(self):
        with pytest.raises(RawRequestError):
            parse_raw_request("GET / HTTP/1.1\r\n\r\n")

    def test_malformed_request_line_raises(self):
        with pytest.raises(RawRequestError):
            parse_raw_request("GARBAGE\r\nHost: x\r\n\r\n")

    def test_malformed_header_raises(self):
        with pytest.raises(RawRequestError):
            parse_raw_request("GET / HTTP/1.1\r\nHost: x\r\nBADHEADER\r\n\r\n")

    def test_empty_raises(self):
        with pytest.raises(RawRequestError):
            parse_raw_request("")

    def test_bare_lf_normalised(self):
        raw = RAW_GET.replace("\r\n", "\n")
        r = parse_raw_request(raw)
        assert r["url"] == "http://target.test/search?q=probe"
