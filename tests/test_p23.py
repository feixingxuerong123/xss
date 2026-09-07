"""Phase 23 regression tests: report XSS fix, JUnit newline, logging."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.report import _safe_url, build_html, build_junit
from xssentinel.core.logger import configure_logging, get_logger


class _F:
    def __init__(self, d):
        self.data = d


def test_safe_url_http():
    assert _safe_url("http://example.com") == "http://example.com"
    assert _safe_url("https://example.com") == "https://example.com"


def test_safe_url_javascript_blocked():
    assert _safe_url("javascript:alert(1)") == ""
    assert _safe_url("data:text/html,<script>") == ""
    assert _safe_url("") == ""
    assert _safe_url(None) == ""


def test_html_report_no_xss_via_poc_url():
    """A javascript: poc_url must NOT become a clickable <a href> link."""
    f = _F({
        "type": "reflected", "url": "http://t/x", "method": "GET",
        "param": "q", "context": "html_element",
        "payload": "javascript:alert(1)",
        "severity": "high", "confidence": "high", "detail": "test",
        "poc": {"url": "javascript:alert(document.cookie)"},
    })
    html = build_html([f], "http://t", {})
    assert 'href="javascript:' not in html, "javascript: link leaked into report!"
    # The raw URL should still be visible as escaped text
    assert "javascript:alert" in html


def test_html_report_safe_http_url_still_clickable():
    f = _F({
        "type": "reflected", "url": "http://t/x", "method": "GET",
        "param": "q", "context": "html_element",
        "payload": "<script>alert(1)</script>",
        "severity": "high", "confidence": "high", "detail": "test",
        "poc": {"url": "http://t/x?q=test"},
    })
    html = build_html([f], "http://t", {})
    assert 'href="http://t/x?q=test"' in html


def test_junit_no_literal_backslash_n():
    """JUnit failure_msg must use real newlines, not literal \\n."""
    f = _F({
        "type": "reflected", "url": "http://t/x", "method": "GET",
        "param": "q", "payload": "<script>alert(1)</script>",
        "severity": "high", "detail": "detected",
    })
    junit = build_junit([f], "http://t", {})
    # The literal two-character sequence backslash + n must NOT appear
    assert "\\n" not in junit, "JUnit contains literal backslash-n!"
    # Real newlines must be present
    assert "\n" in junit


def test_logging_configure_and_emit():
    configure_logging("debug")
    log = get_logger("test_p23")
    log.info("logging works")


if __name__ == "__main__":
    tests = [
        test_safe_url_http,
        test_safe_url_javascript_blocked,
        test_html_report_no_xss_via_poc_url,
        test_html_report_safe_http_url_still_clickable,
        test_junit_no_literal_backslash_n,
        test_logging_configure_and_emit,
    ]
    for t in tests:
        t()
        print(f"[+] PASS: {t.__name__}")
    print(f"\nALL {len(tests)} P23 TESTS PASSED")
