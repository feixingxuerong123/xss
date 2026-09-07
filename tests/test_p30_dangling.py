"""Unit tests for the Dangling Markup Injection detection layer (Phase 30-2).

Tests cover:
  * analyze_page() static analysis -- detects pages at risk of dangling
    markup exfiltration (attribute reflection + nearby sensitive data).
  * verify_dangling() dynamic verification -- confirms a payload actually
    captured DOM content (quote unencoded + captured length > 0).
  * build_poc_html() PoC builder.
  * Negative controls: safe pages produce no violations.
  * Edge cases: empty input, encoded quotes, no closing quote, distance
    threshold.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import dangling_markup as dml


# ---------------------------------------------------------------------------
# Fixture HTML samples
# ---------------------------------------------------------------------------

# Page with CSRF token + attribute reflection of marker "PROBE" -- classic
# dangling markup risk: attacker injects dangling URL to capture the token.
CSRF_REFLECT_HTML = (
    '<html><body>'
    '<a href="/path?q=PROBE">link</a>'
    '<form action="/submit">'
    '<input type="hidden" name="csrf" value="abc123secret">'
    '<input type="text" name="q">'
    '</form>'
    '</body></html>'
)

# Page with hidden input value + attribute reflection.
HIDDEN_REFLECT_HTML = (
    '<html><body>'
    '<form action="/update">'
    '<input type="hidden" name="id" value="user-98765-profile">'
    '<a href="/p?next=PROBE">next</a>'
    '</form>'
    '</body></html>'
)

# Page with session meta tag + attribute reflection.
SESSION_META_HTML = (
    '<html><head>'
    '<meta name="csrf-token" content="tok_meta_xyz789">'
    '</head><body>'
    '<a href="/x?r=PROBE">x</a>'
    '</body></html>'
)

# Page with sensitive data + URL attributes but NO marker reflection --
# should report dangling_markup_potential (medium severity).
POTENTIAL_HTML = (
    '<html><body>'
    '<form action="/submit">'
    '<input type="hidden" name="csrfmiddlewaretoken" value="django_token_abc">'
    '</form>'
    '<a href="https://example.com/page">link</a>'
    '</body></html>'
)

# Safe page: no sensitive data, no reflection.
SAFE_HTML = (
    '<html><body>'
    '<a href="/page">link</a>'
    '<p>hello world</p>'
    '</body></html>'
)

# Page with sensitive data but NO URL attributes at all -- no risk.
NO_URL_ATTR_HTML = (
    '<html><body>'
    '<form>'
    '<input type="hidden" name="csrf" value="tok123">'
    '</form>'
    '<p>text only</p>'
    '</body></html>'
)

# Page where sensitive data is far from the reflection point (> 2000 chars).
DISTANT_SECRET_HTML = (
    '<html><body>'
    '<a href="/p?q=PROBE">link</a>'
    + ('<p>padding content without secrets</p>' * 150)
    + '<input type="hidden" name="csrf" value="far_away_token">'
    '</body></html>'
)


# ---------------------------------------------------------------------------
# analyze_page tests
# ---------------------------------------------------------------------------
class TestAnalyzePage:
    def test_csrf_reflect_risk_detected(self):
        result = dml.analyze_page(CSRF_REFLECT_HTML, extra_markers=["PROBE"])
        types = [v["type"] for v in result["violations"]]
        assert "dangling_markup_risk" in types, \
            f"expected dangling_markup_risk, got: {types}"

    def test_hidden_input_reflect_risk_detected(self):
        result = dml.analyze_page(HIDDEN_REFLECT_HTML, extra_markers=["PROBE"])
        types = [v["type"] for v in result["violations"]]
        assert "dangling_markup_risk" in types

    def test_session_meta_reflect_risk_detected(self):
        result = dml.analyze_page(SESSION_META_HTML, extra_markers=["PROBE"])
        types = [v["type"] for v in result["violations"]]
        assert "dangling_markup_risk" in types

    def test_potential_detected_without_marker(self):
        """Sensitive data + URL attributes but no marker -> potential."""
        result = dml.analyze_page(POTENTIAL_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "dangling_markup_potential" in types

    def test_risk_severity_is_high(self):
        result = dml.analyze_page(CSRF_REFLECT_HTML, extra_markers=["PROBE"])
        risk = [v for v in result["violations"] if v["type"] == "dangling_markup_risk"]
        assert risk and risk[0]["severity"] == "high"

    def test_potential_severity_is_medium(self):
        result = dml.analyze_page(POTENTIAL_HTML)
        pot = [v for v in result["violations"] if v["type"] == "dangling_markup_potential"]
        assert pot and pot[0]["severity"] == "medium"

    def test_risk_has_sensitive_data_type(self):
        result = dml.analyze_page(CSRF_REFLECT_HTML, extra_markers=["PROBE"])
        risk = [v for v in result["violations"] if v["type"] == "dangling_markup_risk"]
        assert risk and risk[0]["sensitive_data_type"] == "csrf_token"

    def test_risk_has_distance(self):
        result = dml.analyze_page(CSRF_REFLECT_HTML, extra_markers=["PROBE"])
        risk = [v for v in result["violations"] if v["type"] == "dangling_markup_risk"]
        assert risk and isinstance(risk[0]["distance"], int)
        assert risk[0]["distance"] > 0

    def test_distant_secret_not_reported(self):
        """Sensitive data > 2000 chars from reflection -> no risk."""
        result = dml.analyze_page(DISTANT_SECRET_HTML, extra_markers=["PROBE"])
        types = [v["type"] for v in result["violations"]]
        # Distant secret should not produce a risk finding (only potential
        # if URL attributes exist -- but the reflection with marker is
        # present, so we specifically check no dangling_markup_risk).
        assert "dangling_markup_risk" not in types, \
            f"distant secret should not be reported as risk: {types}"


# ---------------------------------------------------------------------------
# Negative controls
# ---------------------------------------------------------------------------
class TestNegativeControl:
    def test_safe_html_no_violations(self):
        result = dml.analyze_page(SAFE_HTML, extra_markers=["PROBE"])
        assert result["violations"] == [], \
            f"expected no violations, got: {[v['type'] for v in result['violations']]}"

    def test_empty_html_no_violations(self):
        assert dml.analyze_page("")["violations"] == []

    def test_no_sensitive_data_no_violations(self):
        """Page with reflection but no sensitive data -> no violation."""
        html = '<html><body><a href="/p?q=PROBE">link</a></body></html>'
        result = dml.analyze_page(html, extra_markers=["PROBE"])
        assert result["violations"] == []

    def test_no_url_attributes_no_violations(self):
        """Sensitive data but no href/src/action -> no violation."""
        result = dml.analyze_page(NO_URL_ATTR_HTML)
        assert result["violations"] == [], \
            f"expected no violations, got: {[v['type'] for v in result['violations']]}"

    def test_marker_not_reflected_no_risk(self):
        """Marker provided but not in HTML -> no risk (only potential)."""
        result = dml.analyze_page(CSRF_REFLECT_HTML, extra_markers=["NOTPRESENT"])
        types = [v["type"] for v in result["violations"]]
        assert "dangling_markup_risk" not in types


# ---------------------------------------------------------------------------
# Violation structure
# ---------------------------------------------------------------------------
class TestViolationStructure:
    def test_each_violation_has_required_keys(self):
        result = dml.analyze_page(CSRF_REFLECT_HTML, extra_markers=["PROBE"])
        for v in result["violations"]:
            assert "type" in v
            assert "severity" in v
            assert "title" in v
            assert "evidence" in v

    def test_severity_is_valid(self):
        result = dml.analyze_page(CSRF_REFLECT_HTML, extra_markers=["PROBE"])
        valid = {"high", "medium", "low", "info"}
        for v in result["violations"]:
            assert v["severity"] in valid, f"invalid severity: {v['severity']}"

    def test_returns_page_url(self):
        result = dml.analyze_page(SAFE_HTML, page_url="http://example.com/x")
        assert result["page_url"] == "http://example.com/x"


# ---------------------------------------------------------------------------
# verify_dangling tests
# ---------------------------------------------------------------------------
class TestVerifyDangling:
    def test_payload_not_reflected(self):
        """Payload absent from response -> reflected=False, success=False."""
        result = dml.verify_dangling("<html>no payload here</html>",
                                      dml.DANGLING_PAYLOADS["attr_dq"])
        assert result["reflected"] is False
        assert result["success"] is False
        assert result["captured_length"] == 0

    def test_payload_reflected_with_unencoded_quote_captures_content(self):
        """Reflected attr_dq payload with unencoded quote -> captures content."""
        payload = dml.DANGLING_PAYLOADS["attr_dq"]
        # Simulate a response where the payload is reflected into an
        # attribute, the quote is unencoded, and CSRF token follows.
        response = (
            '<html><body>'
            f'<input value="{payload}'  # payload reflected, quote unencoded
            '<input type="hidden" name="csrf" value="secret_tok">'
            '</body></html>'
        )
        result = dml.verify_dangling(response, payload)
        assert result["reflected"] is True
        assert result["quote_unencoded"] is True
        assert result["captured_length"] > 0
        assert result["success"] is True

    def test_captured_content_contains_csrf_token(self):
        """Captured content with CSRF token -> contains_sensitive_data.

        Uses single-quoted attributes downstream so the double-quote
        dangling payload captures past them (browser only stops at the
        matching quote type).
        """
        payload = dml.DANGLING_PAYLOADS["attr_dq"]
        response = (
            f'<input value="{payload}'
            "<input type='hidden' name='csrf' value='leaked_tok_abc'>"
            '"'
        )
        result = dml.verify_dangling(response, payload)
        assert result["contains_sensitive_data"] is True
        assert result["sensitive_data_type"] == "csrf_token"

    def test_captured_content_contains_hidden_input(self):
        """Captured content with hidden input value -> contains_sensitive_data."""
        payload = dml.DANGLING_PAYLOADS["attr_dq"]
        response = (
            f'<input value="{payload}'
            "<input type='hidden' name='id' value='user-secret-123'>"
            '"'
        )
        result = dml.verify_dangling(response, payload)
        assert result["contains_sensitive_data"] is True
        assert result["sensitive_data_type"] == "hidden_input_value"

    def test_captured_content_contains_generic_secret(self):
        """Captured content with generic secret pattern -> sensitive."""
        payload = dml.DANGLING_PAYLOADS["attr_dq"]
        response = (
            f'<input value="{payload}'
            "<meta name='x' content='token=generic_secret_value_abc'>"
            '"'
        )
        result = dml.verify_dangling(response, payload)
        assert result["contains_sensitive_data"] is True
        # generic_secret or session_meta -- either is acceptable
        assert result["sensitive_data_type"] is not None

    def test_no_closing_quote_captures_to_end(self):
        """No closing quote after payload -> capture extends to end of response."""
        payload = dml.DANGLING_PAYLOADS["attr_dq"]
        response = f'<input value="{payload}some trailing content without quotes'
        result = dml.verify_dangling(response, payload)
        assert result["success"] is True
        assert result["captured_length"] > 0
        assert "trailing content" in result["captured_preview"]

    def test_url_dangling_payload(self):
        """URL-context dangling payload (no leading quote) with unencoded attr quote."""
        payload = dml.DANGLING_PAYLOADS["url_dangling"]
        # The attribute's opening quote is unencoded (the " before payload).
        response = (
            f'<a href="{payload}'
            '<input type="hidden" name="csrf" value="tok_xyz">'
            '"'
        )
        result = dml.verify_dangling(response, payload)
        assert result["reflected"] is True
        assert result["quote_unencoded"] is True
        assert result["success"] is True

    def test_empty_response(self):
        result = dml.verify_dangling("", dml.DANGLING_PAYLOADS["attr_dq"])
        assert result["reflected"] is False
        assert result["success"] is False

    def test_empty_payload(self):
        result = dml.verify_dangling("<html></html>", "")
        assert result["reflected"] is False
        assert result["success"] is False

    def test_captured_preview_truncated(self):
        """Captured preview should be at most 200 chars."""
        payload = dml.DANGLING_PAYLOADS["attr_dq"]
        long_content = "x" * 500
        response = f'<input value="{payload}{long_content}"'
        result = dml.verify_dangling(response, payload)
        assert len(result["captured_preview"]) <= 200


# ---------------------------------------------------------------------------
# build_poc_html tests
# ---------------------------------------------------------------------------
class TestBuildPoc:
    @pytest.mark.parametrize("context", ["attr_dq", "attr_sq", "attr_noquote",
                                          "url_dangling"])
    def test_poc_returns_nonempty_string(self, context):
        poc = dml.build_poc_html("http://example.com/", context=context)
        assert isinstance(poc, str)
        assert len(poc) > 10

    def test_poc_contains_url(self):
        poc = dml.build_poc_html("http://example.com/", context="attr_dq")
        assert "http://example.com/" in poc

    def test_poc_contains_attacker_url(self):
        """PoC should reference the attacker exfiltration URL."""
        poc = dml.build_poc_html("http://example.com/", context="attr_dq")
        assert "attacker.example" in poc or "attacker" in poc.lower()

    def test_poc_with_captured_content(self):
        poc = dml.build_poc_html("http://example.com/", context="attr_dq",
                                  captured_content="csrf_token=abc123")
        assert "csrf_token=abc123" in poc or "Captured" in poc

    def test_poc_unknown_context_uses_default(self):
        """Unknown context falls back to attr_dq payload."""
        poc = dml.build_poc_html("http://example.com/", context="unknown_ctx")
        assert isinstance(poc, str)
        assert "attacker.example" in poc
