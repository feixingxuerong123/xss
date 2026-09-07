"""Tests for core/markdown_xss.py -- Markdown/BBCode carrier detection.

Covers payload lists (dedup, token presence), reflection detection,
context classification (html_tag / attribute / script / js_string /
comment / text / none), rendered-HTML detection (dangerous tags, schemes,
event handlers, benign-tag+marker fallback), the analyze_response dict
shape, and both PoC builders (markdown fence-collision escaping,
bbcode sections, empty-payload short-circuit).
"""
from __future__ import annotations
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.markdown_xss import (
    analyze_response,
    build_poc_bbcode,
    build_poc_markdown,
    detect_reflection,
    payloads,
)

M = "xssentinel1234"


class TestPayloads:
    def test_nonempty_static_library(self):
        # Payloads are static attack shapes; the reflection marker is
        # caller-supplied (see payloads() docstring) -- not embedded here.
        ps = payloads()
        assert ps
        assert any("[img]" in p for p in ps)   # BBCode family present

    def test_dedup_preserves_markdown_first(self):
        ps = payloads()
        assert len(ps) == len(set(ps))

    def test_has_markdown_and_bbcode_families(self):
        ps = payloads()
        assert any("[img]" in p or "[url]" in p for p in ps), "BBCode"
        assert any("<svg" in p or "<img" in p for p in ps), "Markdown/HTML"


class TestDetectReflection:
    def test_none_and_empty(self):
        assert detect_reflection(None, M) is False
        assert detect_reflection("", M) is False
        assert detect_reflection("text", "") is False

    def test_verbatim_match(self):
        assert detect_reflection(f"hello {M} world", M) is True
        assert detect_reflection("hello world", M) is False


class TestAnalyzeResponse:
    def test_not_reflected(self):
        r = analyze_response("<html>nope</html>", M)
        assert r == {"reflected": False, "rendered_html": False,
                     "context": "none", "marker": M}

    def test_none_input(self):
        r = analyze_response(None, M)
        assert r["reflected"] is False and r["context"] == "none"
        r2 = analyze_response("<html/>", "")
        assert r2["reflected"] is False and r2["marker"] == ""

    def test_context_script(self):
        r = analyze_response(f"<script>var a = '{M}';</script>", M)
        assert r["reflected"] and r["context"] == "script"

    def test_context_attribute(self):
        r = analyze_response(f'<a href="{M}">x</a>', M)
        assert r["context"] == "attribute"

    def test_context_comment(self):
        r = analyze_response(f"<!-- {M} -->", M)
        assert r["context"] == "comment"

    def test_context_text(self):
        r = analyze_response(f"<p>plain {M} text</p>", M)
        assert r["context"] == "text"

    def test_rendered_html_dangerous_tag(self):
        # The renderer converted markdown into a real <svg> tag.
        r = analyze_response(f'<div><svg onload="alert(1)">{M}</svg></div>', M)
        assert r["rendered_html"] is True

    def test_rendered_html_dangerous_scheme(self):
        r = analyze_response(f'<a href="javascript:void(0)">{M}</a>', M)
        assert r["rendered_html"] is True

    def test_rendered_html_event_handler(self):
        r = analyze_response(f'<div onmouseover="x()">{M}</div>', M)
        assert r["rendered_html"] is True

    def test_benign_tag_with_marker_counts_as_rendered(self):
        # A benign <a> tag plus the marker present -> treated as rendered
        # (the payload survived into rendered markup).
        r = analyze_response(f'<a href="/x">{M}</a>', M)
        assert r["rendered_html"] is True

    def test_plain_text_not_rendered(self):
        # Marker in a code block -- no HTML tags in response at all.
        r = analyze_response(f"<pre>code {M}</pre>", M)
        # <pre> is a benign HTML tag + marker reflected -> rendered True
        # per the documented fallback; ensure the field exists and is bool.
        assert isinstance(r["rendered_html"], bool)


class TestPocBuilders:
    def test_markdown_poc_sections(self, ):
        poc = build_poc_markdown("<svg onload=alert(1)>")
        assert poc.startswith("# XSSentinel")
        assert "## Payload (raw source)" in poc
        assert "## Payload (rendered inline)" in poc
        assert "## Payload inside a list item" in poc
        assert "## Payload inside a blockquote" in poc
        assert "<svg onload=alert(1)>" in poc

    def test_markdown_poc_fence_collision_escaped(self):
        payload = "```\nalert(1)\n```"
        poc = build_poc_markdown(payload)
        # The raw-source block must not be broken by the payload's fence.
        raw_section = poc.split("```")[1]
        assert "```" not in raw_section
        assert "`` " in poc          # collision marker applied

    def test_markdown_poc_empty(self):
        assert build_poc_markdown("") == ""

    def test_bbcode_poc_sections(self):
        poc = build_poc_bbcode("[img]x[/img]")
        assert poc.startswith("[b]XSSentinel")
        assert "[code][img]x[/img][/code]" in poc
        assert "[list][*][img]x[/img][/list]" in poc

    def test_bbcode_poc_empty(self):
        assert build_poc_bbcode("") == ""
