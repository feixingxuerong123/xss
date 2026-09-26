# -*- coding: utf-8 -*-
"""Verifier unit suite: the judgment layer's edges, pinned directly.

scanner/async carry the verifier through every scan, but its own
decision edges had no direct tests except event-handler and js-URI/CSP
slices.  Pinned here:

  * mark() -- every alert shape (bare, arg'd, tagged-template) and the
    concat stamp's two fallbacks (arm an on* handler value, arm a
    javascript: URI) plus the unarmed no-op contract,
  * verify_semantic() -- RCDATA inertness BOTH ways (the raw-text scan
    exists precisely because BeautifulSoup mis-parses inside
    <textarea>/<title>/<xmp>), and the closing-tag breakout next to it,
  * the CSP inline matrix, including the Phase 98 subtlety: with a
    nonce/hash present, 'unsafe-inline' is INERT per CSP L2+, so the
    gate must still block,
  * is_marker_escaped() -- the adjacent-entity contract that drives the
    Phase 27-1 budget convergence.

No network, no browser.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import context as ctx
from xssentinel.core import verifier

TOK = "xssv_deadbeef"


# ---------------------------------------------------------------------------
# mark()
# ---------------------------------------------------------------------------

class TestMark:
    def test_bare_alert_is_stamped(self):
        out = verifier.mark("<script>alert(1)</script>", TOK)
        assert f"alert('{TOK}')" in out

    def test_alert_with_argument_is_replaced_wholesale(self):
        out = verifier.mark("<script>alert(document.domain)</script>", TOK)
        assert "document.domain" not in out
        assert f"alert('{TOK}')" in out

    def test_quoted_argument_shape(self):
        out = verifier.mark("<script>alert('xss')</script>", TOK)
        assert f"alert('{TOK}')" in out and "'xss'" not in out

    def test_tagged_template_alert(self):
        out = verifier.mark("<script>alert`1`</script>", TOK)
        assert f"alert`{TOK}`" in out

    def test_concat_stamp_replaces_the_callable(self):
        out = verifier.mark('<a href="javascript:alert(1)">x</a>', TOK,
                            style="concat")
        assert "window['ale'+'rt']" in out and f"('{TOK}')" in out
        assert "alert(" not in out, "a literal callable must not survive"

    def test_concat_arms_an_unarmed_on_handler(self):
        out = verifier.mark("<img src=x onerror=win()", TOK, style="concat")
        assert f"window['ale'+'rt']('{TOK}')" in out
        assert out.count("onerror") == 1

    def test_concat_arms_a_bare_javascript_uri(self):
        out = verifier.mark("<a href=javascript:1>x</a>", TOK,
                            style="concat")
        assert f"window['ale'+'rt']('{TOK}')" in out

    def test_unarmed_payload_without_a_hook_is_returned_unchanged(self):
        p = "<div>nothing here</div>"
        assert verifier.mark(p, TOK, style="concat") == p


# ---------------------------------------------------------------------------
# verify_semantic(): RCDATA both ways
# ---------------------------------------------------------------------------

class TestRcdataInertness:
    def test_script_inside_textarea_is_inert(self):
        page = ("<html><body><textarea>user wrote "
                f"<script>alert('{TOK}')</script> here</textarea>"
                "</body></html>")
        v = verifier.verify_semantic(page, TOK)
        assert not v["confirmed"], v

    def test_script_inside_title_is_inert(self):
        page = f"<html><head><title>a <script>alert('{TOK}')</script></title>"
        v = verifier.verify_semantic(page, TOK)
        assert not v["confirmed"], v

    def test_closing_the_textarea_breaks_out_and_confirms(self):
        page = ("<html><body><textarea>user wrote "
                f"</textarea><script>alert('{TOK}')</script>"
                "</body></html>")
        v = verifier.verify_semantic(page, TOK)
        assert v["confirmed"], v

    def test_unclosed_rcdata_still_inert_via_the_raw_scan(self):
        # BeautifulSoup's tree may differ from the browser here; the
        # raw-text scan must hold the line on its own.
        page = (f"<html><body><textarea>user wrote "
                f"<script>alert('{TOK}')</script>")
        v = verifier.verify_semantic(page, TOK)
        assert not v["confirmed"], v

    def test_escaped_reflection_is_not_confirmed(self):
        page = f"<div>&lt;script&gt;alert('{TOK}')&lt;/script&gt;</div>"
        v = verifier.verify_semantic(page, TOK)
        assert not v["confirmed"], v

    def test_plain_token_in_text_is_not_confirmed(self):
        v = verifier.verify_semantic(f"<div>{TOK}</div>", TOK)
        assert not v["confirmed"], v


# ---------------------------------------------------------------------------
# CSP inline matrix
# ---------------------------------------------------------------------------

class TestCspGateMatrix:
    def _hdr(self, csp):
        return {"Content-Security-Policy": csp}

    def test_none_and_self_block(self):
        assert verifier._csp_blocks_inline(self._hdr("script-src 'none'"))
        assert verifier._csp_blocks_inline(self._hdr("script-src 'self'"))

    def test_unsafe_inline_alone_allows(self):
        assert not verifier._csp_blocks_inline(
            self._hdr("script-src 'unsafe-inline'"))

    def test_nonce_only_blocks(self):
        assert verifier._csp_blocks_inline(
            self._hdr("script-src 'nonce-abc123='"))

    def test_unsafe_inline_with_nonce_still_blocks(self):
        # CSP L2+: a nonce/hash source makes 'unsafe-inline' INERT -- the
        # gate must not be fooled by the permissive-looking pair.
        assert verifier._csp_blocks_inline(self._hdr(
            "script-src 'unsafe-inline' 'nonce-abc123='"))

    def test_default_src_none_without_script_src_blocks(self):
        assert verifier._csp_blocks_inline(self._hdr("default-src 'none'"))

    def test_default_src_none_with_explicit_open_script_src_allows(self):
        assert not verifier._csp_blocks_inline(self._hdr(
            "default-src 'none'; script-src 'unsafe-inline'"))

    def test_no_header_or_no_csp_allows(self):
        assert not verifier._csp_blocks_inline(None)
        assert not verifier._csp_blocks_inline({})

    def test_header_lookup_is_case_insensitive(self):
        assert verifier._csp_blocks_inline(
            {"content-security-policy": "script-src 'none'"})


# ---------------------------------------------------------------------------
# is_marker_escaped (Phase 27-1 convergence trigger; canonical home is
# core/context.py -- verifier imports it from there)
# ---------------------------------------------------------------------------

class TestMarkerEscaped:
    def test_verbatim_neighbors_are_not_escaped(self):
        assert not ctx.is_marker_escaped("value=MARKER; rest", "MARKER")

    def test_entity_before_marker(self):
        assert ctx.is_marker_escaped("value=&lt;MARKER", "MARKER")

    def test_entity_after_marker(self):
        assert ctx.is_marker_escaped("MARKER&gt; tail", "MARKER")

    def test_double_encoded_entity(self):
        assert ctx.is_marker_escaped("x&amp;lt;MARKER", "MARKER")

    def test_marker_not_present(self):
        assert not ctx.is_marker_escaped("nothing here", "MARKER")
