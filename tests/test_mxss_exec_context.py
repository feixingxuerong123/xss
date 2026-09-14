# -*- coding: utf-8 -*-
"""Phase 128: the mXSS confirmation path was escaping-blind.

`verifier._mxss_confirm` used to ask "does the token appear anywhere in the
response AND does the page carry a mutating sink?".  `mutation.analyze`'s
`reflected` flag is a bare substring test, so an **HTML-escaped** token
sitting in a text node counted as reflected -- and any page with
innerHTML/DOMParser in a script then produced a high-severity `reflected`
finding the moment the token appeared.  That fires on every ordinary app
that escapes its output while carrying a mutating sink.

The fix requires the token to have landed in a genuinely EXECUTABLE context
in the served bytes (`verifier._marker_in_exec_context`), which itself had
to be escape-aware: its handler/URI patterns originally scanned the whole
document, so `&lt;img src=x onerror=alert(&#x27;TOKEN&#x27;)&gt;` inside a
text node matched.
"""
from __future__ import annotations

import html as html_mod
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.verifier import _marker_in_exec_context, _mxss_confirm

TOKEN = "xssv_abc123"
_SINK_SCRIPT = ("<script>var d = new DOMParser().parseFromString('x',"
                "'text/html');</script>")


def _esc(value: str) -> str:
    return html_mod.escape(value, quote=True)


class TestMarkerInExecContext:
    """The static exec-context judgement must not see through escaping."""

    def test_raw_reflected_handler_counts(self):
        page = "<div><img src=x onerror=alert('%s')></div>" % TOKEN
        assert _marker_in_exec_context(page, TOKEN) is True

    def test_escaped_text_node_does_not_count(self):
        page = ("<div id=stage>%s</div>"
                % _esc("<img src=x onerror=alert('%s')>" % TOKEN))
        assert _marker_in_exec_context(page, TOKEN) is False

    def test_handler_inside_another_attribute_value_does_not_count(self):
        page = '<img alt="x onerror=alert(\'%s\')">' % TOKEN
        assert _marker_in_exec_context(page, TOKEN) is False

    def test_live_script_block_counts(self):
        page = '<script>var x = "%s";</script>' % TOKEN
        assert _marker_in_exec_context(page, TOKEN) is True

    def test_javascript_uri_counts(self):
        page = "<a href=\"javascript:alert('%s')\">x</a>" % TOKEN
        assert _marker_in_exec_context(page, TOKEN) is True

    def test_quoted_handler_value_counts(self):
        page = "<svg onload=\"alert('%s')\"></svg>" % TOKEN
        assert _marker_in_exec_context(page, TOKEN) is True

    def test_absent_marker(self):
        assert _marker_in_exec_context(
            "<div>nothing</div>", TOKEN) is False
        assert _marker_in_exec_context("", TOKEN) is False


class TestMxssConfirmIsNotEscapingBlind:
    """The verifier branch that produced the false positive."""

    def test_escaped_reflection_beside_a_sink_is_not_confirmed(self):
        page = ("<div id=stage>%s</div>%s"
                % (_esc("<img src=x onerror=alert('%s')>" % TOKEN),
                   _SINK_SCRIPT))
        assert _mxss_confirm(page, TOKEN, page.find(TOKEN)) is None

    def test_raw_reflection_beside_a_sink_is_confirmed(self):
        page = ("<div id=stage><img src=x onerror=alert('%s')></div>%s"
                % (TOKEN, _SINK_SCRIPT))
        verdict = _mxss_confirm(page, TOKEN, page.find(TOKEN))
        assert verdict and verdict.get("confirmed") is True

    def test_escaped_reflection_without_a_sink_is_not_confirmed(self):
        page = "<div id=stage>%s</div>" % _esc(
            "<img src=x onerror=alert('%s')>" % TOKEN)
        assert _mxss_confirm(page, TOKEN, page.find(TOKEN)) is None
