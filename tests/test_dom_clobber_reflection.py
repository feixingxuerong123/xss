# -*- coding: utf-8 -*-
"""Phase 123: dom_clobber reflection detection must see a REAL attribute.

Before the fix, `detect_reflection` asked only whether the response text
reads `id=<token>`.  That question survives HTML escaping:

    <div id="stage">&lt;a id=xclob_123 ...&gt;</div>

is the CORRECTLY ESCAPED version of the payload -- no element can be
created, no clobbering is possible -- yet the text still reads
`id=xclob_123`.  Combined with a `getElementById(...)` script and a
dangerous sink anywhere on the page (i.e. most real applications), the
layer reported `dom_clobber` with severity high.  A false-positive
generator, not a detector.

The tests below lock the corrected semantics: only when a genuine,
unescaped element carries id/name == token is the reflection real.
"""
from __future__ import annotations

import html as html_mod
import re

from xssentinel.core import dom_clobber

TOKEN = "xclob_abc123"
PAYLOAD = ('<a id=%s name=%s href="javascript:alert(1)">x</a>'
           % (TOKEN, TOKEN))


def _escaped(value: str) -> str:
    return html_mod.escape(value, quote=True)


def _stripped(value: str) -> str:
    return re.sub(r"<[^>]*>", "", value)


def test_raw_reflection_is_detected():
    assert dom_clobber.detect_reflection(
        '<div id="stage">%s</div>' % PAYLOAD, TOKEN) is True


def test_escaped_in_text_node_is_not_reflection():
    """The whole point: escaping must defeat the check (it used to not)."""
    assert dom_clobber.detect_reflection(
        '<div id="stage">%s</div>' % _escaped(PAYLOAD), TOKEN) is False


def test_escaped_inside_quoted_attribute_is_not_reflection():
    """Token sitting in alt's VALUE must not count as an id attribute."""
    assert dom_clobber.detect_reflection(
        '<img alt="%s">' % _escaped(PAYLOAD), TOKEN) is False


def test_strip_tags_sanitizer_is_not_reflection():
    assert dom_clobber.detect_reflection(
        '<div id="stage">%s</div>' % _stripped(PAYLOAD), TOKEN) is False


def test_token_in_unrelated_attribute_value_is_not_reflection():
    assert dom_clobber.detect_reflection(
        '<img alt="%s">' % TOKEN, TOKEN) is False


def test_absent_token_is_not_reflection():
    assert dom_clobber.detect_reflection(
        '<div id="stage">nothing here</div>', TOKEN) is False


def test_genuine_element_with_token_still_detected():
    """The fix must not blind the layer to real clobberable elements."""
    for page in ('<div id=%s>hi</div>' % TOKEN,
                 '<div id="%s">hi</div>' % TOKEN,
                 '<input name="%s">' % TOKEN,
                 '<DIV ID=%s>x</DIV>' % TOKEN,
                 '<form><input name=%s></form>' % TOKEN):
        assert dom_clobber.detect_reflection(page, TOKEN) is True, page


def test_empty_inputs_are_safe():
    assert dom_clobber.detect_reflection("", TOKEN) is False
    assert dom_clobber.detect_reflection("<div id=x>y</div>", "") is False


def test_analyze_agrees_on_exploitability_premise():
    """analyze() drives the fallback path -- same premise must hold."""
    raw = dom_clobber.analyze('<div id="stage">%s</div>' % PAYLOAD, TOKEN)
    esc = dom_clobber.analyze(
        '<div id="stage">%s</div>' % _escaped(PAYLOAD), TOKEN)
    assert raw["reflected"] is True
    assert esc["reflected"] is False
