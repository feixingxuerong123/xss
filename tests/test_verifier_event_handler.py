"""Phase 91: the raw-text event-handler guard must not confirm inert text.

The ``event_handler`` branch of ``_fallback_executable`` exists because
lxml drops attributes on slash-form tags (``<svg/onload=...>``), so the
structural pass never sees them.  Phase 84 let the token sit anywhere
inside the handler value, which also re-admitted *escaped* reflections:
``html.escape(quote=True)`` turns the breakout quote into ``&#x27;``, so
the ``on*`` text stays inside the attribute value where a browser treats
it as text.  The same happens with entity-free transforms (UTF-7-style
``+ACY-``).  The guard now walks the tag's quote state instead of
pattern-matching, which separates a real attribute boundary from text.

Every TP below is a payload that genuinely executes in a browser; every FP
below is inert.  Losing a TP here is a silent detection regression, so the
two halves are asserted with equal weight.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.verifier import (  # noqa: E402
    _fallback_executable,
    _on_attr_is_real,
    verify_semantic,
)

TOK = "xssv_063fa417"


def _fb(html: str, token: str = TOK) -> bool:
    """Run just the event_handler raw-text guard at the token position."""
    return _fallback_executable(html, html.find(token), token,
                                "event_handler")


# --------------------------------------------------------------------------
# _on_attr_is_real -- the quote-state walker
# --------------------------------------------------------------------------

def test_quote_walker_inside_sq_value() -> None:
    tag = "<input type='text' value='&#x27; onmouseover=alert(1)'>"
    assert _on_attr_is_real(tag, tag.find("onmouseover")) is False


def test_quote_walker_after_closed_sq_value() -> None:
    tag = "<input type='text' value='' onmouseover=alert(1)>"
    assert _on_attr_is_real(tag, tag.find("onmouseover")) is True


def test_quote_walker_after_closed_dq_value() -> None:
    tag = '<input type="text" value="" onmouseover=alert(1)>'
    assert _on_attr_is_real(tag, tag.find("onmouseover")) is True


def test_quote_walker_unquoted_value() -> None:
    tag = "<input type=text value=x onmouseover=alert(1)>"
    assert _on_attr_is_real(tag, tag.find("onmouseover")) is True


def test_quote_walker_space_before_quoted_value() -> None:
    # HTML allows whitespace between = and the opening quote.
    tag = "<input value= 'x' onmouseover=alert(1)>"
    assert _on_attr_is_real(tag, tag.find("onmouseover")) is True


def test_quote_walker_amp_entity_does_not_open_value() -> None:
    # &amp; is not a quote: with a real space breakout this is exploitable.
    tag = '<img src="a&amp;b" alt=x onmouseover=alert(1)>'
    assert _on_attr_is_real(tag, tag.find("onmouseover")) is True


def test_quote_walker_slash_form_svg() -> None:
    tag = "<svg/onload=alert(1)>"
    assert _on_attr_is_real(tag, tag.find("onload")) is True


# --------------------------------------------------------------------------
# FALSE POSITIVES -- must NOT confirm
# --------------------------------------------------------------------------

def test_fp_escaped_single_quoted_attribute() -> None:
    """neg-escape-03: html.escape(quote=True) neutralises the breakout."""
    html = ("<!DOCTYPE html><html><body><input type='text' value='"
            "&#x27; onmouseover=alert(&#x27;" + TOK + "&#x27;) x=&#x27;'>"
            "</body></html>")
    assert verify_semantic(html, TOK)["confirmed"] is False
    assert _fb(html) is False


def test_fp_escaped_double_quoted_attribute() -> None:
    html = ('<input type="text" value="&quot; onmouseover=alert(&quot;'
            + TOK + '&quot;)">')
    assert verify_semantic(html, TOK)["confirmed"] is False
    assert _fb(html) is False


def test_fp_utf7_style_no_entity() -> None:
    """No entity at all -- only quote state can reject this one."""
    html = ("<input type='text' value='+ACY- onmouseover=alert+ADs-+ACY-"
            + TOK + "+ACY-+AD0- x=+ACY-'>")
    assert verify_semantic(html, TOK)["confirmed"] is False
    assert _fb(html) is False


def test_fp_escaped_element_body_svg_onload() -> None:
    html = "<div>&lt;svg/onload=alert('" + TOK + "')&gt;</div>"
    assert verify_semantic(html, TOK)["confirmed"] is False


def test_fp_token_absent() -> None:
    assert verify_semantic("<div>clean</div>", TOK)["confirmed"] is False


# --------------------------------------------------------------------------
# TRUE POSITIVES -- must still confirm
# --------------------------------------------------------------------------

def test_tp_double_quote_breakout() -> None:
    html = ('<input type="text" value="" onmouseover=alert("' + TOK + ')" '
            'x="">')
    assert verify_semantic(html, TOK)["confirmed"] is True


def test_tp_single_quote_breakout() -> None:
    html = ("<input type='text' value='' onmouseover=alert('" + TOK + "')' "
            "x=''>")
    assert verify_semantic(html, TOK)["confirmed"] is True


def test_tp_unquoted_attribute_breakout() -> None:
    html = "<input type=text value=x onmouseover=alert('" + TOK + "')>"
    assert verify_semantic(html, TOK)["confirmed"] is True


def test_tp_slash_form_svg_onload() -> None:
    """The case Phase 84 was written for -- must survive the new guard."""
    html = "<svg/onload=alert('" + TOK + "')>"
    assert verify_semantic(html, TOK)["confirmed"] is True
    assert _fb(html) is True


def test_tp_unquoted_value_slash_does_not_break_out() -> None:
    """<img src=x/onerror=...> is inert: '/' does not end an unquoted value.

    lxml agrees (src='x/onerror=alert(1)', no onerror attribute), so this
    is a false positive the guard must reject -- and it is the reason the
    walker tracks unquoted values, not just quotes.
    """
    html = "<img src=x/onerror=alert('" + TOK + "')>"
    assert verify_semantic(html, TOK)["confirmed"] is False
    assert _fb(html) is False


def test_tp_unquoted_value_space_does_break_out() -> None:
    """Same shape with a space: a real attribute boundary."""
    html = "<img src=x onerror=alert('" + TOK + "')>"
    assert verify_semantic(html, TOK)["confirmed"] is True


def test_tp_amp_entity_before_breakout() -> None:
    """&amp; in an earlier attribute must not mask a real breakout."""
    html = ('<img src="a&amp;b" alt=x onmouseover=alert("' + TOK + '")>')
    assert verify_semantic(html, TOK)["confirmed"] is True
    assert _fb(html) is True


def test_fp_unquoted_value_swallows_next_handler() -> None:
    """``alt= onmouseover=...`` makes the handler alt's VALUE (no space)."""
    html = ('<img src="a&amp;b" alt= onmouseover=alert("' + TOK + '")>')
    assert verify_semantic(html, TOK)["confirmed"] is False
    assert _fb(html) is False


def test_tp_handler_value_carries_token_after_quotes() -> None:
    html = ('<div onmouseover="alert(&quot;' + TOK + '&quot;)">x</div>')
    assert verify_semantic(html, TOK)["confirmed"] is True


def test_tp_script_block_still_confirms() -> None:
    """Guards are per-context -- the script branch must be untouched."""
    html = "<script>var a='x';alert('" + TOK + "');</script>"
    assert verify_semantic(html, TOK)["confirmed"] is True


def test_tp_csp_blocks_inline_handler() -> None:
    """A real handler under a blocking CSP is reported non-executable."""
    html = "<div onmouseover=alert('" + TOK + "')>x</div>"
    out = verify_semantic(html, TOK,
                          {"Content-Security-Policy": "script-src 'none'"})
    assert out["confirmed"] is False
    assert out["context"] == "event_handler"
