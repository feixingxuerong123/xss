# -*- coding: utf-8 -*-
"""Phase 113b: the redirect layer must not call a fixed jump exploitable.

find_redirect_sinks() decided ``user_controlled`` from a 260-char context
window searched with USER_INPUT_RE -- whose alternatives include
``location.href``.  The sink statement ITSELF is normally
``location.href = ...``, so that alternative matched the sink's own
LEFT-hand side and EVERY location.href assignment was judged
attacker-controlled.

Found with the first benchmark case ever written for this layer: a page
with a static ``<a href='...?redirect=/home'>`` and
``location.href = '/home';`` was reported as open-redirect -> XSS.

The fix looks at the assignment's RIGHT-hand side: a string literal
cannot carry attacker input.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import redirect_xss as rx


def _exploitable(html):
    return rx.analyze_page(html)["exploitable"]


def test_literal_destination_is_not_exploitable():
    assert not _exploitable("<script>location.href = '/home';</script>")
    assert not _exploitable('<script>location.href = "/home";</script>')


def test_the_reported_false_positive_shape():
    """The exact page that used to trip it: a static redirect link plus a
    literal assignment."""
    html = ("<a href='/go?redirect=/home'>Home</a>"
            "<script>location.href = '/home';</script>")
    assert not _exploitable(html), (
        "a fixed redirect next to a ?redirect= link is not a finding")


def test_real_param_driven_sink_is_still_exploitable():
    html = ("<script>var t = new URLSearchParams(location.search)"
            ".get('redirect'); if (t) { location.href = t; }</script>")
    assert _exploitable(html), "the true positive must survive the fix"


def test_hash_driven_sink_is_still_exploitable():
    html = "<script>location.href = location.hash.slice(1);</script>"
    assert _exploitable(html)


def test_sink_without_any_input_source_is_not_exploitable():
    html = "<script>var dest = getDefaultPage(); location.href = dest;</script>"
    assert not _exploitable(html), (
        "no user-input reference in the snippet -> not exploitable")
