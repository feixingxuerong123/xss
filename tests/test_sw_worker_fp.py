# -*- coding: utf-8 -*-
"""Phase 114: literal worker/SW URLs are not user controlled.

Same bug family as the Phase 113b redirect fix: the ±300 char window
search with USER_INPUT_RE flipped a LITERAL ``register(\"/sw.js\")`` /
``new Worker(\"/w.js\")`` to exploitable whenever an unrelated script
nearby referenced URLSearchParams / location.search.  Verified before
the fix; the pair of cases below reproduces it.

A quoted literal cannot carry attacker input; the window search stays,
because for a variable expression the taint source really is nearby.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import sw_xss, worker_xss

UNRELATED = ('<script>var dbg = new URLSearchParams(location.search)'
             '.get("dbg");</script>')


def test_sw_literal_with_unrelated_input_source_is_not_exploitable():
    page = UNRELATED + '<script>navigator.serviceWorker.register("/sw.js");</script>'
    assert not sw_xss.analyze_page(page)["exploitable"]


def test_sw_param_driven_register_is_still_exploitable():
    page = ('<script>var p = new URLSearchParams(location.search).get("sw");'
            'navigator.serviceWorker.register(p || "/sw.js");</script>')
    assert sw_xss.analyze_page(page)["exploitable"]


def test_worker_literal_with_unrelated_input_source_is_not_exploitable():
    page = UNRELATED + '<script>new Worker("/w.js");</script>'
    assert not worker_xss.analyze_page(page)["exploitable"]


def test_worker_param_driven_is_still_exploitable():
    page = ('<script>var w = new URLSearchParams(location.search).get("w");'
            'new Worker(w);</script>')
    assert worker_xss.analyze_page(page)["exploitable"]
