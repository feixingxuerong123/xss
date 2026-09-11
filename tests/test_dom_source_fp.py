# -*- coding: utf-8 -*-
"""Phase 114b: the DOM layer must not make a sink its own taint source.

Third instance of the same bug family (after redirect_xss in 113b and
sw/worker in 114): the regex DOM layer searches a window around each
sink for a SOURCE keyword -- and ``location.href =`` CONTAINS
``location``, so every location assignment was "fed by location".
Found via the benchmark's safe twin neg-redirect-01:
``location.href = '/home';`` was reported as a medium DOM finding.

Fix: blank the sink text out of the window before searching, keeping the
right-hand side (a real source often lives there).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import dom as dom_mod


def _sinks(code):
    return dom_mod.analyze_script(code)


def test_literal_location_assignment_has_no_source():
    code = "location.href = '/home';"
    for f in _sinks(code):
        assert f.get("source") in (None, ""), (
            f"the sink's own LHS must not count as a source: {f}")


def test_rhs_source_still_detected():
    code = "location.href = location.hash.slice(1);"
    found = [f for f in _sinks(code) if f.get("source")]
    assert found, "a real source in the RHS must still be found"


def test_var_source_still_detected():
    code = ("var u = new URLSearchParams(location.search).get('x');"
            "location.href = u;")
    found = [f for f in _sinks(code) if f.get("source")]
    assert found, "URLSearchParams source must still be found"


def test_medium_confidence_requires_a_source():
    """The exact FP shape: severity must not ride on the sink's own LHS."""
    code = "location.href = '/home';"
    for f in _sinks(code):
        if f.get("confidence") == "medium":
            raise AssertionError(
                "medium confidence without a real source -- this is what "
                "made neg-redirect-01 a false positive")
