# -*- coding: utf-8 -*-
"""Layer accounting must not claim a layer ran when it never got there.

Every detection layer records itself into the coverage matrix that ends up in
the CLIENT's report.  Three sites recorded `touch_layer` BEFORE invoking the
layer and wrapped both in `except Exception` -- so a layer that died on entry
(bad import, renamed symbol, wrong arity) still reported "ran", and the one
instrument meant to reveal a silently dead layer was itself fooled by one.

L6_dom_dynamic was fixed first (scanner_layers.py:93-105) with a comment
explaining exactly that.  L7_time_based and L8_request were the remaining two
instances of the same shape, fixed in Phase 176u.  This file pins all three so
the pattern cannot come back one layer at a time:

  * the touch must happen AFTER the layer's real call, and
  * the failure path must record status="failed" (a swallowed exception with no
    row at all is how this hid in the first place).

The detector is checked against a synthetic bad sample below.  A guard that
cannot find the bug it was written for is not a guard -- that is the lesson from
`ctx.classify`, which sat undetected in the async engine until a benchmark case
measured it.

Run:  pytest tests/test_layer_accounting.py
"""
from __future__ import annotations

import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _tree(rel_path):
    with open(os.path.join(ROOT, rel_path), encoding="utf-8") as f:
        return ast.parse(f.read())


def _calls(tree, attr):
    """Line numbers of every `*.attr(...)` call in the tree."""
    return [n.lineno for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == attr]


def _touch_layer_lines(tree, layer_id):
    out = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("touch_layer", "record_layer")):
            continue
        if n.func.attr != "touch_layer":
            continue
        for a in n.args:
            if isinstance(a, ast.Constant) and a.value == layer_id:
                out.append(n.lineno)
    return out


def _work_lines(tree, func_name):
    """Lines where the layer's actual work is invoked.

    Two shapes count: a direct call (``mod.work(...)``) and the callable
    handed to a runner (``asyncio.to_thread(mod.work, ...)``) -- the async
    engine never calls its sync layer functions directly, it passes them
    into a worker thread, so call-func matching alone would find nothing
    there and the ordering check would pass vacuously.  Argument matching
    is restricted to *call arguments* on purpose: a bare ``import`` or a
    module-level ``from x import work`` must not count as "the work ran".
    """
    def _matches(node):
        return ((isinstance(node, ast.Attribute) and node.attr == func_name)
                or (isinstance(node, ast.Name) and node.id == func_name))

    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        if _matches(n.func):
            out.append(n.lineno)
        for a in list(n.args) + [kw.value for kw in n.keywords]:
            if _matches(a):
                out.append(n.lineno)
    return out


def _failed_rows(tree, layer_id):
    """`record_layer(..., layer_id, ..., status="failed")` lines."""
    out = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "record_layer"):
            continue
        if not any(isinstance(a, ast.Constant) and a.value == layer_id
                   for a in n.args):
            continue
        for kw in n.keywords:
            if kw.arg == "status" and isinstance(kw.value, ast.Constant) \
                    and kw.value.value == "failed":
                out.append(n.lineno)
    return out


# (file, layer id, the symbol that IS the layer)
SITES = [
    ("xssentinel/core/scanner_layers.py", "L6_dom_dynamic", "analyze"),
    ("xssentinel/core/scanner.py", "L7_time_based", "scan_time_based"),
    ("xssentinel/core/async_scanner.py", "L8_request", "run_request_layers"),
]

# The pre-fix shape, written out rather than pulled from history: recording on
# line 3, work on line 4, everything swallowed.
_BAD_SAMPLE = (
    "def _scan(self, url):\n"
    "    try:\n"
    "        self.coverage.touch_layer(url, \"LX_test\", \"GET\")\n"
    "        some_mod.layer_work(self, url)\n"
    "    except Exception:\n"
    "        pass\n"
)


def _diagnose(src_text):
    """(touches_before_work, failed_rows) for the LX_test layer."""
    t = ast.parse(src_text)
    touches = _touch_layer_lines(t, "LX_test")
    work = _work_lines(t, "layer_work")
    before = [x for x in touches if work and x < min(work)]
    return before, _failed_rows(t, "LX_test")


def test_the_detector_finds_the_bug_it_was_written_for():
    """Self-check first: if this fails, every assertion below is vacuous."""
    before, failed = _diagnose(_BAD_SAMPLE)
    assert before, ("the detector cannot see `touch_layer` placed before the "
                    "layer call -- it would report clean code as guilty and "
                    "guilty code as clean")
    assert not failed, "the pre-fix shape has no failed-row by construction"
    # ... and it must stay quiet on the corrected shape
    fixed = _BAD_SAMPLE.replace(
        "        self.coverage.touch_layer(url, \"LX_test\", \"GET\")\n"
        "        some_mod.layer_work(self, url)\n",
        "        some_mod.layer_work(self, url)\n"
        "        self.coverage.touch_layer(url, \"LX_test\", \"GET\")\n")
    assert fixed != _BAD_SAMPLE, "the corrected-shape probe did not apply"
    before2, _ = _diagnose(fixed)
    assert not before2, "detector fires on correct code too"


def test_recording_happens_after_the_layer_ran():
    """No site may claim "ran" before the call that could have failed."""
    bad = []
    for rel, layer, work_sym in SITES:
        t = _tree(rel)
        touches = _touch_layer_lines(t, layer)
        work = _work_lines(t, work_sym)
        assert touches, "%s: no touch_layer(%r) at all -- the layer stopped " \
                        "reporting itself, which this file cannot tell apart " \
                        "from 'never existed'" % (rel, layer)
        assert work, "%s: cannot find the layer call (%s) to order against -- " \
                     "the check would pass vacuously" % (rel, work_sym)
        first_work = min(work)
        for ln in touches:
            if ln < first_work:
                bad.append("%s: touch_layer(%s) at line %d precedes %s() at %d"
                           % (rel, layer, ln, work_sym, first_work))
    assert not bad, "layer recorded as ran before it ran:\n  " + "\n  ".join(bad)


def test_failure_path_records_a_failed_row():
    """A swallowed exception must leave a row, not silence.

    Without this the fix above is only half a fix: moving `touch_layer` after
    the call means a broken layer records NOTHING, and "nothing" reads to the
    next reader as "this endpoint had no such layer" rather than "it failed".
    """
    missing = []
    for rel, layer, _sym in SITES:
        if not _failed_rows(_tree(rel), layer):
            missing.append("%s: no record_layer(%s, status=\"failed\")"
                           % (rel, layer))
    assert not missing, "layer failures are silent:\n  " + "\n  ".join(missing)
