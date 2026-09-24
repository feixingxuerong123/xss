# -*- coding: utf-8 -*-
"""Async-engine wiring guards that must never skip.

`tests/test_async_pipeline.py` carries a module-level
`skipif(not SOCKETPAIR_OK)`, which flips under load on this host -- so a test
placed there can silently stop existing.  These checks need no event loop and no
socket, so they live here where they always run.

The bug they pin: `ctx.classify` has never existed in `xssentinel.core.context`.
`async_scanner` called it inside `try: ... except Exception: context =
"html_element"`, so EVERY parameter scan raised AttributeError, swallowed it, and
selected payloads from the wrong corpus.  Measured: async spent 104 requests and
missed `pos-url-04` and `pos-cdata-01`, both of which sync confirms; after the
fix both are TP at 36 and 31 requests -- 3x the work for nothing.

Run:  pytest tests/test_async_wiring.py
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import async_scanner as ASYNC  # noqa: E402


def _source():
    path = str(ASYNC.__file__)
    return open(path, encoding="utf-8").read()


def _missing_calls(src):
    """Every `name.attr(...)` where `name` is bound in the module namespace and
    `attr` does not exist on it.

    Resolution uses the module's OWN namespace rather than re-implementing
    import semantics, because relative imports (`from . import context as ctx`)
are exactly what a hand-rolled resolver gets wrong -- and a resolver that
    fails silently turns this guard into a no-op.  That is not hypothetical:
    the first draft did precisely that and "passed" against a file that still
    called the nonexistent symbol.
    """
    ns = vars(ASYNC)
    missing = []
    # Every ATTRIBUTE REFERENCE, not just call targets: the original bug is
    # `asyncio.to_thread(ctx.classify, ...)`, where the nonexistent name is an
    # ARGUMENT.  A pattern that looked only at `name.attr(...)` reported "all
    # clear" against the broken file -- caught by the self-check below.
    for n in ast.walk(ast.parse(src)):
        if not (isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name)):
            continue
        holder = ns.get(n.value.id)
        if holder is None or isinstance(holder, (str, bytes, int, float, bool)):
            continue
        if not hasattr(holder, n.attr):
            missing.append("%s.%s at line %d" % (n.value.id, n.attr, n.lineno))
    return sorted(set(missing))


def test_every_module_symbol_async_calls_actually_exists():
    """A missing attribute + a broad `except` = a feature that quietly never ran.

    Same class as the Phase 63 async-L1 outage and the Phase 37 missing
    `for_context`, both hidden by swallowed exceptions instead of being
    reported.  This is the mechanical version of checking the wiring.
    """
    bad = _missing_calls(_source())
    assert not bad, ("async_scanner calls symbols that do not exist; a bare "
                     "except would hide them as a degraded scan: "
                     + ", ".join(bad))


def test_the_guard_actually_catches_the_original_bug():
    """Self-check on the detector: it must find the bug it was written for.

    Without this line, a guard that silently matches nothing is indistinguishable
    from a fixed engine -- the false-green shape that has now bitten this project
    four times in one day.  It skips once the fix is committed and HEAD no longer
    contains the broken call, rather than lying about coverage.
    """
    head = subprocess.run(
        ["git", "show", "HEAD:xssentinel/core/async_scanner.py"],
        capture_output=True, text=True, encoding="utf-8",
        cwd=ROOT).stdout
    if "ctx.classify" not in head:
        pytest.skip("HEAD no longer carries the bug this guard was written for")
    caught = _missing_calls(head)
    assert any("ctx.classify" in c for c in caught), (
        "the detector is vacuous -- it missed the very bug it exists for "
        "(it reported: %s)" % (caught or "nothing at all"))


def test_async_does_not_call_the_nonexistent_classifier():
    """Checked as an attribute REFERENCE, not a substring and not only a call
    target: the name appears legitimately in this module's comments, and the
    actual call site passes it as an argument to `asyncio.to_thread`."""
    hits = [n.lineno for n in ast.walk(ast.parse(_source()))
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
            and n.value.id == "ctx" and n.attr == "classify"]
    assert not hits, ("context.classify does not exist -- referencing it raises "
                      "AttributeError, which used to be swallowed into "
                      "'html_element'; lines: %s" % hits)


def test_cdata_reflection_classifies_as_cdata():
    """The context value keys the sibling-corpus table: cdata -> script_block.

    Without it the engine never sends the payloads that work inside a CDATA
    section, which is half of why async missed this endpoint at any budget.
    """
    from xssentinel.core import context as ctx
    from xssentinel.core import payloads as payloads_mod
    marker = "xssentinel_bench_probe"
    page = ("<html><head><title>t</title></head><body>"
            "<svg><![CDATA[" + marker + "]]></svg></body></html>")
    info = ctx.analyze(page, marker)
    assert info and info["context"] == "cdata", (
        "got %r -- context drives corpus selection" % (info or {}).get("context"))
    cands = payloads_mod.cross_context_candidates("cdata", 10)
    assert any("]]>" in c for c in cands), (
        "the cdata corpus must contribute a CDATA-closing breakout; without it "
        "this endpoint is unscannable regardless of budget")
