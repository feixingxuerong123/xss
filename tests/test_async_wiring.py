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
import importlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import async_scanner as ASYNC  # noqa: E402


def _source():
    path = str(ASYNC.__file__)
    return open(path, encoding="utf-8").read()


# The pre-fix shape, written out rather than pulled from history.  `ctx` resolves
# to the real context module, exactly as it does in the engine.
_BROKEN_SNIPPET = (
    "import asyncio\n"
    "from . import context as ctx\n"
    "async def _scan(text, marker):\n"
    "    try:\n"
    "        context = await asyncio.to_thread(ctx.classify, text, marker)\n"
    "    except Exception:\n"
    "        context = 'html_element'\n"
    "    return context\n"
)

# The same failure mode one layer up: the async engine imports every advanced
# layer INSIDE the method that uses it, so those module names never reach the
# module namespace.  A nonexistent attribute on one of them raises
# AttributeError, and the enclosing `except Exception` turns it into a layer
# that silently reports "nothing found".
_BROKEN_LAZY_SNIPPET = (
    "import asyncio\n"
    "async def _mine(url, text):\n"
    "    from . import form_miner\n"
    "    try:\n"
    "        return form_miner.forms_to_endpointz(text, url)\n"
    "    except Exception:\n"
    "        return []\n"
)


def _imported_names(tree):
    """Resolve imports that are NOT in the module namespace.

    Every async layer is imported lazily *inside* its method (``from . import
    form_miner``), so those bindings never appear in ``vars(ASYNC)``.  A guard
    that resolves names only from the module namespace therefore skips every
    one of those call sites -- which is how this file could pass while the
    Phase 176s additions (form_miner / js_miner / time_xss) went unchecked.
    Same blind spot, different layer.
    """
    pkg = ASYNC.__name__.rpartition(".")[0]
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.level:
            # `from . import X` has n.module == None and X in n.names; the
            # package attribute only exists once SOMETHING has imported that
            # submodule -- so reading getattr(package, X) makes this guard
            # depend on test collection order, and a layer nobody loaded yet
            # becomes invisible.  Import each target explicitly instead.
            holders = []
            if n.module:
                try:
                    holders.append(importlib.import_module("." + n.module, pkg))
                except Exception:
                    pass
            for a in n.names:
                if a.name == "*":
                    continue
                target = None
                for h in holders:
                    target = getattr(h, a.name, None)
                    if target is not None:
                        break
                if target is None:
                    try:
                        target = importlib.import_module("." + a.name, pkg)
                    except Exception:
                        target = None
                if target is not None:
                    out[a.asname or a.name] = target
        elif isinstance(n, ast.Import):
            for a in n.names:
                # `import a.b` binds `a`, `import a.b as c` binds `c`
                if a.asname:
                    try:
                        out[a.asname] = importlib.import_module(a.name)
                    except Exception:
                        pass
    return out


def _missing_calls(src):
    """Every `name.attr` where `name` is an imported module and `attr` does
    not exist on it.

    Resolution uses the module's OWN namespace plus the file's lazy imports
    rather than re-implementing import semantics, because relative imports
    (`from . import context as ctx`) are exactly what a hand-rolled resolver
    gets wrong -- and a resolver that fails silently turns this guard into a
    no-op.  That is not hypothetical: the first draft did precisely that and
    "passed" against a file that still called the nonexistent symbol.
    """
    tree = ast.parse(src)
    ns = dict(vars(ASYNC))
    ns.update(_imported_names(tree))
    missing = []
    # Every ATTRIBUTE REFERENCE, not just call targets: the original bug is
    # `asyncio.to_thread(ctx.classify, ...)`, where the nonexistent name is an
    # ARGUMENT.  A pattern that looked only at `name.attr(...)` reported "all
    # clear" against the broken file -- caught by the self-check below.
    for n in ast.walk(tree):
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

    Deliberately SYNTHETIC, not `git show HEAD:...`.  The first version read
    HEAD and expected `ctx.classify` there; once the fix was committed, the
    string still appeared -- inside the comment explaining the old bug -- so the
    premise check passed while the detector correctly found nothing, and the
    test failed for the opposite of the reason it exists.  A mutation harness
    that depends on repository history rots the moment history moves; this one
    cannot.
    """
    caught = _missing_calls(_BROKEN_SNIPPET)
    assert any("ctx.classify" in c for c in caught), (
        "the detector is vacuous -- it missed the very bug it exists for "
        "(it reported: %s)" % (caught or "nothing at all"))
    # and it must not fire on the shape that replaced it
    assert not _missing_calls(_BROKEN_SNIPPET.replace(
        "ctx.classify", "ctx.analyze")), "detector fires on correct code too"


def test_the_guard_sees_lazily_imported_layers():
    """Second blind spot, closed: layer imports live inside methods.

    `_BROKEN_LAZY_SNIPPET` mirrors how the async engine actually imports its
    layers (`from . import form_miner` inside the function body).  Before this
    test existed, `_missing_calls` resolved names from `vars(ASYNC)` only, so
    every lazily imported module was invisible to it -- a Phase 176s typo in
    `form_miner.forms_to_endpoints` would have shipped green, been swallowed by
    the surrounding `except Exception: _log.debug(...)`, and looked like a layer
    that simply found nothing.
    """
    caught = _missing_calls(_BROKEN_LAZY_SNIPPET)
    assert any("form_miner.forms_to_endpointz" in c for c in caught), (
        "the guard cannot see lazily imported modules -- it reports clean for "
        "code that calls a nonexistent layer function (got: %s)"
        % (caught or "nothing"))
    assert not _missing_calls(_BROKEN_LAZY_SNIPPET.replace(
        "forms_to_endpointz", "forms_to_endpoints")), (
        "the guard fires on correct lazy imports too, which would make the "
        "real check unrunnable")


def _lazy_refs(tree, lazy):
    """`(holder, attr, line)` for every reference through a lazily imported
    module -- i.e. exactly the class of call site the old resolver skipped."""
    ns = dict(vars(ASYNC))
    return sorted({(n.value.id, n.attr, n.lineno) for n in ast.walk(tree)
                   if isinstance(n, ast.Attribute)
                   and isinstance(n.value, ast.Name)
                   and n.value.id in lazy and n.value.id not in ns})


def test_the_guard_sees_the_real_lazy_call_sites_not_just_the_synthetic():
    """Mutate each actual lazy call site and require the guard to notice.

    Line-targeted on purpose.  The first version of this check did a global
    `src.replace(name, name + "ZZ", 1)`, and for `advanced_layers.run_page_layers`
    the first textual hit was a DOCSTRING at line 1206 rather than the call at
    1236 -- so the harness mutated prose, the guard correctly stayed silent, and
    the check reported two false "MISSED" verdicts against working code.  A
    mutation harness that edits the wrong line is worse than none: it makes a
    sound detector look broken.
    """
    src = _source()
    tree = ast.parse(src)
    refs = _lazy_refs(tree, _imported_names(tree))
    assert refs, ("no lazily imported layer call sites found -- the premise of "
                  "this check changed; it would now pass vacuously")
    # The Phase 176s layers are the reason this exists; if one disappears from
    # the engine this test must say so rather than quietly shrink.
    for want in ("form_miner", "js_miner", "tx_mod", "advanced_layers"):
        assert any(h == want for h, _a, _l in refs), (
            "expected %s to be called through a lazy import; found only %s"
            % (want, sorted({h for h, _a, _l in refs})))
    lines = src.split("\n")
    for holder, attr, lineno in refs:
        row = lines[lineno - 1]
        assert "%s.%s" % (holder, attr) in row, (
            "line %d no longer holds %s.%s -- this check is mutating the wrong "
            "text and cannot be trusted" % (lineno, holder, attr))
        broken = "%s.%sZZ" % (holder, attr)
        mutated = "\n".join(
            lines[:lineno - 1] + [row.replace("%s.%s" % (holder, attr), broken)]
            + lines[lineno:])
        hit = [m for m in _missing_calls(mutated) if broken in m]
        assert hit, ("guard is blind to a broken call through a lazy import at "
                     "line %d (%s): %s" % (lineno, broken, hit or "silent"))


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


# ---------------------------------------------------------------------------
# Phase 176t behavioural guards for the two async divergences fixed after the
# first parity sweep (both were invisible in a finding count).
# ---------------------------------------------------------------------------

def _bare_scanner():
    """An AsyncScanner with __init__ skipped -- the convention this repo's
    async tests already use (see the `getattr` note on _AsyncScannerShim)."""
    from xssentinel.core.async_scanner import AsyncScanner
    sc = AsyncScanner.__new__(AsyncScanner)
    sc.verbose = False
    return sc


def test_dom_browser_is_pointed_at_a_url_that_carries_the_params(monkeypatch):
    """`location.search` vectors need the query IN the navigated URL.

    Async keeps ``url`` and ``params`` apart internally, so the DOM layer used
    to hand the browser the bare path; the page then genuinely had an empty
    ``location.search``, the analyzer correctly found nothing, and the case
    (pos-dom-02) was scored as a clean miss.  Sync re-attaches the parameters
    before this same call (scanner.py:479-486) -- which is why sync confirmed it
    and async never could, at any budget.
    """
    import asyncio
    seen = {}

    class _FakeEngine:
        def analyze(self, url):
            seen["url"] = url
            return []

    sc = _bare_scanner()
    sc._resolve_dom_engine = lambda: _FakeEngine()
    monkeypatch.setattr(ASYNC.dom_engine_mod, "page_has_client_js",
                        lambda t: True, raising=False)
    monkeypatch.setattr(ASYNC.dom_engine_mod, "page_can_run_sink",
                        lambda t: True, raising=False)

    asyncio.run(_drain(sc._scan_dom_async("http://h/p", "<html><script>x"
                                          "</script></html>", "GET",
                                          {"x": "probe"})))
    assert seen.get("url") == "http://h/p?x=probe", (
        "the browser must see the injected parameter; got %r"
        % seen.get("url"))

    # ... and a URL that already has a query gets `&`, not a second `?`
    seen.clear()
    asyncio.run(_drain(sc._scan_dom_async("http://h/p?a=1", "<html></html>",
                                          "GET", {"x": "probe"})))
    assert seen.get("url") == "http://h/p?a=1&x=probe"

    # Negative control: sync's guard is GET-only, so a POST target must NOT be
    # rewritten (its parameter lives in the body, not the query).
    seen.clear()
    asyncio.run(_drain(sc._scan_dom_async("http://h/p", "<html></html>",
                                          "POST", {"x": "probe"})))
    assert seen.get("url") == "http://h/p", (
        "POST params belong in the body; appending them invents a query the "
        "target never reads")


async def _drain(agen):
    async for _ in agen:
        pass


def test_missing_layer_module_escalates_instead_of_logging_nothing(
        monkeypatch, caplog):
    """A layer that cannot be imported must say so at WARNING.

    `layer_guard` is the project's answer to "a broad except turned a whole
    layer off in silence" (Phase 63 / 84), and sync's crawl follows it
    (scanner_crawl.py:349-352).  The async mining helper added in Phase 176s
    originally caught everything at DEBUG -- the same hole, new code.

    Scope note: only ImportError/NameError escalate (layer_guard.py:43-48
    keeps AttributeError at DEBUG on purpose, because duck-type probes are
    routine here).  A *renamed* layer function is therefore caught statically
    above, by `test_every_module_symbol_async_calls_actually_exists`, not by
    this log level -- which is the right split: a typo should fail a test, not
    just print.
    """
    import asyncio
    import logging
    from xssentinel.core import form_miner

    def _boom(*a, **k):
        raise NameError("forms_to_endpoints is not defined")

    monkeypatch.setattr(form_miner, "forms_to_endpoints", _boom)
    sc = _bare_scanner()
    with caplog.at_level(logging.DEBUG):
        out = asyncio.run(sc._crawl_mine_endpoints("<html></html>",
                                                   "http://h/p", 0))
    assert out == [], "a failed layer must not raise into the crawl"
    warns = [r.getMessage() for r in caplog.records
             if r.levelno >= logging.WARNING]
    assert any("async_form_miner" in m for m in warns), (
        "the layer failed on a wiring defect and nothing was logged at "
        "WARNING -- this is the silent layer-off shape; records: %s" % warns)


def test_ordinary_layer_error_stays_quiet(monkeypatch, caplog):
    """Counterpart: the escalation must stay specific to wiring defects.

    If every exception warned, the log would be noise on real targets and the
    signal would stop meaning "the scanner itself is broken".
    """
    import asyncio
    import logging
    from xssentinel.core import form_miner

    def _boom(*a, **k):
        raise ValueError("odd markup from the target")

    monkeypatch.setattr(form_miner, "forms_to_endpoints", _boom)
    sc = _bare_scanner()
    with caplog.at_level(logging.DEBUG):
        out = asyncio.run(sc._crawl_mine_endpoints("<html></html>",
                                                   "http://h/p", 0))
    assert out == []
    warns = [r.getMessage() for r in caplog.records
             if r.levelno >= logging.WARNING]
    assert not any("async_form_miner" in m for m in warns), (
        "a target-side ValueError escalated: %s" % warns)


def test_the_dom_layer_is_actually_CALLED_with_the_params():
    """The fix lives in two places, and a test of only one is half a guard.

    `test_dom_browser_is_pointed_at_a_url_that_carries_the_params` calls
    ``_scan_dom_async`` directly, so it passes even if the page-phase call site
    goes back to ``self._scan_dom_async(url, text)`` -- which is the shape the
    bug actually was.  This checks the call itself: four positional arguments,
    method and params included.
    """
    tree = ast.parse(_source())
    sites = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute)
             and n.func.attr == "_scan_dom_async"
             and isinstance(n.func.value, ast.Name)
             and n.func.value.id == "self"]
    assert sites, ("no `self._scan_dom_async(...)` call site found -- either "
                   "the page phase stopped calling it or this check's premise "
                   "moved, and in both cases it guards nothing")
    for n in sites:
        assert len(n.args) >= 4, (
            "line %d: called with %d positional args; the browser needs "
            "method+params or location.search vectors are unconfirmable again"
            % (n.lineno, len(n.args)))
