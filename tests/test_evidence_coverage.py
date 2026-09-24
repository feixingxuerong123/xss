# -*- coding: utf-8 -*-
"""No finding may reach a client report without stating how sure we are.

`evidence_class` (see `findings._grade_evidence`) is the field that separates
"the browser ran this" from "nothing ever looked at this".  A finding that omits
it renders as an unqualified claim in the HTML, which is the exact defect the
grading work started with -- so every `Finding(...)` construction site owes an
answer, and this file is what keeps that from decaying one new layer at a time.

Why a count and not a path list: line numbers move with every edit, so a list of
`file:line` exemptions rots into noise on the first refactor.  The number below
is a ratchet -- fixing a site lets you lower it, adding an un-graded `Finding()`
fails here instead of failing quietly in a client's report.

Run:  pytest tests/test_evidence_coverage.py
"""
from __future__ import annotations

import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PKG = os.path.join(ROOT, "xssentinel")

# Sites that construct a Finding without stating a tier.  Measured 2026-09-24:
#   async_scanner 15, cli_commands 2, cli_runner 2, api/server 1,
#   layers/common 1  (that last one fans out ~32 finding types and needs a
#   per-caller verdict -- ~10 of its callers gate on verify_semantic, the rest
#   are static -- so it is NOT safe to stamp one tier on all of them).
# Lower this number as they are graded; never raise it.  It started at 35, and
# 14 sites in the sync pipeline (scanner_layers 9, upload_probe 3, scenarios 1,
# plus the polyglot row) are now graded -- 13 as `browser-unavailable` (header
# audits / pure reflection: nothing judged execution) and the verify_semantic
# ones as the new `model-only` tier, because calling a sandbox verdict
# "browser-unavailable" erases the judgement that WAS made.
_UNGRADED_BUDGET = 21

# Anything that lowers the total to here is not "fixed", it is a deleted probe.
_MIN_SITES = 40


def _sites():
    """Every `Finding(...)` construction in the package: (path, lineno, graded)."""
    out = []
    for base, dirs, files in os.walk(PKG):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fn in sorted(files):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(base, fn)
            try:
                src = open(path, encoding="utf-8").read()
                tree = ast.parse(src)
            except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fname = getattr(node.func, "attr", None) or \
                    getattr(node.func, "id", None)
                if fname != "Finding":
                    continue
                seg = ast.get_source_segment(src, node) or ""
                graded = "evidence_class" in seg or any(
                    k.arg == "evidence_class" for k in node.keywords)
                out.append((os.path.relpath(path, ROOT), node.lineno, graded))
    return out


def test_the_ruler_finds_known_sites():
    """Self-check: this parser must see the sites it claims to see.

    A counter that silently matches nothing would make every assertion below
    pass for the wrong reason -- the failure mode that has already bitten this
    project twice with path-separator-sensitive greps.
    """
    sites = _sites()
    assert len(sites) >= _MIN_SITES, f"parser sees only {len(sites)} sites"
    graded = [s for s in sites if s[2]]
    assert graded, "parser found zero graded sites: the check is broken"
    # the module that started it all must still be one of them
    assert any("scanner.py" in p for p, _l, g in graded if g)


def test_no_new_un_graded_finding_site():
    un = [f"{p}:{ln}" for p, ln, g in sorted(_sites()) if not g]
    assert len(un) <= _UNGRADED_BUDGET, (
        f"{len(un)} Finding() sites state no evidence_class (budget "
        f"{_UNGRADED_BUDGET}). Every one of these renders as an unqualified "
        f"claim in the client report:\n  " + "\n  ".join(un))


def test_graded_modules_stay_fully_graded():
    """Modules that have committed to stating a tier carry zero exemptions.

    A new layer added to one of these must state its evidence class; a new
    module is not exempt just because it exists -- it has to be added to the
    budget list above, which is where the debt becomes visible.
    """
    committed = ("core/scanner.py", "core/scanner_stored.py",
                 "core/scanner_crawl.py", "core/passive_proxy.py",
                 "core/time_xss.py", "core/scanner_layers.py",
                 "core/upload_probe.py", "core/scenarios.py")
    bad = []
    for path, lineno, graded in _sites():
        norm = path.replace(os.sep, "/").split("xssentinel/")[-1]
        if norm in committed and not graded:
            bad.append(f"{norm}:{lineno}")
    assert not bad, "un-graded findings in committed modules: " + ", ".join(bad)
