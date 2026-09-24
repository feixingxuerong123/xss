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
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PKG = os.path.join(ROOT, "xssentinel")

# Sites that construct a Finding without stating a tier.  Measured 2026-09-24
# after grading 27 sites: only `layers/common.py` remains, and it is left
# deliberately -- 32 finding types fan out of that one helper, ~10 of its
# callers gate on verify_semantic and the rest are static, so one default tier
# would be invented data (task: classify per caller).
_UNGRADED_BUDGET = 0

# `Finding(**f)` where f is a NAME is a pass-through: the tier belongs to the
# code that built the dict, and stamping it here would OVERWRITE a correct
# value.  `layers/common.py` is the exception that proves the rule -- it is the
# one choke point every advanced layer routes through, and it derives the tier
# from the caller's own `headless` argument (pinned by
# `test_the_layer_choke_point_still_defaults_a_class` below).
#
# Keyed by MODULE + COUNT, not file:line -- an insertion anywhere above a site
# shifts its line number, so a line-pinned allow-list rots the moment the file
# is edited (it did, once, within this same session).  Per-module counts still
# catch a new pass-through hiding next to an old one.
_PASSTHROUGH_SITES = {
    "xssentinel/cli_commands.py": 2,       # retire_js + sqli advisory dicts
    "xssentinel/cli_runner.py": 2,         # same, batch path
    "xssentinel/api/server.py": 1,         # rehydrating findings from the store
    "xssentinel/core/layers/common.py": 1,  # the layer choke point, graded here
}

# Anything that lowers the total to here is not "fixed", it is a deleted probe.
_MIN_SITES = 40


def _is_passthrough(node):
    """True for `Finding(**f)` where f is a NAME -- forwarding, not authoring.

    A dict LITERAL (`Finding(**{...})`) is still authoring: its keys are right
    there in the source, and most real emit sites are written that way.
    """
    return (not node.args and len(node.keywords) == 1
            and node.keywords[0].arg is None
            and isinstance(node.keywords[0].value, ast.Name))


def _sites():
    """Every `Finding(...)` construction: (path, lineno, graded, passthrough)."""
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
                pass_through = _is_passthrough(node)
                seg = ast.get_source_segment(src, node) or ""
                graded = pass_through or "evidence_class" in seg or any(
                    k.arg == "evidence_class" for k in node.keywords)
                out.append((os.path.relpath(path, ROOT).replace(os.sep, "/"),
                            node.lineno, graded, pass_through))
    return out


def test_passthrough_sites_are_the_known_ones():
    """Forwarding sites are exempt for a stated reason, so the reason is pinned.

    A new `Finding(**f)` anywhere fails this, and so does one added inside an
    already-exempt module -- counts are per module, not per file.
    """
    seen = Counter(p for p, _l, _g, pt in _sites() if pt)
    assert dict(seen) == _PASSTHROUGH_SITES, (
        "pass-through set drifted; expected %s got %s"
        % (_PASSTHROUGH_SITES, dict(seen)))


def test_the_ruler_finds_known_sites():
    """Self-check: this parser must see the sites it claims to see.

    A counter that silently matches nothing would make every assertion below
    pass for the wrong reason -- the failure mode that has already bitten this
    project twice with path-separator-sensitive greps.
    """
    sites = _sites()
    assert len(sites) >= _MIN_SITES, f"parser sees only {len(sites)} sites"
    graded = [s for s in sites if s[2] and not s[3]]
    assert graded, "parser found zero authored+graded sites: the check is broken"
    # the module that started it all must still be one of them
    assert any("scanner.py" in p for p, _l, g, _pt in graded if g)


def test_no_new_un_graded_finding_site():
    un = [f"{p}:{ln}" for p, ln, g, _pt in sorted(_sites()) if not g]
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
                 "core/upload_probe.py", "core/scenarios.py",
                 "core/async_scanner.py")
    bad = []
    for path, lineno, graded, _pt in _sites():
        norm = path.replace(os.sep, "/").split("xssentinel/")[-1]
        if norm in committed and not graded:
            bad.append(f"{norm}:{lineno}")
    assert not bad, "un-graded findings in committed modules: " + ", ".join(bad)


def test_the_layer_choke_point_still_defaults_a_class():
    """The exemption for `layers/common.py` is only true while that helper
    keeps stating a tier -- so the behavior is pinned, not assumed.

    The tier must come from what the CALLER already declared (a `headless`
    dict), never from a guess about the layer: 32 different finding types flow
    through this one function.
    """
    from xssentinel.core.findings import (EVIDENCE_BROWSER_EXECUTED,
                                          EVIDENCE_NO_BROWSER)
    from xssentinel.core.layers.common import _make_finding

    plain = _make_finding(url="http://t/", ftype="postmessage_xss")
    assert plain.data["evidence_class"] == EVIDENCE_NO_BROWSER

    ran = _make_finding(url="http://t/", ftype="worker_xss",
                        headless={"available": True, "confirmed": True})
    assert ran.data["evidence_class"] == EVIDENCE_BROWSER_EXECUTED

    # A caller that knows better wins: setdefault must not clobber it.
    stated = _make_finding(url="http://t/", ftype="dangling_markup_potential",
                           evidence_class="model-only")
    assert stated.data["evidence_class"] == "model-only"
