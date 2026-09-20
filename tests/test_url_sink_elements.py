# -*- coding: utf-8 -*-
"""Phase 168: URL sinks are element-aware, and attribute values are not markup.

Two defects measured before fixing (benchmark/sink_execution.py, headless
Chromium 2026-09-18):

1. ``_structural_confirm`` accepted ANY element's ``href``/``src`` carrying a
   ``javascript:`` URL, so ``<img src=javascript:...>``,
   ``<link href=javascript:...>`` and ``<embed src=javascript:...>`` were
   reported with an execution claim while running nothing.

2. The raw-text fallback could not tell markup from an attribute VALUE, so a
   payload such as ``data:text/html,<script>TOKEN</script>`` reflected into any
   attribute read as "token inside a <script> element" and confirmed -- while
   the browser keeps that text in the attribute and parses no script
   (``img.src`` / ``script.src`` / ``link.href`` with such a value measured as
   executing nothing).

``iframe.srcdoc`` is the documented exception to (2): its value IS parsed as a
document, and it is measured to execute.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.verifier import verify_semantic  # noqa: E402

TOK = "xssv_1234abcd"
JS = f"javascript:alert('{TOK}')"
DATA = f"data:text/html,<script>{TOK}</script>"


def _page(markup: str) -> str:
    return f"<html><head></head><body>{markup}</body></html>"


def _v(markup: str) -> dict:
    return verify_semantic(_page(markup), TOK)


def _doc(markup: str) -> str:
    """A full document with no enclosing <body>.

    Needed for <frameset>: an enclosing <body> switches the parser's
    frameset-ok flag off, so the frameset and the <frame> inside it are both
    dropped.  That is a different shape from the one that executes -- see
    ``test_frame_in_a_frameset_confirms_but_a_bare_frame_does_not``.
    """
    return f"<!DOCTYPE html><html><head></head>{markup}</html>"


def _vd(markup: str) -> dict:
    return verify_semantic(_doc(markup), TOK)


def test_executing_shapes_confirm():
    for markup in (f'<iframe src="{JS}">',
                   f'<iframe srcdoc="<script>{TOK}</script>">'):
        r = _v(markup)
        assert r["confirmed"], f"{markup} should confirm: {r}"
        assert not r.get("requires_activation"), markup


def test_frame_in_a_frameset_confirms_but_a_bare_frame_does_not():
    """``<frame>`` is only a sink where the parser actually keeps it.

    An earlier version of this file asserted that a bare ``<frame
    src=javascript:>`` confirms.  It does not, and the sandbox gate is what
    caught the difference -- so both halves are pinned here, because a "this
    shape is inert" verdict is exactly the kind someone later "fixes" back into
    an over-claim.

    Measured over a real HTTP origin (``_p168_frame_probe.py``), reporting the
    nodes the parser actually built next to each result:

        <iframe src=javascript:>                    EXEC   built=[iframe]
        <frame src=javascript:>           (bare)    no     built=[]  <- dropped
        <frameset><frame src=javascript:>           EXEC   built=[frameset,frame]
        createElement('frame') + appendChild        EXEC   built=[frame]

    A bare ``<frame>`` start tag never becomes a node, so nothing can execute
    from it.  Inside a frameset it does execute, and the structural rule plus
    the sandbox agree with both.  (``benchmark/results/sink_execution.json``
    reports ``frame.src`` as executing: that shape builds the element with
    ``createElement``, so it never goes through the parser.)
    """
    r = _vd(f'<frameset><frame src="{JS}"></frameset>')
    assert r["confirmed"], r
    assert not r.get("requires_activation"), r

    bare = _v(f'<frame src="{JS}">')
    assert not bare["confirmed"], bare
    assert bare.get("sandbox_state") == "inert", bare


def test_activation_gated_shapes_confirm_and_say_so():
    for markup in (f'<a href="{JS}">x</a>',
                   f'<area href="{JS}">',
                   f'<form action="{JS}"></form>',
                   f'<button formaction="{JS}">x</button>'):
        r = _v(markup)
        assert r["confirmed"], f"{markup} is a real XSS behind activation: {r}"
        assert r.get("requires_activation") is True, markup


def test_measured_non_executing_url_shapes_stay_silent():
    """benchmark/sink_execution.py measured these as running nothing."""
    for markup in (f'<img src="{JS}">',
                   f'<link href="{JS}">',
                   f'<script src="{JS}"></script>',
                   f'<base href="{JS}">',
                   f'<embed src="{JS}">',
                   f'<object data="{JS}"></object>',
                   '<meta http-equiv="refresh" content="0;url='
                   + JS + '">'):
        r = _v(markup)
        assert not r["confirmed"], (
            f"{markup} does not execute in Chromium; claiming it over-states: "
            f"{r}")


def test_attribute_hosted_markup_is_not_markup():
    """The FP class: a data: URL containing <script> inside ANY attribute."""
    for markup in (f'<img src="{DATA}">',
                   f'<a href="{DATA}">x</a>',
                   f'<link href="{DATA}">',
                   f'<embed src="{DATA}">',
                   f'<div title="{DATA}">x</div>'):
        r = _v(markup)
        assert not r["confirmed"], (
            f"the <script> text is inside an attribute value, not markup: {r}")
        assert "attribute value" in (r.get("detail") or ""), r


def test_srcdoc_still_treats_its_value_as_a_document():
    """The exception to the attribute rule -- measured to execute."""
    r = _v(f'<iframe srcdoc="<script>{TOK}</script>">')
    assert r["confirmed"] and r["context"] == "script_block", r


def test_real_markup_script_still_confirms():
    r = _v(f"<div><script>{TOK}</script></div>")
    assert r["confirmed"] and r["context"] == "script_block", r
