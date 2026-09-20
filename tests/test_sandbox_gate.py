# -*- coding: utf-8 -*-
"""The sandbox gate inside `verify_semantic`: it may retract, it may restore,
and it may do neither where it is not qualified.

`verify_semantic` is the single pure-Python confirmation every scan layer goes
through, which makes it the right place for the sandbox and the wrong place to
be clever.  The rules under test:

  * the sandbox may VETO a confirmation it can prove inert;
  * it may RESTORE a rejection that its own namespace/break-out model explains
    (the `<svg><style><img onerror>` family, which this module reads as CSS and
    used to drop);
  * it may do NEITHER when a CSP header is present, because it parses no CSP and
    the verdict may rest on a nonce it cannot see;
  * it may do NEITHER when the confirmation came from a mechanism it does not
    model (mutation XSS, a framework template, a CSS context);
  * XSS_SANDBOX_GATE=0 restores the pre-sandbox behaviour exactly, so a
    benchmark regression can be bisected rather than argued about.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.verifier import verify_semantic  # noqa: E402

T = "xssv_7788ab"


def v(html, headers=None):
    """Default to `{}`, not `None`.

    The gate promotes only when the CSP state is *known*; a helper that forgot
    the argument would quietly route every promotion test down the no-promotion
    path and pass for the wrong reason.  Pass `headers="none"` to test that path
    on purpose.
    """
    if headers is None:
        headers = {}
    if headers == "none":
        return verify_semantic(html, T)
    return verify_semantic(html, T, headers)


# ---------------------------------------------------------------------------
# Restore direction
# ---------------------------------------------------------------------------

def test_svg_style_breakout_is_no_longer_a_false_negative():
    """Chromium executes `<svg><style><img onerror=...>` on the FIRST parse: the
    img breaks out of foreign content and becomes a live HTML sibling.  The
    context model in this module reads the content of `<svg><style>` as CSS and
    returned not-confirmed for it, which is how a vector this common got missed
    (measured: benchmark/results/browser_dom_oracle.json, `img-onerror x
    svg_style` executes via the parser)."""
    html = f'<svg><style><img src=x onerror="alert(\'{T}\')"></style></svg>'
    assert v(html)["confirmed"] is True


def test_math_and_svg_integration_point_breakouts_restore_too():
    for html in (
        f'<math><mtext><img src=x onerror=alert("{T}")></mtext></math>',
        f'<svg><title><img src=x onerror="alert(\'{T}\')"></title></svg>',
    ):
        assert v(html)["confirmed"] is True, html


# ---------------------------------------------------------------------------
# Veto direction
# ---------------------------------------------------------------------------

def test_markup_trapped_in_an_attribute_value_is_vetoed():
    assert v(f'<div class="<img src=x onerror=alert(\'{T}\')">t</div>'
             )["confirmed"] is False


def test_foreign_element_carrying_an_html_handler_is_not_credited():
    """The element exists and the handler is on it, but an <input> in the SVG
    namespace has no focus behaviour to raise onfocus -- measured no-exec."""
    html = f'<svg><style><input autofocus onfocus=alert(\'{T}\')></style></svg>'
    assert v(html)["confirmed"] is False


def test_javascript_uri_on_a_non_executing_element_stays_inert():
    assert v(f'<div><img src="javascript:alert(\'{T}\')"></div>'
             )["confirmed"] is False
    assert v(f'<div><iframe src="javascript:alert(\'{T}\')"></iframe>'
             )["confirmed"] is True


def test_the_gate_never_invents_a_finding_from_no_reflection():
    assert v("<div>nothing carrying the token here</div>")["confirmed"] is False


# ---------------------------------------------------------------------------
# The guard rails
# ---------------------------------------------------------------------------

def test_csp_blocks_promotion_but_never_the_veto():
    """The two directions of the gate do not carry the same risk, so they do not
    share the same guard.

    A Content-Security-Policy can only make markup *less* able to execute.  So
    "no executable node carries the token" is a conclusion that survives any
    policy -- the veto stays.  Claiming execution is the reverse: it needs the
    policy to be known-absent, because a strict `script-src` is exactly what
    makes an otherwise-live `<img onerror>` harmless.  Measured: promoting with
    an empty header dict "confirmed" the three defended `neg-csp-*` cases.

    And `response_headers=None` is not the same as `response_headers={}`.
    Absent means "the caller never looked", which is no evidence of an absent
    policy -- so promotion requires the headers to have been supplied at all.
    """
    inert_looking = f'<div class="<img src=x onerror=alert(\'{T}\')">t</div>'
    csp = {"Content-Security-Policy": "script-src 'self'"}
    # The veto does not need to know about CSP -- but on these bytes the
    # pre-existing CSP layer gets there first and denies the confirmation
    # itself, so the gate is not what decided.  Asserting "sandbox" appears in
    # the detail under CSP would be asserting a veto that never runs.
    assert "sandbox" in str(v(inert_looking).get("detail", ""))
    under_csp = v(inert_looking, csp)
    assert under_csp["confirmed"] is False
    assert "sandbox" not in str(under_csp.get("detail", ""))
    # promotion needs a known-absent policy
    restore_case = f'<svg><style><img src=x onerror="alert(\'{T}\')"></style></svg>'
    assert v(restore_case, {})["confirmed"] is True
    assert v(restore_case, csp)["confirmed"] is False
    # headers never supplied at all is "unknown", not "absent"
    assert verify_semantic(restore_case, T)["confirmed"] is False


def test_exempt_contexts_are_never_vetoed():
    """A confirmation resting on a mechanism the sandbox does not model stays
    standing even if the sandbox would call the bytes inert."""
    html = f'<div>{{{{ "{T}" }}}}</div>'
    got = v(html)
    assert got["confirmed"] is True and got["context"] == "template_angular"
    assert "sandbox" not in str(got.get("detail", ""))


def test_environment_kill_switch_restores_previous_behaviour(monkeypatch):
    """A benchmark regression has to be bisectable.  With the gate off,
    `verify_semantic` is exactly what it was before the sandbox existed."""
    html = f'<svg><style><img src=x onerror="alert(\'{T}\')"></style></svg>'
    monkeypatch.setenv("XSS_SANDBOX_GATE", "0")
    assert v(html)["confirmed"] is False
    monkeypatch.setenv("XSS_SANDBOX_GATE", "1")
    assert v(html)["confirmed"] is True


def test_a_string_logged_is_not_a_string_executed():
    """The trap this gate fell into first, in the other direction.

    `js_console_log` escapes `"` and `</` and reflects the value inside
    `console.log("...")`.  An HTML-entity-encoded payload therefore arrives as
    literal `&quot;&gt;&lt;&#x2F;script&gt;...` characters -- no tag, no breakout,
    and the token sitting in the argument of a perfectly ordinary call.  Reading
    "token is an argument of a call" as proof of execution confirmed this
    defended case (and `neg-sanitizer-01`) as a false positive.

    What makes `alert('TOKEN')` a finding is not that it is a call: it is that
    the token was stamped into *that* call, whose argument is the observable
    effect.  The rule has to be about the marker convention, not about syntax.
    """
    tok = "xssv_7fc673da"
    reflected = ("&quot;>&lt;&#x2F;script&gt;&lt;script&gt;alert&#40;&apos;"
                 + tok + "&apos;&#41;&lt;&#x2F;script&gt;")
    escaped = reflected.replace("\\", "\\\\").replace('"', '\\"')
    doc = ('<!DOCTYPE html><html><head><title>bench</title></head><body>'
           f'<script>console.log("{escaped}");</script></body></html>')
    assert v(doc)["confirmed"] is False
    # the same quoting, but the token lands in the call the marker belongs to
    landed = verify_semantic(
        f'<html><body><script>alert("{tok}")</script></body></html>', tok)
    assert landed["confirmed"] is True


def test_the_gate_never_failed_silently_over_the_whole_hostile_corpus():
    """A broad `except` around a decision is how a gate turns itself off while
    every report still looks healthy.

    The gate runs on every response a scan sees.  So: throw the corpus of
    truncated, malformed and NUL-carrying documents at it, and assert the
    swallow-list stayed empty -- i.e. that the fallback path was never taken.
    Same discipline as the "0 hits on a layer is a layer that never ran" lesson:
    a component contributing nothing looks exactly like a component working.
    """
    from xssentinel.core import verifier

    verifier.SANDBOX_GATE_ERRORS.clear()
    junk = ["<", "<div", "<script>", "<svg><", "<!--", "<p " * 200,
            f"<img src=x onerror={T}", "\x00" * 50, "<table><td></tr>",
            f"<title>{T}", "</script>" * 40, "<svg" + "<style" * 60,
            f'<a href="javascript:{T}">', "<math><mtext>" + f"<input autofocus onfocus={T}>",
            "<![CDATA[" + f"<img src=x onerror={T}>"]
    for j in junk:
        verify_semantic(j, T)
        verify_semantic(j, T, {"Content-Type": "text/html"})
    assert verifier.SANDBOX_GATE_ERRORS == [], verifier.SANDBOX_GATE_ERRORS[:3]


def test_verifier_never_raises_on_hostile_input():
    """The gate runs on every response a scan sees, including truncated and
    malformed ones.  An exception there costs findings."""
    for junk in ("<", "<div", "<script>", "<svg><", "<!--", "<p "*200,
                 f"<img src=x onerror={T}", "\x00" * 50, "<table><td></tr>",
                 f"<title>{T}", "</script>" * 40, "<svg" + "<style" * 60):
        for headers in (None, {"Content-Type": "text/html"}):
            out = verify_semantic(junk, T, headers)
            assert isinstance(out, dict) and "confirmed" in out
