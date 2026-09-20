# -*- coding: utf-8 -*-
"""The sandbox must stay right about HTML, or it must say so.

`xssentinel/core/sandbox.py` replaces a Chromium launch for the
"does this reflected markup execute?" question.  That claim has a shelf life:
one parser rule edited for one payload can silently flip a hundred other cases,
and the cost is asymmetric -- an inert verdict on something the browser runs is
a missed vulnerability the scanner never reports.

So this test replays the recorded Chromium ground truth
(benchmark/results/browser_dom_oracle.json -- 900 payload x context x sink cases,
regenerate with `python -m benchmark.browser_dom_oracle`) and asserts the two
numbers that decide whether the sandbox may be consulted at all:

    MISSED == 0   the sandbox never calls a browser-executing payload inert
    OVER   == 0   the sandbox never claims execution the browser denied

Anything the sandbox cannot decide must land in UNKNOWN instead, which costs a
browser probe but not a wrong answer.  The UNKNOWN budget is asserted too: if it
grows past a quarter of the corpus the sandbox has stopped being worth its
keep, and that is a fact worth failing on rather than discovering later.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import sandbox  # noqa: E402

ORACLE = os.path.join(ROOT, "benchmark", "results", "browser_dom_oracle.json")
TOKEN = "__x()"          # the oracle's quote-free sentinel

pytestmark = pytest.mark.skipif(
    not os.path.exists(ORACLE),
    reason="no recorded browser ground truth; run `python -m "
           "benchmark.browser_dom_oracle` to regenerate it")


def _rows():
    with open(ORACLE, encoding="utf-8") as fh:
        return json.load(fh)["rows"]


def _classify(rows, sink, key):
    """Fold (sandbox verdict, browser result) into the four outcomes that
    matter.  `activation` is agreement, not an over-claim: the harness never
    performs a user gesture, so a gesture-gated payload not executing is the
    expected browser answer."""
    missed, over, unknown = [], [], []
    live_ok = inert_ok = activation_only = 0
    for r in rows:
        browser = r.get(key)
        if browser is None:
            continue                      # inconclusive is not evidence
        v = sandbox.judge(r["document"], TOKEN, sink=sink)
        claimed = v.state == "live" and not v.activation
        if v.state == "unknown":
            unknown.append((r["payload"], r["host"], v.reason))
        elif v.state == "live" and v.activation:
            activation_only += 1
            if browser:
                over.append((r["payload"], r["host"],
                             "browser ran a payload the sandbox gated on user "
                             "activation: " + v.reason))
        elif browser and not claimed:
            missed.append((r["payload"], r["host"], v.reason))
        elif claimed:
            live_ok += 1
        else:
            inert_ok += 1
    return dict(missed=missed, over=over, unknown=unknown, live=live_ok,
                inert=inert_ok, activation=activation_only, scored=len(
                    [r for r in rows if r.get(key) is not None]))


@pytest.mark.parametrize("sink,key", (("parser", "exec_parser"),
                                      ("innerhtml", "exec_ihn1")))
def test_no_real_xss_is_called_inert(sink, key):
    got = _classify(_rows(), sink, key)
    assert not got["missed"], (
        f"{len(got['missed'])} case(s) Chromium executes while the sandbox says "
        f"inert -- a missed XSS. First few:\n"
        + "\n".join(f"  {p} x {h}: {why[:90]}"
                    for p, h, why in got["missed"][:6]))


@pytest.mark.parametrize("sink,key", (("parser", "exec_parser"),
                                      ("innerhtml", "exec_ihn1")))
def test_no_execution_is_claimed_that_the_browser_denied(sink, key):
    got = _classify(_rows(), sink, key)
    assert not got["over"], (
        f"{len(got['over'])} over-claim(s): the sandbox reports execution "
        f"Chromium denied. First few:\n"
        + "\n".join(f"  {p} x {h}: {why[:90]}"
                    for p, h, why in got["over"][:6]))


@pytest.mark.parametrize("sink,key", (("parser", "exec_parser"),
                                      ("innerhtml", "exec_ihn1")))
def test_unknown_stays_a_minority(sink, key):
    rows = _rows()
    got = _classify(rows, sink, key)
    scored = got["activation"] + got["live"] + got["inert"] + len(got["unknown"])
    assert scored, "nothing was scored -- is the oracle stale?"
    share = len(got["unknown"]) / scored
    assert share < 0.25, (
        f"{len(got['unknown'])}/{scored} cases ({share:.0%}) fall back to the "
        f"browser; the sandbox is no longer earning its keep as a pre-screen")


def test_every_browser_recorded_mutation_vector_is_caught():
    """The round-trip arm has to see what the browser sees, in both directions.

    This test asserted something weaker when written, because the corpus then
    recorded zero `exec_ihn2 and not exec_ihn1` rows and it was tempting to
    generalise that into "a bare innerHTML round-trip cannot create XSS -- you
    need a sanitizer in the middle".  The generalisation was wrong, and
    `benchmark/sanitizer_probe.py` found the counter-example with no sanitizer
    anywhere near it:

        <math><mtext><table><mglyph><style><img onerror=...>

    foster-parenting the empty <table> moves it; the re-parse then hits the
    mglyph MathML namespace exception, <style> leaves the HTML raw-text content
    model, and the text becomes a live tag.  That payload is now in the oracle
    corpus, so the claim under test is the narrow checkable one: every mutation
    vector the browser recorded is caught, and none is invented.
    """
    rows = _rows()
    missed, false_claims = [], []
    for r in rows:
        e1, e2 = r.get("exec_ihn1"), r.get("exec_ihn2")
        if e1 is None or e2 is None:
            continue
        v = sandbox.judge_roundtrip(r["document"], TOKEN, sink="innerhtml")
        sandbox_mxss = (v.state == "live" and not v.activation
                        and "MUTATED" in (v.evidence or ""))
        if e2 and not e1 and not sandbox_mxss:
            missed.append((r["payload"], r["host"], v.state, v.reason[:70]))
        elif not (e2 and not e1) and sandbox_mxss:
            false_claims.append((r["payload"], r["host"], v.reason[:70]))
    recorded = sum(1 for r in rows
                   if r.get("exec_ihn2") and not r.get("exec_ihn1"))
    assert recorded, (
        "the corpus records no mutation vector at all, so this test proves "
        "nothing -- re-collect with `python -m benchmark.browser_dom_oracle`;"
        " the mxss-* payloads exist for exactly this arm")
    assert not missed, (
        f"{len(missed)} browser mXSS case(s) the round-trip missed:\n"
        + "\n".join(f"  {p} x {h}: {st} {why}" for p, h, st, why in missed[:6]))
    assert not false_claims, (
        f"{len(false_claims)} invented mXSS case(s):\n"
        + "\n".join(f"  {p} x {h}: {w}" for p, h, w in false_claims[:6]))


def test_serialisation_reproduces_chromium_on_the_vast_majority():
    """Not a byte-exactness requirement -- attribute quoting and implied-element
    differences are cosmetic for liveness.  It is a floor: if the serialiser
    drifts far enough to disagree on a third of shapes, the round-trip it feeds
    the mXSS verdict with is no longer the browser's round-trip."""
    rows = [r for r in _rows() if r.get("serialized")]
    same = sum(1 for r in rows if sandbox.serialize(
        sandbox.parse(r["document"], fragment=True).root) == r["serialized"])
    assert same >= 0.8 * len(rows), (
        f"only {same}/{len(rows)} serialisations match Chromium byte for byte")
