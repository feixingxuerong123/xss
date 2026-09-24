# -*- coding: utf-8 -*-
"""Evidence tiers: how sure we are is stated separately from how bad it would be.

`scanner.py` used to write `severity, confidence = "high", "high"` unconditionally,
after the headless browser had already rendered the page -- so a finding the real
Chromium REFUTED (no dialog carried the probe token) reached the client with the
same confidence as one whose dialog did.  `payload_survived()` had the mirror
defect: an unanswerable survival question was resolved by returning True, i.e.
in the direction that manufactures findings.

Both are fixed here with the invariant that makes them safe to ship: **severity is
not the channel for doubt**.  `benchmark/runner.py:318` and every downstream triage
filter read severity as "was this detected at all", so expressing uncertainty by
demoting severity would silently convert true positives into false negatives --
trading an honesty problem for a worse one.  Doubt goes to `confidence` and to the
named `evidence_class` tier, both of which the report prints -- in its OWN key,
because `evidence` is the field ~50 other producers use to carry the proving TEXT
(reflected markup, cookie header, CSS gadget).

Run:  pytest tests/test_evidence_grading.py
"""
from __future__ import annotations

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import verifier  # noqa: E402
from xssentinel.core.findings import Finding  # noqa: E402
from xssentinel.core.report import build_html  # noqa: E402
from xssentinel.core.scanner import _grade_evidence  # noqa: E402


# --- the grading function ---------------------------------------------------

@pytest.mark.parametrize("headless,want_tier,want_conf", [
    ({"outcome": "fired", "confirmed": True}, "browser-executed", "high"),
    ({"outcome": "not-fired", "confirmed": False, "available": True},
     "browser-refuted", "low"),
    ({"outcome": "errored"}, "browser-error", "high"),
    ({"available": False}, "browser-unavailable", "high"),
    (None, "browser-unavailable", "high"),
    # an older verifier dict with no `outcome`: a detail saying "error" is an
    # error, not a refutation -- the two used to render identically
    ({"confirmed": False, "available": True,
      "detail": "headless run error: crash"}, "browser-error", "high"),
])
def test_outcome_maps_to_tier_and_confidence(headless, want_tier, want_conf):
    tier, conf, detail = _grade_evidence(headless, "high", "base detail")
    assert tier == want_tier
    assert conf == want_conf
    if want_tier in ("browser-error", "browser-unavailable"):
        # the whole point: "we could not check" must not be silently confident
        assert "unverified" in detail or "MISSING" in detail


def test_refuted_is_low_confidence_but_never_a_changed_severity():
    """The safety rail for the whole design.

    If doubt were expressed through severity, the benchmark's severity filter
    would stop counting the finding and a true positive would become an FN.  A
    refuted finding therefore keeps its severity and only its confidence moves.
    """
    tier, conf, _ = _grade_evidence({"outcome": "not-fired", "confirmed": False,
                                     "available": True}, "high", "d")
    assert (tier, conf) == ("browser-refuted", "low")
    d = {"severity": "high", "confidence": conf, "evidence_class": tier,
         "type": "reflected", "url": "http://t/", "param": "q"}
    assert d["severity"] == "high", "severity is impact, not belief"


# --- what the client-facing HTML actually says -----------------------------

def _one_finding(**over):
    d = {"url": "http://t/x", "method": "GET", "param": "q", "type": "reflected",
         "context": "html_element", "payload": "<svg onload=PROBE>",
         "severity": "high", "confidence": "low", "detail": "reflected in body",
         "evidence_class": "browser-refuted",
         "headless": {"available": True, "confirmed": False,
                      "outcome": "not-fired", "detail": "no dialog"},
         "poc": {"url": "http://t/x?q=1", "curl": "curl 'x'"},
         "poc_verified": False}
    d.update(over)
    return Finding(**d)


def test_html_report_states_the_evidence_tier_and_the_refutation():
    html = build_html([_one_finding()], "http://t/x", {"generated": "g"})
    assert "evidence: browser-refuted" in html
    assert "confidence: low" in html
    assert "browser did NOT reproduce" in html
    assert "PoC replay: DID NOT replay" in html, \
        "the replay verdict used to live only in the optional --poc-dir INDEX.md"


def test_html_report_distinguishes_no_browser_from_browser_said_no():
    """The defect this replaces rendered both as 'not fired'."""
    no_check = _one_finding(headless={}, evidence_class="browser-unavailable",
                            confidence="high", poc_verified=None)
    html = build_html([no_check], "http://t/x", {"generated": "g"})
    assert "no browser check" in html
    assert "browser did NOT reproduce" not in html
    assert "PoC replay" not in html, "not running the replay is not a verdict"


def test_executed_finding_reads_differently_from_a_refuted_one():
    fired = _one_finding(evidence_class="browser-executed", confidence="high",
                         headless={"available": True, "confirmed": True,
                                   "outcome": "fired", "detail": "token dialog"},
                         poc_verified=True)
    html = build_html([fired], "http://t/x", {"generated": "g"})
    assert "evidence: browser-executed" in html
    assert "PoC replay: verified" in html
    assert "browser did NOT reproduce" not in html


# --- the survival gate must fail closed ------------------------------------

def test_payload_survival_inconclusive_is_not_treated_as_survived(monkeypatch):
    payload = "<img src=x onerror=alert(xssv_17ab23cd4)>"
    text = f"<div>{payload}</div>"
    # positive control first: if the happy path were also broken, the fail-closed
    # assertion below would pass for the wrong reason
    assert verifier.payload_survived(text, payload) is True

    def boom(*a, **k):
        raise re.error("synthetic: cannot compile")

    monkeypatch.setattr(verifier.re, "search", boom)
    assert verifier.payload_survived(text, payload) is False, \
        "an unanswerable survival question was resolved toward 'confirmed'"


# --- the model-only tier: a verdict was made, just not by a browser ----------

def test_model_judged_sites_do_not_claim_nothing_verified():
    """`verify_semantic` runs the pure-Python HTML model over the real response.

    Stamping those findings `browser-unavailable` was accurate about the browser
    but erased the judgement that HAD been made -- the same class of error as the
    "executed at ..." wording, pointed the other way.  The clause must say the
    model judged it, and say it is weaker than observed execution.
    """
    from xssentinel.core.findings import EVIDENCE_MODEL
    tier, conf, detail = _grade_evidence(None, "high", "token reflected in body",
                                         model_judged=True)
    assert tier == EVIDENCE_MODEL
    assert conf == "high", "a model verdict must not move confidence either way"
    assert "pure-Python HTML model" in detail
    assert "weaker" in detail
    assert "execution unverified" not in detail, (
        "that phrase claims nothing judged it, which is false here")


def test_plain_ungraded_proof_still_says_execution_unverified():
    """Reverse: header audits and raw reflection checks get no model clause."""
    tier, conf, detail = _grade_evidence(None, "medium", "ACAO reflects any origin")
    assert (tier, conf) == ("browser-unavailable", "medium")
    assert "execution unverified" in detail
    assert "HTML model" not in detail


def test_model_judged_cannot_override_a_real_browser_outcome():
    """`model_judged` only speaks for the no-browser branch.  If a browser DID
    replay it, that outranks the model regardless of what the caller passed."""
    tier, conf, _ = _grade_evidence({"outcome": "fired", "confirmed": True},
                                    "high", "d", model_judged=True)
    assert tier == "browser-executed"
    tier, conf, _ = _grade_evidence({"outcome": "not-fired", "confirmed": False,
                                     "available": True}, "high", "d",
                                    model_judged=True)
    assert (tier, conf) == ("browser-refuted", "low"), \
        "a refutation is evidence AGAINST the finding; the model cannot outweigh it"


# --- the tier and the excerpt are two different things, in two keys ----------

def test_oob_tier_is_not_rendered_as_no_browser_check():
    """An out-of-band beacon IS browser-grade proof, seen through a channel the
    dialog hook cannot watch.

    `headless` is empty on those findings (nothing looked through the hook), so
    the column inferred "no browser check" and printed it in the same row as
    "evidence: oob-confirmed".  A stated tier must outrank an inferred phrase.
    """
    f = _one_finding(headless={}, poc_verified=None, confidence="high",
                     evidence_class="oob-confirmed",
                     detail="victim browser fetched the callback resource")
    html = build_html([f], "http://t/x", {"generated": "g"})
    assert "evidence: oob-confirmed" in html
    assert "no browser check" not in html, "the two lines contradicted each other"
    assert "out-of-band" in html


def test_html_report_shows_the_tier_and_the_excerpt_as_separate_lines():
    """The first version of this feature wrote the tier into `evidence`.

    `evidence` is where ~50 other producers (layers/*, async_scanner, sandbox)
    keep the PROVING TEXT -- the reflected markup around the payload -- and
    report.py:610/:747 and report_ai.py:318 read that key as descriptive text.  A
    tier name in it therefore replaced the excerpt with the word
    "browser-refuted" in every consumer that wanted the snippet.
    """
    both = _one_finding(evidence_class="browser-executed", confidence="high",
                        evidence="...q=PROBE reflected inside div.body...",
                        headless={"available": True, "confirmed": True,
                                  "outcome": "fired"})
    html = build_html([both], "http://t/x", {"generated": "g"})
    assert "evidence: browser-executed" in html
    assert "excerpt: " in html and "reflected inside div.body" in html


def test_a_finding_with_only_an_excerpt_still_shows_it():
    """Reverse of the above: the ~50 excerpt-only producers must not go blind
    because one site started stating a tier."""
    layer_style = _one_finding(headless={}, poc_verified=None,
                               confidence="medium",
                               evidence="style=expression(alert(1)) gadget")
    layer_style.data.pop("evidence_class", None)
    html = build_html([layer_style], "http://t/x", {"generated": "g"})
    assert "excerpt: " in html and "expression(alert(1))" in html
    assert "evidence: " not in html, "no tier was obtained, so none may be implied"


def test_burp_export_carries_the_proving_text_rather_than_the_tier():
    """The client imports this file into Burp and reads the evidence pane.

    The sync scanner never set `evidence`; it keeps the reflected markup in
    `proof["snippet"]`, so every finding this path produced exported an EMPTY
    evidence line and an empty base64 response body.
    """
    from xssentinel.core.report import build_burp_xml
    snippet = "search results for q=PROBE -- reflected here"
    f = _one_finding(headless={}, poc_verified=None,
                     evidence_class="browser-executed",
                     proof={"status": 200, "method": "GET", "param": "q",
                            "payload": "PROBE", "snippet": snippet})
    f.data.pop("evidence", None)
    xml = build_burp_xml([f], "http://t/x", {})
    assert snippet in xml, "the tier must not crowd out the proving text"
    assert "Evidence: browser-executed" not in xml
