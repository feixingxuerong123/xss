# -*- coding: utf-8 -*-
"""Guard the oracle artifact itself, because everything else is scored against it.

`benchmark/results/browser_dom_oracle.json` is not a fixture like the others: it
is the *answer key* for `sandbox_fidelity.py`, for `corpus_gap.py`, and for the
`MISSED 0 / OVER 0` claim in every delivery report.  Until now nothing checked it.
That gap cost a session: two full runs of the same matrix disagreed on 7 rows --
including `img-onerror x text`, whose stored answer was `exec_ihn1=False` while a
stamped re-measure returns True three times out of three -- and the disagreement
was only found by hand because no test looked.

So this file asserts three things about the artifact:

    structure   it holds one row per (payload, host), each with a document that
                really contains the payload it claims to have measured;
    provenance  every recorded execution says WHICH page stamped it, and no row
                carries another row's stamp (that is the contamination this
                harness used to be blind to);
    canaries    a handful of shapes whose browser answer is beyond doubt, so a
                generator that regresses -- a settle that became too short, a
                navigation that stopped waiting for load -- fails here instead of
                quietly moving the headline number.

The provenance assertions skip when the artifact predates stamping, so this test
passes against an old file and starts biting against a new one.

Run:  pytest tests/test_oracle_integrity.py
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from benchmark.browser_dom_oracle import PAYLOADS  # noqa: E402

ORACLE = os.path.join(ROOT, "benchmark", "results", "browser_dom_oracle.json")
PAYLOAD_OF = dict((p, b) for p, b, _t in PAYLOADS)


@pytest.fixture(scope="module")
def art():
    if not os.path.exists(ORACLE):
        pytest.skip("oracle not measured yet: run `python -m "
                    "benchmark.browser_dom_oracle`")
    return json.load(open(ORACLE, encoding="utf-8"))


def _rows(art):
    return {(r["payload"], r["host"]): r for r in art["rows"]}


def test_one_row_per_payload_and_host(art):
    n_p, n_h = len(art["payloads"]), len(art["hosts"])
    assert art["count"] == len(art["rows"]) == n_p * n_h, (
        f"{art['count']} rows vs {n_p}x{n_h}: the matrix is partial, and a "
        "partial answer key silently shrinks every denominator scored against it")
    seen = _rows(art)
    assert len(seen) == n_p * n_h, "duplicate (payload, host) rows"


def test_every_row_measured_the_payload_it_names(art):
    bad = [r["payload"] + "/" + r["host"] for r in art["rows"]
           if PAYLOAD_OF.get(r["payload"]) not in r["document"]]
    assert not bad, f"rows whose document does not contain their payload: {bad[:5]}"


def test_hits_carry_their_own_stamp_and_no_one_elses(art):
    """Provenance.  A row whose stamp names a DIFFERENT row's page is a lost
    measurement (another document wrote the slot), not a browser fact -- and the
    artifact must not pretend otherwise."""
    if not any("stamp_paths" in r for r in art["rows"]):
        pytest.skip("artifact predates stamped hits; re-measure with the current "
                    "benchmark.browser_dom_oracle")
    missing = [r["payload"] + "/" + r["host"] for r in art["rows"]
               if r.get("exec_parser") and not r.get("parser_stamp")]
    assert not missing, f"hits with no stamp to vouch for them: {missing[:5]}"
    stray = []
    for r in art["rows"]:
        want = r["stamp_paths"]
        for arm, key in (("parser", "parser_stamp"), ("ihn1", "ihn1_stamp"),
                         ("ihn2", "ihn2_stamp")):
            got = r.get(key)
            if got is not None and got != want["parser" if arm == "parser"
                                                 else "sink"]:
                stray.append(f"{r['payload']}/{r['host']}:{arm}->{got}")
    assert not stray, (f"late writes from another row landed in {len(stray)} "
                       f"reads: {stray[:6]} -- those rows must be re-measured, "
                       "not scored")


# --- canaries ---------------------------------------------------------------
# Each of these was re-measured directly (benchmark/oracle_reproduce.py, and the
# stamped generator's own first rows) and is not in doubt: a markup handler in
# body content fires, the same bytes parked inside a quoted attribute cannot.
@pytest.mark.parametrize("payload,host,key,want", [
    ("img-onerror", "text", "exec_parser", True),
    ("img-onerror", "text", "exec_ihn1", True),
    ("img-onerror", "attr_dq", "exec_parser", False),
    ("img-onerror", "attr_dq", "exec_ihn1", False),
])
def test_canaries_still_say_what_the_browser_said(art, payload, host, key, want):
    rows = _rows(art)
    row = rows.get((payload, host), {})
    got = row.get(key)
    assert got is want, (
        f"{payload}/{host} {key} = {got}, browser truth is {want}. This shape is "
        "not in doubt, so a disagreement means the ANSWER KEY is stale, not that "
        f"sandbox.py changed (row provenance: {row.get('stamp_paths')!r} / "
        f"stamps {row.get('parser_stamp')!r} {row.get('ihn1_stamp')!r}). Fix: "
        "`python -m benchmark.browser_dom_oracle`, then re-score with "
        "`python -m benchmark.sandbox_fidelity`.")
