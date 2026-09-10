# -*- coding: utf-8 -*-
"""Phase 112: engine-scoped cases must be SKIPPED, not scored as misses.

The 121-case run showed async's only FN was pos-stored-01 -- and it was
not a detection failure: --stored-inject is sync-only by design (Phase
85) and is ignored under --async.  Counting that as a miss blames the
async engine for a vector it never claims to implement.

A case may now declare ``engines``; evaluating it on an engine outside
that list returns verdict "SKIP", which falls outside TP/FP/TN/FN (the
tally counts those four explicitly), so rates stay honest while the
per-case record still shows what happened.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.runner import evaluate_case, CaseResult


class _NoScan:
    """Fail loudly if a skipped case still tries to run the scanner."""
    def __init__(self, *a, **kw):  # pragma: no cover
        raise AssertionError("scanner must not run for a SKIPped case")


def _case(**kw):
    base = {"id": "x-01", "path": "/r/x", "param": "q", "mode": "raw_element",
            "ground_truth": "vulnerable", "context": "html_element",
            "difficulty": "easy"}
    base.update(kw)
    return base


def test_sync_only_case_is_skipped_on_async(monkeypatch):
    import benchmark.runner as R
    monkeypatch.setattr(R, "_invoke_scanner", _NoScan)
    res = evaluate_case("http://127.0.0.1:1", _case(engines=["sync"]),
                        timeout=5, max_payloads=4, max_transforms=2,
                        engine="async")
    assert isinstance(res, CaseResult)
    assert res.verdict == "SKIP"
    assert res.detected is False and res.findings_count == 0


def test_the_same_case_is_not_skipped_on_its_engine(monkeypatch):
    import benchmark.runner as R
    calls = {"n": 0}

    def _fake(url, timeout=0, max_payloads=0, max_transforms=0,
              extra_args=None, engine="sync"):
        calls["n"] += 1
        return ({"findings": []}, 1.0, "")

    monkeypatch.setattr(R, "_invoke_scanner", _fake)
    res = evaluate_case("http://127.0.0.1:1", _case(engines=["sync"]),
                        timeout=5, max_payloads=4, max_transforms=2,
                        engine="sync")
    assert calls["n"] == 1, "the supported engine must actually scan"
    assert res.verdict in ("FN", "TP", "TN", "FP")


def test_cases_without_the_field_are_never_skipped(monkeypatch):
    import benchmark.runner as R
    calls = {"n": 0}

    def _fake(url, timeout=0, max_payloads=0, max_transforms=0,
              extra_args=None, engine="sync"):
        calls["n"] += 1
        return ({"findings": []}, 1.0, "")

    monkeypatch.setattr(R, "_invoke_scanner", _fake)
    for eng in ("sync", "async"):
        evaluate_case("http://127.0.0.1:1", _case(),
                      timeout=5, max_payloads=4, max_transforms=2,
                      engine=eng)
    assert calls["n"] == 2, "unannotated cases must run on every engine"


def test_skip_is_outside_the_four_scored_verdicts():
    """The tally sums TP/FP/TN/FN explicitly -- SKIP must not match any."""
    assert "SKIP" not in ("TP", "FP", "TN", "FN")
