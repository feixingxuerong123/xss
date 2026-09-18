# -*- coding: utf-8 -*-
"""Phase 160: the benchmark scorer must not hide a false positive.

``benchmark/runner._is_detected`` narrowed to ``case["finding_types"]``
whenever a case declared them.  On a SAFE case that is a blind spot: a
high-severity finding from another layer was scored TN.  Measured with
``_p160_fp_scan.py``: 5 of 75 safe cases carried an invisible finding, among
them neg-dom-08's ``trusted_types_policy_bypass``.

Rule now: on a safe case any high/medium/critical non-CSP finding counts,
whatever its type; low/info do not (a static DOM hint is hygiene, not an
XSS claim); positives keep the narrowing so unrelated noise cannot be
credited as the vector the case is about.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.runner import _is_detected  # noqa: E402

_SAFE = {
    "id": "neg-synthetic-01",
    "path": "/dom/tt-innerhtml-safe#/route",
    "param": "q",
    "ground_truth": "safe",
    "finding_types": ["dom_dynamic"],
}


def _rep(*findings):
    return {"findings": list(findings)}


def _finding(**kw):
    f = {"url": "http://127.0.0.1:18877/dom/tt-innerhtml-safe?q=test",
         "type": "dom_dynamic", "severity": "high", "param": "q"}
    f.update(kw)
    return f


def test_safe_case_counts_a_finding_from_another_layer():
    """The regression: a declared finding_types must not hide other layers."""
    rep = _rep(_finding(type="trusted_types_policy_bypass",
                        severity="high", param=None))
    detected, count, _ = _is_detected(rep, _SAFE)
    assert detected is True, (
        "a high-severity finding on a safe page is a false positive, "
        "whatever layer produced it")


def test_safe_case_ignores_low_severity_hygiene():
    for t in ("dom", "trusted_types_policy_unused", "csp_missing"):
        rep = _rep(_finding(type=t, severity="low", param=None))
        detected, count, _ = _is_detected(rep, _SAFE)
        assert detected is False, f"{t} at low severity is hygiene, not FP"


def test_safe_case_ignores_csp_and_fuzzer_noise():
    rep = _rep(_finding(type="csp_weak_directive", severity="medium"),
               _finding(type="fuzzer_triage", severity="medium"))
    detected, _, _ = _is_detected(rep, _SAFE)
    assert detected is False


def test_positive_case_still_requires_the_declared_type():
    """The other half: noise must not be credited as the vector."""
    case = dict(_SAFE, id="pos-synthetic-01", ground_truth="vulnerable")
    rep = _rep(_finding(type="trusted_types_policy_bypass", param=None))
    detected, _, _ = _is_detected(rep, case)
    assert detected is False, "unrelated finding on a positive case: no credit"

    rep = _rep(_finding(type="dom_dynamic"))
    detected, _, _ = _is_detected(rep, case)
    assert detected is True
