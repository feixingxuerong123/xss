# -*- coding: utf-8 -*-
"""Phase 109: benchmark relevance must understand non-query carriers.

Writing the first benchmark cases for cookie / path / error / CORS
vectors exposed a scoring bug that had nothing to do with detection:
the scanner DID find them, but _is_detected filtered findings by
``param`` name -- and these vectors label their carrier instead
("(cookie:lang)", "(path)", "(error_path)").  Every real hit was scored
as a false negative.

A case can now declare ``finding_types`` (the finding type(s) it is
about); those count as relevant regardless of carrier labelling.  Cases
without the field keep the old param-matching behaviour exactly, so the
107 pre-existing cases are unaffected.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark.runner import _is_detected


def _report(*findings):
    return {"findings": list(findings)}


def test_legacy_behavior_is_unchanged_without_finding_types():
    case = {"path": "/r/elem01", "param": "q", "ground_truth": "vulnerable"}
    rep = _report({"type": "reflected", "param": "q", "severity": "high",
                   "url": "http://h/r/elem01"})
    detected, n, _ = _is_detected(rep, case)
    assert detected and n == 1


def test_carrier_label_no_longer_hides_a_real_finding():
    """The exact shape that used to score a cookie hit as an FN."""
    case = {"path": "/r/ck01", "param": "q", "ground_truth": "vulnerable",
            "finding_types": ["cookie_xss"]}
    rep = _report({"type": "cookie_xss", "param": "(cookie:lang)",
                   "severity": "high", "url": "http://h/r/ck01"})
    detected, n, _ = _is_detected(rep, case)
    assert detected and n == 1, "cookie carrier must count as relevant"


def test_path_finding_with_prefix_path_matches():
    case = {"path": "/r/pth01/*", "param": "q",
            "ground_truth": "vulnerable", "finding_types": ["path_xss"]}
    rep = _report({"type": "path_xss", "param": "(path)",
                   "severity": "high",
                   "url": "http://h/r/pth01/%3Csvg%20onload=%3E"})
    detected, n, _ = _is_detected(rep, case)
    assert detected, "the '*' in a prefix route must not block matching"


def test_wrong_type_is_not_counted_for_a_declared_case():
    case = {"path": "/r/ck01", "param": "q", "ground_truth": "safe",
            "finding_types": ["cookie_xss"]}
    # a reflected finding on the same path is a DIFFERENT vector and must
    # not be scored against this case
    rep = _report({"type": "reflected", "param": "q", "severity": "high",
                   "url": "http://h/r/ck01"})
    detected, n, _ = _is_detected(rep, case)
    assert not detected and n == 0


def test_declared_type_on_another_path_is_not_counted():
    case = {"path": "/r/ck01", "param": "q", "ground_truth": "safe",
            "finding_types": ["cookie_xss"]}
    rep = _report({"type": "cookie_xss", "param": "(cookie:lang)",
                   "severity": "high", "url": "http://h/r/OTHER"})
    detected, _, _ = _is_detected(rep, case)
    assert not detected, "path must still scope the relevance"
