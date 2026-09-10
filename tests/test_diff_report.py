# -*- coding: utf-8 -*-
"""Phase 104: regression-diff (re-test) logic.

The re-test loop is how a finding actually gets closed: the client fixes
something, you re-scan, and the report must say what is NEW, what is
FIXED, and what got WORSE.  diff_report.py implements that (new / fixed /
unchanged / regressed / improved + a CI verdict) and the CLI exposes it
via --diff -- but the 259 lines had no test at all, so a silent error
here would ship straight into the client's re-test report.

All of it is pure (no network), so these tests are fast and total.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.diff_report import (
    _finding_key, _norm_url, _severity_rank, diff_findings,
    diff_report_html, diff_report_json, load_report,
)


def _f(url="https://example.com/a", param="q", ctx="html_element",
       sev="high", ftype="reflected"):
    return {"type": ftype, "url": url, "param": param,
            "context": ctx, "severity": sev}


def test_norm_url_ignores_fragment_and_default_port():
    assert _norm_url("https://example.com:443/a#frag") == \
        _norm_url("https://example.com/a")
    assert _norm_url("http://example.com:80/a") == \
        _norm_url("http://example.com/a")
    # a non-default port is part of the identity
    assert _norm_url("https://example.com:8443/a") != \
        _norm_url("https://example.com/a")


def test_finding_key_is_stable_across_irrelevant_differences():
    a = _f(url="https://example.com:443/a?x=1#f")
    b = _f(url="https://EXAMPLE.com/a?x=1")
    assert _finding_key(a) == _finding_key(b)
    # ...but a different param / context / type IS a different issue
    assert _finding_key(_f(param="other")) != _finding_key(a)
    assert _finding_key(_f(ctx="attr")) != _finding_key(a)
    assert _finding_key(_f(ftype="dom")) != _finding_key(a)


def test_severity_rank_ordering_and_unknown_defaults_to_info():
    assert _severity_rank("critical") > _severity_rank("high") \
        > _severity_rank("medium") > _severity_rank("low") \
        > _severity_rank("info")
    assert _severity_rank(None) == 0
    assert _severity_rank("nonsense") == 0
    assert _severity_rank("HIGH") == _severity_rank("high")  # case-insensitive


def test_new_fixed_and_unchanged():
    base = [_f(param="a"), _f(param="b")]
    cur = [_f(param="b"), _f(param="c")]
    d = diff_findings(base, cur)
    assert [x["param"] for x in d["new"]] == ["c"]
    assert [x["param"] for x in d["fixed"]] == ["a"]
    assert [(b["param"], c["param"]) for b, c in d["unchanged"]] == [("b", "b")]
    assert d["summary"]["new"] == 1 and d["summary"]["fixed"] == 1


def test_regression_and_improvement_are_classified_by_severity():
    base = [_f(param="a", sev="low"), _f(param="b", sev="high")]
    cur = [_f(param="a", sev="critical"), _f(param="b", sev="medium")]
    d = diff_findings(base, cur)
    assert [(b["param"], c["param"]) for b, c in d["regressed"]] == [("a", "a")]
    assert [(b["param"], c["param"]) for b, c in d["improved"]] == [("b", "b")]
    # a regression must never be silently counted as "unchanged"
    assert d["unchanged"] == []


def test_ci_verdict_fails_on_new_or_regressed_only():
    clean = diff_report_json([_f(param="a")], [_f(param="a")])
    assert json.loads(clean)["ci_verdict"] == "PASS"
    new = diff_report_json([], [_f(param="z")])
    assert json.loads(new)["ci_verdict"] == "FAIL"
    worse = diff_report_json([_f(param="a", sev="low")],
                             [_f(param="a", sev="high")])
    assert json.loads(worse)["ci_verdict"] == "FAIL"
    # FIXING things must not fail the build
    better = diff_report_json([_f(param="a", sev="high")], [])
    assert json.loads(better)["ci_verdict"] == "PASS"


def test_load_report_rejects_a_benchmark_result(tmp_path):
    """Phase 105: this used to silently return [] .

    Feeding --diff a benchmark/results/*.json (cases[]) produced "0 new,
    0 fixed, 0 regressed" -- a re-test report claiming nothing changed
    when it had compared nothing, and a green CI verdict on top of it.
    Wrong input must fail loudly.
    """
    p = tmp_path / "bench.json"
    p.write_text(json.dumps({"meta": {}, "cases": [{"case_id": "a"}]}),
                 encoding="utf-8")
    with pytest.raises(ValueError) as ei:
        load_report(str(p))
    assert "BENCHMARK" in str(ei.value)


def test_load_report_rejects_foreign_and_malformed_json(tmp_path):
    for name, payload in (
        ("unrelated.json", {"meta": {}, "rows": []}),
        ("findings_not_list.json", {"findings": {"a": 1}}),
        ("toplevel_list.json", [1, 2, 3]),
    ):
        p = tmp_path / name
        p.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ValueError):
            load_report(str(p))


def test_load_report_accepts_an_empty_findings_list(tmp_path):
    # "0 findings" is a legitimate scan result (a clean target), not an
    # error -- it must NOT be rejected.
    p = tmp_path / "clean.json"
    p.write_text(json.dumps({"findings": []}), encoding="utf-8")
    assert load_report(str(p)) == []


def test_html_report_renders_all_categories():
    html = diff_report_html([_f(param="a")],
                            [_f(param="b"), _f(param="a", sev="critical")],
                            target="https://example.com")
    assert "https://example.com" in html
    for section in ("new", "fixed", "regressed"):
        assert section.lower() in html.lower()


def test_load_report_reads_findings_from_a_scan_json(tmp_path):
    p = tmp_path / "scan.json"
    p.write_text(json.dumps({"meta": {}, "findings": [_f(param="q")]}),
                 encoding="utf-8")
    rows = load_report(str(p))
    assert len(rows) == 1 and rows[0]["param"] == "q"
