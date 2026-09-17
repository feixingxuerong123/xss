"""Tests for benchmark.adapters — dalfox verdict parsing & comparison metrics.

These tests are pure-logic: no network, no subprocess, no dalfox binary.
They lock in the verdict-calibration fixes:
  1. dalfox --format json emits JSONL (one finding per line), NOT a JSON
     array — the old parser mis-scored single-finding runs as FN and
     multi-finding runs fell into an over-broad "reflected" regex (FP).
  2. Timeout / crash / bad-output runs carry error != None and must be
     excluded from the confusion matrix (never silently scored TN/FN).
  3. dalfox --format json (v2.x array mode, observed 2026-09-17) ALWAYS
     appends a trailing empty object {} — and prints [{}] alone when
     nothing was found. Any-dict-counts parsing therefore scored every
     safe case as detected (FPR=100% artifact across all 179 cases).
"""
from benchmark.adapters import (
    _parse_dalfox_findings,
    _scan_case_dict,
    run_comparison,
)

import pytest


# ---------------------------------------------------------------------------
# _parse_dalfox_findings
# ---------------------------------------------------------------------------

class TestParseDalfoxFindings:
    def test_empty_output_means_no_findings(self):
        assert _parse_dalfox_findings("") == []
        assert _parse_dalfox_findings("   \n  ") == []

    def test_single_finding_jsonl_is_detected(self):
        # dalfox v2.x: single finding = one bare JSON object line.
        # OLD BUG: json.loads succeeded -> dict -> .get("findings") -> None
        #          -> scored as NOT detected (false negative).
        line = ('{"data":"alert(1)","poc":"curl http://x/?q=\\"<script\\""'
                ',"type":"found","param":"q"}')
        findings = _parse_dalfox_findings(line)
        assert len(findings) == 1
        assert findings[0]["param"] == "q"

    def test_multiple_findings_jsonl(self):
        # OLD BUG: whole-output json.loads failed (JSONL is not one JSON
        # doc) -> fell into regex fallback matching "reflected" -> FP.
        out = (
            '{"data":"a","type":"found","param":"q"}\n'
            '{"data":"b","type":"found","param":"q"}\n'
            '{"data":"c","type":"found","param":"q"}\n'
        )
        findings = _parse_dalfox_findings(out)
        assert len(findings) == 3

    def test_json_array_still_supported(self):
        out = '[{"data":"a","type":"found"},{"data":"b","type":"found"}]'
        assert len(_parse_dalfox_findings(out)) == 2

    def test_wrapper_dict_still_supported(self):
        out = '{"findings": [{"data":"a","type":"found"}]}'
        findings = _parse_dalfox_findings(out)
        assert len(findings) == 1

    def test_non_dict_json_lines_ignored(self):
        out = '[1, 2]\n{"data":"a","type":"found"}'
        # whole-output parse fails (two docs) -> JSONL branch:
        # the [1, 2] line parses but is not a dict (skipped),
        # the finding object is kept.
        assert _parse_dalfox_findings(out) == [{"data": "a", "type": "found"}]
        assert _parse_dalfox_findings("[1, 2]") == []  # ints filtered out

    def test_trailing_empty_object_is_not_a_finding(self):
        # REAL BUG (2026-09-17): dalfox --format json always appends a
        # trailing {} to its array; "[{}]" (no findings at all) scored as
        # 1 finding -> every safe case FP across the whole 179-case run.
        assert _parse_dalfox_findings("[{}]") == []
        assert _parse_dalfox_findings("[\n{}\n]") == []

    def test_array_mode_v_finding_plus_trailing_empty_object(self):
        # Exact shape observed against the real binary on a vulnerable case:
        # one real finding (type=V, payload, evidence) + trailing {}.
        real = ('{"type":"V","inject_type":"inHTML-URL","poc_type":"plain",'
                '"method":"GET","data":"http://x/?q=payload","param":"q",'
                '"payload":"<sVg/onload=alert(1) class=dalfox>",'
                '"evidence":"<div>test...</div>","cwe":"CWE-79",'
                '"severity":"High","message_id":158,"message_str":"Triggered"}')
        out = "[%s,\n{}]" % real
        findings = _parse_dalfox_findings(out)
        assert len(findings) == 1
        assert findings[0]["type"] == "V"
        assert findings[0]["param"] == "q"

    def test_signalless_entries_are_not_findings(self):
        # Info/meta entries without type V/found and without poc/payload
        # must not count — otherwise reflection-only chatter becomes FP.
        assert _parse_dalfox_findings('[{"data":"a"}]') == []
        assert _parse_dalfox_findings('{"type":"I","message":"scan done"}') == []
        # ...but poc/payload-bearing entries do, even with an odd type.
        assert len(_parse_dalfox_findings('[{"type":"X","payload":"<svg>"}]')) == 1

    def test_garbage_lines_do_not_crash(self):
        out = ('some progress noise\n'
               '{"data":"a","type":"found"}\n'
               'another noise line\n')
        findings = _parse_dalfox_findings(out)
        assert len(findings) == 1

    def test_stderr_chatter_is_never_parsed(self):
        # Progress noise like "found reflected parameter" must never count
        # as a finding — only stdout JSONL lines do.
        assert _parse_dalfox_findings("") == []


# ---------------------------------------------------------------------------
# run_comparison: error handling
# ---------------------------------------------------------------------------

class _FakeAdapter:
    """Replays pre-recorded scan_case results, no I/O."""

    def __init__(self, name, results):
        self.name = name
        self._results = results

    def available(self):
        return True

    def scan_case(self, base_url, case):
        return self._results[case["id"]]


_CASES = [
    {"id": "pos-1", "path": "/r/1", "param": "q",
     "ground_truth": "vulnerable"},
    {"id": "pos-2", "path": "/r/2", "param": "q",
     "ground_truth": "vulnerable"},
    {"id": "neg-1", "path": "/s/1", "param": "q",
     "ground_truth": "safe"},
    {"id": "neg-2", "path": "/s/2", "param": "q",
     "ground_truth": "safe"},
]


class TestRunComparisonErrorDimension:
    def test_timeout_on_safe_case_is_error_not_tn(self):
        # OLD BUG: safe case timeout -> detected=False -> silently a TN,
        # inflating apparent specificity.
        results = {
            "pos-1": _scan_case_dict(True, "", 1.0),
            "pos-2": _scan_case_dict(True, "", 1.0),
            "neg-1": _scan_case_dict(False, "TIMEOUT", 90.0, "timeout"),
            "neg-2": _scan_case_dict(False, "", 1.0),
        }
        out = run_comparison("http://x", _CASES,
                             adapters=[_FakeAdapter("t", results)])
        m = out["t"]
        assert m["tp"] == 2 and m["tn"] == 1 and m["fp"] == 0 and m["fn"] == 0
        assert m["errors"] == 1
        assert m["completed"] == 3
        assert m["recall"] == 1.0
        assert m["fpr"] == 0.0
        assert [d["verdict"] for d in m["details"]] == ["TP", "TP", "ERROR", "TN"]
        assert m["details"][2]["error"] == "timeout"

    def test_timeout_on_vuln_case_is_error_not_fn(self):
        results = {
            "pos-1": _scan_case_dict(False, "TIMEOUT", 90.0, "timeout"),
            "pos-2": _scan_case_dict(True, "", 1.0),
            "neg-1": _scan_case_dict(False, "", 1.0),
            "neg-2": _scan_case_dict(False, "", 1.0),
        }
        out = run_comparison("http://x", _CASES,
                             adapters=[_FakeAdapter("t", results)])
        m = out["t"]
        # pos-1 excluded: not an FN
        assert m["fn"] == 0 and m["errors"] == 1
        assert m["recall"] == 1.0  # 1/1 among completed vuln cases

    def test_bad_json_output_on_vulnerable_case_is_error_not_fn(self):
        results = {
            "pos-1": _scan_case_dict(False, "garbage", 2.0,
                                      "bad-json-output (rc=1)"),
            "pos-2": _scan_case_dict(True, "", 1.0),
            "neg-1": _scan_case_dict(False, "", 1.0),
            "neg-2": _scan_case_dict(False, "", 1.0),
        }
        out = run_comparison("http://x", _CASES,
                             adapters=[_FakeAdapter("t", results)])
        assert out["t"]["errors"] == 1 and out["t"]["fn"] == 0

    def test_normal_confusion_matrix_unchanged(self):
        results = {
            "pos-1": _scan_case_dict(True, "", 1.0),
            "pos-2": _scan_case_dict(False, "", 1.0),
            "neg-1": _scan_case_dict(True, "", 1.0),
            "neg-2": _scan_case_dict(False, "", 1.0),
        }
        out = run_comparison("http://x", _CASES,
                             adapters=[_FakeAdapter("t", results)])
        m = out["t"]
        assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (1, 1, 1, 1)
        assert m["errors"] == 0 and m["completed"] == 4
        assert m["recall"] == pytest.approx(0.5)
        assert m["fpr"] == pytest.approx(0.5)

    def test_dalfox_replay_of_smoke_run_shapes(self):
        # Replay: dalfox finds multiple findings on a vuln case (JSONL),
        # and produces NOTHING on a correctly-escaped safe case.
        vuln_jsonl = ('{"data":"<svg/onload=alert(1)>","type":"found",'
                      '"param":"q"}\n'
                      '{"data":"alert(1)","type":"found","param":"q"}\n')
        results = {
            "pos-1": _scan_case_dict(
                bool(_parse_dalfox_findings(vuln_jsonl)), vuln_jsonl, 3.4),
            "pos-2": _scan_case_dict(True, '{"data":"a"}', 2.0),
            "neg-1": _scan_case_dict(bool(_parse_dalfox_findings("")), "", 2.1),
            "neg-2": _scan_case_dict(bool(_parse_dalfox_findings("")), "", 2.0),
        }
        out = run_comparison("http://x", _CASES,
                             adapters=[_FakeAdapter("dalfox", results)])
        m = out["dalfox"]
        assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (2, 0, 2, 0)
        assert m["fpr"] == 0.0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
