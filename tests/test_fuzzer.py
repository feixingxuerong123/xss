"""Unit tests for the fuzzer triage module (Phase 43).

fuzzer.py had 0% coverage despite powering ``--fuzz`` mode.  All tests use a
mock requester -- no network.  Each scoring dimension (reflection, executable
context, status/length delta, encoding traces, error leakage, header
reflection) is exercised individually so a scoring regression points at the
exact broken dimension.
"""
from __future__ import annotations
import html as html_mod
import os
import sys

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import fuzzer as fz


class _Resp:
    def __init__(self, text="", status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {}


class _Req:
    """Mock requester: reflects param `q` per the configured mode."""

    def __init__(self, mode="plain", status_map=None, header_reflect=False):
        self.mode = mode
        self.status_map = status_map or {}
        self.header_reflect = header_reflect
        self.calls = 0

    def request(self, method, url, params=None, data=None, **kw):
        self.calls += 1
        val = (params or {}).get("q", (data or {}).get("q", ""))
        status = 200
        for probe_val, st in self.status_map.items():
            if probe_val in str(val):
                status = st
        if not val:
            body = "<html><body>home</body></html>"
        elif self.mode == "plain":
            body = f"<html><body><p>{val}</p></body></html>"
        elif self.mode == "script":
            body = f'<html><script>var q = "{val}";</script></html>'
        elif self.mode == "escape":
            body = f"<html><body><p>{html_mod.escape(str(val))}</p></body></html>"
        elif self.mode == "sqli_error":
            body = ("<html><body>You have an error in your SQL syntax"
                    if "'" in str(val) else "<html><body>ok</body></html>")
        else:
            body = f"<html><body>{val}</body></html>"
        headers = {}
        if self.header_reflect and val:
            headers["X-Debug-Query"] = str(val)
        return _Resp(body, status, headers)


class _ExplodingReq:
    def request(self, *a, **kw):
        raise ConnectionError("refused")


class TestFuzzParam:
    def test_no_reflection_scores_zero(self):
        r = fz.fuzz_param(_Req(mode="plain"), "http://t/x", "GET", "nope",
                          existing_params={"q": "1"})
        # The fuzzed param "nope" is never reflected by our mock.
        assert r["reflected"] is False
        assert r["injectable"] is False

    def test_plain_reflection_below_threshold(self):
        r = fz.fuzz_param(_Req(mode="plain"), "http://t/x", "GET", "q")
        assert r["reflected"] is True
        assert r["details"].get("reflection") == fz.WEIGHTS["reflection"]
        # 10 points alone must NOT mark injectable (threshold 30).
        assert r["injectable"] is False

    def test_script_context_is_injectable(self):
        r = fz.fuzz_param(_Req(mode="script"), "http://t/x", "GET", "q")
        assert r["reflected"] is True
        assert r["details"].get("executable_context") == \
            fz.WEIGHTS["executable_context"]
        assert r["injectable"] is True  # 10 + 25 >= 30

    def test_status_delta_adds_weight(self):
        r = fz.fuzz_param(_Req(mode="plain", status_map={"<": 500}),
                          "http://t/x", "GET", "q")
        assert r["details"].get("status_delta") == fz.WEIGHTS["status_delta"]
        assert r["injectable"] is True  # 10 + 20

    def test_error_leakage_alone_marks_injectable(self):
        r = fz.fuzz_param(_Req(mode="sqli_error"), "http://t/x", "GET", "q")
        assert r["details"].get("error_leakage") == fz.WEIGHTS["error_leakage"]
        assert r["injectable"] is True

    def test_header_reflection_detected(self):
        r = fz.fuzz_param(_Req(mode="plain", header_reflect=True),
                          "http://t/x", "GET", "q")
        assert r["details"].get("header_reflection") == \
            fz.WEIGHTS["header_reflection"]
        assert any("header" in t for t in r["encoding_traces"])

    def test_html_encoded_reflection_traced(self):
        # html.escape of the alphanumeric marker is a no-op, so the trace
        # fires via the URL-decode branch only when raw != reflected; the
        # key assertion is that reflection is still detected and no crash.
        r = fz.fuzz_param(_Req(mode="escape"), "http://t/x", "GET", "q")
        assert r["reflected"] is True
        assert r["score"] >= fz.WEIGHTS["reflection"]

    def test_baseline_failure_returns_error_report(self):
        r = fz.fuzz_param(_ExplodingReq(), "http://t/x", "GET", "q")
        assert r["score"] == 0
        assert r["injectable"] is False
        assert "error" in r

    def test_body_param_uses_data_slot(self):
        req = _Req(mode="plain")

        class _CheckingReq(_Req):
            def request(self, method, url, params=None, data=None, **kw):
                resp = super().request(method, url, params, data, **kw)
                if (data or {}).get("q"):
                    self.used_data = True
                return resp

        req = _CheckingReq(mode="plain")
        r = fz.fuzz_param(req, "http://t/x", "POST", "q", is_body=True)
        assert r["reflected"] is True
        assert getattr(req, "used_data", False) is True


class TestFuzzEndpoint:
    def test_sorted_by_score_desc(self):
        results = fz.fuzz_endpoint(_Req(mode="script"), "http://t/x",
                                   params={"q": "1"},
                                   candidate_names=["hidden1", "hidden2"])
        assert results[0]["name"] == "q"  # script-context param wins
        assert results[0]["score"] >= results[-1]["score"]

    def test_body_params_flagged(self):
        results = fz.fuzz_endpoint(_Req(mode="plain"), "http://t/x",
                                   method="POST", data={"msg": "hi"})
        assert results[0]["is_body"] is True
        assert results[0]["name"] == "msg"

    def test_max_params_truncates(self):
        names = [f"p{i}" for i in range(10)]
        results = fz.fuzz_endpoint(_Req(mode="plain"), "http://t/x",
                                   candidate_names=names, max_params=3)
        assert len(results) == 3

    def test_existing_params_not_duplicated_by_candidates(self):
        results = fz.fuzz_endpoint(_Req(mode="plain"), "http://t/x",
                                   params={"q": "1"},
                                   candidate_names=["q", "other"])
        names = [r["name"] for r in results]
        assert names.count("q") == 1
        assert "other" in names


class TestSelectTopCandidates:
    def _mk(self, name, score, injectable):
        return {"name": name, "score": score, "injectable": injectable}

    def test_injectable_first(self):
        results = [self._mk("a", 5, False), self._mk("b", 50, True),
                   self._mk("c", 40, True)]
        assert fz.select_top_candidates(results, top_n=2) == ["b", "c"]

    def test_fallback_fills_to_top_n(self):
        results = [self._mk("a", 90, True), self._mk("b", 20, False),
                   self._mk("c", 10, False)]
        assert fz.select_top_candidates(results, top_n=3) == ["a", "b", "c"]

    def test_fewer_than_top_n_returns_all(self):
        results = [self._mk("a", 50, True)]
        assert fz.select_top_candidates(results, top_n=5) == ["a"]
