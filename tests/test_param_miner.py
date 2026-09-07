"""Tests for core/param_miner.py -- hidden parameter mining.

Fake-requester driven: baseline / probe / mode-detection / interesting
criteria / candidate filtering / wordlist loading / best_targets ranking,
plus the JSON and GraphQL mode auto-detection paths.  No network.
"""
from __future__ import annotations
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.param_miner import (
    candidate_list,
    best_targets,
    load_wordlist,
    merged_candidates,
    mine_params,
)


class _Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _FakeReq:
    """Scripted requester: each call pops the next scripted response."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def request(self, method, url, params=None, data=None, headers=None):
        self.calls.append({"method": method, "params": dict(params or {}),
                           "data": data,   # keep raw (may be a JSON str)
                           "headers": dict(headers or {})})
        if not self._responses:
            return _Resp("")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class TestWordlists:
    def test_candidate_list_nonempty_and_unique(self):
        c = candidate_list()
        assert len(c) >= 80
        assert len(c) == len(set(c))

    def test_load_wordlist_comments_and_blanks(self, tmp_path):
        wf = tmp_path / "wl.txt"
        wf.write_text("alpha\n# comment\n\nbeta\n", encoding="utf-8")
        assert load_wordlist(str(wf)) == ["alpha", "beta"]

    def test_merged_candidates_prepends_extras(self):
        # Operator hints get the FIRST probe slots (order-stable dedup).
        merged = merged_candidates(["mycustomparam"])
        assert merged[0] == "mycustomparam"
        assert merged[1:] == candidate_list()


class TestMineParams:
    def test_baseline_failure_returns_empty(self):
        req = _FakeReq([ConnectionError("killed")])
        assert mine_params(req, "http://t/") == []

    def test_reflected_param_found_form_mode(self):
        # Baseline (no marker) then one scripted response reflecting the
        # FIRST candidate's marker ("xsstest_0" -> candidate "q").
        req = _FakeReq([
            _Resp("<html>empty page</html>"),
            _Resp("<html>empty page xsstest_0</html>"),
        ] + [_Resp("<html>empty page</html>")] * 200)
        found = mine_params(req, "http://t/search", verbose=False,
                            max_params=10)
        names = [f["name"] for f in found]
        assert "q" in names
        f = [f for f in found if f["name"] == "q"][0]
        assert f["reflected"] is True and f["mode"] == "form"

    def test_status_delta_is_interesting(self):
        # The 3rd candidate probe returns 500 while baseline is 200.
        baseline = _Resp("<html>ok</html>")
        probes = [_Resp("<html>ok</html>")] * 200
        probes[2] = _Resp("<html>err</html>", status_code=500)
        req = _FakeReq([baseline] + probes)
        found = mine_params(req, "http://t/search", max_params=10)
        third = candidate_list()[2]
        f = [f for f in found if f["name"] == third]
        assert f and f[0]["status_delta"] == 300

    def test_boring_responses_yield_nothing(self):
        req = _FakeReq([_Resp("<html>ok</html>")] * 400)
        assert mine_params(req, "http://t/") == []

    def test_json_mode_auto_detection(self):
        baseline = _Resp('{"ok": true}',
                         headers={"Content-Type": "application/json"})
        reflect = _Resp('{"ok": true, "echo": "xsstest_0"}',
                        headers={"Content-Type": "application/json"})
        req = _FakeReq([baseline, reflect] + [_Resp('{"ok": true}')] * 200)
        found = mine_params(req, "http://t/api", max_params=10)
        f = [f for f in found if f["name"] == "q"]
        assert f and f[0]["mode"] == "json"
        # probes carried a JSON body with the JSON content type
        assert any(isinstance(c["data"], str) and c["data"]
                   and c["headers"].get("Content-Type") == "application/json"
                   for c in req.calls[1:])

    def test_existing_params_are_skipped(self):
        baseline = _Resp("<html>ok</html>")
        probes = [_Resp("<html>ok</html>")] * 400
        req = _FakeReq([baseline] + probes)
        mine_params(req, "http://t/", existing_params={"q": "1"})
        names = [c["params"].get("q") for c in req.calls[1:]]
        assert all(v != "xsstest_0" for v in names)  # q never probed

    def test_max_params_budget(self):
        baseline = _Resp("<html>ok</html>")
        req = _FakeReq([baseline] + [_Resp("<html>ok</html>")] * 400)
        mine_params(req, "http://t/", max_params=3)
        assert len(req.calls) == 4        # 1 baseline + 3 probes


class TestBestTargets:
    def test_reflected_first_then_delta(self):
        found = [
            {"name": "long_delta", "reflected": False, "length_delta": 900},
            {"name": "reflected", "reflected": True, "length_delta": 5},
        ]
        assert best_targets(found)[0] == "reflected"

    def test_top_n_cap(self):
        found = [{"name": f"p{i}", "reflected": True,
                  "length_delta": i} for i in range(20)]
        assert len(best_targets(found, top_n=5)) == 5


class _EchoReq:
    """Responds with a page echoing any xsstest_* marker it was sent --
    the mirror-page shape that used to flood the triage."""

    def __init__(self):
        import re as _re
        self.calls = 0

    def request(self, method, url, params=None, data=None, headers=None):
        self.calls += 1
        marker = ""
        for v in (params or {}).values():
            if isinstance(v, str) and v.startswith("xsstest_"):
                marker = v
        if not marker and isinstance(data, str):
            import re as _re
            m = _re.search(r"xsstest_[0-9a-zA-Z_]*", data)
            marker = m.group(0) if m else ""
        if marker:
            return _Resp(f"<html>echo {marker}</html>")
        return _Resp("<html>static page</html>")


class TestMirrorProtection:
    """Phase 78: sentinel probe + rolling reflection collapse."""

    def test_mirror_page_detected_by_sentinels(self):
        req = _EchoReq()          # reflects everything, incl. sentinels
        found = mine_params(req, "http://t/search")
        assert found == []        # mining skipped, no noise
        # 1 baseline + 3 sentinels only -- the 100-candidate flood never
        # happened.
        assert req.calls == 4

    def test_normal_page_not_affected(self):
        # Only ONE of the sentinels reflects (partial echo) -> mining
        # proceeds normally and finds real params.
        class _PartialEcho(_EchoReq):
            def request(self, method, url, params=None, data=None,
                        headers=None):
                marker = ""
                for v in (params or {}).values():
                    if isinstance(v, str) and v.startswith("xsstest_"):
                        marker = v
                if not marker and isinstance(data, str):
                    import re as _re
                    m = _re.search(r"xsstest_[0-9a-zA-Z_]*", data)
                    marker = m.group(0) if m else ""
                if marker and not marker.endswith("s0"):
                    # reflect all but the first sentinel
                    return _Resp(f"<html>echo {marker}</html>")
                return _Resp("<html>static page</html>")

        req = _PartialEcho()
        found = mine_params(req, "http://t/search")
        assert found, "normal reflection mining must still work"

    def test_ewma_collapse_on_high_reflection_ratio(self):
        # Sentinels pass (first one is a dud), but the candidate stream
        # reflects ~everything: the rolling ratio must stop the flood.
        class _DudFirstSentinel(_EchoReq):
            def __init__(self):
                super().__init__()
                self._n = 0

            def request(self, method, url, params=None, data=None,
                        headers=None):
                self._n += 1
                if self._n <= 2:      # baseline + FIRST sentinel dud
                    return _Resp("<html>static page</html>")
                marker = ""
                for v in (params or {}).values():
                    if isinstance(v, str) and v.startswith("xsstest_"):
                        marker = v
                if not marker and isinstance(data, str):
                    import re as _re
                    m = _re.search(r"xsstest_[0-9a-zA-Z_]*", data)
                    marker = m.group(0) if m else ""
                if marker:
                    return _Resp(f"<html>echo {marker}</html>")
                return _Resp("<html>static page</html>")

        req = _DudFirstSentinel()
        found = mine_params(req, "http://t/search")
        # Collapse fired well before exhausting 100 candidates.
        assert req.calls < 1 + 3 + 15 + 5
        # Collapse keeps ONE reflected representative + delta signals.
        reflected = [f for f in found if f["reflected"]]
        assert len(reflected) <= 1


class TestBavProbes:
    """Phase 81: BAV follow-up probes (SSTI / open-redirect / CRLF)."""

    class _BavReq:
        """Dispatches on the injected value's BAV signature."""

        def __init__(self):
            import re as _re
            self.calls = []

        def request(self, method, url, params=None, data=None, headers=None):
            marker = ""
            for v in (params or {}).values():
                if isinstance(v, str) and "xsstest_" in v:
                    marker = v
            if not marker and isinstance(data, str):
                import re as _re
                m = _re.search(r"xsstest_[0-9a-zA-Z_]*", data)
                marker = m.group(0) if m else ""
            if marker:
                return _Resp(f"<html>echo {marker}</html>")
            if "{{777*'7'}}" in str(params) + str(data):
                return _Resp("<html>computed: 5439</html>")
            if "bav-redirect.example" in str(params) + str(data):
                return _Resp("", status_code=302,
                             headers={"Location":
                                      "https://bav-redirect.example/r"})
            if "a%0d%0a" in str(params) + str(data):
                return _Resp("<html>ok</html>",
                             headers={"X-BAV-Probe": "1"})
            return _Resp("<html>static</html>")

    def test_bav_probe_detects_all_three_kinds(self):
        from xssentinel.core.param_miner import bav_probe
        req = self._BavReq()
        out = bav_probe(req, "http://t/search", "GET", "q", "form", {}, {})
        kinds = {r["kind"] for r in out}
        assert kinds == {"ssti", "open_redirect", "crlf"}, out
        ssti = [r for r in out if r["kind"] == "ssti"][0]
        assert "5439" in ssti["detail"]

    def test_bav_probe_clean_param_returns_empty(self):
        from xssentinel.core.param_miner import bav_probe
        req = _FakeReq([_Resp("<html>static</html>")] * 10)
        assert bav_probe(req, "http://t/", "GET", "q", "form", {}, {}) == []

    def test_mine_params_bav_flag_attaches_results(self):
        req = self._BavReq()
        found = mine_params(req, "http://t/search", bav=True, max_params=10)
        # every interesting param carries a bav list (this fixture echoes
        # nothing BAV-shaped unless the probe value is the signature --
        # the _BavReq dispatches on the probe value, so found params DO
        # get their probes).
        for f in found:
            assert "bav" in f
            assert isinstance(f["bav"], list)

    def test_bav_flag_default_off(self):
        req = self._BavReq()
        found = mine_params(req, "http://t/search", max_params=10)
        for f in found:
            assert "bav" not in f


class TestCrawlerBavWiring:
    """Phase 82: CrawlMixin._mine_hidden_params turns BAV confirmations
    into real findings when the scanner runs with bav=True."""

    def _crawl_self(self, bav):
        from types import SimpleNamespace

        class _NullCov:
            def touch_layer(self, *a, **kw):
                pass

            def record_request(self, *a, **kw):
                pass

        outer = TestBavProbes()
        req = outer._BavReq()
        return SimpleNamespace(
            req=req, max_payloads=10, param_wordlist=None,
            verbose=False, coverage=_NullCov(),
            bav=bav, added=[],
            _add=lambda f: outer_sc.added.append(f),
        ), req

    def test_bav_confirmation_becomes_finding(self):
        from xssentinel.core.scanner_crawl import CrawlMixin
        outer_sc = None
        outer_sc_holder = self
        # Build the fake self with a shared findings collector.
        added = []
        outer = TestBavProbes()
        req = outer._BavReq()
        from types import SimpleNamespace

        class _NullCov:
            def touch_layer(self, *a, **kw):
                pass

            def record_request(self, *a, **kw):
                pass

        fake = SimpleNamespace(
            req=req, max_payloads=10, param_wordlist=None,
            verbose=False, coverage=_NullCov(), bav=True, added=added,
        )
        fake._add = lambda f: added.append(f)
        CrawlMixin._mine_hidden_params(
            fake, "http://t/search", "GET", {}, {}, bav=True)
        bav_findings = [f for f in added
                        if f.data.get("type") == "bav"]
        assert bav_findings, [f.data.get("type") for f in added]
        kinds = {f.data["context"] for f in bav_findings}
        assert kinds == {"ssti", "open_redirect", "crlf"}
        assert all(f.data["severity"] == "medium" for f in bav_findings)

    def test_bav_off_produces_no_findings(self):
        from xssentinel.core.scanner_crawl import CrawlMixin
        added = []
        outer = TestBavProbes()
        req = outer._BavReq()
        from types import SimpleNamespace

        class _NullCov:
            def touch_layer(self, *a, **kw):
                pass

            def record_request(self, *a, **kw):
                pass

        fake = SimpleNamespace(
            req=req, max_payloads=10, param_wordlist=None,
            verbose=False, coverage=_NullCov(), bav=False, added=added,
        )
        fake._add = lambda f: added.append(f)
        CrawlMixin._mine_hidden_params(
            fake, "http://t/search", "GET", {}, {}, bav=False)
        assert not [f for f in added if f.data.get("type") == "bav"]
