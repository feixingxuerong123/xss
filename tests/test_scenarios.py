"""Phase 41: declarative multi-step detection scenarios.

Integration-tested against the range2 stored fixtures (POST store ->
GET view) with the real Scanner; loader validation tested standalone.
"""
from __future__ import annotations
import json
import os
import sys
import threading

# Make xssentinel + the range2 fixture importable from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

from range2_server import start_range2
from xssentinel.core import scenarios as sc_mod
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner


@pytest.fixture(scope="module")
def range_base():
    # Phase 43: RUNTIME health gate — skip (not fail) when the loopback
    # has degraded mid-session.
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    srv = start_range2(8896)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _write(tmp_path, payload: dict) -> str:
    p = tmp_path / "scenarios.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


def _comment_scenario() -> dict:
    return {
        "id": "comment-stored-xss",
        "title": "stored via comment",
        "match": {"param_names": ["comment"]},
        "steps": [
            {"name": "inject", "method": "POST", "path": "/r2/stored/store",
             "param": "q", "payload": "<script>alert('{token}')</script>"},
            {"name": "check", "method": "GET", "path": "/r2/stored/view"},
        ],
    }


class TestLoader:
    def test_load_and_validate(self, tmp_path):
        path = _write(tmp_path, {"scenarios": [_comment_scenario()]})
        out = sc_mod.load_scenarios(path)
        assert len(out) == 1
        assert out[0]["id"] == "comment-stored-xss"

    def test_incomplete_scenario_skipped(self, tmp_path):
        path = _write(tmp_path, {"scenarios": [
            {"id": "broken", "steps": [{"name": "no-method"}]},
            _comment_scenario(),
        ]})
        out = sc_mod.load_scenarios(path)
        assert [s["id"] for s in out] == ["comment-stored-xss"]

    def test_scenario_matches_filter(self):
        sc = {"match": {"param_names": ["comment"]}}
        assert sc_mod.scenario_matches(sc, "comment") is True
        assert sc_mod.scenario_matches(sc, "q") is False

    def test_no_filter_always_matches(self):
        assert sc_mod.scenario_matches({"id": "x"}, "anything") is True


class TestScenarioExecution:
    def test_stored_flow_confirmed(self, range_base, tmp_path):
        path = _write(tmp_path, {"scenarios": [_comment_scenario()]})
        sc = Scanner(requester=Requester(timeout=8), verbose=False,
                     max_payloads=6, max_transforms=4,
                     scenario_file=path)
        sc.scan_target(f"{range_base}/r2/stored/view", method="GET",
                       params={"comment": "probe"})
        hits = [f for f in sc.findings if f.data.get("type") == "scenario"]
        assert hits, "scenario finding missing"
        f0 = hits[0].data
        assert f0["confidence"] == "high"
        assert "comment-stored-xss" in str(f0["transform"])
        assert "confirmed" in f0["detail"]

    def test_unmatched_param_runs_nothing(self, range_base, tmp_path):
        path = _write(tmp_path, {"scenarios": [_comment_scenario()]})
        sc = Scanner(requester=Requester(timeout=8), verbose=False,
                     max_payloads=4, max_transforms=2, scenario_file=path)
        # 'nickname' does not match the scenario's param_names filter.
        sc.scan_target(f"{range_base}/r2/stored/view", method="GET",
                       params={"nickname": "probe"})
        assert not [f for f in sc.findings
                    if f.data.get("type") == "scenario"]


class TestDocumentedParamPlaceholder:
    """Phase 127: the documented format writes "param": "{param}".

    The placeholder used to be expanded only in `path` and `payload`, never
    in the step's field name -- so the injection went out under a field
    literally named "{param}", the app stored nothing, and the scenario
    silently never confirmed.  Every scenario written from the module
    docstring was affected.
    """

    def _scenario(self) -> dict:
        return {
            "id": "q-stored-xss",
            "title": "documented {param} placeholder",
            "match": {"param_names": ["q"]},
            "steps": [
                {"name": "inject", "method": "POST",
                 "path": "/r2/stored/store", "param": "{param}",
                 "payload": "<script>alert('{token}')</script>"},
                {"name": "check", "method": "GET",
                 "path": "/r2/stored/view"},
            ],
        }

    def test_placeholder_expands_to_the_scanned_param(self, range_base,
                                                      tmp_path):
        path = _write(tmp_path, {"scenarios": [self._scenario()]})
        sc = Scanner(requester=Requester(timeout=8), verbose=False,
                     max_payloads=4, max_transforms=2, scenario_file=path)
        sc.scan_target(f"{range_base}/r2/stored/store", method="POST",
                       params={}, data={"q": "probe"})
        hits = [f for f in sc.findings if f.data.get("type") == "scenario"]
        assert hits, ("a scenario written with the documented {param} "
                      "placeholder must post under the real field name")
