# -*- coding: utf-8 -*-
"""Phase 78 mirror-page protection, pinned.

A page that reflects EVERYTHING makes every hidden-parameter candidate
score "interesting" and floods the triage with noise.  Two guards exist:

  * the sentinel pre-probe: three random sentinel names that cannot
    collide with real params must NOT all reflect; if they do, mining
    is skipped before the flood starts (4 requests, not hundreds),
  * the rolling reflection ratio: >=13 of the last 15 probes reflected
    collapses the run, keeping ONE reflected representative and the
    discriminative (non-reflected) delta signals.

Wire format note: in mine_params the candidate NAME is the params KEY
and the marker is its VALUE -- a fake must judge sentinels by the key
and echo the value, or nothing it asserts means anything.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.param_miner import mine_params


class _Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _QuietReq:
    """Never reflects anything, status always 200."""

    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None, headers=None):
        self.calls.append({"params": dict(params or {}), "data": data})
        return _Resp("<html>ok</html>")


class _EchoReq(_QuietReq):
    """Reflects the marker VALUE for every non-sentinel param -- the
    mirror-page shape.  Sentinels stay quiet (that is what makes them
    sentinels).  ``status_overrides`` maps a call index (post-append) to
    a NON-reflecting 500 response: the discriminative delta shape."""

    def __init__(self, status_overrides=None):
        super().__init__()
        self.status_overrides = status_overrides or {}

    def request(self, method, url, params=None, data=None, headers=None):
        self.calls.append({"params": dict(params or {}), "data": data})
        name = next(iter((params or {}).keys()), "")
        if not name or "_xss_sentinel_" in str(name):
            return _Resp("<html>ok</html>")
        idx = len(self.calls)
        if idx in self.status_overrides:
            return _Resp("<html>ok</html>",
                         status_code=self.status_overrides[idx])
        marker = next(iter((params or {}).values()), "")
        return _Resp(f"<html>echo: {marker}</html>")


class TestSentinelPreProbe:
    def test_mirror_page_skips_mining_in_four_requests(self):
        class AllReflect(_EchoReq):
            """A true mirror reflects EVERYTHING -- sentinel names too.
            That is exactly the signature the sentinel gate exists for."""

            def request(self, method, url, params=None, data=None,
                        headers=None):
                self.calls.append({"params": dict(params or {}),
                                   "data": data})
                marker = next(iter((params or {}).values()), "")
                return _Resp(f"<html>echo: {marker}</html>")

        req = AllReflect()
        found = mine_params(req, "http://t/", max_params=40)
        assert found == [], "a mirror page must mine nothing"
        assert len(req.calls) == 4, (
            f"mirror detection costs baseline + 3 sentinels, got "
            f"{len(req.calls)} requests")

    def test_honest_page_passes_the_sentinel_gate(self):
        # The sentinel gate only arms above 15 candidates, so the honest
        # path needs a max_params big enough to cross it.
        req = _QuietReq()
        found = mine_params(req, "http://t/", max_params=20)
        # baseline + 3 sentinels + 20 candidate probes; nothing reflects
        # and no status moves, so nothing is interesting.
        assert len(req.calls) == 24, (
            "baseline + 3 sentinels + 20 probes expected, got "
            f"{len(req.calls)}")
        assert found == []

    def test_sentinel_errors_do_not_stop_mining(self):
        class ExplodingSentinels(_QuietReq):
            def request(self, method, url, params=None, data=None,
                        headers=None):
                name = next(iter((params or {}).keys()), "")
                if "_xss_sentinel_" in str(name):
                    # Raises BEFORE the call is recorded: the miner must
                    # tolerate the gap, not treat it as a mirror verdict.
                    raise ConnectionError("loopback hiccup")
                return super().request(method, url, params, data,
                                       headers)

        req = ExplodingSentinels()
        found = mine_params(req, "http://t/", max_params=16)
        # baseline + 16 candidate probes; the 3 sentinel calls raised
        # before recording, so they leave no count behind.
        assert len(req.calls) == 17
        assert found == []


class TestRollingCollapse:
    def test_full_mirror_collapses_at_fifteen_probes(self):
        req = _EchoReq()   # sentinels quiet, every candidate reflects
        found = mine_params(req, "http://t/", max_params=40)
        # baseline + 3 sentinels + 15 probes, then the ratio hits 15/15.
        assert len(req.calls) == 19, (
            f"collapse must stop the flood at 15 candidate probes, "
            f"got {len(req.calls)} requests")
        reflected = [f for f in found if f["reflected"]]
        assert len(reflected) <= 1, (
            "a mirror keeps ONE reflected representative, not "
            f"{len(reflected)}")

    def test_discriminative_delta_signals_survive_the_collapse(self):
        # Two probes inside the first-15 window do NOT reflect but change
        # the status code -- those are discriminative and must survive
        # the collapse next to the single reflected representative.
        # Call indices are post-append: baseline=1, sentinels=2..4,
        # probes start at 5.
        req = _EchoReq(status_overrides={10: 500, 17: 500})
        found = mine_params(req, "http://t/", max_params=40)
        assert len(req.calls) == 19, "collapse must still fire"
        reflected = [f for f in found if f["reflected"]]
        delta = [f for f in found if not f["reflected"]]
        assert len(reflected) <= 1
        assert len(delta) == 2, (
            f"the two status-delta params must survive, got {delta}")
        assert all(f["status_delta"] != 0 for f in delta)
