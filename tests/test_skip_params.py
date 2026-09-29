"""Phase 184: --skip-param (DalFox parity) + built-in tracking-noise filter.

Contracts locked here:
  * the operator skip set applies to BOTH engines' L1 probe loops,
    case-insensitively;
  * hidden-param mining skips the built-in NOISE_PARAMS (tracking litter)
    plus the operator set -- but declared page params are still probed by
    L1, so the noise list can never cause a false negative;
  * CLI parsing is forgiving (whitespace, case) and absent -> empty set.
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.param_miner import NOISE_PARAMS, mine_params
from xssentinel.core.scanner import Scanner
from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.cli_runner import _operator_skip_params


class _Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _FakeReq:
    """Static responder: same body every time; records every request."""

    def __init__(self):
        self.params_seen = []

    def request(self, method, url, params=None, data=None, headers=None):
        self.params_seen.extend((params or {}).keys())
        return _Resp("<html>ok</html>")


def test_mine_params_skips_noise_and_operator_set():
    req = _FakeReq()
    mine_params(req, "http://t/", extra_candidates=[
        "utm_source", "q", "profile", "session"], max_params=50,
        skip_params={"profile"})
    # utm_source: built-in noise.  profile: operator skip.
    # q and session survive.
    assert "utm_source" not in req.params_seen
    assert "profile" not in req.params_seen
    assert "q" in req.params_seen
    assert "session" in req.params_seen


def test_noise_params_never_hide_declared_page_params():
    """The L1 probe loop is the FN guard: noise filtering lives ONLY in
    mining.  A page that DECLARED utm_source still gets probed."""
    s = Scanner(skip_params=[])
    assert "utm_source" not in s.skip_params
    assert NOISE_PARAMS  # the default list is non-empty


def test_sync_probe_loop_honours_skip_params(monkeypatch):
    s = Scanner(skip_params={"Track", "csrf"})
    probed = []
    monkeypatch.setattr(s, "_scan_param",
                        lambda req, url, method, params, data, p, b:
                        probed.append((p, b)))
    s.scan_endpoint("http://t/", params={"q": "1", "Track": "2"},
                    data={"bio": "x", "CSRF": "t"})
    assert ("q", False) in probed and ("bio", True) in probed
    assert all(str(p).lower() not in ("track", "csrf") for p, _ in probed)


def test_async_probe_loop_honours_skip_params():
    a = AsyncScanner(skip_params={"Track"})
    probed = []

    async def fake_probe(session, url, method, param, params, data,
                         is_body, baseline_text):
        probed.append(param)
        return
        yield  # pragma: no cover - generator marker

    a._probe_param = fake_probe

    async def run():
        out = []
        async for _ in a._scan_reflected(None, "http://t/", "GET",
                                         {"q": "1", "Track": "2"}, {},
                                         "<html></html>"):
            pass
        return out

    asyncio.run(run())
    assert "q" in probed and "Track" not in probed


def test_cli_parsing_forgiving_and_absent_empty():
    import argparse
    assert _operator_skip_params(
        argparse.Namespace(skip_param=" A , b ,")) == {"a", "b"}
    assert _operator_skip_params(argparse.Namespace(skip_param=None)) == set()
    assert _operator_skip_params(argparse.Namespace()) == set()
