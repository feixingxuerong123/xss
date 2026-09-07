"""P0-1: pipeline integration tests INSIDE pytest (Phase 37).

Brings the L1 main flow (scanner._scan_param and friends) into the pytest
safety net: a compact slice of Attack Range #2 runs on every test pass, so
a main-flow regression FAILS PYTEST instead of waiting for a manual
benchmark/range2 drill.

Scope: 11 cases covering every confirmation path (semantic, mXSS, stored,
nonce-leak exploit, L6 headless DOM) plus safe-echo guards.  Runs in
~20-30s.  Full drills remain available via tests/run_range2.py and
`python -m benchmark.runner`.
"""
from __future__ import annotations
import os
import sys

# Make xssentinel + the range2 fixture importable from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

from range2_server import start_range2
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


def _scan(base: str, path: str, param: str = "q", **kw) -> Scanner:
    sc = Scanner(requester=Requester(timeout=8), verbose=False,
                 max_payloads=10, max_transforms=6, **kw)
    sc.scan_target(f"{base}{path}", method="GET", params={param: "probe"})
    return sc


# -- vulnerability slice: one case per confirmation path --------------------

VULN_SLICE = [
    "/r2/strip-script-recursive",   # filter-bypass -> semantic confirm
    "/r2/attr-sq-encode-dq",        # single-quote attr breakout
    "/r2/unclosed-quote",           # unclosed attribute swallow
    "/r2/regex-context",            # JS regex literal context
]


@pytest.mark.parametrize("path", VULN_SLICE)
def test_vuln_slice_confirmed(range_base, path):
    sc = _scan(range_base, path)
    assert sc.findings, f"main flow missed a real vuln: {path}"
    assert any(f.data.get("severity") in ("high", "medium")
               for f in sc.findings)


def test_mxss_confirmed(range_base):
    sc = _scan(range_base, "/r2/mxss-svg-style")
    types = {f.data.get("type") for f in sc.findings}
    assert "mutation_xss" in types or "dom_dynamic" in types, types


def test_stored_two_step_confirmed(range_base):
    sc = Scanner(requester=Requester(timeout=8), verbose=False,
                 max_payloads=10, max_transforms=6)
    sc.scan_stored(f"{range_base}/r2/stored/store",
                   view_url=f"{range_base}/r2/stored/view",
                   method="POST", param="q")
    sc.scan_target(f"{range_base}/r2/stored/view", method="GET")
    assert any(f.data.get("type") == "stored" for f in sc.findings)


def test_csp_nonce_leak_exploited(range_base):
    sc = _scan(range_base, "/r2/csp-nonce-leak")
    assert sc.findings, "nonce-leak exploitation did not fire"
    assert any("nonce" in str(f.data.get("transform"))
               for f in sc.findings)


def test_dom_cookie_confirmed_headless(range_base):
    sc = _scan(range_base, "/r2/dom-cookie", param="v", use_headless=True)
    types = {f.data.get("type") for f in sc.findings}
    assert types & {"dom_dynamic", "dom", "cookie_sink_flow"}, types


# -- safe slice: the zero-FP guarantee stays inside pytest ------------------

SAFE_SLICE = [
    "/r2/safe/js-json-encode",      # correct \u003c JSON-in-script encoding
    "/r2/safe/upper-entity",        # &LT; is not decoded by browsers
]


@pytest.mark.parametrize("path", SAFE_SLICE)
def test_safe_slice_not_reported(range_base, path):
    sc = _scan(range_base, path)
    assert not sc.findings, f"false positive on {path}: " + str(
        [f.data.get("type") for f in sc.findings])
