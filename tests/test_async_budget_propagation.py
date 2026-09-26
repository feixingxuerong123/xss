# -*- coding: utf-8 -*-
"""Async error taxonomy: what stops the scan vs what a param survives.

The async engine wraps every stage in ``except (BudgetExhausted,
CircuitOpen): raise`` followed by broader ``except Exception`` handlers
that skip-and-continue.  That taxonomy is the Phase 86 contract:

  * a deliberate scan stop (budget gone, circuit open) must PROPAGATE --
    swallowing it would turn "we spent the budget" into "this param had
    nothing", silently;
  * any other transport error must NOT kill the scan -- one dead
    connection is not a verdict.

These branches had no direct tests (the benchmark exercises the happy
path; a wedged file here hung the local gate for 2x540s instead).  All
tests are fake-session, no network, sub-second.
"""
from __future__ import annotations
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK

from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.core.budget import BudgetExhausted, CircuitOpen

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


class _Resp:
    def __init__(self, text, headers=None):
        self._t = text
        self.headers = headers or {}

    async def text(self):
        return self._t

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _ScriptedSession:
    """Each request pops the next behaviour: a str echoes it raw (a
    live reflection), an Exception instance is raised.  When the script
    runs out, ``default`` applies (echo, or a standing error)."""

    def __init__(self, script, default="echo"):
        self.script = list(script)
        self.default = default
        self.calls = 0

    def request(self, method, url, params=None, data=None,
                headers=None, proxy=None):
        self.calls += 1
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        item = self.script.pop(0) if self.script else self.default
        if isinstance(item, Exception):
            raise item
        body = item if item != "echo" else val
        return _Resp(f"<html><body><div>{body}</div></body></html>")


def _collect(session, params=None):
    """Drive _probe_param in a fresh loop; L7 hand-off stubbed."""
    original = AsyncScanner._scan_advanced_param_layers

    async def _noop(self, *a, **k):
        if False:                     # pragma: no cover -- keeps it a gen
            yield None

    AsyncScanner._scan_advanced_param_layers = _noop
    try:
        async def run():
            asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0,
                               max_payloads=4, max_transforms=1)
            asc._semaphore = asyncio.Semaphore(4)
            out = []
            async for f in asc._probe_param(session, "http://t/x", "GET",
                                            "q", params or {"q": "x"}, {},
                                            False, "x"):
                out.append(f)
            return out

        return asyncio.run(run())
    finally:
        AsyncScanner._scan_advanced_param_layers = original


class TestBudgetStopsPropagate:
    def test_budget_exhaustion_on_the_marker_probe_propagates(self):
        s = _ScriptedSession([BudgetExhausted("requests: 500/500")])
        with pytest.raises(BudgetExhausted):
            _collect(s)
        assert s.calls == 1, "the stop must be immediate, not retried"

    def test_circuit_open_on_the_marker_probe_propagates(self):
        s = _ScriptedSession([CircuitOpen("target is dead")])
        with pytest.raises(CircuitOpen):
            _collect(s)

    def test_budget_exhaustion_mid_payload_loop_propagates(self):
        # call 1: marker reflected -> we proceed; call 2: sandwich probe;
        # call 3: the first payload variant hits the dead budget.  A
        # swallow here would read as "this param is safe" -- the exact
        # false negative Phase 86 forbids.
        s = _ScriptedSession(["echo", "echo",
                              BudgetExhausted("requests: 500/500")])
        with pytest.raises(BudgetExhausted):
            _collect(s)

    def test_circuit_open_mid_payload_loop_propagates(self):
        s = _ScriptedSession(["echo", "echo",
                              CircuitOpen("connection reset storm")])
        with pytest.raises(CircuitOpen):
            _collect(s)


class TestGenericErrorsDegrade:
    def test_transport_error_on_the_marker_probe_skips_the_param(self):
        s = _ScriptedSession([ConnectionError("reset by peer")])
        assert _collect(s) == [], "a dead probe is not a verdict"

    def test_transport_error_on_a_variant_tries_the_next_variant(self):
        # call 3 (first variant) dies, call 4 (the polyglot) reflects and
        # confirms: one dead request must not cost the finding.
        s = _ScriptedSession(["echo", "echo",
                              ConnectionError("reset by peer"),
                              "echo"])
        findings = _collect(s)
        assert findings, "a single failed variant must not cost the param"
        assert findings[0].data["type"] == "reflected"
        assert findings[0].data["confidence"] == "high"

    def test_all_variants_failing_yields_nothing_and_does_not_raise(self):
        s = _ScriptedSession(["echo", "echo"],
                             default=ConnectionError("dead"))
        assert _collect(s) == []
