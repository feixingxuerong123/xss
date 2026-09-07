"""Live e2e: async + real-browser DOM confirmation (Phase 65 closure).

Mirrors the sync range2 drill's dom-hash-srcdoc case but drives it through
AsyncScanner with dom_engine='auto' -- the flow that was silently
unavailable before Phase 65 (cli_runner hardcoded dom_engine='off').
Skipped when Playwright is not installed or the loopback is degraded.
"""
from __future__ import annotations
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.core import dom_engine
from range2_server import start_range2  # noqa: E402

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

_HAS_PW = dom_engine.DynamicDomAnalyzer.available()

pytestmark = [
    pytest.mark.skipif(not SOCKETPAIR_OK,
                       reason="loopback socketpair degraded"),
    pytest.mark.skipif(not _HAS_PW,
                       reason="Playwright not installed"),
]


def test_async_dom_dynamic_confirmed_live():
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    import asyncio

    server = start_range2(8896)
    base = f"http://127.0.0.1:{server.server_port}"
    time.sleep(0.2)
    try:
        async def run():
            asc = AsyncScanner(
                max_concurrent=2, per_host_delay=0, jitter=0,
                max_payloads=6, max_transforms=2, timeout=15,
                dom_engine="auto", verbose=False)
            out = []
            # Same operator flow as the sync drill: the attacker-controlled
            # value rides the query string; the real browser must observe it
            # flowing into innerHTML via the srcdoc hash chain.
            async for f in asc.scan(f"{base}/r2/dom-hash-srcdoc?v=probe",
                                    params={}):
                out.append(f)
            return out

        found = asyncio.run(run())
        dyn = [f.data for f in found if f.data.get("type") == "dom_dynamic"]
        assert dyn, [f.data.get("type") for f in found]
        assert dyn[0]["severity"] == "high"
        assert dyn[0]["headless"]["confirmed"] is True
    finally:
        server.shutdown()
