"""Phase 133 lock: async mines hidden parameters before probing.

Sync enriches each endpoint with ``param_miner``'s discoveries before it
probes it (scanner.py:302-324).  Async had no equivalent, so an endpoint
whose interesting parameter has no UI hint was only ever probed with the
parameters already in the URL -- benchmark case pos-pmmine-01 was a clean
sync TP (46 requests) / async FN (10 requests).  After this phase: async
TP in 17 requests.

Two failure modes are locked here:

1. The shim is what async uses to reach the sync miner.  If it lacks an
   attribute the miner reads, ``layer_guard`` classifies the resulting
   AttributeError as a *wiring* error, logs a warning and switches the
   layer OFF -- a silent degrade that looks like "nothing found".
2. The mining result has to actually reach the probe, not just be
   computed: ``scan()`` must merge it into ``params``.
"""
from __future__ import annotations

import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.async_scanner import AsyncScanner, _AsyncScannerShim  # noqa: E402


class _MinerResp:
    """Shaped for ``param_miner``: ``text`` is an attribute, not a coroutine."""

    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = dict(headers or {})


class _AioResp:
    """Shaped for aiohttp: ``text()`` is awaitable and the object is a CM."""

    def __init__(self, text, status=200, headers=None):
        self._text = text
        self.status = status
        self.headers = dict(headers or {})

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _StaticReq:
    """Minimal Requester stand-in: every probe gets the same inert page."""

    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None, headers=None,
                **kw):
        self.calls.append({"params": dict(params or {}),
                           "data": dict(data or {})})
        return _MinerResp("<html><body>static</body></html>")


def _bare_scanner():
    """Scanner built without __init__ (the miner reads only a few attrs)."""
    asc = AsyncScanner.__new__(AsyncScanner)
    asc.verbose = False
    asc.waf_name = None
    asc.json_body = None
    asc.max_payloads = 10
    return asc


# --------------------------------------------------------------------------
# 1. the shim satisfies the miner's contract
# --------------------------------------------------------------------------

def test_shim_exposes_what_the_param_miner_reads():
    shim = _AsyncScannerShim(_bare_scanner())
    for attr in ("req", "max_payloads", "param_wordlist", "verbose",
                 "coverage", "_add", "bav"):
        assert hasattr(shim, attr), f"shim lacks {attr!r}"
    assert callable(getattr(shim, "_mine_hidden_params", None)), (
        "the shim must resolve CrawlMixin._mine_hidden_params -- otherwise "
        "param mining is silently switched off by layer_guard")


def test_shim_actually_runs_the_miner_without_raising():
    shim = _AsyncScannerShim(_bare_scanner())
    shim.req = _StaticReq()
    found = shim._mine_hidden_params("http://t/x", "GET", {"q": "1"}, {})
    assert isinstance(found, dict), found


def test_shim_does_not_enable_bav():
    """--bav is documented sync-only; the shim must not half-enable it."""
    shim = _AsyncScannerShim(_bare_scanner())
    assert shim.bav is False
    assert shim.param_wordlist is None


# --------------------------------------------------------------------------
# 1b. mining traffic has to show up in the scan's request count
# --------------------------------------------------------------------------

class _CountingInner:
    """Stands in for the sync Requester; counts calls like the real one."""

    def __init__(self):
        self.calls = 0
        self.sentinel = "delegated-attribute"

    def request(self, method, url, params=None, data=None, headers=None,
                **kw):
        self.calls += 1
        return _MinerResp("<html><body>static</body></html>")


def test_counting_requester_delegates_and_counts():
    from xssentinel.core.requester import CountingRequester

    inner = _CountingInner()
    bumps = []
    proxy = CountingRequester(inner, lambda: bumps.append(1))
    proxy.request("GET", "http://t/x")
    proxy.request("GET", "http://t/x")
    assert len(bumps) == 2, bumps
    assert inner.calls == 2
    # everything else must pass straight through
    assert proxy.sentinel == "delegated-attribute"


def test_mine_hidden_params_async_counts_the_miner_traffic(monkeypatch):
    """param_miner never bumps a counter, so the proxy has to.

    Sync's mining rides the scan's budgeted Requester and is therefore
    counted; async's goes through a separate sync Requester, so without
    the proxy the requests would be invisible in the report.
    """
    inner = _CountingInner()
    monkeypatch.setattr(AsyncScanner, "_get_sync_requester",
                        lambda self: inner)

    asc = _bare_scanner()
    asc.requests_made = 0
    found = asyncio.run(
        asc._mine_hidden_params_async("http://t/x", "GET", {"q": "1"}, {}))

    assert isinstance(found, dict)
    assert inner.calls > 0, "sanity: the miner must have sent probes"
    assert asc.requests_made == inner.calls, (
        f"miner traffic not counted: requests_made={asc.requests_made} "
        f"vs {inner.calls} real calls")


# --------------------------------------------------------------------------
# 2. scan() merges the discoveries into the probed parameters
# --------------------------------------------------------------------------

def _noop_agen(*_a, **_k):
    """Async-generator no-op, for the page layers that need a transport."""
    if False:                        # pragma: no cover
        yield None


class _FakeAiohttp(types.ModuleType):
    def __init__(self):
        super().__init__("aiohttp")
        self.ClientTimeout = lambda **kw: kw
        self.TCPConnector = lambda **kw: kw

    def ClientSession(self, **kw):
        session = _FakeSession()

        class _CM:
            async def __aenter__(_self):
                return session

            async def __aexit__(_self, *a):
                return False

        return _CM()


class _FakeSession:
    def request(self, method, url, params=None, data=None, headers=None,
                proxy=None, **kw):
        return _AioResp("<html><body><div>probe</div></body></html>")

    def get(self, url, **kw):
        return self.request("GET", url, **kw)


def _drive_scan(monkeypatch, advanced_layers):
    """Run scan() offline with the page layers stubbed out."""
    seen = {"mine": [], "reflected": None}

    async def _fake_mine(self, url, method, params, data):
        seen["mine"].append(dict(params))
        return {"hidden": "1"}

    async def _fake_reflected(self, session, url, method, params, data,
                              baseline):
        seen["reflected"] = dict(params)
        if False:                    # pragma: no cover
            yield None

    monkeypatch.setattr(AsyncScanner, "_mine_hidden_params_async",
                        _fake_mine)
    monkeypatch.setattr(AsyncScanner, "_scan_reflected", _fake_reflected)
    for name in ("_scan_dom_async", "_scan_advanced_page",
                 "_scan_request_layers", "_scan_csp_async",
                 "_scan_jsonp_async", "_scan_cors_async",
                 "_scan_xsleak_audit_async"):
        monkeypatch.setattr(AsyncScanner, name, _noop_agen)

    real = sys.modules.get("aiohttp")
    sys.modules["aiohttp"] = _FakeAiohttp()
    try:
        async def run():
            asc = AsyncScanner(max_concurrent=2, per_host_delay=0, jitter=0,
                               timeout=5, max_payloads=4,
                               advanced_layers=advanced_layers)
            out = []
            async for f in asc.scan("http://t/search", params={"q": "probe"}):
                out.append(f)
            return out

        return asyncio.run(run()), seen
    finally:
        if real is None:
            sys.modules.pop("aiohttp", None)
        else:
            sys.modules["aiohttp"] = real


def test_scan_mines_and_merges_discovered_params(monkeypatch):
    _out, seen = _drive_scan(monkeypatch, advanced_layers=True)
    assert seen["mine"], "scan() never called the hidden-param miner"
    assert seen["reflected"] is not None, "L1 layer never ran"
    assert seen["reflected"].get("hidden") == "1", (
        "the mined parameter never reached the probe -- mining is computed "
        f"but not merged (params={seen['reflected']})")
    assert seen["reflected"].get("q") == "probe", (
        "the endpoint's own parameters must survive the merge")


def test_scan_skips_mining_when_advanced_layers_are_off(monkeypatch):
    """Mirrors sync, which gates param mining on ``_advanced_layers``."""
    _out, seen = _drive_scan(monkeypatch, advanced_layers=False)
    assert seen["mine"] == [], "mining ran despite advanced_layers=False"
    assert seen["reflected"] is not None
    assert "hidden" not in seen["reflected"]
