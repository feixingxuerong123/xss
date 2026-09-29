"""Tests for Phase 51 -- the remaining half of the stealth item.

The pentest audit flagged "stealth 无代理池、无 header 轮换、无请求 jitter"
after Phase 46 had wired only the UA and marker flags.  These tests cover
the new primitives AND the property that matters most for an opt-in
feature: **with the flags off, the Requester behaves exactly as before**
(same session proxies, no injected headers, fixed pacing).
"""
from __future__ import annotations
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core.requester import RateLimiter, Requester
from xssentinel.core.stealth import (
    HeaderRotator, ProxyPool, jitter_interval, load_proxies,
)


class _Resp:
    """Minimal stand-in for requests.Response (no breaker/hook installed)."""
    status_code = 200
    headers = {}
    content = b""


def _capture(req):
    """Replace the session transport and record (method, url, kwargs)."""
    calls = []

    def _fake(method, url, **kw):
        calls.append((method, url, kw))
        return _Resp()

    req.session.request = _fake
    return calls


# ---------------------------------------------------------------------------
# Pacing jitter
# ---------------------------------------------------------------------------
class TestJitter:
    def test_zero_ratio_is_exact(self):
        assert jitter_interval(0.2, 0) == 0.2
        assert jitter_interval(0.2, None) == 0.2

    def test_ratio_spreads_within_bounds(self):
        samples = [jitter_interval(0.2, 0.5) for _ in range(200)]
        assert all(0.1 <= s <= 0.3 for s in samples)
        assert len({round(s, 6) for s in samples}) > 50  # actually random

    def test_rate_limiter_fixed_without_jitter(self, monkeypatch):
        # First acquire() must not sleep (nothing to pace yet); the second
        # (back-to-back) sleeps the full fixed 0.1s interval.  (The old
        # variant also patched a literal time.sleep(0) that the monkeypatch
        # counted -- making the assertions self-contradictory.)
        slept = []
        monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))
        rl = RateLimiter(10)            # 0.1s interval
        rl.acquire()                    # primes _last, no sleep
        rl.acquire()                    # back-to-back -> sleep 0.1
        assert len(slept) == 1          # first call doesn't sleep
        # slept[0] is the REMAINING interval: full 0.1s minus only the
        # microsecond-scale overhead of the previous acquire() call.  The
        # original <1e-6 tolerance asserted sub-microsecond call speed and
        # flaked on loaded CI runners (measured 1.1us overhead -> red).
        # The contract is "paces the full interval, never more, never a
        # fraction of it": overhead budget 10ms is 4 orders of magnitude
        # looser than the flake point and still fails any real pacing bug
        # (half-interval, double-interval, no sleep at all).
        assert 0 < slept[0] <= 0.1
        assert 0.1 - slept[0] < 0.01, slept

    def test_rate_limiter_sleep_is_jittered(self, monkeypatch):
        slept = []
        monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))
        rl = RateLimiter(10, jitter=0.5)
        rl.acquire()                    # primes _last
        for _ in range(12):
            rl.acquire()
        assert len(slept) == 12
        # interval 0.1s +/-50% -> sleeps inside [0.05, 0.15].  The bounds
        # carry 1ms slack: wait itself is 0.1 minus call overhead, so the
        # exact 0.05 lower bound is reachable as 0.0499999... on a slow
        # call (same flake family as the fixed-interval test above).
        assert all(0.049 <= s <= 0.151 for s in slept), slept
        assert len({round(s, 6) for s in slept}) > 1  # not metronomic

    def test_requester_propagates_jitter(self):
        req = Requester(rate_limit=5, jitter=0.4)
        assert req.rate_limiter.jitter == 0.4
        assert req.rate_limiter.rate == 5


# ---------------------------------------------------------------------------
# Header rotation
# ---------------------------------------------------------------------------
class TestHeaderRotator:
    def test_firefox_ua_gets_no_chrome_headers(self):
        # A Firefox UA sending Sec-CH-UA is itself a bot signal.
        h = HeaderRotator("Mozilla/5.0 (X11; Linux x86_64; rv:127.0) "
                          "Gecko/20100101 Firefox/127.0").next_headers()
        assert not any(k.lower().startswith("sec-ch-ua") for k in h)
        assert h["Accept-Language"] == "en-US,en;q=0.5"

    def test_chrome_ua_gets_client_hints(self):
        h = HeaderRotator("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/126.0.0.0 Safari/537.36").next_headers()
        assert any(k.lower() == "sec-ch-ua" for k in h)

    def test_rotation_varies_language_and_site(self):
        r = HeaderRotator("Mozilla/5.0 (Macintosh) Safari/605.1.15")
        langs = {r.next_headers()["Accept-Language"] for _ in range(4)}
        sites = set()
        r2 = HeaderRotator()
        for _ in range(4):
            sites.add(r2.next_headers()["Sec-Fetch-Site"])
        assert len(langs) > 1
        assert len(sites) > 1

    def test_never_emits_headers_requests_owns(self):
        r = HeaderRotator("Mozilla/5.0 Chrome/126.0")
        for _ in range(6):
            keys = {k.lower() for k in r.next_headers()}
            for forbidden in ("host", "content-length", "content-type",
                              "accept-encoding", "connection", "cookie",
                              "authorization", "user-agent"):
                assert forbidden not in keys


class TestRequesterHeaderRotation:
    def test_off_by_default_is_unchanged(self):
        req = Requester()
        calls = _capture(req)
        req.get("http://x/a", params={"q": "1"})
        assert calls[0][2].get("headers") is None

    def test_rotated_headers_reach_the_transport(self):
        req = Requester(rotate_headers=True)
        calls = _capture(req)
        req.get("http://x/a", params={"q": "1"})
        req.get("http://x/b", params={"q": "2"})
        h1 = calls[0][2]["headers"]
        h2 = calls[1][2]["headers"]
        assert "Accept-Language" in h1 and "Sec-Fetch-Site" in h1
        assert h1["Accept-Language"] != h2["Accept-Language"]  # rotated

    def test_caller_header_wins_over_rotation(self):
        req = Requester(rotate_headers=True)
        calls = _capture(req)
        req.get("http://x/a", params={"q": "1"},
                headers={"Accept-Language": "de-DE,de;q=0.9"})
        assert calls[0][2]["headers"]["Accept-Language"] == "de-DE,de;q=0.9"


# ---------------------------------------------------------------------------
# Proxy pool
# ---------------------------------------------------------------------------
class TestLoadProxies:
    def test_comma_list_normalizes_and_dedupes(self):
        out = load_proxies("1.2.3.4:8080, http://5.6.7.8:3128, 1.2.3.4:8080")
        assert out == ["http://1.2.3.4:8080", "http://5.6.7.8:3128"]

    def test_file_and_comments(self, tmp_path):
        f = tmp_path / "proxies.txt"
        f.write_text("# comment\n\n10.0.0.1:3128\nhttp://10.0.0.2:8080\n",
                     encoding="utf-8")
        assert load_proxies(str(f)) == ["http://10.0.0.1:3128",
                                        "http://10.0.0.2:8080"]

    def test_empty(self):
        assert load_proxies(None) == []
        assert load_proxies("") == []


class TestProxyPool:
    def test_round_robin_cycles(self):
        pool = ProxyPool(["http://a:1", "http://b:2", "http://c:3"])
        seq = [pool.next() for _ in range(4)]
        assert seq[0] != seq[1] != seq[2]
        assert seq[3] == seq[0]  # wrapped around

    def test_dead_entries_are_skipped(self):
        pool = ProxyPool(["http://a:1", "http://b:2"])
        first = pool.next()
        pool.mark_dead(first)
        assert pool.next() != first
        assert pool.live == [p for p in pool.all if p != first]

    def test_empty_pool_yields_none(self):
        pool = ProxyPool([])
        assert pool.next() is None and pool.as_kwargs() is None


class TestRequesterProxyPool:
    def test_no_pool_passes_no_proxies_kwarg(self):
        req = Requester()
        calls = _capture(req)
        req.get("http://x/a", params={"q": "1"})
        assert "proxies" not in calls[0][2]

    def test_pool_rotates_per_request(self):
        req = Requester(proxy_pool=["http://a:1", "http://b:2"])
        calls = _capture(req)
        req.get("http://x/a", params={"q": "1"})
        req.get("http://x/b", params={"q": "2"})
        p1 = calls[0][2]["proxies"]
        p2 = calls[1][2]["proxies"]
        assert p1 != p2
        assert p1["http"] == p1["https"]  # both schemes routed

    def test_dead_proxy_fails_over_once(self):
        import requests
        req = Requester(proxy_pool=["http://dead:1", "http://live:2"])
        seen = []

        def _fake(method, url, **kw):
            seen.append(kw.get("proxies"))
            if len(seen) == 1:
                raise requests.exceptions.ProxyError("dead relay")
            return _Resp()

        req.session.request = _fake
        req.get("http://x/a", params={"q": "1"})
        assert len(seen) == 2
        assert seen[0]["http"] == "http://dead:1"
        assert seen[1]["http"] == "http://live:2"
        assert "http://dead:1" in req.proxy_pool.dead

    def test_clone_shares_pool_and_keeps_stealth(self):
        req = Requester(proxy_pool=["http://a:1"], rotate_headers=True,
                        jitter=0.3)
        clone = req.clone()
        assert clone.proxy_pool is req.proxy_pool   # shared rotation state
        assert clone.header_rotator is not None
        assert clone.rate_limiter.jitter == 0.3


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------
class TestCliFlags:
    def test_flags_exist_and_default_off(self):
        from xssentinel.__main__ import build_parser
        args = build_parser().parse_args(["-u", "http://x/"])
        assert getattr(args, "proxy_list", None) is None
        assert args.rotate_headers is False
        assert args.jitter_ratio == 0.0

    def test_proxy_list_parsed(self):
        from xssentinel.__main__ import build_parser
        args = build_parser().parse_args(
            ["-u", "http://x/", "--proxy-list", "1.1.1.1:8080,2.2.2.2:3128",
             "--rotate-headers", "--jitter-ratio", "0.4"])
        assert args.rotate_headers is True
        assert args.jitter_ratio == 0.4
        assert load_proxies(args.proxy_list) == ["http://1.1.1.1:8080",
                                                 "http://2.2.2.2:3128"]
