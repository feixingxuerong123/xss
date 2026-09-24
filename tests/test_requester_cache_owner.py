# -*- coding: utf-8 -*-
"""Who owns a cached GET?  The Requester that filled it -- nobody else.

Two clone-related ownership bugs live in `Requester`, and they point in opposite
directions, which is why they are tested together:

    the cache IS per-object        -- a clone does not see the parent's entries,
                                      so invalidating the wrong object clears the
                                      wrong cache;
    the token bucket IS NOT        -- every clone of one requester is the same
                                      scan against the same client, and separate
                                      buckets multiply the request rate.

`scanner_stored.scan_stored` reads the stored page through a *fresh-session*
Requester (`view_req = self._fresh_session_view_req(req)`) while the comment
above the read says "invalidate any cached GET for the view URL" -- but it calls
`req.invalidate(view_url)`, on the scan session, and `Requester.invalidate` only
touches `self._cache` (requester.py:352-361).  So with
`--stored-fresh-session` the viewer served itself: from the second payload
variant onward it re-read its own copy of the page as it looked after variant 1,
`verify_semantic` could not find the newer token, and the stored pass could
report "not stored" having really tested one payload out of n.

These tests are about the mechanism, so they patch out the recording side
effects and drive `get()` directly: no server, no sockets.

Run:  pytest tests/test_requester_cache_owner.py
"""
from __future__ import annotations

import pytest

from xssentinel.core.requester import Requester

URL = "http://target.invalid/guestbook"


class _Resp:
    """Just enough of a requests.Response for get()'s cache path."""

    def __init__(self, body: str):
        self.text = body
        self.content = body.encode("utf-8")
        self.status_code = 200
        self.headers = {"Content-Type": "text/html"}
        self.url = URL
        self.encoding = "utf-8"


@pytest.fixture
def served(monkeypatch):
    """Replace the network with a counter: every real send changes the body."""
    calls: list[str] = []

    def fake_send(self, method, url, **kw):
        calls.append(url)
        return _Resp(f"body-{len(calls)}")

    monkeypatch.setattr(Requester, "_send", fake_send)
    monkeypatch.setattr(Requester, "_post_record", lambda self, r: None)
    monkeypatch.setattr(Requester, "_fire_hook", lambda self, *a, **k: None)
    return calls


def test_a_get_is_served_from_the_cache_of_the_requester_that_asked(served):
    r = Requester()
    assert r.get(URL).text == "body-1"
    assert r.get(URL).text == "body-1", "second bare GET should not hit network"
    assert len(served) == 1
    assert r.cache_hits == 1


def test_invalidate_reaches_only_the_callers_own_cache(served):
    """The stored-path bug, in miniature.

    Invalidating the SCAN session cannot make the VIEWER re-read -- so the
    `req.invalidate(view_url)` line in `scan_stored` was doing nothing for the
    object that actually fetches the page.
    """
    viewer = Requester()
    assert viewer.get(URL).text == "body-1"

    Requester().invalidate(URL)          # a different object's cache: no effect

    assert viewer.get(URL).text == "body-1"
    assert len(served) == 1, "the wrong invalidate must not look like a re-read"

    # what the fixed call site does instead
    assert viewer.get(URL, cache_get=False).text == "body-2"
    assert len(served) == 2


def test_uncached_read_does_not_poison_the_cache(served):
    """`cache_get=False` is a bypass, not a refresh: it must not silently
    repopulate, or a caller mixing both modes gets an answer whose provenance is
    ambiguous."""
    r = Requester()
    assert r.get(URL, cache_get=False).text == "body-1"
    assert r.get(URL).text == "body-2"           # first cached read = a miss
    assert r.get(URL).text == "body-2"           # now served from cache
    assert len(served) == 2


def test_clones_share_one_token_bucket():
    """The opposite contract: request *state* is per-clone, throttling is not.

    `Scanner` clones the requester once per endpoint (scanner.py:370) and again
    per parameter (scanner.py:424), so a bucket per clone lets a scan with
    `--threads N --rate-limit R` send up to N x R requests per second -- against
    a client's production system, with the report claiming R.
    """
    parent = Requester(rate_limit=5)
    first, second = parent.clone(), parent.clone()
    assert first.rate_limiter is parent.rate_limiter
    assert second.rate_limiter is parent.rate_limiter
    assert first.rate_limiter.rate == 5
    # caches stay separate (that is the point of the tests above)
    assert first._cache is not parent._cache
    # and the sharing this file documents was already intended for budget/breaker
    assert first.budget is parent.budget
    assert first.breaker is parent.breaker
