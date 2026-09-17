# -*- coding: utf-8 -*-
"""Phase 155: the DOM probe navigation waits on COMMIT, not on the page load.

These lock the cost contract of ``DynamicDomAnalyzer._bounded_goto`` without
starting a browser:

* the wait shape is ``commit`` -- anything that waits for subresources turns
  "page loads a dead CDN asset" into "the probe budget is spent after two
  probes" (measured: pos-sri-01 was 32s / 2 probes, now 11s / 8 probes);
* the per-navigation timeout still cannot exceed the remaining probe budget,
  otherwise one slow page overruns the whole budget (Phase 148).
"""
from __future__ import annotations

import time

from xssentinel.core.dom_engine import DynamicDomAnalyzer


class _FakePage:
    """Records what the goto was asked to do."""

    def __init__(self, raise_on_goto=False):
        self.calls = []
        self.raise_on_goto = raise_on_goto

    def goto(self, url, wait_until=None, timeout=None):
        self.calls.append({"url": url, "wait_until": wait_until,
                           "timeout": timeout})
        if self.raise_on_goto:
            raise RuntimeError("navigation failed")


def test_bounded_goto_waits_for_commit_not_subresources():
    page = _FakePage()
    DynamicDomAnalyzer(timeout=20)._bounded_goto(
        page, "http://t/p?q=1", time.monotonic() + 30.0)
    assert len(page.calls) == 1
    # commit returns as soon as the navigation resolves; waiting for
    # domcontentloaded/load lets ONE unreachable third-party script decide
    # how many probes fit into the budget.
    assert page.calls[0]["wait_until"] == "commit"


def test_bounded_goto_caps_timeout_at_remaining_budget():
    page = _FakePage()
    # 1.5s of budget left, user timeout 20s -> the cap must win.
    DynamicDomAnalyzer(timeout=20)._bounded_goto(
        page, "http://t/p", time.monotonic() + 1.5)
    assert 1000 <= page.calls[0]["timeout"] <= 1700

    # ample budget left -> the caller's timeout is the cap.
    page = _FakePage()
    DynamicDomAnalyzer(timeout=7)._bounded_goto(
        page, "http://t/p", time.monotonic() + 60.0)
    assert 6500 <= page.calls[0]["timeout"] <= 7200


def test_bounded_goto_survives_a_failed_navigation():
    # A probe whose navigation errors must not abort the probe loop: the
    # sink can fire before the error surfaces, and the caller reads the
    # hit log afterwards either way.  An exception escaping here used to
    # cost every remaining probe.
    page = _FakePage(raise_on_goto=True)
    DynamicDomAnalyzer(timeout=20)._bounded_goto(
        page, "http://t/p", time.monotonic() + 30.0)
    assert len(page.calls) == 1
