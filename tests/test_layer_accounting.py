# -*- coding: utf-8 -*-
"""Phase 108: per-layer request accounting.

The cross-tool run made our speed gap measurable (30.5s vs 13.7s for
nuclei's DAST templates).  This is the instrumentation that answers the
next question -- which layers spend the requests -- and it must stay
cheap and correct: it runs on every single outbound request of every
scan.

Design: two existing choke points, zero call-site changes.
  * CoverageTracker.touch_layer()  -- already marks all 58 layer
    boundaries; it now also records the current layer for this thread.
  * Requester._send()              -- the one place every request goes
    through; it accounts the request to the current layer.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import coverage as cov


def test_counter_attributes_to_current_layer():
    cov.reset_layer_request_counts()
    cov.set_current_layer("L1_reflected")
    cov.count_layer_request()
    cov.count_layer_request()
    cov.set_current_layer("L8_header")
    cov.count_layer_request()
    assert cov.layer_request_counts() == {"L1_reflected": 2, "L8_header": 1}


def test_requests_without_a_layer_are_not_hidden():
    cov.reset_layer_request_counts()
    # simulate a fresh thread that never touched a layer
    import threading
    got = {}

    def _worker():
        cov.count_layer_request()
        got.update(cov.layer_request_counts())

    t = threading.Thread(target=_worker)
    t.start()
    t.join()
    assert got.get(cov.UNATTRIBUTED_LAYER) == 1


def test_touch_layer_marks_the_current_layer():
    """The hook that makes the 58 existing call sites enough."""
    from xssentinel.core.coverage import CoverageTracker
    cov.reset_layer_request_counts()
    tr = CoverageTracker()
    tr.touch_layer("http://example.com/x", "L7_jsonp", "GET", "detail")
    assert cov.current_layer() == "L7_jsonp"
    # ...and the tracker still records the endpoint as before
    eps = list(tr._endpoints.values())
    assert eps and "L7_jsonp" in eps[0].layers


def test_counts_are_thread_local_for_the_marker_but_shared_for_totals():
    cov.reset_layer_request_counts()
    import threading
    seen = {}

    def _worker():
        cov.set_current_layer("L8_cookie")
        seen["marker"] = cov.current_layer()
        cov.count_layer_request()

    t = threading.Thread(target=_worker)
    t.start()
    t.join()
    assert seen["marker"] == "L8_cookie"
    # the worker's layer marker must NOT leak into this thread
    assert cov.current_layer() != "L8_cookie"
    assert cov.layer_request_counts()["L8_cookie"] == 1


def test_reset_clears_only_the_counters():
    cov.set_current_layer("L1_reflected")
    cov.reset_layer_request_counts()
    assert cov.layer_request_counts() == {}
    assert cov.current_layer() == "L1_reflected"
