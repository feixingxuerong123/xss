"""Tests for the OOB (out-of-band) blind-XSS listeners (Phase 43).

SelfHostedListener is exercised against a REAL loopback HTTP server (its own
embedded ThreadingHTTPServer) so token attribution, callback URL shape, poll
semantics, and the context-manager lifecycle are all verified end-to-end.
InteractshListener is only tested for graceful degradation (no network).
"""
from __future__ import annotations
import os
import sys
import time
import urllib.request

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core import oob
from xssentinel.core.oob import SelfHostedListener, make_listener


class TestMakeListener:
    def test_self_returns_self_hosted(self):
        lst = make_listener("self", port=None)
        assert isinstance(lst, SelfHostedListener)

    def test_interactsh_returns_interactsh(self):
        lst = make_listener("interactsh")
        assert lst.name == "interactsh"

    def test_unknown_mode_raises(self):
        with pytest.raises(ValueError):
            make_listener("carrier-pigeon")


class TestSelfHostedListener:
    def test_token_format_and_uniqueness(self):
        lst = SelfHostedListener(port=None)
        t1, t2 = lst.token(), lst.token()
        assert t1.startswith("xssv_")
        assert t1 != t2

    def test_callback_url_shape(self):
        lst = SelfHostedListener(host="127.0.0.1", port=None)
        assert lst.callback_url("tok123") == "http://127.0.0.1:None/tok123" \
            or lst.callback_url("tok123").endswith("/tok123")

    def test_full_lifecycle_records_callback(self):
        """start -> GET the callback URL -> poll() must return the token."""
        lst = SelfHostedListener(host="127.0.0.1", port=None)
        lst.start()
        try:
            assert lst.port and lst.port > 0  # OS-assigned port read back
            tok = lst.token()
            url = lst.callback_url(tok)
            # Simulate the victim browser beaconing back.
            urllib.request.urlopen(url, timeout=5).read()
            hit = lst.poll({tok}, timeout=3)
            assert tok in hit
        finally:
            lst.stop()
        assert lst._started is False

    def test_poll_empty_expected_returns_empty_immediately(self):
        lst = SelfHostedListener(port=None)
        lst.start()
        try:
            t0 = time.time()
            assert lst.poll(set(), timeout=5) == set()
            assert time.time() - t0 < 1.0  # no waiting on empty expectation
        finally:
            lst.stop()

    def test_poll_timeout_returns_empty(self):
        lst = SelfHostedListener(port=None)
        lst.start()
        try:
            t0 = time.time()
            hit = lst.poll({"never_arrives"}, timeout=1)
            assert hit == set()
            assert 0.9 <= time.time() - t0 < 3.0  # waited, but bounded
        finally:
            lst.stop()

    def test_context_manager_starts_and_stops(self):
        with SelfHostedListener(port=None) as lst:
            assert lst._started is True
            assert lst.port and lst.port > 0
        assert lst._started is False

    def test_double_start_is_idempotent(self):
        lst = SelfHostedListener(port=None)
        lst.start()
        port1 = lst.port
        lst.start()  # must not rebind
        assert lst.port == port1
        lst.stop()


class TestInteractshDegradation:
    def test_start_failure_raises_runtime_error(self):
        # Point at an unroutable address; start must surface a RuntimeError
        # (the scanner catches this and disables blind confirmation).
        lst = oob.InteractshListener(server="http://127.0.0.1:1", timeout=1)
        with pytest.raises(RuntimeError):
            lst.start()

    def test_poll_without_start_returns_empty(self):
        lst = oob.InteractshListener(server="http://127.0.0.1:1", timeout=1)
        assert lst.poll({"tok"}, timeout=1) == set()
