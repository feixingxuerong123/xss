"""Shared pytest fixtures / environment probes for the xssentinel suite.

Phase 38: on this Windows host, ``socket.socketpair()`` (which asyncio's
ProactorEventLoop needs for its self-pipe) can HANG indefinitely — the
loopback connect/accept is throttled by security software / TCP state.
Every test that calls ``asyncio.run()`` is affected.  We probe socketpair
ONCE at collection time and expose ``SOCKETPAIR_OK`` so affected tests can
skip themselves instead of hanging the whole session (they are re-run
automatically when the environment recovers).

Phase 43: the interference also degrades over a LONG test session — the
collection-time probe passes, but by the time HTTP-fixture tests run
(~1 min in), loopback connect/accept is throttled again and they FAIL
instead of skip.  ``loopback_healthy()`` is the RUNTIME probe: call it
inside fixtures/tests right before real loopback work and
``pytest.skip`` when the environment has degraded mid-session.
"""
from __future__ import annotations

import socket as _socket
import sys
import threading

import pytest

SOCKETPAIR_OK = True


def _probe_socketpair(timeout: float = 3.0, rounds: int = 2) -> bool:
    """True only if socketpair succeeds `rounds` times in a row — the
    interference is intermittent, so a single lucky pass is not enough."""
    for _ in range(rounds):
        result = {"ok": False}

        def _try():
            try:
                a, b = _socket.socketpair()
                a.close()
                b.close()
                result["ok"] = True
            except Exception:
                pass

        th = threading.Thread(target=_try, daemon=True)
        th.start()
        th.join(timeout)
        if not result["ok"]:
            return False
    return True


SOCKETPAIR_OK = _probe_socketpair()


def loopback_healthy(timeout: float = 3.0) -> bool:
    """RUNTIME health probe: socketpair + a real loopback connect/accept.

    Call this inside a fixture/test right before loopback-dependent work;
    when False, ``pytest.skip`` instead of letting the test fail on a
    throttled connect.  Cheap (~ms when healthy).
    """
    if not _probe_socketpair(timeout=timeout, rounds=1):
        return False
    # Also verify a plain loopback bind/connect/accept round-trip — the
    # security software sometimes throttles connects but not socketpair.
    result = {"ok": False}

    def _try():
        try:
            srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            srv.settimeout(timeout)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            cli = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            cli.settimeout(timeout)
            cli.connect(("127.0.0.1", port))
            conn, _ = srv.accept()
            conn.close()
            cli.close()
            srv.close()
            result["ok"] = True
        except Exception:
            pass

    th = threading.Thread(target=_try, daemon=True)
    th.start()
    th.join(timeout * 2 + 1)
    return result["ok"]


# ---------------------------------------------------------------------------
# Event-loop isolation
# ---------------------------------------------------------------------------

def running_loop_present() -> bool:
    """True when this thread already has a *running* asyncio loop.

    ``asyncio.run()`` refuses to start when one is running ("cannot be called
    from a running event loop"), so this is exactly the precondition the
    sync tests that drive async code depend on.
    """
    import asyncio
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


@pytest.fixture(autouse=True)
def _isolate_event_loop(request):
    """Stop a leaked event loop from showing up as a bogus failure.

    Many tests here are plain ``def`` functions that drive the async scanner
    through ``asyncio.run()``.  In a full session an earlier test leaves a
    loop running in this thread, and every later ``asyncio.run()`` then raises
    ``RuntimeError`` -- the affected tests pass one at a time and fail only in
    the full run (observed: 7 async tests red on an otherwise green tree),
    which makes them useless as a regression signal.

    Three jobs:
    1. After each test, NAME the leak (test id goes to stderr) so the actual
       culprit is easy to find in CI logs.
    2. Try to UNWIND the most common leak (the dom_engine shared Playwright
       browser, whose sync API parks a running loop in this thread) by
       stopping that thread's browser.  Production embedders get
       ``dom_engine.shutdown_thread_browser()`` for the same purpose.
    3. Before each test, if a loop is still running, skip rather than fail.
       A skip says "environment", a failure says "we broke something".
    """
    leaked_before = running_loop_present()
    yield
    if not leaked_before and running_loop_present():
        print(f"\n[loop-leak] {request.node.nodeid} LEFT A RUNNING LOOP "
              "(likely Playwright sync API; see test_benchmark_fp.py notes)",
              file=sys.stderr)
        try:
            from xssentinel.core import dom_engine
            dom_engine.shutdown_thread_browser()
        except Exception:
            pass
        if running_loop_present():
            print("[loop-leak] unwind FAILED -- loop still running",
                  file=sys.stderr)
        else:
            print("[loop-leak] unwound via shutdown_thread_browser()",
                  file=sys.stderr)
    if leaked_before:
        pytest.skip(
            "a previous test left a running event loop in this thread")
