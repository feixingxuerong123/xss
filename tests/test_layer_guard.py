"""Phase 94: layer dispatch must isolate failures and escalate wiring errors.

Two audit findings shaped this suite:

* Phase 63 -- one AttributeError in the async shim aborted ALL 17 page
  layers, so async mode silently reported none of them.
* Phase 84 -- ``scanner_crawl`` never imported ``param_miner``; the
  NameError was eaten at DEBUG and L9 mining "worked" while doing
  nothing.

The contract now is:

* a wiring-class error (ImportError / NameError / UnboundLocalError /
  SyntaxError) logs at WARNING and names the layer -- it can never be the
  target's fault;
* any other error stays at DEBUG (duck-typing and shape probing are
  normal here, warning on them would cry wolf);
* a layer failing never stops the layers after it;
* BudgetExhausted / CircuitOpen still propagate (a budget stop is a
  deliberate scan end, not a layer bug).
"""
from __future__ import annotations

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core import advanced_layers
from xssentinel.core import layer_guard
from xssentinel.core.async_scanner import _drain_agen
from xssentinel.core.budget import BudgetExhausted


class _Scanner:
    """Just enough scanner for the dispatchers: verbose + a call log."""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.ran = []

    def _record(self, name):
        self.ran.append(name)


@pytest.fixture
def scanner():
    return _Scanner()


# --------------------------------------------------------------------------
# layer_guard.run_layer
# --------------------------------------------------------------------------

def test_wiring_error_escalates_to_warning(scanner, caplog) -> None:
    def boom():
        raise NameError("param_miner is not defined")
    with caplog.at_level(logging.WARNING):
        layer_guard.run_layer(scanner, "param_miner", boom)
    msgs = [r for r in caplog.records
            if r.levelno == logging.WARNING and "param_miner" in r.message]
    assert msgs, "wiring error was not escalated to WARNING"
    assert "NameError" in msgs[0].getMessage()


def test_non_wiring_error_stays_debug(scanner, caplog) -> None:
    def soft():
        raise KeyError("optional header missing")
    with caplog.at_level(logging.DEBUG):
        layer_guard.run_layer(scanner, "csp", soft)
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_success_runs_normally(scanner) -> None:
    seen = []
    layer_guard.run_layer(scanner, "ok", seen.append, 1)
    assert seen == [1]


def test_arguments_are_forwarded(scanner) -> None:
    seen = []
    layer_guard.run_layer(scanner, "ok", lambda a, b, c=None: seen.append((a, b, c)),
                          1, 2, c=3)
    assert seen == [(1, 2, 3)]


def test_budget_exhausted_propagates(scanner) -> None:
    def stop():
        raise BudgetExhausted("request budget spent")
    with pytest.raises(BudgetExhausted):
        layer_guard.run_layer(scanner, "reflected", stop)


# --------------------------------------------------------------------------
# dispatch loops: one broken layer must not kill the rest
# --------------------------------------------------------------------------

def test_page_layers_continue_after_wiring_failure(scanner, caplog,
                                                   monkeypatch) -> None:
    def broken(scanner, url, text):
        raise ImportError("cannot import name 'dom_helpers'")

    def healthy(scanner, url, text):
        scanner._record("healthy")

    monkeypatch.setattr(advanced_layers, "_scan_prototype", broken)
    monkeypatch.setattr(advanced_layers, "_scan_service_worker", healthy)

    with caplog.at_level(logging.WARNING):
        advanced_layers.run_page_layers(scanner, None, "http://t/x", "<p>x</p>")

    assert "healthy" in scanner.ran, \
        "a wiring failure in one layer stopped the layers after it"
    warn = [r for r in caplog.records
            if r.levelno == logging.WARNING and "prototype" in r.message]
    assert warn, "the broken layer was not named in a WARNING"


def test_page_layers_continue_after_soft_failure(scanner, caplog,
                                                 monkeypatch) -> None:
    def broken(scanner, url, text):
        raise KeyError("x")

    def healthy(scanner, url, text):
        scanner._record("healthy")

    monkeypatch.setattr(advanced_layers, "_scan_redirect", broken)
    monkeypatch.setattr(advanced_layers, "_scan_framework", healthy)

    with caplog.at_level(logging.DEBUG):
        advanced_layers.run_page_layers(scanner, None, "http://t/x", "<p>x</p>")

    assert "healthy" in scanner.ran
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_request_layers_are_isolated_too(scanner, monkeypatch) -> None:
    def broken(scanner, req, url):
        raise NameError("_scan_cookie_xss is not defined")

    def healthy(scanner, req, url):
        scanner._record("healthy")

    monkeypatch.setattr(advanced_layers, "_scan_cookie_xss", broken)
    monkeypatch.setattr(advanced_layers, "_scan_error_xss", healthy)

    advanced_layers.run_request_layers(scanner, None, "http://t/x")
    assert "healthy" in scanner.ran


# --------------------------------------------------------------------------
# async drain: attribution + escalation
# --------------------------------------------------------------------------

def _run_agen(coro, caplog):
    async def main():
        sink: list = []
        await _drain_agen(coro, sink, name="L5_advanced_page")
        return sink
    return asyncio_run(main())


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)


def test_drain_agen_escalates_wiring_error(caplog) -> None:
    async def agen():
        raise NameError("advanced_layers is not defined")
        yield  # pragma: no cover -- makes this an async generator

    with caplog.at_level(logging.WARNING):
        sink = _run_agen(agen(), caplog)
    assert sink == []
    msgs = [r for r in caplog.records
            if r.levelno == logging.WARNING and "L5_advanced_page" in r.message]
    assert msgs, "async wiring error was not attributed to its layer"


def test_drain_agen_propagates_budget_stop() -> None:
    async def agen():
        raise BudgetExhausted("request budget spent")
        yield  # pragma: no cover

    with pytest.raises(BudgetExhausted):
        _run_agen(agen(), None)


def test_drain_agen_collects_findings() -> None:
    async def agen():
        yield "f1"
        yield "f2"

    assert _run_agen(agen(), None) == ["f1", "f2"]
