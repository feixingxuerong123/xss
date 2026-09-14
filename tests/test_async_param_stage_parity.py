"""Phase 132 parity lock: the async engine must reach its late stages.

The bug this locks: ``_probe_param`` returned the moment a payload was
confirmed, so on any endpoint where the plain payload worked -- the easy
majority -- the position shift, the CSP-nonce exploit and the whole L7
parameter family (mutation / DOM clobber / template / polyglot / markup)
never ran.  Sync breaks out of its loop instead and reaches
``_run_advanced_layers`` unconditionally (scanner.py:667 gates the loop on
``not confirmed``; :707 calls the layers with no gate).

Measured effect on the project's own case pos-clobber-01, before/after:
    sync   45 requests, findings = reflected + dom_clobber + dom
    before 13 requests, findings = reflected + dom          (FN)
    after  16 requests, findings = reflected + dom_clobber + dom

These tests drive ``_probe_param`` with a fake aiohttp session and a
stubbed advanced-layers stage, so they need no network and no browser.
"""
from __future__ import annotations

import asyncio
import html
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.async_scanner import AsyncScanner  # noqa: E402


class _Resp:
    def __init__(self, text):
        self._t = text
        self.headers = {}

    async def text(self):
        return self._t

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    """Echoes ``q`` raw (live markup) or HTML-escaped, like the real echo."""

    def __init__(self, escape=False):
        self.calls = []
        self.escape = escape

    def request(self, method, url, params=None, data=None,
                headers=None, proxy=None):
        self.calls.append({"params": dict(params or {}),
                           "data": dict(data or {})})
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        body = html.escape(val, quote=True) if self.escape else val
        return _Resp(f"<html><body><div>{body}</div></body></html>")


def _collect(params, escape=False, monkeypatch=None):
    """Drive ``_probe_param`` with the advanced stage stubbed out.

    Returns ``(findings, session, advanced_calls)`` where
    ``advanced_calls`` records the (param, is_body) pairs the engine
    handed to ``_scan_advanced_param_layers``.
    """
    advanced_calls = []

    async def _stub(self, url, method, params, data, param, is_body,
                    marker, resp_text):
        advanced_calls.append((param, is_body))
        if False:                     # pragma: no cover -- makes it a gen
            yield None

    monkeypatch.setattr(AsyncScanner, "_scan_advanced_param_layers", _stub)

    async def run():
        asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0)
        asc._semaphore = asyncio.Semaphore(4)
        session = _Session(escape=escape)
        out = []
        async for f in asc._probe_param(session, "http://t/x", "GET", "q",
                                        params, {}, False, "x"):
            out.append(f)
        return out, session

    findings, session = asyncio.run(run())
    return findings, session, advanced_calls


# --------------------------------------------------------------------------
# 1. the advanced stage runs even after the payload loop confirms
# --------------------------------------------------------------------------

def test_advanced_layers_reached_on_a_confirmed_reflection(monkeypatch):
    """The regression: this was empty because the payload loop returned."""
    findings, _session, advanced = _collect({"q": "probe"},
                                            monkeypatch=monkeypatch)
    assert findings, "sanity: the live echo must confirm"
    assert findings[0].data["type"] == "reflected"
    assert advanced == [("q", False)], (
        "async skipped the L7 parameter layers on a confirmed reflection "
        f"-- that is the FN this test locks (advanced calls: {advanced})")


def test_advanced_layers_reached_on_an_unconfirmed_reflection(monkeypatch):
    """The pre-existing path must keep working (escaped echo: no confirm)."""
    findings, _session, advanced = _collect({"q": "probe"}, escape=True,
                                            monkeypatch=monkeypatch)
    assert findings == []
    assert advanced == [("q", False)], advanced


def test_advanced_layers_reached_once_per_parameter(monkeypatch):
    """Each probed parameter hands off to the advanced stage exactly once.

    (The engine is told the parameter name, so an empty ``params`` dict is
    still probed -- ``_probe_kv`` injects it.)
    """
    findings, _session, advanced = _collect({}, monkeypatch=monkeypatch)
    assert findings, "sanity: the injected parameter must still reflect"
    assert advanced == [("q", False)], advanced


# --------------------------------------------------------------------------
# 2. the stages that sync gates off must stay gated off
# --------------------------------------------------------------------------

def test_position_shift_does_not_refire_after_confirmation(monkeypatch):
    """Sync gates the position shift on ``not confirmed`` (scanner.py:693).

    Without that gate async would re-fire into the body on every already
    confirmed param -- extra requests and a duplicate finding type.
    """
    findings, session, _advanced = _collect({"q": "probe"},
                                            monkeypatch=monkeypatch)
    assert findings
    assert any(f.data["type"] == "reflected" for f in findings)
    assert not any("position_shift" in str(f.data.get("transform"))
                   for f in findings), "position shift re-fired after confirm"
    body_calls = [c for c in session.calls if c["data"].get("q")]
    assert not body_calls, (
        "position shift must not re-fire into the body once confirmed")


def test_position_shift_still_refires_when_unconfirmed(monkeypatch):
    """The escaped path keeps its pre-existing behaviour."""
    findings, session, _advanced = _collect({"q": "probe"}, escape=True,
                                            monkeypatch=monkeypatch)
    assert findings == []
    body_calls = [c for c in session.calls if c["data"].get("q")]
    assert body_calls, "position shift no longer re-fires into the body"
