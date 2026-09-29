"""Phase 183 (option B): async --headless wiring.

The unit under test is the OUTERMOST scan() wrapper: which findings get a
real-browser replay, the replay-tuple dedup, the concurrency cap (the
dedicated thread pool IS the cap), evidence re-grading through the same
``_grade_evidence`` the sync engine uses, and the failure degradation path.

Everything runs WITHOUT a browser and WITHOUT network: ``_scan_raw`` is
replaced by a fake generator yielding crafted findings, and
``verifier.verify_headless`` is monkeypatched with a recording fake.
"""
import asyncio
import threading

import pytest

from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.core import verifier as verifier_mod
from xssentinel.core.findings import (Finding, EVIDENCE_OOB,
                                      EVIDENCE_BROWSER_EXECUTED)

_MARKED = "<svg onload=alert('xssp_q_deadbeef')>"


def _finding(**over):
    d = {"url": "http://t/s", "method": "GET", "param": "q",
         "context": "html_element", "payload": _MARKED,
         "severity": "high", "confidence": "high", "detail": "reflected",
         "param_in": "query"}
    d.update(over)
    return Finding(**d)


def _scanner(monkeypatch, findings, verifier=None, cap=1, **kw):
    """Scanner whose layer stack yields ``findings`` and whose browser
    verdict comes from ``verifier`` (default: everything fires)."""
    s = AsyncScanner(use_headless=True, headless_concurrency=cap, **kw)
    s._aiohttp_available = True

    async def fake_raw(url, method="GET", params=None, data=None):
        for f in findings:
            yield f

    s._scan_raw = fake_raw

    calls = {"n": 0, "args": [], "max_concurrent": 0, "_live": 0}
    lock = threading.Lock()

    def fake_verify(url, method, params, data, headers, token, timeout=20):
        with lock:
            calls["n"] += 1
            calls["_live"] += 1
            calls["max_concurrent"] = max(calls["max_concurrent"],
                                          calls["_live"])
            calls["args"].append({"url": url, "method": method,
                                  "params": params, "data": data,
                                  "headers": headers, "token": token})
        try:
            if isinstance(verifier, Exception):
                raise verifier
            import time
            time.sleep(0.05)        # widen the race window for the cap test
            return (verifier or {"available": True, "confirmed": True,
                                 "outcome": "fired",
                                 "detail": "dialogs fired carrying token"})
        finally:
            with lock:
                calls["_live"] -= 1

    monkeypatch.setattr(verifier_mod, "verify_headless", fake_verify)
    return s, calls


async def _collect(s):
    out = []
    async for f in s.scan("http://t/s"):
        out.append(f)
    return out


def test_fired_finding_is_browser_confirmed(monkeypatch):
    s, calls = _scanner(monkeypatch, [_finding()])
    out = asyncio.run(_collect(s))
    assert len(out) == 1
    d = out[0].data
    assert d["headless"]["outcome"] == "fired"
    assert d["evidence_class"] == EVIDENCE_BROWSER_EXECUTED
    assert d["confidence"] == "high"
    # The replay must ride the SAME carrier the finding rode: query param,
    # the exact marked payload, and the extracted probe token.
    call = calls["args"][0]
    assert call["params"] == {"q": _MARKED} and call["data"] is None
    assert call["token"] == "xssp_q_deadbeef"
    assert pool_is_shutdown(s)


def pool_is_shutdown(s):
    return getattr(s, "_headless_pool", None) is None


def test_not_fired_downgrades_confidence(monkeypatch):
    refuted = {"available": True, "confirmed": False, "outcome": "not-fired",
               "detail": "no token dialog"}
    s, _ = _scanner(monkeypatch, [_finding()], verifier=refuted)
    out = asyncio.run(_collect(s))
    d = out[0].data
    assert d["headless"]["outcome"] == "not-fired"
    assert d["confidence"] == "low"
    assert "browser replay did NOT reproduce" in d["detail"]


def test_dedup_same_replay_tuple_verifies_once(monkeypatch):
    s, calls = _scanner(monkeypatch, [_finding(), _finding()])
    out = asyncio.run(_collect(s))
    assert len(out) == 2
    assert calls["n"] == 1
    # The duplicate keeps its original (unverified) shape: no headless dict
    # invented for a replay that never happened.
    assert out[1].data.get("headless") is None


def test_oob_confirmed_finding_skipped(monkeypatch):
    s, calls = _scanner(
        monkeypatch, [_finding(evidence_class=EVIDENCE_OOB, param="ua",
                               payload="xssp_ua_cafe",
                               detail="OOB beacon hit")])
    out = asyncio.run(_collect(s))
    assert calls["n"] == 0
    assert out[0].data.get("headless") is None


def test_placeholder_audit_payload_skipped(monkeypatch):
    s, calls = _scanner(
        monkeypatch, [_finding(payload="(SRI hash mismatch on /app.js)",
                               param="(none)")])
    asyncio.run(_collect(s))
    assert calls["n"] == 0


def test_unattributable_payload_skipped(monkeypatch):
    # No alert() argument and no marker run: verification could only
    # produce an unproven "not-fired", so the wrapper must not verify.
    s, calls = _scanner(monkeypatch, [_finding(payload="';alert(1)//")])
    asyncio.run(_collect(s))
    assert calls["n"] == 0


def test_already_headless_finding_untouched(monkeypatch):
    real = {"available": True, "confirmed": True, "outcome": "fired",
            "detail": "dom layer ran a real browser"}
    s, calls = _scanner(monkeypatch,
                        [_finding(headless=real, type="dom_dynamic")])
    out = asyncio.run(_collect(s))
    assert calls["n"] == 0
    assert out[0].data["headless"] is real     # same object, not replaced


def test_json_carrier_body_finding_skipped(monkeypatch):
    s, calls = _scanner(
        monkeypatch, [_finding(param_in="body", param="user.name",
                               method="POST")])
    s.json_body = {"user": {"name": ""}}
    asyncio.run(_collect(s))
    assert calls["n"] == 0


def test_concurrency_cap_two(monkeypatch):
    fs = [_finding(url=f"http://t/s{i}") for i in range(4)]
    s, calls = _scanner(monkeypatch, fs, cap=2)
    asyncio.run(_collect(s))
    assert calls["n"] == 4
    assert calls["max_concurrent"] <= 2


def test_concurrency_cap_one_is_sequential(monkeypatch):
    fs = [_finding(url=f"http://t/s{i}") for i in range(3)]
    s, calls = _scanner(monkeypatch, fs, cap=1)
    asyncio.run(_collect(s))
    assert calls["n"] == 3
    assert calls["max_concurrent"] == 1


def test_verifier_exception_degrades_to_errored(monkeypatch):
    s, calls = _scanner(monkeypatch, [_finding()],
                        verifier=RuntimeError("chromium exploded"))
    out = asyncio.run(_collect(s))
    d = out[0].data
    assert d["headless"]["outcome"] == "errored"
    assert "async headless verify error" in d["headless"]["detail"]
    # errored keeps the original confidence (grading cannot downgrade
    # without a real verdict) but names the missing evidence class.
    assert d["confidence"] == "high"
    assert d["evidence_class"] == "browser-error"


def test_headless_off_is_pure_passthrough(monkeypatch):
    s = AsyncScanner(use_headless=False)
    s._aiohttp_available = True

    async def fake_raw(url, method="GET", params=None, data=None):
        yield _finding()

    s._scan_raw = fake_raw
    called = []

    def fake_verify(*a, **k):
        called.append(a)
        return {"available": True, "confirmed": True, "outcome": "fired"}

    monkeypatch.setattr(verifier_mod, "verify_headless", fake_verify)
    out = asyncio.run(_collect(s))
    assert len(out) == 1
    assert called == []
    assert out[0].data.get("headless") is None
    assert out[0].data["confidence"] == "high"


def test_replay_carries_auth_headers(monkeypatch):
    s, calls = _scanner(monkeypatch, [_finding()],
                        headers={"X-Base": "1"},
                        auth_headers={"Authorization": "Bearer t"})
    asyncio.run(_collect(s))
    h = calls["args"][0]["headers"]
    assert h["X-Base"] == "1" and h["Authorization"] == "Bearer t"


def test_cli_sync_only_flags_no_longer_list_headless():
    from xssentinel.cli_runner import _ASYNC_SYNC_ONLY_FLAGS
    assert "headless" not in _ASYNC_SYNC_ONLY_FLAGS


@pytest.mark.parametrize("payload,want", [
    (_MARKED, "xssp_q_deadbeef"),
    ("a;window['ale'+'rt']('xssp_q_cafe')//", "xssp_q_cafe"),
    ("alert`xssp_q_beef`", "xssp_q_beef"),
    ("<img src=x onerror=alert('xssp_i_1234')>", "xssp_i_1234"),
    ("no marker at all", None),
])
def test_probe_token_extraction(payload, want):
    assert AsyncScanner._probe_token(payload) == want
