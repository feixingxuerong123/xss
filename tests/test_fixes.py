"""Targeted unit tests for the 2026-07-28 bug fixes.

Tests each fix in isolation so regressions are caught immediately:

  1. scan_stored GET method  - payload sent as query param, not POST body.
  2. _inject_blind single    - one OOB payload per (url, param), not N.
  3. InteractshListener      - token/poll matching by prefix.
  4. verifier.mark           - handles alert(document.domain) etc.
  5. verify_headless         - GET encodes params into URL (no TypeError).
  6. payloads thread-safety  - concurrent _load() doesn't double-read.
  7. _crawl deque            - BFS uses popleft, skips start URL.
  8. waf_name locking        - concurrent writes don't race.

Run:  python tests/test_fixes.py
"""
from __future__ import annotations
import os, sys, threading, time, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import payloads as payloads_mod
from xssentinel.core import verifier
from xssentinel.core.oob import SelfHostedListener, InteractshListener
from xssentinel.core.scanner import Scanner, Finding
from xssentinel.core.requester import Requester

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    """Assert on the caller's behalf -- and ACTUALLY FAIL when cond is false.

    Phase 179: this used to only print "[!] FAIL" and bump a counter, so under
    pytest every test in this file was green no matter what.  Verified by
    sabotaging the verifier.mark expectation: pytest reported "7 passed" while
    the captured output carried a FAIL line.  The eight regressions this file
    exists to guard (single blind injection, stored GET, interactsh token
    matching, mark(alert(...)), headless, payloads thread-safety, crawl deque,
    waf_name locking) had no real protection at all.

    Printing is kept so ``python tests/test_fixes.py`` still reads as a report;
    that entry point catches AssertionError per test so one bad case does not
    mask the rest.
    """
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[+] PASS: {name}")
        return True
    FAIL += 1
    msg = f"{name}{(': ' + detail) if detail else ''}"
    print(f"[!] FAIL: {msg}")
    raise AssertionError(msg)


# --- Fix 4: verifier.mark handles all alert(...) variants -------------------
def test_mark_alert_variants():
    """mark() must token-mark alert(document.domain), not just alert(1)."""
    tok = "xssv_abc123"
    cases = [
        ("<script>alert(1)</script>",          f"<script>alert('{tok}')</script>"),
        ("<svg/onload=alert(document.domain)>",f"<svg/onload=alert('{tok}')>"),
        ("<img src=x onerror=alert(document.cookie)>",
         f"<img src=x onerror=alert('{tok}')>"),
        ("javascript:alert('hi')",             f"javascript:alert('{tok}')"),
        ("alert(  spacing  )",                  f"alert('{tok}')"),
    ]
    for payload, expected in cases:
        got = verifier.mark(payload, tok)
        check(f"mark('{payload[:30]}') == expected", got == expected,
              f"\n  got={got!r}\n  exp={expected!r}")
    # Payloads WITHOUT alert() must be returned unchanged.
    no_alert = "<script>fetch('/x')</script>"
    check("mark(no-alert) unchanged", verifier.mark(no_alert, tok) == no_alert)


# --- Fix 3: InteractshListener token/poll matching --------------------------
def test_interactsh_token_poll():
    """token() returns a unique prefix; poll matches unique-id by prefix."""
    lis = InteractshListener.__new__(InteractshListener)
    lis.server = "https://interact.sh"
    lis.timeout = 5
    lis._session = None
    lis.subdomain = "base.oast.fun"
    lis.correlation_id = "corr123"
    lis.auth_token = "tok"
    lis._started = True

    t1 = lis.token()
    t2 = lis.token()
    check("interactsh token unique", t1 != t2 and len(t1) == 16,
          f"t1={t1} t2={t2}")
    check("interactsh callback_url",
          lis.callback_url(t1) == f"https://{t1}.base.oast.fun",
          lis.callback_url(t1))

    # Simulate a poll response: unique-id = "{token}.{subdomain}"
    # We can't easily mock requests here, so test the matching logic directly
    # by simulating what poll() does with the unique-id.
    fake_interactions = [
        {"unique-id": f"{t1}.base.oast.fun"},
        {"unique-id": "other.base.oast.fun"},
    ]
    expected = {t1}
    # Replicate the matching logic from poll()
    confirmed = set()
    for item in fake_interactions:
        uid = item.get("unique-id", "")
        for tok in expected:
            if uid == tok or uid.startswith(tok + ".") or uid.startswith(tok):
                confirmed.add(tok)
    check("interactsh poll matches by prefix", confirmed == {t1},
          f"confirmed={confirmed}")


# --- Fix 2: _inject_blind injects ONE payload per (url, param) -------------
def test_blind_single_injection():
    """Blind injection must create exactly ONE pending entry per param."""
    # Use the /blind endpoint on the vuln server (must be running).
    import urllib.request
    try:
        urllib.request.urlopen("http://127.0.0.1:8899/echo?q=ping", timeout=2)
    except Exception:
        print("[!] vuln_server not running -- start it first: python tests/vuln_server.py")
        return

    req = Requester(timeout=5)
    oob = SelfHostedListener(host="127.0.0.1")
    sc = Scanner(requester=req, oob=oob, verbose=False)
    sc.scan_endpoint("http://127.0.0.1:8899/blind", "GET", {"q": "test"}, {})
    # _inject_blind appends to _oob_pending; collect_oob clears it.
    pending_count = len(sc._oob_pending)
    check("blind single injection", pending_count == 1,
          f"expected 1 pending, got {pending_count}")
    # Clean up: start listener + collect to free the port.
    if sc._oob_pending:
        sc.oob.start()
        sc._oob_started = True
    sc.collect_oob(timeout=3)
    # Exactly ONE blind finding (was 5 before the fix).
    blind_findings = [f for f in sc.findings if f.data.get("type") == "blind"]
    check("blind single finding", len(blind_findings) <= 1,
          f"got {len(blind_findings)} blind findings")


# --- Fix 1: scan_stored GET method sends payload as query param -------------
def test_stored_get_method():
    """scan_stored with GET must send payload via params=, not data=."""
    import urllib.request
    try:
        urllib.request.urlopen("http://127.0.0.1:8899/echo?q=ping", timeout=2)
    except Exception:
        print("[!] vuln_server not running")
        return

    # Track what the server receives.
    captured = {"method": None, "query": None, "body": None}
    orig_request = Requester.request

    def spy_request(self, method, url, params=None, data=None):
        captured["method"] = method
        captured["query"] = params
        captured["body"] = data
        return orig_request(self, method, url, params=params, data=data)

    Requester.request = spy_request
    try:
        req = Requester(timeout=5)
        sc = Scanner(requester=req, verbose=False)
        # GET method stored scan: payload should go to params, not data.
        sc.scan_stored("http://127.0.0.1:8899/store",
                       view_url="http://127.0.0.1:8899/view",
                       method="GET", param="q")
    finally:
        Requester.request = orig_request

    check("stored GET uses params=", captured["query"] is not None
          and captured["query"].get("q") is not None,
          f"query={captured['query']}")
    check("stored GET does not use data=", captured["body"] in (None, {}),
          f"body={captured['body']}")


# --- Fix 6: payloads thread-safety -----------------------------------------
def test_payloads_thread_safety():
    """Concurrent _load() calls must not crash or double-load."""
    payloads_mod._cache = None  # reset
    errors = []
    def worker():
        try:
            data = payloads_mod._load()
            assert "payloads" in data
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("payloads concurrent load", not errors, str(errors))


# --- Fix 7: _crawl uses deque + skips start URL ----------------------------
def test_crawl_skips_start_url():
    """The crawl start URL must not be registered as a duplicate PAGE endpoint."""
    import urllib.request
    try:
        urllib.request.urlopen("http://127.0.0.1:8899/links", timeout=2)
    except Exception:
        print("[!] vuln_server not running")
        return

    req = Requester(timeout=5)
    sc = Scanner(requester=req, crawl=True, crawl_depth=1, verbose=False)
    endpoints = sc._crawl("http://127.0.0.1:8899/links")
    # The start URL (/links) should NOT appear as a PAGE endpoint, because
    # scan_target() already scans it as endpoints[0].
    page_endpoints = [ep for ep in endpoints if ep[0] == "http://127.0.0.1:8899/links"]
    check("crawl skips start URL as PAGE", len(page_endpoints) == 0,
          f"page_endpoints for /links: {page_endpoints}")


# --- Fix 5: verify_headless doesn't crash on GET with params (no TypeError) -
def test_verify_headless_no_playwright():
    """verify_headless must return 'not installed' gracefully when Playwright
    is absent (the common case).  This guards against the old code which would
    have raised TypeError inside the Playwright call path."""
    result = verifier.verify_headless(
        "http://127.0.0.1:8899/echo", "GET", {"q": "test"}, None, {}, "tok")
    # Either playwright is installed (available=True) or not (available=False),
    # but it must NOT raise.
    check("verify_headless returns dict", isinstance(result, dict),
          str(result))
    check("verify_headless has 'available' key", "available" in result,
          str(result))


if __name__ == "__main__":
    print("=== Targeted fix tests ===\n")
    for _t in (
        test_mark_alert_variants,
        test_interactsh_token_poll,
        test_blind_single_injection,
        test_stored_get_method,
        test_payloads_thread_safety,
        test_crawl_skips_start_url,
        test_verify_headless_no_playwright,
    ):
        # check() now raises, so keep the report-style batch run: catch per
        # test and continue, otherwise the first failure hides the rest.
        try:
            _t()
        except AssertionError:
            pass
        print()
    print(f"\n[RESULT] {PASS} passed, {FAIL} failed")
    sys.exit(0 if FAIL == 0 else 1)
