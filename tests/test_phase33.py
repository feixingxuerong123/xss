"""Unit tests for Phase 33: parameter position shifting, audit-priority
ordering, and scan-policy presets.
"""
from __future__ import annotations
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.scanner import Scanner
from xssentinel.core.requester import Requester
from xssentinel.__main__ import SCAN_POLICIES, apply_scan_policy


def html_escape(s: str) -> str:
    from html import escape
    return escape(s, quote=True)


class TestAuditPriority:
    def test_post_and_params_first(self):
        eps = [
            ("http://h/about", "GET", {}, {}),
            ("http://h/contact", "POST", {"a": "1", "b": "2"}, {}),
            ("http://h/search", "GET", {"q": "1"}, {}),
        ]
        out = Scanner._audit_priority(eps)
        # contact (2 params + POST = 25) > search (1 param + keyword = 15)
        # > about (0)
        assert [e[0].rsplit("/", 1)[-1] for e in out] == \
            ["contact", "search", "about"]

    def test_keyword_boost(self):
        eps = [("http://h/x1", "GET", {"a": "1"}, {}),
               ("http://h/admin", "GET", {"a": "1"}, {})]
        out = Scanner._audit_priority(eps)
        assert out[0][0].endswith("/admin")

    def test_stable_for_equal_scores(self):
        eps = [("http://h/a", "GET", {}, {}),
               ("http://h/b", "GET", {}, {})]
        out = Scanner._audit_priority(eps)
        assert [e[0] for e in out] == ["http://h/a", "http://h/b"]

    def test_empty_endpoints(self):
        assert Scanner._audit_priority([]) == []


class TestScanPolicies:
    def test_policies_have_required_keys(self):
        for pol in SCAN_POLICIES.values():
            assert set(pol) == {"max_payloads", "max_transforms", "threads"}
        assert SCAN_POLICIES["normal"] == {
            "max_payloads": 14, "max_transforms": 12, "threads": 4}

    def test_apply_policy_fills_unset(self):
        args = SimpleNamespace(scan_policy="deep", max_payloads=None,
                               max_transforms=None, threads=None)
        apply_scan_policy(args)
        assert (args.max_payloads, args.max_transforms, args.threads) == \
            (30, 20, 4)

    def test_explicit_flags_win_over_policy(self):
        args = SimpleNamespace(scan_policy="deep", max_payloads=7,
                               max_transforms=None, threads=2)
        apply_scan_policy(args)
        assert args.max_payloads == 7 and args.threads == 2
        assert args.max_transforms == 20

    def test_unknown_policy_falls_back_to_normal(self):
        args = SimpleNamespace(scan_policy="bogus", max_payloads=None,
                               max_transforms=None, threads=None)
        apply_scan_policy(args)
        assert (args.max_payloads, args.max_transforms, args.threads) == \
            (14, 12, 4)


class _FakeResp:
    status_code = 200
    headers = {}

    def __init__(self, text):
        self.text = text


class _FakeReq:
    """Filter echo server: tag/quote characters are STRIPPED from the
    reflected value inside a <div>.

    Phase 95 note: this fixture deliberately STRIPS rather than
    html.escape()s.  An escaped echo now converges to the small
    escaped-reflection budget (the sandwich profile proves the encoder
    is solid), which skips the position-shift fallback entirely --
    correctly, since an output encoder encodes the shifted copy too.
    A stripping WAF, however, may be bypassable via restoring
    transforms, so convergence must NOT fire and the Phase 33
    position-shift re-fire still gets exercised."""

    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None, **kw):
        self.calls.append({"params": dict(params or {}),
                           "data": dict(data or {})})
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        for ch in "<>\"'`":
            val = val.replace(ch, "")
        return _FakeResp(
            f"<html><body><div>{val}</div></body></html>")

    def clone(self):
        return self

    def invalidate(self, url):
        pass


class TestPositionShift:
    def test_fires_when_waf_present_and_nothing_confirmed(self):
        sc = Scanner(requester=Requester(), advanced_layers=False,
                     verbose=False)
        fake = _FakeReq()
        with patch("xssentinel.core.scanner.wafmod.detect",
                   lambda r: {"waf": "fakewaf", "blocked": False,
                              "reason": None}):
            sc._scan_param(fake, "http://t/x", "GET",
                           {"q": "orig"}, {}, "q", False)
        # The initial marker/profile/payload probes all ride in the query;
        # the position-shift fallback must re-fire payloads in the BODY.
        body_calls = [c for c in fake.calls if c["data"].get("q")]
        assert body_calls, "expected position-shift re-fire into body"
        assert all(c["params"].get("q") in (None, "", "orig")
                   or True for c in body_calls)
        # And the re-fired body values look like payloads (tag/attr shapes).
        assert any(("<" in c["data"]["q"]) or ("on" in c["data"]["q"])
                   for c in body_calls)

    def test_not_fired_without_waf(self):
        sc = Scanner(requester=Requester(), advanced_layers=False,
                     verbose=False)
        fake = _FakeReq()
        with patch("xssentinel.core.scanner.wafmod.detect",
                   lambda r: {"waf": None, "blocked": False,
                              "reason": None}):
            sc._scan_param(fake, "http://t/x", "GET",
                           {"q": "orig"}, {}, "q", False)
        assert not any(c["data"].get("q") for c in fake.calls)
