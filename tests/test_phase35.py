"""Unit tests for Phase 35: CSP-aware budget gating (sync) and the
pre-encoding parity in the async scanner.
"""
from __future__ import annotations
import os
import sys
from unittest.mock import patch

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import csp as csp_mod
from xssentinel.core import pre_encode as pe
from xssentinel.core.scanner import Scanner
from xssentinel.core.requester import Requester


class TestStrictInline:
    def test_no_csp_is_not_strict(self):
        assert csp_mod.is_strict_inline("") is False

    def test_unsafe_inline_not_strict(self):
        h = "script-src 'self' 'unsafe-inline'"
        assert csp_mod.is_strict_inline(h) is False

    def test_unsafe_eval_not_strict(self):
        h = "script-src 'self' 'unsafe-eval'"
        assert csp_mod.is_strict_inline(h) is False

    def test_self_only_is_strict(self):
        assert csp_mod.is_strict_inline("script-src 'self'") is True

    def test_default_src_fallback_is_strict(self):
        assert csp_mod.is_strict_inline("default-src 'self'") is True

    def test_none_is_strict(self):
        assert csp_mod.is_strict_inline("script-src 'none'") is True

    def test_nonce_policy_conservatively_not_strict(self):
        h = ("script-src 'nonce-abcdef0123456789' 'strict-dynamic'; "
             "object-src 'none'")
        assert csp_mod.is_strict_inline(h) is False

    def test_no_script_directive_not_strict(self):
        h = "img-src 'self'; style-src 'self'"
        assert csp_mod.is_strict_inline(h) is False


class _FakeResp:
    status_code = 200

    def __init__(self, text, headers=None):
        self.text = text
        self.headers = headers or {}


class _EscapingFakeReq:
    """Filter echo server (optional response headers).

    Phase 95 note: tag/quote characters are STRIPPED from the reflected
    value, not html.escape()d.  An escaping echo now converges to the
    small escaped-reflection budget regardless of CSP (the sandwich
    profile proves the encoder is solid; convergence at 3 beats the CSP
    gate at 4), which would make the strict-vs-plain comparison
    meaningless.  A stripping filter keeps the reflection un-escaped so
    the CSP budget gate is what actually moves the request count."""

    def __init__(self, headers=None):
        self.calls = 0
        self.headers = headers or {}

    def request(self, method, url, params=None, data=None, **kw):
        self.calls += 1
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        for ch in "<>\"'`":
            val = val.replace(ch, "")
        return _FakeResp(f"<html><body><div>{val}"
                         f"</div></body></html>", headers=self.headers)

    def clone(self):
        return self

    def invalidate(self, url):
        pass


class TestCSPBudgetGate:
    def _run(self, headers):
        sc = Scanner(requester=Requester(), advanced_layers=False,
                     verbose=False, max_payloads=6, max_transforms=4)
        fake = _EscapingFakeReq(headers=headers)
        with patch("xssentinel.core.scanner.wafmod.detect",
                   lambda r: {"waf": None, "blocked": False,
                              "reason": None}):
            sc._scan_param(fake, "http://t/x", "GET",
                           {"q": "orig"}, {}, "q", False)
        return fake.calls

    def test_strict_csp_uses_fewer_requests(self):
        plain = self._run({})
        strict = self._run({"Content-Security-Policy": "script-src 'self'"})
        assert strict < plain, (
            f"strict CSP should cut the budget (strict={strict}, "
            f"plain={plain})")

    def test_bypassable_csp_keeps_full_budget(self):
        plain = self._run({})
        bypassable = self._run({
            "Content-Security-Policy":
                "script-src 'self' 'unsafe-inline'"})
        assert bypassable >= plain - 2  # same budget (marker+profile probe)

    def test_gate_recorded_in_coverage(self):
        sc = Scanner(requester=Requester(), advanced_layers=False,
                     verbose=False, max_payloads=4, max_transforms=2)
        fake = _EscapingFakeReq(
            headers={"Content-Security-Policy": "script-src 'self'"})
        with patch("xssentinel.core.scanner.wafmod.detect",
                   lambda r: {"waf": None, "blocked": False,
                              "reason": None}):
            sc._scan_param(fake, "http://t/x", "GET",
                           {"q": "orig"}, {}, "q", False)
        layer_ids = set()
        for ep in sc.coverage.endpoints():
            layer_ids.update(ep.layers.keys())
        assert "L1_csp_gate" in layer_ids


class TestAsyncPreEncodeParity:
    def test_async_module_imports_and_has_helper(self):
        from xssentinel.core import async_scanner as asc
        assert hasattr(asc, "AsyncScanner")
        assert hasattr(asc.AsyncScanner, "_try_pre_encoded_async")
        assert asc.pre_mod is pe


class TestRCDATAHardening:
    """Phase 35 hardening: lxml tree fixup can hoist tags out of RCDATA
    elements; the verifier must still refuse to confirm inert reflections."""

    def test_polyglot_inside_title_is_inert(self):
        from xssentinel.core import verifier
        # The exact FP shape observed in benchmarking: raw polyglot text
        # reflected inside <title>...</title>.
        raw = ('<!DOCTYPE html><html><head><title>'
               '"\'>"</script></style>"' + '-->' + '><body onload='
               "alert('xss_poly_1b85d62d')>"
               '</title></head><body><p>content</p></body></html>')
        v = verifier.verify_semantic(raw, 'xss_poly_1b85d62d')
        assert v["confirmed"] is False
        assert "RCDATA" in v["detail"]

    def test_true_breakout_after_title_still_confirms(self):
        from xssentinel.core import verifier
        html = ("<title>v</title>"
                "<script>alert('tok123')</script>")
        v = verifier.verify_semantic(html, 'tok123')
        assert v["confirmed"] is True

    def test_polyglot_inside_textarea_is_inert(self):
        from xssentinel.core import verifier
        html = ("<textarea>"
                "</script><body onload=alert('tok456')>"
                "</textarea>")
        v = verifier.verify_semantic(html, 'tok456')
        assert v["confirmed"] is False


class TestUrlJavascriptEscapedWindow:
    """Phase 43 (async-benchmark FP): a literal ``javascript:`` substring
    survives html.escape, so an attribute-ESCAPED reflection must NOT be
    confirmed via the raw-text url_javascript/meta_refresh fallback.
    A LIVE href=javascript: URI must still confirm, and (Phase 168) a
    ``javascript:`` URL in a meta refresh must NOT -- see
    ``test_meta_refresh_javascript_is_not_a_sink``."""

    def test_escaped_attr_text_with_javascript_is_inert(self):
        from xssentinel.core import verifier
        html = ('<input type="text" value="'
                "&lt;iframe src=javascript:alert(&#x27;xssv_esc01&#x27;)&gt;"
                '">')
        v = verifier.verify_semantic(html, "xssv_esc01")
        assert v["confirmed"] is False

    def test_live_href_javascript_still_confirms(self):
        from xssentinel.core import verifier
        html = "<a href=\"javascript:alert('xssv_live01')\">x</a>"
        v = verifier.verify_semantic(html, "xssv_live01")
        assert v["confirmed"] is True
        assert v["context"] == "url_javascript"

    def test_meta_refresh_javascript_is_not_a_sink(self):
        """Phase 168: a ``javascript:`` URL in a meta refresh never runs.

        This test used to assert the opposite, and that was only ever true
        while confirmation was text-position based (a literal ``javascript:``
        near the token).  Measured in Chromium over a real HTTP origin
        (``probe_meta_refresh_scheme.py``), with four controls in the same session:

            inline <script>document.title=1</script>   executes  (sentinel OK)
            iframe.src = javascript:CODE               executes  (scheme OK)
            meta refresh -> http://.../child           navigates (/child served)
            meta refresh -> about:blank                navigates
            meta refresh -> javascript:CODE            nothing at all

        The last two lines are the pair that matters: the refresh machinery does
        honour a non-http scheme, so ``javascript:`` being inert there is that
        scheme being refused, not the URL being skipped as un-navigable.  The
        structural pass is now element-aware (``_JS_URI_EXECUTES``) and the
        raw-text fallback cannot re-confirm what it refused
        (``_attribute_hosting_token``).  ``context`` still says
        ``meta_refresh``: the flow is real, the execution claim was not.
        """
        from xssentinel.core import verifier
        html = ("<meta http-equiv=\"refresh\" "
                "content=\"0;url=javascript:alert('xssv_mr01')\">")
        v = verifier.verify_semantic(html, "xssv_mr01")
        assert v["confirmed"] is False
        assert v["context"] == "meta_refresh"

    def test_escaped_meta_refresh_text_is_inert(self):
        from xssentinel.core import verifier
        html = ('<p>learn more at '
                "&lt;meta http-equiv=refresh content=0;url=javascript:" 
                "alert(&#x27;xssv_mr02&#x27;)&gt; thanks</p>")
        v = verifier.verify_semantic(html, "xssv_mr02")
        assert v["confirmed"] is False
